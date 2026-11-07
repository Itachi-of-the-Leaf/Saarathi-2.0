import json

import httpx
import pytest

from saarathi.core.coordinator import AuthorizationError, Coordinator
from saarathi.core.risk_engine import RiskEngine
from saarathi.database import TaskRepository, get_db_reader, init_db
from saarathi.integrations.github import GitHubVerifier
from saarathi.integrations.switch_commands import SwitchCommandError, SwitchCommandHandler
from saarathi.services.auditor import AuditorEngine


@pytest.mark.asyncio
async def test_structured_switch_commands_use_authoritative_backend(tmp_path):
    db_path = str(tmp_path / "switch_commands.db")
    await init_db(db_path)
    coordinator = Coordinator(db_path)
    repository = TaskRepository(db_path)
    handler = SwitchCommandHandler(coordinator, repository, RiskEngine(db_path))

    created = await handler.execute(
        {
            "action": "create_task",
            "request_id": "create-1",
            "title": "Build command adapter",
            "expected_paths": ["saarathi/**"],
            "owner_member_id": "samarth",
        },
        "room_switch_demo",
        "soham",
        "evt-create-1",
    )
    task_id = created["task_id"]

    fetched = await handler.execute(
        {"action": "get_task", "request_id": "get-1", "task_id": task_id},
        "room_switch_demo",
        "samarth",
        "evt-get-1",
    )
    assert fetched["task"]["task_id"] == task_id
    assert fetched["task"]["owner_member_id"] == "samarth"

    listed = await handler.execute(
        {"action": "list_tasks", "request_id": "list-1", "filter_owner_member_id": "samarth"},
        "room_switch_demo",
        "samarth",
        "evt-list-1",
    )
    assert [task["task_id"] for task in listed["tasks"]] == [task_id]

    await handler.execute(
        {
            "action": "assign_task",
            "request_id": "assign-1",
            "task_id": task_id,
            "owner_member_id": "atharva",
        },
        "room_switch_demo",
        "soham",
        "evt-assign-1",
    )
    assert (await repository.get_task(task_id))["owner_member_id"] == "atharva"

    with pytest.raises(AuthorizationError):
        await handler.execute(
            {
                "action": "assign_task",
                "request_id": "assign-2",
                "task_id": task_id,
                "owner_member_id": "parth",
            },
            "room_switch_demo",
            "samarth",
            "evt-assign-2",
        )


@pytest.mark.asyncio
async def test_structured_status_dependencies_and_blockers(tmp_path):
    db_path = str(tmp_path / "switch_dependency_commands.db")
    await init_db(db_path)
    coordinator = Coordinator(db_path)
    repository = TaskRepository(db_path)
    handler = SwitchCommandHandler(coordinator, repository, RiskEngine(db_path))

    first = await handler.execute(
        {
            "action": "create_task",
            "request_id": "create-a",
            "title": "Dependency A",
            "expected_paths": ["src/**"],
        },
        "room_switch_demo",
        "samarth",
        "evt-a",
    )
    second = await handler.execute(
        {
            "action": "create_task",
            "request_id": "create-b",
            "title": "Dependency B",
            "expected_paths": ["tests/**"],
        },
        "room_switch_demo",
        "samarth",
        "evt-b",
    )
    task_a = first["task_id"]
    task_b = second["task_id"]
    await coordinator.set_task_dependencies("room_switch_demo", "soham", task_b, [task_a])

    dependencies = await handler.execute(
        {"action": "get_dependencies", "request_id": "deps-1", "task_id": task_b},
        "room_switch_demo",
        "samarth",
        "evt-deps-1",
    )
    assert [task["task_id"] for task in dependencies["prerequisites"]] == [task_a]

    blockers = await handler.execute(
        {"action": "get_blockers", "request_id": "blockers-1", "task_id": task_b},
        "room_switch_demo",
        "samarth",
        "evt-blockers-1",
    )
    assert [task["task_id"] for task in blockers["blocked_by"]] == [task_a]

    updated = await handler.execute(
        {
            "action": "update_task_status",
            "request_id": "status-1",
            "task_id": task_a,
            "status": "IN_PROGRESS",
        },
        "room_switch_demo",
        "samarth",
        "evt-status-1",
    )
    assert updated["task"]["status"] == "IN_PROGRESS"

    blocked = await handler.execute(
        {
            "action": "update_task_status",
            "request_id": "status-2",
            "task_id": task_a,
            "status": "BLOCKED",
            "blocker_reason": "Waiting for review",
        },
        "room_switch_demo",
        "samarth",
        "evt-status-2",
    )
    assert blocked["task"]["status"] == "BLOCKED"
    assert blocked["task"]["blocker"] == "Waiting for review"


@pytest.mark.asyncio
async def test_auditor_emits_correlated_structured_response_and_rejects_invalid_input(tmp_path):
    db_path = str(tmp_path / "switch_event_commands.db")
    await init_db(db_path)
    engine = AuditorEngine(db_path)

    await engine._process_inbox_event(
        {
            "id": "evt-structured-create",
            "type": "saarathi.command",
            "room_id": "room_switch_demo",
            "user_id": "soham",
            "command": {
                "action": "create_task",
                "request_id": "corr-1",
                "title": "Structured task",
                "expected_paths": ["src/**"],
            },
        }
    )
    await engine._process_inbox_event(
        {
            "id": "evt-structured-invalid",
            "type": "saarathi.command",
            "room_id": "room_switch_demo",
            "user_id": "soham",
            "command": {"action": "get_task", "request_id": "corr-2"},
        }
    )

    async with get_db_reader(db_path) as db:
        cursor = await db.execute("SELECT body FROM outbox ORDER BY created_at ASC")
        responses = [json.loads(row["body"]) for row in await cursor.fetchall()]
    assert responses[0]["ok"] is True
    assert responses[0]["request_id"] == "corr-1"
    assert responses[1]["ok"] is False
    assert responses[1]["request_id"] == "corr-2"
    assert responses[1]["error"]["code"] == "invalid_command"


@pytest.mark.asyncio
async def test_structured_submit_proof_returns_github_evidence_and_completes_atomically(tmp_path):
    db_path = str(tmp_path / "switch_proof_commands.db")
    await init_db(db_path)
    head_sha = "abc1234567890abcdef1234567890abcdef1234"

    def github_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/42/files" in url:
            return httpx.Response(200, json=[{"filename": "src/core.py", "status": "modified"}])
        if "/pulls/42" in url:
            return httpx.Response(200, json={"user": {"login": "samarth"}, "head": {"sha": head_sha}})
        if "/check-runs" in url:
            return httpx.Response(
                200,
                json={
                    "check_runs": [
                        {
                            "id": 101,
                            "name": "test",
                            "head_sha": head_sha,
                            "status": "completed",
                            "conclusion": "success",
                            "started_at": "2026-11-07T10:00:00Z",
                            "completed_at": "2026-11-07T10:01:00Z",
                            "app": {"id": 1, "slug": "github-actions"},
                            "run_attempt": 1,
                        },
                        {
                            "id": 102,
                            "name": "lint",
                            "head_sha": head_sha,
                            "status": "completed",
                            "conclusion": "success",
                            "started_at": "2026-11-07T10:00:00Z",
                            "completed_at": "2026-11-07T10:01:00Z",
                            "app": {"id": 1, "slug": "github-actions"},
                            "run_attempt": 1,
                        },
                    ]
                },
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(github_handler)) as client:
        coordinator = Coordinator(db_path, verifier=GitHubVerifier(client=client))
        repository = TaskRepository(db_path)
        handler = SwitchCommandHandler(coordinator, repository, RiskEngine(db_path))
        created = await handler.execute(
            {
                "action": "create_task",
                "request_id": "proof-create",
                "title": "Prove GitHub work",
                "expected_paths": ["src/**"],
            },
            "room_switch_demo",
            "samarth",
            "evt-proof-create",
        )
        task_id = created["task_id"]
        await handler.execute(
            {"action": "update_task_status", "request_id": "proof-start", "task_id": task_id, "status": "IN_PROGRESS"},
            "room_switch_demo",
            "samarth",
            "evt-proof-start",
        )
        result = await handler.execute(
            {
                "action": "submit_proof",
                "request_id": "proof-submit",
                "task_id": task_id,
                "pr_url": "https://github.com/switch-org/switch-core/pull/42",
            },
            "room_switch_demo",
            "samarth",
            "evt-proof-submit",
            delivery_target={"channel_id": "C0123456789", "thread_ts": "1730977200.123456"},
        )

    verification = result["verification"]
    assert verification["status"] == "VERIFIED"
    assert verification["author_login"] == "samarth"
    assert verification["head_sha"] == head_sha
    assert verification["changed_paths"] == ["src/core.py"]
    assert {check["name"] for check in verification["selected_checks"]} == {"test", "lint"}
    assert (await repository.get_task(task_id))["status"] == "COMPLETE"
    async with get_db_reader(db_path) as db:
        cursor = await db.execute(
            "SELECT destination, destination_json FROM outbox WHERE body LIKE '%VERIFIED & COMPLETE%'"
        )
        completion_notice = await cursor.fetchone()
    assert completion_notice["destination"] == "slack"
    assert json.loads(completion_notice["destination_json"])["thread_ts"] == "1730977200.123456"

    with pytest.raises(SwitchCommandError):
        await handler.execute(
            {
                "action": "update_task_status",
                "request_id": "direct-complete",
                "task_id": task_id,
                "status": "COMPLETE",
            },
            "room_switch_demo",
            "samarth",
            "evt-direct-complete",
        )

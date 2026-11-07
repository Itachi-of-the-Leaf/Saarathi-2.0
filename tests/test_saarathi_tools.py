import json

import pytest

from saarathi.database import get_db_reader, init_db
from saarathi_tools import SaarathiToolBridge, call_tool


@pytest.mark.asyncio
async def test_tool_bridge_creates_and_reschedules_deadline(tmp_path):
    db_path = str(tmp_path / "tool_bridge.db")
    bridge = SaarathiToolBridge(db_path)

    created = await bridge.create_task_with_deadline(
        room_id="room_switch_demo",
        actor_id="samarth",
        title="Tool-created task",
        due_in_minutes=15,
        scope=["src/**"],
    )
    assert created["status"] == "CREATED"
    assert created["due_at"] is not None

    scheduled = await bridge.schedule_deadline(
        "room_switch_demo", "samarth", created["task_id"], 30
    )
    assert scheduled["status"] == "SCHEDULED"
    assert scheduled["version"] == 2

    async with get_db_reader(db_path) as db:
        cursor = await db.execute(
            "SELECT due_at, version FROM tasks WHERE task_id = ?",
            (created["task_id"],),
        )
        task = await cursor.fetchone()
        event_cursor = await db.execute(
            "SELECT kind, details_json FROM task_events WHERE task_id = ? ORDER BY created_at DESC LIMIT 1",
            (created["task_id"],),
        )
        event = await event_cursor.fetchone()

    assert task["version"] == 2
    assert task["due_at"] == scheduled["due_at"]
    assert event["kind"] == "TASK_DEADLINE_UPDATED"
    assert json.loads(event["details_json"])["due_at"] == scheduled["due_at"]


@pytest.mark.asyncio
async def test_tool_bridge_status_blast_radius_and_dispatch(tmp_path):
    db_path = str(tmp_path / "tool_dispatch.db")
    bridge = SaarathiToolBridge(db_path)
    created = await bridge.create_task_with_deadline(
        "room_switch_demo", "samarth", "Status task"
    )

    status = await bridge.get_project_status("room_switch_demo")
    assert any(task["task_id"] == created["task_id"] for task in status["in_progress"])

    blast = await bridge.check_blocker_blast_radius(
        "room_switch_demo", created["task_id"]
    )
    assert blast["task_id"] == created["task_id"]
    assert blast["blast_radius_score"] == 0

    unknown = await call_tool("not_a_tool", {}, db_path)
    assert unknown["status"] == "ERROR"


@pytest.mark.asyncio
async def test_verify_pr_tool_delegates_to_existing_proof_gate(tmp_path):
    db_path = str(tmp_path / "tool_proof.db")
    await init_db(db_path)
    bridge = SaarathiToolBridge(db_path)
    calls = []

    async def fake_submit_proof(**kwargs):
        calls.append(kwargs)
        return {"status": "REJECTED", "reason": "test result"}

    bridge.coord.submit_proof = fake_submit_proof
    result = await bridge.verify_pr_proof(
        "room_switch_demo",
        "samarth",
        "task_123",
        "https://github.com/example/repo/pull/1",
    )

    assert result["status"] == "REJECTED"
    assert calls[0]["task_id"] == "task_123"
    assert calls[0]["pr_url"].endswith("/pull/1")

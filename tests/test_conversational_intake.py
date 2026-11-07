"""
test_conversational_intake.py: Unit tests for conversational LLM intake and fast regex fallback.
"""

import pytest
import httpx
from saarathi.services.auditor import parse_conversational_intent, _regex_intent_fallback, _heuristic_intent_fallback

@pytest.mark.asyncio
async def test_fast_regex_fallback():
    # 1. Create task
    res = await parse_conversational_intent("@Saarathi create Build JWT scope:src/auth/**,tests/auth/**", "soham")
    assert res["intent"] in ("CREATE_OR_CHAIN_TASK", "CREATE_TASK")
    assert "JWT" in res["task_title"]
    assert res["expected_scope"] == ["src/auth/**", "tests/auth/**"]

    # 2. Claim done with PR URL
    res = await parse_conversational_intent("@Saarathi done https://github.com/switch-org/switch-core/pull/10 for task task_123", "samarth")
    assert res["intent"] == "CLAIM_DONE"
    assert res["pr_url"] == "https://github.com/switch-org/switch-core/pull/10"
    assert res["task_id"] == "task_123"

    # 3. Block task
    res = await parse_conversational_intent("@Saarathi block task_123 reason:Waiting for review", "atharva")
    assert res["intent"] == "REPORT_BLOCKER"
    assert res["task_id"] == "task_123"
    assert "Waiting for review" in res["blocker_reason"]

    # 4. Unblock task
    res = await parse_conversational_intent("@Saarathi unblock task_123", "soham")
    assert res["intent"] == "CLEAR_BLOCKER"
    assert res["task_id"] == "task_123"

    # 5. Start task
    res = await parse_conversational_intent("@Saarathi start task_123", "parth")
    assert res["intent"] == "START_TASK"
    assert res["task_id"] == "task_123"


@pytest.mark.asyncio
async def test_conversational_intake_mocked_llm():
    # Simulate non-regex conversational message hitting LLM
    mock_llm_json = {
        "id": "chatcmpl-123",
        "choices": [
            {
                "message": {
                    "content": '{"intent": "CLAIM_DONE", "task_title": null, "owner": null, "expected_scope": null, "pr_url": "https://github.com/switch-org/switch-core/pull/99", "task_id": "task_abc", "blocker_reason": null}'
                }
            }
        ]
    }

    def mock_transport(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_llm_json)

    transport = httpx.MockTransport(mock_transport)
    async with httpx.AsyncClient(transport=transport) as client:
        # Patch LLM_API_KEY for test
        import saarathi.services.auditor as main
        orig_key = main.LLM_API_KEY
        main.LLM_API_KEY = "mock_key"
        try:
            res = await parse_conversational_intent(
                "@Saarathi hey team, I just opened PR https://github.com/switch-org/switch-core/pull/99 for task_abc, please verify!",
                "samarth",
                http_client=client,
            )
            assert res["intent"] == "CLAIM_DONE"
            assert res["pr_url"] == "https://github.com/switch-org/switch-core/pull/99"
            assert res["task_id"] == "task_abc"
        finally:
            main.LLM_API_KEY = orig_key


@pytest.mark.asyncio
async def test_claim_done_without_pr_url():
    # User claims done in natural language without providing any GitHub PR URL
    res = await parse_conversational_intent("@Saarathi done with the feature", "soham")
    assert res["intent"] == "CLAIM_DONE"
    assert res["pr_url"] is None


def test_secret_sanitizer():
    from saarathi.services.auditor import sanitize_public_output

    sample = (
        "Logs: ghp_1234567890abcdef1234567890abcdef1234, "
        "pat: github_pat_11AEXAMPLE000000000000_secret_here, "
        "sk: sk-proj-1234567890abcdef1234567890, "
        "auth: Bearer my_secret_token_1234567890"
    )
    scrubbed = sanitize_public_output(sample)
    assert "ghp_" not in scrubbed
    assert "github_pat_" not in scrubbed
    assert "sk-" not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed
    assert "my_secret_token" not in scrubbed


@pytest.mark.asyncio
async def test_conversational_chaining_and_deadlock_mediation(tmp_path):
    from saarathi.database import init_db, get_db_reader
    from saarathi.services.auditor import AuditorEngine

    test_db = str(tmp_path / "chaining_test.db")
    await init_db(test_db)
    engine = AuditorEngine(test_db)

    # Simulate message creating 2 tasks with cyclic dependency
    cyclic_event = {
        "id": "evt_cycle_1",
        "room_id": "room_switch_demo",
        "user_id": "soham",
        "text": "@Saarathi create Task A and Task B",
    }
    # Mock parse_conversational_intent returning a cycle
    import saarathi.services.auditor as main
    orig_parse = main.parse_conversational_intent

    async def mock_cycle_parse(t, s, **kw):
        return {
            "intent": "CREATE_OR_CHAIN_TASK",
            "tasks": [
                {"title": "Task A", "owner": "samarth", "due_at": None, "depends_on_title": "Task B", "scope": ["src/**"]},
                {"title": "Task B", "owner": "parth", "due_at": None, "depends_on_title": "Task A", "scope": ["tests/**"]},
            ],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    main.parse_conversational_intent = mock_cycle_parse
    try:
        await engine._process_inbox_event(cyclic_event)
        async with get_db_reader(test_db) as db:
            cur = await db.execute("SELECT body FROM outbox WHERE body LIKE '%Deadlock Detected%'")
            row = await cur.fetchone()
            assert row is not None, "Deadlock mediation message should be posted"
            assert "Mediation Recommendation" in row["body"]
    finally:
        main.parse_conversational_intent = orig_parse


@pytest.mark.asyncio
async def test_availability_and_reallocation(tmp_path):
    from saarathi.database import init_db, get_db_reader
    from saarathi.services.auditor import AuditorEngine

    test_db = str(tmp_path / "avail_test.db")
    await init_db(test_db)
    engine = AuditorEngine(test_db)

    # Create active task for samarth
    tid = await engine.coordinator.create_task(
        room_id="room_switch_demo",
        actor_switch_id="samarth",
        title="Samarth Backend Feature",
        expected_paths=["src/**"],
        owner_member_id="samarth",
    )
    await engine.coordinator.start_task("room_switch_demo", "samarth", tid)

    # Samarth goes AFK
    afk_event = {
        "id": "evt_afk_1",
        "room_id": "room_switch_demo",
        "user_id": "samarth",
        "text": "@Saarathi afk for 3 hours",
    }
    await engine._process_inbox_event(afk_event)

    # Check member is unavailable
    m = await engine.repo.get_member_by_switch_id("samarth")
    assert m["is_available"] == 0
    assert m["unavailable_until"] is not None

    # Check task was reallocated to lowest-load peer
    task_after = await engine.repo.get_task(tid)
    assert task_after["owner_member_id"] != "samarth", "Task should be reallocated"


@pytest.mark.asyncio
async def test_lead_only_reassignment(tmp_path):
    from saarathi.database import init_db, get_db_reader
    from saarathi.services.auditor import AuditorEngine

    test_db = str(tmp_path / "reassign_test.db")
    await init_db(test_db)
    engine = AuditorEngine(test_db)

    tid = await engine.coordinator.create_task(
        room_id="room_switch_demo",
        actor_switch_id="soham",
        title="Core Task",
        expected_paths=["src/**"],
        owner_member_id="samarth",
    )

    # 1. Non-lead (parth) tries to reassign -> rejected
    unauth_event = {
        "id": "evt_reassign_unauth",
        "room_id": "room_switch_demo",
        "user_id": "parth",
        "text": f"@Saarathi reassign {tid} to atharva",
    }
    await engine._process_inbox_event(unauth_event)
    async with get_db_reader(test_db) as db:
        cur = await db.execute("SELECT body FROM outbox WHERE body LIKE '%Permission Denied%'")
        row = await cur.fetchone()
        assert row is not None, "Non-lead reassignment should be rejected"

    # 2. Lead (soham) reassigns -> succeeds
    lead_event = {
        "id": "evt_reassign_lead",
        "room_id": "room_switch_demo",
        "user_id": "soham",
        "text": f"@Saarathi reassign {tid} to atharva",
    }
    await engine._process_inbox_event(lead_event)
    task_after = await engine.repo.get_task(tid)
    assert task_after["owner_member_id"] == "atharva"


@pytest.mark.asyncio
async def test_status_query_gods_eye(tmp_path):
    from saarathi.database import init_db, get_db_reader
    from saarathi.services.auditor import AuditorEngine

    test_db = str(tmp_path / "status_test.db")
    await init_db(test_db)
    engine = AuditorEngine(test_db)

    # Ask for status
    status_event = {
        "id": "evt_status_1",
        "room_id": "room_switch_demo",
        "user_id": "soham",
        "text": "@Saarathi status",
    }
    await engine._process_inbox_event(status_event)
    async with get_db_reader(test_db) as db:
        cur = await db.execute("SELECT body FROM outbox WHERE body LIKE '%God''s Eye View%'")
        row = await cur.fetchone()
        assert row is not None, "Status summary should be queued"
        assert "🟢" in row["body"]
        assert "🟡" in row["body"]
        assert "🔴" in row["body"]


@pytest.mark.asyncio
async def test_deadline_hound_tiers(tmp_path):
    from datetime import datetime, timedelta, timezone
    from saarathi.database import init_db, get_db_reader, get_db_writer
    from saarathi.services.auditor import AuditorEngine

    test_db = str(tmp_path / "deadline_test.db")
    await init_db(test_db)
    engine = AuditorEngine(test_db)

    now = datetime.now(timezone.utc)

    # 1. Task due in 30 minutes -> Tier 1 reminder
    tid_1 = await engine.coordinator.create_task(
        room_id="room_switch_demo",
        actor_switch_id="soham",
        title="Upcoming Task",
        expected_paths=["src/**"],
        owner_member_id="samarth",
        due_at=(now + timedelta(minutes=30)).isoformat(),
    )
    await engine._check_deadlines()
    t1 = await engine.repo.get_task(tid_1)
    assert t1["last_reminded_tier"] == 1

    # 2. Task 10 minutes overdue -> Tier 2 alert
    tid_2 = await engine.coordinator.create_task(
        room_id="room_switch_demo",
        actor_switch_id="soham",
        title="Overdue Task",
        expected_paths=["src/**"],
        owner_member_id="atharva",
        due_at=(now - timedelta(minutes=10)).isoformat(),
    )
    await engine._check_deadlines()
    t2 = await engine.repo.get_task(tid_2)
    assert t2["last_reminded_tier"] == 2

    # 3. Task 70 minutes overdue -> Tier 3 escalation
    tid_3 = await engine.coordinator.create_task(
        room_id="room_switch_demo",
        actor_switch_id="soham",
        title="Critical Overdue Task",
        expected_paths=["src/**"],
        owner_member_id="parth",
        due_at=(now - timedelta(minutes=70)).isoformat(),
    )
    await engine._check_deadlines()
    t3 = await engine.repo.get_task(tid_3)
    assert t3["last_reminded_tier"] == 3



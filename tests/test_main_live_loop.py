"""
test_main_live_loop.py: Integration test verifying the auditor service's three concurrent loops:
1. Ingesting event via SwitchAdapter
2. Coordinator executing command
3. Outbox background dispatcher delivering reply
4. Advancing processed_cursor
"""

import asyncio
import json
import os
import pytest
import httpx
from saarathi.database import init_db, get_db_writer, get_db_reader, TaskRepository
from saarathi.integrations.slack import SlackAdapter
from saarathi.services.auditor import SwitchAdapter, AuditorEngine, AGENT_ID

TEST_MAIN_DB = "test_main_loop.db"

@pytest.fixture(autouse=True)
async def setup_main_db():
    for f in [TEST_MAIN_DB, f"{TEST_MAIN_DB}-wal", f"{TEST_MAIN_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    await init_db(TEST_MAIN_DB)

    # Seed member & room membership
    async with get_db_writer(TEST_MAIN_DB) as conn:
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("carol_dev", "sw_carol", "carol"),
        )
        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'member', 1)",
            ("room_demo", "carol_dev"),
        )

    yield

    for f in [TEST_MAIN_DB, f"{TEST_MAIN_DB}-wal", f"{TEST_MAIN_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


@pytest.mark.asyncio
async def test_inbox_ingest_and_outbox_dispatch():
    engine = AuditorEngine(TEST_MAIN_DB)
    repo = TaskRepository(TEST_MAIN_DB)

    # 1. Simulate inbound Switch event
    event_payload = {
        "id": "evt_msg_100",
        "room_id": "room_demo",
        "user_id": "sw_carol",
        "text": "@Saarathi create Add Prometheus Metrics scope:src/metrics/**,tests/metrics/**",
        "cursor": "cur_100",
    }

    # Ingest event
    is_new, ev_id = await engine.adapter.ingest_event(event_payload)
    assert is_new is True
    assert ev_id == "evt_msg_100"

    # Duplicate delivery should return is_new = False
    is_new_dup, _ = await engine.adapter.ingest_event(event_payload)
    assert is_new_dup is False

    # Process event
    await engine._process_inbox_event(event_payload)

    # Verify task was created in database
    async with get_db_reader(TEST_MAIN_DB) as db:
        cur = await db.execute("SELECT * FROM tasks WHERE room_id = 'room_demo'")
        task = await cur.fetchone()
        assert task is not None
        assert "Prometheus" in task["title"]
        assert task["owner_member_id"] == "carol_dev"

        # Verify cursor advanced
        cur = await db.execute("SELECT received_cursor, processed_cursor FROM room_cursors WHERE room_id = 'room_demo'")
        c_row = await cur.fetchone()
        assert c_row["received_cursor"] == "cur_100"
        assert c_row["processed_cursor"] == "cur_100"

        # Verify Outbox row is queued
        cur = await db.execute("SELECT * FROM outbox WHERE room_id = 'room_demo'")
        out_row = await cur.fetchone()
        assert out_row is not None
        assert out_row["status"] == "READY"

    # 2. Test Outbox Dispatcher with mock post
    delivered_posts = []

    def mock_switch_post(request: httpx.Request) -> httpx.Response:
        delivered_posts.append(request)
        return httpx.Response(201, json={"id": "remote_msg_999"})

    transport = httpx.MockTransport(mock_switch_post)
    async with httpx.AsyncClient(transport=transport) as http_client:
        claimed = await engine._claim_due_outbox_rows()
        assert len(claimed) >= 1

        for row in claimed:
            await engine._dispatch_outbox_message(http_client, row, headers={})

    assert len(delivered_posts) >= 1
    async with get_db_reader(TEST_MAIN_DB) as db:
        cur = await db.execute("SELECT status, remote_message_id, sent_at FROM outbox WHERE room_id = 'room_demo'")
        sent_row = await cur.fetchone()
        assert sent_row["status"] == "SENT"
        assert sent_row["remote_message_id"] == "remote_msg_999"
        assert sent_row["sent_at"] is not None


@pytest.mark.asyncio
async def test_structured_switch_reply_routes_to_slack_thread_and_is_idempotent():
    engine = AuditorEngine(TEST_MAIN_DB)
    engine.slack_adapter = SlackAdapter(token="xoxb-test-token")

    event = {
        "id": "evt_slack_001",
        "type": "saarathi.command",
        "room_id": "room_demo",
        "user_id": "sw_carol",
        "slack": {"channel_id": "C0123456789", "thread_ts": "1730977200.123456"},
        "command": {"action": "list_tasks", "request_id": "slack-req-001"},
    }
    await engine._process_inbox_event(event)
    await engine._process_inbox_event(event)

    async with get_db_reader(TEST_MAIN_DB) as db:
        cur = await db.execute(
            "SELECT * FROM outbox WHERE idempotency_key = 'command_result_slack-req-001'"
        )
        rows = await cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["destination"] == "slack"
    assert json.loads(rows[0]["destination_json"]) == {
        "channel_id": "C0123456789",
        "thread_ts": "1730977200.123456",
    }

    delivered = []

    def mock_slack_post(request: httpx.Request) -> httpx.Response:
        delivered.append(request)
        assert request.headers["Authorization"] == "Bearer xoxb-test-token"
        body = json.loads(request.content)
        assert body["channel"] == "C0123456789"
        assert body["thread_ts"] == "1730977200.123456"
        assert body["client_msg_id"] == "command_result_slack-req-001"
        return httpx.Response(200, json={"ok": True, "ts": "1730977201.123456"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_slack_post)) as client:
        claimed = await engine._claim_due_outbox_rows()
        slack_rows = [row for row in claimed if row["destination"] == "slack"]
        assert len(slack_rows) == 1
        await engine._dispatch_outbox_message(client, slack_rows[0], headers={})

    assert len(delivered) == 1
    async with get_db_reader(TEST_MAIN_DB) as db:
        cur = await db.execute(
            "SELECT status, remote_message_id FROM outbox WHERE idempotency_key = 'command_result_slack-req-001'"
        )
        sent = await cur.fetchone()
    assert sent["status"] == "SENT"
    assert sent["remote_message_id"] == "1730977201.123456"


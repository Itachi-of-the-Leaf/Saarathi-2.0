"""
test_main_live_loop.py: Integration test verifying main.py's three concurrent loops:
1. Ingesting event via SwitchAdapter
2. Coordinator executing command
3. Outbox background dispatcher delivering reply
4. Advancing processed_cursor
"""

import asyncio
import os
import pytest
import httpx
from database import init_db, get_db_writer, get_db_reader, TaskRepository
from main import SwitchAdapter, AuditorEngine, AGENT_ID

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

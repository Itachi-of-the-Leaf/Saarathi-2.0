"""
test_risk_engine.py: Unit tests for RiskEngine critical path and blast radius analysis.
"""

import pytest
from saarathi.database import init_db, get_db_writer, TaskRepository
from saarathi.core.coordinator import Coordinator
from saarathi.core.risk_engine import RiskEngine

TEST_RISK_DB = "test_risk.db"

@pytest.fixture(autouse=True)
async def setup_risk_db():
    import os
    for f in [TEST_RISK_DB, f"{TEST_RISK_DB}-wal", f"{TEST_RISK_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    await init_db(TEST_RISK_DB)
    async with get_db_writer(TEST_RISK_DB) as conn:
        await conn.execute("INSERT OR IGNORE INTO members (member_id, switch_user_id, github_login, active) VALUES ('alice', 'sw_alice', 'alice', 1)")
        await conn.execute("INSERT OR IGNORE INTO members (member_id, switch_user_id, github_login, active) VALUES ('bob', 'sw_bob', 'bob', 1)")
        await conn.execute("INSERT OR IGNORE INTO room_memberships (room_id, member_id, role, active) VALUES ('room_risk', 'alice', 'lead', 1)")
        await conn.execute("INSERT OR IGNORE INTO room_memberships (room_id, member_id, role, active) VALUES ('room_risk', 'bob', 'member', 1)")

    yield

    for f in [TEST_RISK_DB, f"{TEST_RISK_DB}-wal", f"{TEST_RISK_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


@pytest.mark.asyncio
async def test_blast_radius_and_critical_path():
    coord = Coordinator(TEST_RISK_DB)
    engine = RiskEngine(TEST_RISK_DB)

    # Create dependency chain: T1 -> T2 -> T3, and T1 -> T4
    t1 = await coord.create_task("room_risk", "sw_alice", "Task 1: Core", ["src/**"], owner_member_id="alice")
    t2 = await coord.create_task("room_risk", "sw_alice", "Task 2: API", ["src/**"], owner_member_id="bob")
    t3 = await coord.create_task("room_risk", "sw_alice", "Task 3: UI", ["src/**"], owner_member_id="bob")
    t4 = await coord.create_task("room_risk", "sw_alice", "Task 4: Docs", ["src/**"], owner_member_id="alice")

    # t2 depends on t1
    await coord.set_task_dependencies("room_risk", "sw_alice", t2, [t1])
    # t3 depends on t2
    await coord.set_task_dependencies("room_risk", "sw_alice", t3, [t2])
    # t4 depends on t1
    await coord.set_task_dependencies("room_risk", "sw_alice", t4, [t1])

    # Test Blast Radius of blocking t1
    blast = await engine.calculate_blocker_blast_radius("room_risk", t1)
    assert blast["blast_radius_score"] == 3  # t2, t3, t4 affected
    assert "bob" in blast["affected_owners"]

    # Test Critical Path (longest path: t1 -> t2 -> t3)
    critical_path = await engine.calculate_critical_path("room_risk")
    assert len(critical_path) == 3
    assert critical_path == [t1, t2, t3]


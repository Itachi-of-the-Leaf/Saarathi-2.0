import asyncio
import os
import pytest
import pytest_asyncio
import httpx

from database import init_db, get_db_writer, get_db_reader, TaskRepository
from proof_gate import GitHubVerifier
from coordinator import (
    Coordinator,
    AuthorizationError,
    DependencyCycleError,
    InvalidStateTransitionError,
)

TEST_DB = "test_coordinator.db"

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    for f in [TEST_DB, f"{TEST_DB}-wal", f"{TEST_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    await init_db(TEST_DB, default_repo="switch-org/switch-core")

    # Seed members & memberships
    async with get_db_writer(TEST_DB) as conn:
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("alice_id", "sw_alice", "alice",),
        )
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("bob_id", "sw_bob", "bob",),
        )
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("lead_id", "sw_lead", "lead",),
        )

        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'member', 1)",
            ("room_1", "alice_id"),
        )
        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'member', 1)",
            ("room_1", "bob_id"),
        )
        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'lead', 1)",
            ("room_1", "lead_id"),
        )

    yield

    for f in [TEST_DB, f"{TEST_DB}-wal", f"{TEST_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


@pytest.mark.asyncio
async def test_task_lifecycle_and_blocking():
    coord = Coordinator(db_path=TEST_DB)

    # Alice creates task
    task_id = await coord.create_task(
        room_id="room_1",
        actor_switch_id="sw_alice",
        title="Implement Auth",
        expected_paths=["src/auth/**"],
    )
    assert task_id is not None

    repo = TaskRepository(TEST_DB)
    task = await repo.get_task(task_id)
    assert task["status"] == "OPEN"
    assert task["version"] == 1

    # Unauthorized user (bob) cannot start alice's task
    with pytest.raises(AuthorizationError):
        await coord.start_task("room_1", "sw_bob", task_id)

    # Alice starts task -> IN_PROGRESS
    await coord.start_task("room_1", "sw_alice", task_id)
    task = await repo.get_task(task_id)
    assert task["status"] == "IN_PROGRESS"
    assert task["version"] == 2

    # Lead blocks task
    await coord.block_task("room_1", "sw_lead", task_id, "Waiting on API design")
    task = await repo.get_task(task_id)
    assert task["status"] == "BLOCKED"
    assert task["blocker"] == "Waiting on API design"

    # Alice cannot submit proof while BLOCKED
    with pytest.raises(InvalidStateTransitionError):
        await coord.submit_proof("room_1", "sw_alice", task_id, "https://github.com/switch-org/switch-core/pull/10")

    # Lead unblocks task
    await coord.unblock_task("room_1", "sw_lead", task_id)
    task = await repo.get_task(task_id)
    assert task["status"] == "IN_PROGRESS"
    assert task["blocker"] is None


@pytest.mark.asyncio
async def test_dependency_cycle_detection():
    coord = Coordinator(db_path=TEST_DB)

    # Create 3 tasks
    t1 = await coord.create_task("room_1", "sw_alice", "Task 1", ["src/**"])
    t2 = await coord.create_task("room_1", "sw_alice", "Task 2", ["src/**"])
    t3 = await coord.create_task("room_1", "sw_alice", "Task 3", ["src/**"])

    # t2 depends on t1 (Valid)
    await coord.set_task_dependencies("room_1", "sw_alice", t2, [t1])

    # t3 depends on t2 (Valid: t3 -> t2 -> t1)
    await coord.set_task_dependencies("room_1", "sw_alice", t3, [t2])

    # Now attempt cycle: t1 depends on t3 (Cycle: t1 -> t3 -> t2 -> t1)
    with pytest.raises(DependencyCycleError) as exc_info:
        await coord.set_task_dependencies("room_1", "sw_alice", t1, [t3])

    assert "Dependency cycle detected" in str(exc_info.value)

    # Verify t1 has 0 dependencies after rollback
    async with get_db_reader(TEST_DB) as db:
        cur = await db.execute("SELECT COUNT(*) AS c FROM task_dependencies WHERE task_id = ?", (t1,))
        count = (await cur.fetchone())["c"]
        assert count == 0


@pytest.mark.asyncio
async def test_proof_gated_completion_success():
    head_sha = "1111222233334444555566667777888899990000"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/99/files" in url:
            return httpx.Response(200, json=[{"filename": "src/auth/jwt.py", "status": "added"}])
        elif "/pulls/99" in url:
            return httpx.Response(200, json={"number": 99, "user": {"login": "alice"}, "head": {"sha": head_sha}})
        elif "/check-runs" in url:
            return httpx.Response(200, json={"check_runs": [
                {
                    "id": 1,
                    "name": "test",
                    "head_sha": head_sha,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-11-06T12:00:00Z",
                    "completed_at": "2026-11-06T12:05:00Z",
                    "run_attempt": 1,
                },
                {
                    "id": 2,
                    "name": "lint",
                    "head_sha": head_sha,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-11-06T12:00:00Z",
                    "completed_at": "2026-11-06T12:02:00Z",
                    "run_attempt": 1,
                }
            ]})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        mock_verifier = GitHubVerifier(client=client)
        coord = Coordinator(db_path=TEST_DB, verifier=mock_verifier)

        # Create task and start it
        tid = await coord.create_task("room_1", "sw_alice", "Auth Core", ["src/auth/**"])
        await coord.start_task("room_1", "sw_alice", tid)

        # Submit proof
        res = await coord.submit_proof(
            room_id="room_1",
            actor_switch_id="sw_alice",
            task_id=tid,
            pr_url="https://github.com/switch-org/switch-core/pull/99",
        )
        assert res["status"] == "VERIFIED"

        repo = TaskRepository(TEST_DB)
        task = await repo.get_task(tid)
        assert task["status"] == "COMPLETE"
        assert task["proof_status"] == "VERIFIED"

        # Verify proof_snapshots entry
        async with get_db_reader(TEST_DB) as db:
            cur = await db.execute("SELECT * FROM proof_snapshots WHERE task_id = ?", (tid,))
            proof = await cur.fetchone()
            assert proof is not None
            assert proof["head_sha"] == head_sha
            assert proof["pr_number"] == 99

            # Verify Outbox entry queued
            cur = await db.execute("SELECT * FROM outbox WHERE room_id = 'room_1' AND body LIKE '%VERIFIED & COMPLETE%'")
            out = await cur.fetchone()
            assert out is not None
            assert out["status"] == "READY"

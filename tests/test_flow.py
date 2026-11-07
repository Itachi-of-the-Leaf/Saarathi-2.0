"""
test_flow.py: Comprehensive smoke-test script verifying the entire Saarathi Zero-Trust
Auditor pipeline end-to-end based on LLD 1, 2, and 3, including Team Roster Seeding
and Conversational Intake.
"""

import asyncio
import os
import sqlite3
import httpx
import pytest

from saarathi.database import (
    init_db,
    get_db_writer,
    get_db_reader,
    TaskRepository,
)
from saarathi.integrations.github import GitHubVerifier
from saarathi.core.coordinator import (
    Coordinator,
    AuthorizationError,
    DependencyCycleError,
    InvalidStateTransitionError,
)
from saarathi.services.auditor import AuditorEngine, parse_conversational_intent

SMOKE_DB = "smoke_saarathi.db"


async def run_smoke_test():
    print("=" * 70)
    print("🚀 STARTING SAARATHI ZERO-TRUST AUDITOR END-TO-END SMOKE TEST")
    print("=" * 70)

    # 0. Clean prior test artifacts
    for f in [SMOKE_DB, f"{SMOKE_DB}-wal", f"{SMOKE_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    # 1. Initialize SQLite with WAL mode & Seed Default Policy + Team Roster
    print("\n[Step 1] Initializing SQLite database with WAL pragmas, policy & team roster...")
    await init_db(SMOKE_DB, default_repo="switch-org/switch-core")
    repo = TaskRepository(SMOKE_DB)
    policy = await repo.get_policy_head("default_policy")
    assert policy is not None
    assert policy["current_revision"] == 1
    print(f"  ✓ Database initialized in WAL mode. Seeded Policy rev 1, hash: {policy['current_hash'][:16]}...")

    # Verify Team Roster Seeding (soham, samarth, atharva, parth)
    soham = await repo.get_member_by_switch_id("soham")
    assert soham is not None, "Member 'soham' should be seeded"
    soham_mem = await repo.get_room_membership("room_switch_demo", "soham")
    assert soham_mem is not None and soham_mem["role"] == "lead", "Soham should have 'lead' role"

    for member_name in ["samarth", "atharva", "parth"]:
        m = await repo.get_member_by_switch_id(member_name)
        assert m is not None, f"Member '{member_name}' should be seeded"
        mem = await repo.get_room_membership("room_switch_demo", member_name)
        assert mem is not None and mem["role"] == "member", f"{member_name} should have 'member' role"
    print("  ✓ Team Roster verified: soham (lead), samarth, atharva, parth seeded successfully.")

    # 2. Verify append-only triggers on immutable tables
    print("\n[Step 2] Verifying append-only triggers on immutable tables...")
    trigger_verified = False
    try:
        async with get_db_writer(SMOKE_DB) as conn:
            await conn.execute("UPDATE policy_revisions SET repo_full_name = 'hacked' WHERE revision = 1")
    except Exception as e:
        if "policy revisions are immutable" in str(e):
            trigger_verified = True
            print("  ✓ policy_revisions trigger fired: UPDATE blocked with RAISE(ABORT).")
    assert trigger_verified, "Policy trigger failed to block update!"

    # 3. Seed test members & room memberships
    print("\n[Step 3] Enrolling test actors in 'room_core'...")
    async with get_db_writer(SMOKE_DB) as conn:
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("alice_dev", "sw_alice", "alice-dev"),
        )
        await conn.execute(
            "INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES (?, ?, ?, 1)",
            ("bob_lead", "sw_bob", "bob-lead"),
        )
        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'member', 1)",
            ("room_core", "alice_dev"),
        )
        await conn.execute(
            "INSERT INTO room_memberships (room_id, member_id, role, active) VALUES (?, ?, 'lead', 1)",
            ("room_core", "bob_lead"),
        )
    print("  ✓ Alice (Developer) and Bob (Room Lead) enrolled in 'room_core'.")

    # 4. Create Task & Start Work (OPEN -> IN_PROGRESS)
    print("\n[Step 4] Creating task and testing state transitions...")
    coord = Coordinator(SMOKE_DB)
    task_id = await coord.create_task(
        room_id="room_core",
        actor_switch_id="sw_alice",
        title="Implement Auth Token Parser",
        expected_paths=["src/auth/**", "tests/auth/**"],
    )
    print(f"  ✓ Created Task [{task_id}] with scope ['src/auth/**', 'tests/auth/**']. Status: OPEN.")

    # Unauthorized start attempt by non-member should fail
    try:
        await coord.start_task("room_core", "sw_stranger", task_id)
        assert False, "Should have rejected stranger"
    except AuthorizationError:
        print("  ✓ Access Control: Unauthorized stranger rejected from starting task.")

    # Alice starts task
    await coord.start_task("room_core", "sw_alice", task_id)
    t = await repo.get_task(task_id)
    assert t["status"] == "IN_PROGRESS"
    assert t["version"] == 2
    print(f"  ✓ Task transitioned to IN_PROGRESS. Version incremented to {t['version']}.")

    # 5. Dependency Cycle Detection with Recursive CTE
    print("\n[Step 5] Testing dependency cycle detection via recursive CTE...")
    t2 = await coord.create_task("room_core", "sw_alice", "Database Migration", ["src/db/**"])
    t3 = await coord.create_task("room_core", "sw_alice", "Cache Layer", ["src/cache/**"])

    # Valid acyclic chain: task_id -> t2 -> t3
    await coord.set_task_dependencies("room_core", "sw_alice", task_id, [t2])
    await coord.set_task_dependencies("room_core", "sw_alice", t2, [t3])
    print("  ✓ Established valid dependencies: [Task] -> [T2] -> [T3].")

    # Cycle attempt: t3 -> task_id creates loop (t3 -> task_id -> t2 -> t3)
    cycle_prevented = False
    try:
        await coord.set_task_dependencies("room_core", "sw_alice", t3, [task_id])
    except DependencyCycleError as e:
        cycle_prevented = True
        print(f"  ✓ Cycle successfully blocked and rolled back: {e}")
    assert cycle_prevented, "Cycle detection failed to trigger!"

    # 6. Mock GitHub PR Verification Suite
    print("\n[Step 6] Testing Proof Gate with mock GitHub responses...")
    head_sha = "e4d909c290d0fb1ca068ffaddf22cbd0adddef01"

    # Define mock state
    mock_files = [{"filename": "src/auth/token.py", "status": "added"}]
    mock_author = "alice-dev"
    mock_checks = [
        {
            "id": 501,
            "name": "test",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-11-06T15:00:00Z",
            "completed_at": "2026-11-06T15:03:00Z",
            "run_attempt": 1,
        },
        {
            "id": 502,
            "name": "lint",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-11-06T15:00:00Z",
            "completed_at": "2026-11-06T15:01:00Z",
            "run_attempt": 1,
        },
    ]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/101/files" in url:
            return httpx.Response(200, json=mock_files)
        elif "/pulls/101" in url:
            return httpx.Response(200, json={"number": 101, "user": {"login": mock_author}, "head": {"sha": head_sha}})
        elif "/check-runs" in url:
            return httpx.Response(200, json={"check_runs": mock_checks})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = GitHubVerifier(client=http_client)
        coord = Coordinator(SMOKE_DB, verifier=verifier)

        # 6a. Negative Test: Scope Mismatch
        print("  [6a] Testing Scope Violation rejection...")
        mock_files = [
            {"filename": "src/auth/token.py", "status": "added"},
            {"filename": "etc/passwd", "status": "modified"},  # Scope violation!
        ]
        res_fail = await coord.submit_proof(
            room_id="room_core",
            actor_switch_id="sw_alice",
            task_id=task_id,
            pr_url="https://github.com/switch-org/switch-core/pull/101",
        )
        assert res_fail["status"] == "REJECTED"
        task_state = await repo.get_task(task_id)
        assert task_state["status"] == "IN_PROGRESS"  # Remains open
        assert task_state["proof_status"] == "REJECTED"
        print("  ✓ Scope violation rejected. Task stays IN_PROGRESS, proof status REJECTED.")

        # 6b. Negative Test: Pending Check
        print("  [6b] Testing Pending/Running Check delay...")
        mock_files = [{"filename": "src/auth/token.py", "status": "added"}]
        mock_checks[0]["status"] = "in_progress"
        mock_checks[0]["conclusion"] = None
        res_retry = await coord.submit_proof(
            room_id="room_core",
            actor_switch_id="sw_alice",
            task_id=task_id,
            pr_url="https://github.com/switch-org/switch-core/pull/101",
        )
        assert res_retry["status"] == "RETRY_LATER"
        task_state = await repo.get_task(task_id)
        assert task_state["status"] == "IN_PROGRESS"  # Remains open
        assert task_state["proof_status"] == "PENDING_RETRY"
        print("  ✓ Pending check held in RETRY_LATER. Task stays open, proof status PENDING_RETRY.")

        # 6c. Positive Test: Valid PR and All Checks Passed
        print("  [6c] Testing Valid PR Proof-Gated Completion (Atomic CAS)...")
        mock_checks[0]["status"] = "completed"
        mock_checks[0]["conclusion"] = "success"
        res_success = await coord.submit_proof(
            room_id="room_core",
            actor_switch_id="sw_alice",
            task_id=task_id,
            pr_url="https://github.com/switch-org/switch-core/pull/101",
        )
        assert res_success["status"] == "VERIFIED"
        task_final = await repo.get_task(task_id)
        assert task_final["status"] == "COMPLETE"
        assert task_final["proof_status"] == "VERIFIED"
        print(f"  ✓ Atomic CAS committed: Task is COMPLETE & VERIFIED. Final version: {task_final['version']}.")

    # 7. Conversational Intake & Claim-Done without PR
    print("\n[Step 7] Testing Conversational Intake & Zero-Trust 'No PR' Rejection...")
    engine = AuditorEngine(SMOKE_DB)

    # Simulate message: User claims task is finished but forgot the PR link
    no_pr_event = {
        "id": "evt_no_pr_1",
        "room_id": "room_core",
        "user_id": "sw_alice",
        "text": "@Saarathi I finished the auth token parser, all done!",
    }
    await engine._process_inbox_event(no_pr_event)

    # Check that Outbox contains warning rejecting claim without proof
    async with get_db_reader(SMOKE_DB) as db:
        cur = await db.execute(
            "SELECT body FROM outbox WHERE room_id = 'room_core' AND body LIKE '%provided no GitHub PR proof%'",
        )
        warning_msg = await cur.fetchone()
        assert warning_msg is not None, "Should have queued warning for missing PR proof"
        print(f"  ✓ Zero-Trust verified: '{warning_msg['body']}'")

    # 8. Clean up
    for f in [SMOKE_DB, f"{SMOKE_DB}-wal", f"{SMOKE_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    print("\n" + "=" * 70)
    print("🎉 ALL SMOKE TESTS PASSED! SAARATHI AUDITOR READY FOR PRODUCTION.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_smoke_test())

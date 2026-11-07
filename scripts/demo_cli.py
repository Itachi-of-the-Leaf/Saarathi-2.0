"""
demo_cli.py: Interactive demonstration script for the Saarathi Zero-Trust Auditor.
Walks through room setup, task creation, dependency cycle detection, scope rejection,
and atomic proof-gated completion with terminal feedback.
"""

import asyncio
import os
import sys
import httpx

from saarathi.database import init_db, get_db_writer, get_db_reader, TaskRepository
from saarathi.integrations.github import GitHubVerifier
from saarathi.core.coordinator import Coordinator, DependencyCycleError, AuthorizationError

DEMO_DB = "demo_saarathi.db"

async def run_demo():
    print("""
======================================================================
     🛡️  SAARATHI 2.0 — ZERO-TRUST AUDITOR INTERACTIVE DEMO 🛡️
     Evidence-Gated Task Completion for Team Chat & Pull Requests
======================================================================
""")

    # Clean old demo db
    for f in [DEMO_DB, f"{DEMO_DB}-wal", f"{DEMO_DB}-shm"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    # 1. Initialize DB
    print("▶ 1. Initializing SQLite with WAL mode & strict safety pragmas...")
    await init_db(DEMO_DB, default_repo="switch-org/switch-core")
    repo = TaskRepository(DEMO_DB)
    pol = await repo.get_policy_head("default_policy")
    print(f"   [OK] Database initialized. Policy #1 Content Hash: {pol['current_hash'][:16]}...\n")

    # 2. Seed Team
    print("▶ 2. Enrolling team members and assigning roles in room 'hackathon_room'...")
    async with get_db_writer(DEMO_DB) as conn:
        await conn.execute("INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES ('alice_dev', 'sw_alice', 'alice-dev', 1)")
        await conn.execute("INSERT INTO members (member_id, switch_user_id, github_login, active) VALUES ('bob_lead', 'sw_bob', 'bob-lead', 1)")
        await conn.execute("INSERT INTO room_memberships (room_id, member_id, role, active) VALUES ('hackathon_room', 'alice_dev', 'member', 1)")
        await conn.execute("INSERT INTO room_memberships (room_id, member_id, role, active) VALUES ('hackathon_room', 'bob_lead', 'lead', 1)")
    print("   [OK] Alice (@alice-dev) registered as Member.")
    print("   [OK] Bob (@bob-lead) registered as Room Lead.\n")

    # 3. Create Tasks
    coord = Coordinator(DEMO_DB)
    print("▶ 3. Creating task with strict expected file scope...")
    task_id = await coord.create_task(
        room_id="hackathon_room",
        actor_switch_id="sw_alice",
        title="Implement Zero-Trust JWT Validator",
        expected_paths=["src/auth/**", "tests/auth/**"],
    )
    print(f"   [OK] Task [{task_id}] created by Alice. Status: OPEN (v1). Scope: ['src/auth/**', 'tests/auth/**']\n")

    # 4. Start Task
    print(f"▶ 4. Alice starts work on task [{task_id}]...")
    await coord.start_task("hackathon_room", "sw_alice", task_id)
    t = await repo.get_task(task_id)
    print(f"   [OK] Task transitioned to: {t['status']} (Version {t['version']})\n")

    # 5. Cycle Detection
    print("▶ 5. Demonstrating recursive CTE dependency cycle prevention...")
    t2 = await coord.create_task("hackathon_room", "sw_alice", "Database Migration", ["src/db/**"])
    await coord.set_task_dependencies("hackathon_room", "sw_alice", task_id, [t2])
    print(f"   [OK] Established dependency: Task [{task_id}] depends on [{t2}].")

    try:
        # Attempt to make t2 depend on task_id (creating cycle)
        print("   Attempting illegal cycle: [{t2}] -> [{task_id}] -> [{t2}]...")
        await coord.set_task_dependencies("hackathon_room", "sw_alice", t2, [task_id])
    except DependencyCycleError as e:
        print(f"   [BLOCKED] Recursive CTE detected loop! Edge rejected & rolled back: {e}\n")

    # 6. Negative Proof Gate: Scope Violation
    print("▶ 6. Submitting PR #42 with unauthorized scope (out-of-tree file change)...")
    head_sha = "a8f34bc981018283726190283746192837461029"

    mock_files = [
        {"filename": "src/auth/validator.py", "status": "added"},
        {"filename": "config/secrets.env", "status": "modified"}, # SCOPE VIOLATION
    ]
    mock_checks = [
        {"id": 1, "name": "test", "head_sha": head_sha, "status": "completed", "conclusion": "success", "run_attempt": 1},
        {"id": 2, "name": "lint", "head_sha": head_sha, "status": "completed", "conclusion": "success", "run_attempt": 1},
    ]

    def mock_gh(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "/files" in url:
            return httpx.Response(200, json=mock_files)
        elif "/pulls/42" in url:
            return httpx.Response(200, json={"number": 42, "user": {"login": "alice-dev"}, "head": {"sha": head_sha}})
        elif "/check-runs" in url:
            return httpx.Response(200, json={"check_runs": mock_checks})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_gh)
    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = GitHubVerifier(client=http_client)
        demo_coord = Coordinator(DEMO_DB, verifier=verifier)

        res_scope_fail = await demo_coord.submit_proof(
            room_id="hackathon_room",
            actor_switch_id="sw_alice",
            task_id=task_id,
            pr_url="https://github.com/switch-org/switch-core/pull/42",
        )
        print(f"   [RESULT] Proof Status: {res_scope_fail['status']}")
        print(f"   [REASON] {res_scope_fail['reason']}")
        t = await repo.get_task(task_id)
        print(f"   [SAFETY] Task stays OPEN: status={t['status']}, proof_status={t['proof_status']}\n")

        # 7. Positive Proof Gate: Valid PR
        print("▶ 7. Correcting PR #42 (clean diff strictly inside allowed scope)...")
        mock_files = [
            {"filename": "src/auth/validator.py", "status": "added"},
            {"filename": "tests/auth/test_validator.py", "status": "added"},
        ]
        res_pass = await demo_coord.submit_proof(
            room_id="hackathon_room",
            actor_switch_id="sw_alice",
            task_id=task_id,
            pr_url="https://github.com/switch-org/switch-core/pull/42",
        )
        print(f"   [RESULT] Proof Status: {res_pass['status']}!")
        t = await repo.get_task(task_id)
        print(f"   [ATOMIC CAS] Task [{task_id}] is now COMPLETE! Final Version: {t['version']}")
        print(f"   [PROOF STORE] Head SHA: {res_pass['sha'][:10]}... tied permanently to task.\n")

    # 8. Inspect Audit Trail
    print("▶ 8. Inspecting Immutable Audit Trail (task_events):")
    async with get_db_reader(DEMO_DB) as db:
        cur = await db.execute("SELECT task_version, kind, created_at FROM task_events WHERE task_id = ? ORDER BY task_version ASC", (task_id,))
        rows = await cur.fetchall()
        for r in rows:
            print(f"   • Version {r['task_version']:2d} | Event: {r['kind']:<22} | Time: {r['created_at']}")

    # 9. Inspect Outbox
    print("\n▶ 9. Inspecting Queued Outbox Messages:")
    async with get_db_reader(DEMO_DB) as db:
        cur = await db.execute("SELECT idempotency_key, body, status FROM outbox WHERE room_id = 'hackathon_room'")
        rows = await cur.fetchall()
        for r in rows:
            print(f"   • [{r['status']}] Key: {r['idempotency_key']}")
            print(f"     Body: {r['body']}")

    print("""
======================================================================
  🎉 DEMO COMPLETE: ZERO-TRUST PROOF GATE OPERATING AS SPECIFIED!
======================================================================
""")

if __name__ == "__main__":
    asyncio.run(run_demo())


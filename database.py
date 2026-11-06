"""
database.py: Database schema, WAL pragmas, serialization lock, triggers,
and repository methods for Saarathi Zero-Trust Auditor based on LLD 1 & LLD 3.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiosqlite
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("saarathi.database")

DEFAULT_DB_PATH = os.getenv("SQLITE_DB_PATH", "saarathi.db")
DEFAULT_POLICY_ID = os.getenv("DEFAULT_POLICY_ID", "default_policy")
DEFAULT_REPO = os.getenv("GITHUB_REPO", "switch-org/switch-core")
DEFAULT_ROOM_ID = os.getenv("SWITCH_ROOM_ID", "room_switch_demo")

# Single in-process lock to serialize write transactions across coroutines
WRITE_LOCK = asyncio.Lock()


def utc_now_iso() -> str:
    """Return ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def compute_policy_hash(
    repo_full_name: str,
    allowed_paths: List[str],
    required_checks: List[Dict[str, Any]],
) -> str:
    """
    Hash canonical policy content:
    (repo + path rules + exact required check keys + optional app IDs).
    """
    canonical = {
        "repo": repo_full_name.strip().lower(),
        "paths": sorted(allowed_paths),
        "checks": sorted(
            [{"name": c["name"], "app_id": c.get("app_id")} for c in required_checks],
            key=lambda x: (x["name"], x.get("app_id") or 0),
        ),
    }
    dumped = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


async def get_connection(
    db_path: str = DEFAULT_DB_PATH, read_only: bool = False
) -> aiosqlite.Connection:
    """
    Create an aiosqlite connection configured with SQLite WAL mode and strict integrity pragmas.
    """
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row

    # Enforce SQLite WAL mode and safety pragmas from LLD 1 & LLD 3
    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA synchronous = FULL;")
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA busy_timeout = 5000;")

    if read_only:
        await conn.execute("PRAGMA query_only = ON;")

    return conn


@asynccontextmanager
async def get_db_writer(
    db_path: str = DEFAULT_DB_PATH,
) -> AsyncIterator[aiosqlite.Connection]:
    """
    Serialize all database write transactions using WRITE_LOCK.
    Opens a connection, starts BEGIN IMMEDIATE, yields, commits, or rolls back.
    """
    async with WRITE_LOCK:
        conn = await get_connection(db_path, read_only=False)
        try:
            await conn.execute("BEGIN IMMEDIATE;")
            yield conn
            await conn.commit()
        except Exception:
            try:
                await conn.rollback()
            except Exception:
                pass
            raise
        finally:
            await conn.close()


@asynccontextmanager
async def get_db_reader(
    db_path: str = DEFAULT_DB_PATH,
) -> AsyncIterator[aiosqlite.Connection]:
    """
    Acquire a dedicated read-only connection with query_only=ON.
    Reads can run concurrently with the writer without blocking under WAL mode.
    """
    conn = await get_connection(db_path, read_only=True)
    try:
        yield conn
    finally:
        await conn.close()


SCHEMA_SQL = """
-- 1. MEMBERS
CREATE TABLE IF NOT EXISTS members (
    member_id TEXT PRIMARY KEY,
    switch_user_id TEXT NOT NULL UNIQUE,
    github_login TEXT UNIQUE,
    active INTEGER NOT NULL CHECK(active IN (0,1))
);

-- 2. ROOM MEMBERSHIPS
CREATE TABLE IF NOT EXISTS room_memberships (
    room_id TEXT NOT NULL,
    member_id TEXT NOT NULL REFERENCES members,
    role TEXT NOT NULL CHECK(role IN ('member','lead')),
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    PRIMARY KEY(room_id,member_id)
);

-- 3. POLICY REVISIONS (IMMUTABLE)
CREATE TABLE IF NOT EXISTS policy_revisions (
    policy_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    repo_full_name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    allowed_paths_json TEXT NOT NULL,
    required_checks_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(policy_id, revision),
    UNIQUE(repo_full_name, revision),
    UNIQUE(policy_id,revision,content_hash)
);

-- 4. POLICY HEADS
CREATE TABLE IF NOT EXISTS policy_heads (
    policy_id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL,
    current_hash TEXT NOT NULL,
    FOREIGN KEY(policy_id,current_revision,current_hash)
    REFERENCES policy_revisions(policy_id,revision,content_hash)
);

-- POLICY IMMUTABILITY TRIGGERS
CREATE TRIGGER IF NOT EXISTS policy_no_update BEFORE UPDATE ON policy_revisions
BEGIN SELECT RAISE(ABORT, 'policy revisions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS policy_no_delete BEFORE DELETE ON policy_revisions
BEGIN SELECT RAISE(ABORT, 'policy revisions are immutable'); END;

-- 5. TASKS
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    title TEXT NOT NULL,
    owner_member_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
    ('OPEN','IN_PROGRESS','BLOCKED','COMPLETE')),
    proof_status TEXT NOT NULL CHECK(proof_status IN
    ('NOT_REQUIRED','AWAITING_PROOF','VERIFYING',
    'PENDING_RETRY','REJECTED','VERIFIED')),
    policy_id TEXT REFERENCES policy_heads,
    expected_paths_json TEXT NOT NULL,
    blocker TEXT,
    active_attempt_id TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id,room_id),
    FOREIGN KEY(room_id,owner_member_id)
    REFERENCES room_memberships(room_id,member_id),
    FOREIGN KEY(active_attempt_id,task_id)
    REFERENCES verification_attempts(attempt_id,task_id)
);

-- 6. TASK DELEGATES
CREATE TABLE IF NOT EXISTS task_delegates (
    task_id TEXT NOT NULL, room_id TEXT NOT NULL,
    member_id TEXT NOT NULL, granted_by TEXT NOT NULL,
    PRIMARY KEY(task_id,member_id),
    FOREIGN KEY(task_id,room_id) REFERENCES
    tasks(task_id,room_id),
    FOREIGN KEY(room_id,member_id)
    REFERENCES room_memberships(room_id,member_id),
    FOREIGN KEY(room_id,granted_by)
    REFERENCES room_memberships(room_id,member_id)
);

-- 7. TASK DEPENDENCIES
CREATE TABLE IF NOT EXISTS task_dependencies (
    room_id TEXT NOT NULL, task_id TEXT NOT NULL,
    depends_on_task_id TEXT NOT NULL,
    PRIMARY KEY(task_id,depends_on_task_id),
    CHECK(task_id <> depends_on_task_id),
    FOREIGN KEY(task_id,room_id) REFERENCES
    tasks(task_id,room_id),
    FOREIGN KEY(depends_on_task_id,room_id)
    REFERENCES tasks(task_id,room_id)
);

CREATE INDEX IF NOT EXISTS task_dependencies_reverse
ON task_dependencies(depends_on_task_id,task_id);

-- 8. SWITCH INBOX
CREATE TABLE IF NOT EXISTS switch_inbox (
    arrival_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    provider_cursor TEXT,
    actor_switch_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
    ('RECEIVED','PROCESSING','DONE','RETRY','ERROR_TERMINAL')),
    processing_token TEXT,
    lease_until TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    result_json TEXT,
    last_error TEXT,
    received_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(room_id,event_id),
    UNIQUE(room_id,provider_cursor)
);

CREATE INDEX IF NOT EXISTS inbox_pending
ON switch_inbox(room_id,state,arrival_seq);

-- 9. ROOM CURSORS
CREATE TABLE IF NOT EXISTS room_cursors (
    agent_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    received_cursor TEXT,
    processed_cursor TEXT,
    PRIMARY KEY(agent_id,room_id)
);

-- 10. VERIFICATION ATTEMPTS
CREATE TABLE IF NOT EXISTS verification_attempts (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks,
    attempt_no INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN
    ('CHECKING','RETRY_LATER','REJECTED','VERIFIED','SUPERSEDED')),
    task_version INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    policy_hash TEXT NOT NULL,
    submitted_by TEXT NOT NULL REFERENCES members,
    pr_url TEXT NOT NULL,
    next_retry_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id,attempt_no),
    UNIQUE(attempt_id,task_id),
    FOREIGN KEY(policy_id,policy_revision,policy_hash)
    REFERENCES policy_revisions(policy_id,revision,content_hash)
);

CREATE INDEX IF NOT EXISTS attempt_retry
ON verification_attempts(state,next_retry_at);

-- 11. PROOF SNAPSHOTS (IMMUTABLE)
CREATE TABLE IF NOT EXISTS proof_snapshots (
    proof_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL REFERENCES tasks,
    repo_full_name TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    author_login TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    policy_hash TEXT NOT NULL,
    changed_paths_json TEXT NOT NULL,
    selected_checks_json TEXT NOT NULL,
    final_read_at TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    FOREIGN KEY(policy_id,policy_revision,policy_hash)
    REFERENCES policy_revisions(policy_id,revision,content_hash),
    FOREIGN KEY(attempt_id,task_id)
    REFERENCES verification_attempts(attempt_id,task_id)
);

CREATE TRIGGER IF NOT EXISTS proof_no_update BEFORE UPDATE ON proof_snapshots
BEGIN SELECT RAISE(ABORT, 'proof snapshots are immutable'); END;

CREATE TRIGGER IF NOT EXISTS proof_no_delete BEFORE DELETE ON proof_snapshots
BEGIN SELECT RAISE(ABORT, 'proof snapshots are immutable'); END;

-- 12. TASK EVENTS (APPEND-ONLY AUDIT LOG)
CREATE TABLE IF NOT EXISTS task_events (
    task_id TEXT NOT NULL REFERENCES tasks,
    task_version INTEGER NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    actor_member_id TEXT,
    source_room_id TEXT,
    source_event_id TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(task_id,task_version)
);

CREATE TRIGGER IF NOT EXISTS task_events_no_update
BEFORE UPDATE ON task_events BEGIN SELECT RAISE(ABORT,
'task_events are append-only'); END;

CREATE TRIGGER IF NOT EXISTS task_events_no_delete
BEFORE DELETE ON task_events BEGIN SELECT RAISE(ABORT,
'task_events are append-only'); END;

-- 13. OUTBOX
CREATE TABLE IF NOT EXISTS outbox (
    outbox_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    room_id TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
    ('READY','CLAIMED','SENT','DEAD')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    claim_token TEXT,
    lease_until TEXT,
    remote_message_id TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);

CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status,next_attempt_at,lease_until);

-- 14. SCHEMA MIGRATIONS
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL,
    checksum TEXT NOT NULL, applied_at TEXT NOT NULL
);

-- Recommended query indexes
CREATE INDEX IF NOT EXISTS idx_tasks_room_status ON tasks(room_id,status);
CREATE INDEX IF NOT EXISTS idx_tasks_owner_status ON tasks(owner_member_id,status);
CREATE INDEX IF NOT EXISTS idx_delegates_member ON task_delegates(member_id);
"""


async def init_db(
    db_path: str = DEFAULT_DB_PATH,
    default_repo: str = DEFAULT_REPO,
    default_policy_id: str = DEFAULT_POLICY_ID,
) -> None:
    """
    Initialize SQLite database with WAL pragmas, full LLD schema,
    append-only triggers, and seed default policy revision #1.
    """
    async with get_db_writer(db_path) as conn:
        # Execute DDL
        await conn.executescript(SCHEMA_SQL)

        # Record migration 1
        await conn.execute(
            """
            INSERT OR IGNORE INTO schema_migrations (version, name, checksum, applied_at)
            VALUES (1, '001_lld_initial_schema', 'initial_lld_v1', ?)
            """,
            (utc_now_iso(),),
        )

        # Seed Policy Revision #1 if not present
        cursor = await conn.execute(
            "SELECT 1 FROM policy_heads WHERE policy_id = ?",
            (default_policy_id,),
        )
        row = await cursor.fetchone()
        if not row:
            allowed_paths = ["src/**", "tests/**", "docs/**"]
            required_checks = [
                {"name": "test", "app_id": None},
                {"name": "lint", "app_id": None},
            ]
            content_hash = compute_policy_hash(
                default_repo, allowed_paths, required_checks
            )
            created_at = utc_now_iso()

            await conn.execute(
                """
                INSERT INTO policy_revisions (
                    policy_id, revision, repo_full_name, content_hash,
                    allowed_paths_json, required_checks_json, created_at
                ) VALUES (?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    default_policy_id,
                    default_repo,
                    content_hash,
                    json.dumps(allowed_paths),
                    json.dumps(required_checks),
                    created_at,
                ),
            )

            await conn.execute(
                """
                INSERT INTO policy_heads (policy_id, current_revision, current_hash)
                VALUES (?, 1, ?)
                """,
                (default_policy_id, content_hash),
            )
            logger.info("Seeded default policy revision #1 for repo %s", default_repo)

        # Seed Team Roster: soham (lead), samarth, atharva, parth (members)
        team_roster = [
            ("soham", "soham", "soham", "lead"),
            ("samarth", "samarth", "samarth", "member"),
            ("atharva", "atharva", "atharva", "member"),
            ("parth", "parth", "parth", "member"),
        ]
        target_room = os.getenv("SWITCH_ROOM_ID", DEFAULT_ROOM_ID)

        for member_id, switch_id, gh_login, role in team_roster:
            await conn.execute(
                """
                INSERT OR IGNORE INTO members (member_id, switch_user_id, github_login, active)
                VALUES (?, ?, ?, 1)
                """,
                (member_id, switch_id, gh_login),
            )
            await conn.execute(
                """
                INSERT OR IGNORE INTO room_memberships (room_id, member_id, role, active)
                VALUES (?, ?, ?, 1)
                """,
                (target_room, member_id, role),
            )
        logger.info("Seeded default team roster (soham[lead], samarth, atharva, parth) for room %s", target_room)


# ============================================================================
# TaskRepository: Database operations adhering strictly to LLD 1 & LLD 3
# ============================================================================


class TaskRepository:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Fetch task record as dictionary."""
        async with get_db_reader(self.db_path) as db:
            cursor = await db.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_task_delegates(self, task_id: str) -> List[str]:
        """Fetch member_ids of delegates for a task."""
        async with get_db_reader(self.db_path) as db:
            cursor = await db.execute(
                "SELECT member_id FROM task_delegates WHERE task_id = ?",
                (task_id,),
            )
            rows = await cursor.fetchall()
            return [r["member_id"] for r in rows]

    async def get_member_by_switch_id(
        self, switch_user_id: str
    ) -> Optional[Dict[str, Any]]:
        """Resolve Switch user ID to member record."""
        clean_id = switch_user_id.lower().replace("sw_", "")
        async with get_db_reader(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT * FROM members
                WHERE (switch_user_id = ? OR member_id = ? OR LOWER(member_id) = ? OR LOWER(switch_user_id) = ?)
                  AND active = 1
                """,
                (switch_user_id, switch_user_id, clean_id, clean_id),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_room_membership(
        self, room_id: str, member_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get member role in room."""
        clean_id = member_id.lower().replace("sw_", "")
        async with get_db_reader(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT * FROM room_memberships
                WHERE room_id = ? AND (member_id = ? OR LOWER(member_id) = ?) AND active = 1
                """,
                (room_id, member_id, clean_id),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_policy_head(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get latest policy revision and content."""
        async with get_db_reader(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT h.policy_id, h.current_revision, h.current_hash,
                       r.repo_full_name, r.allowed_paths_json, r.required_checks_json
                FROM policy_heads h
                JOIN policy_revisions r
                  ON h.policy_id = r.policy_id
                 AND h.current_revision = r.revision
                 AND h.current_hash = r.content_hash
                WHERE h.policy_id = ?
                """,
                (policy_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def set_task_dependencies(
        self,
        room_id: str,
        task_id: str,
        candidate_dependencies: List[str],
        actor_member_id: Optional[str] = None,
        source_event_id: Optional[str] = None,
    ) -> bool:
        """
        Dependency replacement protocol with recursive CTE cycle detection:
        1. BEGIN IMMEDIATE transaction.
        2. Delete existing dependencies for task.
        3. Insert proposed candidate edges.
        4. Run recursive CTE reachability query.
        5. If cycle detected: ROLLBACK and raise ValueError.
        6. Otherwise CAS-increment task.version, append task_event, COMMIT.
        """
        async with get_db_writer(self.db_path) as conn:
            # 1. Clear current dependencies
            await conn.execute(
                "DELETE FROM task_dependencies WHERE task_id = ?", (task_id,)
            )

            # 2. Insert candidate dependencies
            for dep_id in candidate_dependencies:
                if dep_id == task_id:
                    raise ValueError(
                        f"Task {task_id} cannot depend on itself (self-cycle)"
                    )
                await conn.execute(
                    """
                    INSERT INTO task_dependencies (room_id, task_id, depends_on_task_id)
                    VALUES (?, ?, ?)
                    """,
                    (room_id, task_id, dep_id),
                )

            # 3. Recursive CTE cycle detection from LLD 1
            cte_sql = """
            WITH RECURSIVE reach(id) AS (
                SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?
                UNION
                SELECT d.depends_on_task_id FROM task_dependencies d
                JOIN reach r ON d.task_id = r.id
            )
            SELECT EXISTS(SELECT 1 FROM reach WHERE id = ?) AS has_cycle;
            """
            cursor = await conn.execute(cte_sql, (task_id, task_id))
            row = await cursor.fetchone()
            has_cycle = bool(row["has_cycle"]) if row else False

            if has_cycle:
                raise ValueError(
                    f"Dependency cycle detected for task {task_id}; aborted and rolled back"
                )

            # 4. CAS-increment task version and record audit event
            now = utc_now_iso()
            cur = await conn.execute(
                """
                UPDATE tasks
                SET version = version + 1, updated_at = ?
                WHERE task_id = ?
                RETURNING version
                """,
                (now, task_id),
            )
            res = await cur.fetchone()
            new_version = res["version"]

            import uuid

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'DEPENDENCIES_UPDATED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    actor_member_id,
                    room_id,
                    source_event_id,
                    json.dumps({"dependencies": candidate_dependencies}),
                    now,
                ),
            )
            return True

    async def start_attempt(
        self,
        attempt_id: str,
        task_id: str,
        submitted_by: str,
        pr_url: str,
        source_room_id: str,
        source_event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new verification attempt and advance task proof_status to 'VERIFYING':
        Increments task.version, sets active_attempt_id, and records audit event.
        """
        async with get_db_writer(self.db_path) as conn:
            # Load task
            t_cur = await conn.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            )
            task = await t_cur.fetchone()
            if not task:
                raise ValueError(f"Task {task_id} not found")

            policy_id = task["policy_id"]
            pol_cur = await conn.execute(
                "SELECT current_revision, current_hash FROM policy_heads WHERE policy_id = ?",
                (policy_id,),
            )
            pol = await pol_cur.fetchone()
            if not pol:
                raise ValueError(
                    f"Policy head not found for policy {policy_id}"
                )

            # Determine next attempt_no
            num_cur = await conn.execute(
                "SELECT COALESCE(MAX(attempt_no), 0) + 1 AS next_no FROM verification_attempts WHERE task_id = ?",
                (task_id,),
            )
            next_no = (await num_cur.fetchone())["next_no"]

            now = utc_now_iso()
            task_version = task["version"]

            # Insert verification attempt
            await conn.execute(
                """
                INSERT INTO verification_attempts (
                    attempt_id, task_id, attempt_no, state,
                    task_version, policy_id, policy_revision, policy_hash,
                    submitted_by, pr_url, created_at, updated_at
                ) VALUES (?, ?, ?, 'CHECKING', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    task_id,
                    next_no,
                    task_version,
                    policy_id,
                    pol["current_revision"],
                    pol["current_hash"],
                    submitted_by,
                    pr_url,
                    now,
                    now,
                ),
            )

            # Advance task proof_status and set active_attempt_id
            new_task_version = task_version + 1
            await conn.execute(
                """
                UPDATE tasks
                SET proof_status = 'VERIFYING',
                    active_attempt_id = ?,
                    version = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (attempt_id, new_task_version, now, task_id),
            )

            # Record task event
            import uuid

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'ATTEMPT_STARTED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_task_version,
                    event_id,
                    submitted_by,
                    source_room_id,
                    source_event_id,
                    json.dumps(
                        {
                            "attempt_id": attempt_id,
                            "attempt_no": next_no,
                            "pr_url": pr_url,
                        }
                    ),
                    now,
                ),
            )

            return {
                "attempt_id": attempt_id,
                "attempt_no": next_no,
                "task_version": new_task_version,
                "policy_id": policy_id,
                "policy_revision": pol["current_revision"],
                "policy_hash": pol["current_hash"],
                "pr_url": pr_url,
            }

    async def finalize_success(
        self,
        snapshot: Dict[str, Any],
        inbox_event_key: Optional[Tuple[str, str]] = None,
        outbox_body: Optional[str] = None,
    ) -> str:
        """
        Atomic completion transaction from LLD 2 & LLD 3:
        1. Guarded CAS on tasks:
           WHERE task_id = :task
             AND version = :captured_task_version
             AND status = 'IN_PROGRESS'
             AND proof_status = 'VERIFYING'
             AND active_attempt_id = :attempt_id
             AND EXISTS (SELECT 1 FROM policy_heads
                         WHERE policy_id = :policy_id
                           AND current_revision = :revision
                           AND current_hash = :hash)
        2. Attempt must still be CHECKING.
        3. Insert immutable proof_snapshots.
        4. Append immutable task_events.
        5. Insert outbox message.
        6. Mark switch_inbox as DONE.
        """
        async with get_db_writer(self.db_path) as conn:
            task_id = snapshot["task_id"]
            attempt_id = snapshot["attempt_id"]
            captured_version = snapshot["task_version"]
            policy_id = snapshot["policy_id"]
            policy_revision = snapshot["policy_revision"]
            policy_hash = snapshot["policy_hash"]
            now = utc_now_iso()

            # Verify attempt is still CHECKING
            att_cur = await conn.execute(
                "SELECT state FROM verification_attempts WHERE attempt_id = ? AND task_id = ?",
                (attempt_id, task_id),
            )
            att_row = await att_cur.fetchone()
            if not att_row or att_row["state"] != "CHECKING":
                return "SUPERSEDED"

            # Execute guarded CAS
            cas_sql = """
            UPDATE tasks
            SET status = 'COMPLETE',
                proof_status = 'VERIFIED',
                version = version + 1,
                updated_at = ?
            WHERE task_id = ?
              AND version = ?
              AND status = 'IN_PROGRESS'
              AND proof_status = 'VERIFYING'
              AND active_attempt_id = ?
              AND EXISTS (
                  SELECT 1 FROM policy_heads
                  WHERE policy_id = ?
                    AND current_revision = ?
                    AND current_hash = ?
              )
            RETURNING version, room_id, title;
            """
            cur = await conn.execute(
                cas_sql,
                (
                    now,
                    task_id,
                    captured_version,
                    attempt_id,
                    policy_id,
                    policy_revision,
                    policy_hash,
                ),
            )
            updated_task = await cur.fetchone()
            if not updated_task:
                # 0 rows updated means CAS conflict or stale state
                return "CONFLICT"

            new_version = updated_task["version"]
            room_id = updated_task["room_id"]
            title = updated_task["title"]

            # Update attempt state to VERIFIED
            await conn.execute(
                "UPDATE verification_attempts SET state = 'VERIFIED', updated_at = ? WHERE attempt_id = ?",
                (now, attempt_id),
            )

            # Insert immutable proof_snapshots
            import uuid

            proof_id = f"proof_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO proof_snapshots (
                    proof_id, attempt_id, task_id, repo_full_name, pr_number,
                    author_login, head_sha, policy_id, policy_revision,
                    policy_hash, changed_paths_json, selected_checks_json,
                    final_read_at, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proof_id,
                    attempt_id,
                    task_id,
                    snapshot["repo_full_name"],
                    snapshot["pr_number"],
                    snapshot["author_login"],
                    snapshot["head_sha"],
                    policy_id,
                    policy_revision,
                    policy_hash,
                    json.dumps(snapshot["changed_paths"]),
                    json.dumps(snapshot["selected_checks"]),
                    snapshot["final_read_at"],
                    now,
                ),
            )

            # Append immutable task_events
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'TASK_COMPLETED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    snapshot.get("author_login"),
                    room_id,
                    snapshot.get("source_event_id"),
                    json.dumps(
                        {
                            "proof_id": proof_id,
                            "sha": snapshot["head_sha"],
                            "pr_number": snapshot["pr_number"],
                        }
                    ),
                    now,
                ),
            )

            # Insert Outbox announcement
            outbox_id = f"out_{uuid.uuid4().hex[:12]}"
            idempotency_key = f"complete_{task_id}_{attempt_id}"
            body_text = outbox_body or (
                f"✅ Task [{task_id}] '{title}' VERIFIED & COMPLETE! "
                f"Verified commit `{snapshot['head_sha'][:7]}` on PR #{snapshot['pr_number']}."
            )
            await conn.execute(
                """
                INSERT INTO outbox (
                    outbox_id, idempotency_key, room_id, body,
                    status, attempts, next_attempt_at, created_at
                ) VALUES (?, ?, ?, ?, 'READY', 0, ?, ?)
                """,
                (outbox_id, idempotency_key, room_id, body_text, now, now),
            )

            # If an inbox event triggered this, mark it DONE
            if inbox_event_key:
                inbox_room_id, inbox_event_id = inbox_event_key
                await conn.execute(
                    """
                    UPDATE switch_inbox
                    SET state = 'DONE',
                        result_json = ?,
                        updated_at = ?
                    WHERE room_id = ? AND event_id = ?
                    """,
                    (
                        json.dumps(
                            {
                                "status": "VERIFIED",
                                "task_id": task_id,
                                "sha": snapshot["head_sha"],
                            }
                        ),
                        now,
                        inbox_room_id,
                        inbox_event_id,
                    ),
                )

            return "COMMITTED"

    async def record_retry(
        self,
        attempt_id: str,
        task_id: str,
        reason: str,
        retry_delay_seconds: int = 30,
    ) -> str:
        """Record retryable failure: sets attempt to RETRY_LATER and task to PENDING_RETRY."""
        async with get_db_writer(self.db_path) as conn:
            from datetime import timedelta

            now_dt = datetime.now(timezone.utc)
            now = now_dt.isoformat()
            retry_at = (now_dt + timedelta(seconds=retry_delay_seconds)).isoformat()

            # Check active attempt
            cur = await conn.execute(
                "UPDATE verification_attempts SET state = 'RETRY_LATER', next_retry_at = ?, last_error = ?, updated_at = ? WHERE attempt_id = ? AND state = 'CHECKING'",
                (retry_at, reason, now, attempt_id),
            )
            if cur.rowcount == 0:
                return "SUPERSEDED"

            await conn.execute(
                "UPDATE tasks SET proof_status = 'PENDING_RETRY', updated_at = ? WHERE task_id = ? AND active_attempt_id = ?",
                (now, task_id, attempt_id),
            )
            return "PENDING_RETRY"

    async def advance_processed_cursor(
        self, agent_id: str, room_id: str
    ) -> Optional[str]:
        """
        Advance processed_cursor according to LLD 3 contract:
        'processed_cursor = latest cursor whose entire earlier FIFO prefix is DONE or ERROR_TERMINAL.'
        """
        async with get_db_writer(self.db_path) as conn:
            # Locate the earliest non-terminal row
            cur = await conn.execute(
                """
                SELECT arrival_seq FROM switch_inbox
                WHERE room_id = ? AND state NOT IN ('DONE', 'ERROR_TERMINAL')
                ORDER BY arrival_seq ASC
                LIMIT 1
                """,
                (room_id,),
            )
            first_non_terminal = await cur.fetchone()

            if first_non_terminal:
                cutoff_seq = first_non_terminal["arrival_seq"]
                p_cur = await conn.execute(
                    """
                    SELECT provider_cursor FROM switch_inbox
                    WHERE room_id = ? AND arrival_seq < ? AND provider_cursor IS NOT NULL
                    ORDER BY arrival_seq DESC
                    LIMIT 1
                    """,
                    (room_id, cutoff_seq),
                )
            else:
                p_cur = await conn.execute(
                    """
                    SELECT provider_cursor FROM switch_inbox
                    WHERE room_id = ? AND state IN ('DONE', 'ERROR_TERMINAL') AND provider_cursor IS NOT NULL
                    ORDER BY arrival_seq DESC
                    LIMIT 1
                    """,
                    (room_id,),
                )

            row = await p_cur.fetchone()
            if row and row["provider_cursor"]:
                cursor_val = row["provider_cursor"]
                await conn.execute(
                    """
                    UPDATE room_cursors
                    SET processed_cursor = ?
                    WHERE agent_id = ? AND room_id = ?
                    """,
                    (cursor_val, agent_id, room_id),
                )
                return cursor_val
            return None

    async def record_rejection(
        self,
        attempt_id: str,
        task_id: str,
        reason: str,
        room_id: Optional[str] = None,
    ) -> str:
        """Record permanent failure: sets attempt to REJECTED and task to REJECTED."""
        async with get_db_writer(self.db_path) as conn:
            now = utc_now_iso()
            cur = await conn.execute(
                "UPDATE verification_attempts SET state = 'REJECTED', last_error = ?, updated_at = ? WHERE attempt_id = ? AND state = 'CHECKING'",
                (reason, now, attempt_id),
            )
            if cur.rowcount == 0:
                return "SUPERSEDED"

            await conn.execute(
                "UPDATE tasks SET proof_status = 'REJECTED', updated_at = ? WHERE task_id = ? AND active_attempt_id = ?",
                (now, task_id, attempt_id),
            )

            # Queue outbox notice explaining rejection
            if room_id:
                import uuid

                outbox_id = f"out_{uuid.uuid4().hex[:12]}"
                idempotency_key = f"reject_{attempt_id}"
                body = f"❌ Proof verification REJECTED for task [{task_id}]: {reason}. Task remains open until corrected."
                await conn.execute(
                    """
                    INSERT OR IGNORE INTO outbox (
                        outbox_id, idempotency_key, room_id, body,
                        status, attempts, next_attempt_at, created_at
                    ) VALUES (?, ?, ?, ?, 'READY', 0, ?, ?)
                    """,
                    (outbox_id, idempotency_key, room_id, body, now, now),
                )

            return "REJECTED"


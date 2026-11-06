"""
coordinator.py: Core Coordinator managing dual state machines (Task + Proof),
Atomic CAS version increments, recursive CTE cycle detection, and role-based authority.
Adheres strictly to LLD 1, LLD 2, and LLD 3.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from database import (
    DEFAULT_DB_PATH,
    DEFAULT_POLICY_ID,
    TaskRepository,
    get_db_reader,
    get_db_writer,
    utc_now_iso,
)
from proof_gate import (
    GitHubVerifier,
    PermanentFailure,
    RetryableFailure,
    VerificationInput,
    VerifiedSnapshot,
)

logger = logging.getLogger("saarathi.coordinator")


class DependencyCycleError(Exception):
    """Raised when a candidate dependency would create a cycle."""
    pass


class AuthorizationError(Exception):
    """Raised when an actor is not authorized for the requested task operation."""
    pass


class InvalidStateTransitionError(Exception):
    """Raised when a task or proof transition violates the state machine."""
    pass


class Coordinator:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        verifier: Optional[GitHubVerifier] = None,
    ):
        self.db_path = db_path
        self.repo = TaskRepository(db_path)
        self.verifier = verifier or GitHubVerifier()

    async def _resolve_actor_authority(
        self, room_id: str, actor_switch_id: str
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Verify actor exists, is active, and has active membership in the task's room.
        Returns (member, membership).
        """
        member = await self.repo.get_member_by_switch_id(actor_switch_id)
        if not member:
            raise AuthorizationError(
                f"Switch user '{actor_switch_id}' is not a recognized or active team member."
            )

        membership = await self.repo.get_room_membership(room_id, member["member_id"])
        if not membership:
            raise AuthorizationError(
                f"Member '{member['member_id']}' does not hold active membership in room '{room_id}'."
            )

        return member, membership

    async def create_task(
        self,
        room_id: str,
        actor_switch_id: str,
        title: str,
        expected_paths: List[str],
        policy_id: str = DEFAULT_POLICY_ID,
        owner_member_id: Optional[str] = None,
        task_id: Optional[str] = None,
        source_event_id: Optional[str] = None,
        due_at: Optional[str] = None,
    ) -> str:
        """
        Create a new task with initial status OPEN and proof_status NOT_REQUIRED / AWAITING_PROOF.
        Task version begins at 1. Appends audit event.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        assigned_owner = owner_member_id or actor["member_id"]

        # Ensure owner is an active member in this room
        owner_mem = await self.repo.get_room_membership(room_id, assigned_owner)
        if not owner_mem:
            raise AuthorizationError(f"Assigned owner '{assigned_owner}' is not a member of room '{room_id}'.")

        tid = task_id or f"task_{uuid.uuid4().hex[:8]}"
        now = utc_now_iso()

        async with get_db_writer(self.db_path) as conn:
            # Insert task
            await conn.execute(
                """
                INSERT INTO tasks (
                    task_id, room_id, title, owner_member_id,
                    status, proof_status, policy_id, expected_paths_json,
                    due_at, last_reminded_tier,
                    version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'OPEN', 'AWAITING_PROOF', ?, ?, ?, 0, 1, ?, ?)
                """,
                (
                    tid,
                    room_id,
                    title,
                    assigned_owner,
                    policy_id,
                    json.dumps(expected_paths),
                    due_at,
                    now,
                    now,
                ),
            )

            # Insert creation audit event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, 1, ?, 'TASK_CREATED', ?, ?, ?, ?, ?)
                """,
                (
                    tid,
                    event_id,
                    actor["member_id"],
                    room_id,
                    source_event_id,
                    json.dumps(
                        {
                            "title": title,
                            "owner": assigned_owner,
                            "paths": expected_paths,
                            "policy_id": policy_id,
                            "due_at": due_at,
                        }
                    ),
                    now,
                ),
            )

        logger.info("Task %s created by %s in room %s", tid, actor["member_id"], room_id)
        return tid

    async def start_task(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        source_event_id: Optional[str] = None,
    ) -> None:
        """
        Transition task OPEN -> IN_PROGRESS.
        Authorized only for task owner or room lead.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        is_owner = task["owner_member_id"] == actor["member_id"]
        is_lead = membership["role"] == "lead"
        if not (is_owner or is_lead):
            raise AuthorizationError("Only the task owner or a room lead may start work on this task.")

        if task["status"] != "OPEN":
            raise InvalidStateTransitionError(
                f"Cannot start task '{task_id}' in status '{task['status']}' (expected OPEN)."
            )

        async with get_db_writer(self.db_path) as conn:
            now = utc_now_iso()
            new_version = task["version"] + 1

            cur = await conn.execute(
                """
                UPDATE tasks
                SET status = 'IN_PROGRESS',
                    version = ?,
                    updated_at = ?
                WHERE task_id = ? AND version = ? AND status = 'OPEN'
                """,
                (new_version, now, task_id, task["version"]),
            )
            if cur.rowcount == 0:
                raise InvalidStateTransitionError("Concurrent update detected; task could not be started.")

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'TASK_STARTED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    actor["member_id"],
                    room_id,
                    source_event_id,
                    json.dumps({"from": "OPEN", "to": "IN_PROGRESS"}),
                    now,
                ),
            )

    async def block_task(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        reason: str,
        source_event_id: Optional[str] = None,
    ) -> None:
        """
        Transition task OPEN/IN_PROGRESS -> BLOCKED.
        Authorized only for task owner or room lead.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        is_owner = task["owner_member_id"] == actor["member_id"]
        is_lead = membership["role"] == "lead"
        if not (is_owner or is_lead):
            raise AuthorizationError("Only the task owner or a room lead may block this task.")

        if task["status"] not in ("OPEN", "IN_PROGRESS"):
            raise InvalidStateTransitionError(
                f"Cannot block task '{task_id}' in status '{task['status']}'."
            )

        async with get_db_writer(self.db_path) as conn:
            now = utc_now_iso()
            new_version = task["version"] + 1

            cur = await conn.execute(
                """
                UPDATE tasks
                SET status = 'BLOCKED',
                    blocker = ?,
                    version = ?,
                    updated_at = ?
                WHERE task_id = ? AND version = ? AND status IN ('OPEN', 'IN_PROGRESS')
                """,
                (reason, new_version, now, task_id, task["version"]),
            )
            if cur.rowcount == 0:
                raise InvalidStateTransitionError("Concurrent update detected; task could not be blocked.")

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'TASK_BLOCKED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    actor["member_id"],
                    room_id,
                    source_event_id,
                    json.dumps({"blocker": reason}),
                    now,
                ),
            )

    async def unblock_task(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        source_event_id: Optional[str] = None,
    ) -> None:
        """
        Transition task BLOCKED -> IN_PROGRESS.
        Authorized only for task owner or room lead.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        is_owner = task["owner_member_id"] == actor["member_id"]
        is_lead = membership["role"] == "lead"
        if not (is_owner or is_lead):
            raise AuthorizationError("Only the task owner or a room lead may unblock this task.")

        if task["status"] != "BLOCKED":
            raise InvalidStateTransitionError(
                f"Cannot unblock task '{task_id}' in status '{task['status']}' (expected BLOCKED)."
            )

        async with get_db_writer(self.db_path) as conn:
            now = utc_now_iso()
            new_version = task["version"] + 1

            cur = await conn.execute(
                """
                UPDATE tasks
                SET status = 'IN_PROGRESS',
                    blocker = NULL,
                    version = ?,
                    updated_at = ?
                WHERE task_id = ? AND version = ? AND status = 'BLOCKED'
                """,
                (new_version, now, task_id, task["version"]),
            )
            if cur.rowcount == 0:
                raise InvalidStateTransitionError("Concurrent update detected; task could not be unblocked.")

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'TASK_UNBLOCKED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    actor["member_id"],
                    room_id,
                    source_event_id,
                    json.dumps({"from": "BLOCKED", "to": "IN_PROGRESS"}),
                    now,
                ),
            )

    async def add_delegate(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        delegate_member_id: str,
        source_event_id: Optional[str] = None,
    ) -> None:
        """
        Record a delegate for a task.
        Only task owner or room lead may grant delegate permissions.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        is_owner = task["owner_member_id"] == actor["member_id"]
        is_lead = membership["role"] == "lead"
        if not (is_owner or is_lead):
            raise AuthorizationError("Only the task owner or room lead may assign delegates.")

        del_membership = await self.repo.get_room_membership(room_id, delegate_member_id)
        if not del_membership:
            raise AuthorizationError(f"Delegate '{delegate_member_id}' is not an active member in room '{room_id}'.")

        async with get_db_writer(self.db_path) as conn:
            now = utc_now_iso()
            await conn.execute(
                """
                INSERT OR IGNORE INTO task_delegates (task_id, room_id, member_id, granted_by)
                VALUES (?, ?, ?, ?)
                """,
                (task_id, room_id, delegate_member_id, actor["member_id"]),
            )

            # Update task version
            new_version = task["version"] + 1
            await conn.execute(
                "UPDATE tasks SET version = ?, updated_at = ? WHERE task_id = ?",
                (new_version, now, task_id),
            )

            # Audit event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            await conn.execute(
                """
                INSERT INTO task_events (
                    task_id, task_version, event_id, kind,
                    actor_member_id, source_room_id, source_event_id,
                    details_json, created_at
                ) VALUES (?, ?, ?, 'DELEGATE_ADDED', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    new_version,
                    event_id,
                    actor["member_id"],
                    room_id,
                    source_event_id,
                    json.dumps({"delegate": delegate_member_id, "granted_by": actor["member_id"]}),
                    now,
                ),
            )

    async def set_task_dependencies(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        candidate_dependencies: List[str],
        source_event_id: Optional[str] = None,
    ) -> bool:
        """
        Update dependencies with recursive CTE cycle check from LLD 1.
        Throws DependencyCycleError if a cycle is detected.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        is_owner = task["owner_member_id"] == actor["member_id"]
        is_lead = membership["role"] == "lead"
        if not (is_owner or is_lead):
            raise AuthorizationError("Only the task owner or room lead may update task dependencies.")

        try:
            return await self.repo.set_task_dependencies(
                room_id=room_id,
                task_id=task_id,
                candidate_dependencies=candidate_dependencies,
                actor_member_id=actor["member_id"],
                source_event_id=source_event_id,
            )
        except ValueError as e:
            raise DependencyCycleError(str(e)) from e

    async def submit_proof(
        self,
        room_id: str,
        actor_switch_id: str,
        task_id: str,
        pr_url: str,
        source_event_id: Optional[str] = None,
        inbox_event_key: Optional[Tuple[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the complete Proof-Gated Completion workflow from LLD 2 & LLD 3:
        1. Validate submitter authority (owner, delegate, or lead).
        2. Ensure task is IN_PROGRESS and not BLOCKED.
        3. Load policy head & create verification attempt (state: CHECKING, task proof: VERIFYING).
        4. Run GitHubVerifier.verify(...) (read-only checks, POSIX globs, 5s TOCTOU guard).
        5. Atomic CAS completion:
           - On VerifiedSnapshot: commit CAS task COMPLETE, insert proof, audit event, outbox message.
           - On RetryableFailure: update attempt RETRY_LATER, task PENDING_RETRY.
           - On PermanentFailure: update attempt REJECTED, task REJECTED, outbox explanation.
        """
        actor, membership = await self._resolve_actor_authority(room_id, actor_switch_id)
        task = await self.repo.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        # Check authorization: must be owner, listed delegate, or room lead
        delegates = await self.repo.get_task_delegates(task_id)
        is_owner = task["owner_member_id"] == actor["member_id"]
        is_delegate = actor["member_id"] in delegates
        is_lead = membership["role"] == "lead"

        if not (is_owner or is_delegate or is_lead):
            raise AuthorizationError(
                f"Member '{actor['member_id']}' is not authorized to submit proof for task '{task_id}'."
            )

        # Task must be IN_PROGRESS (cannot complete an OPEN or BLOCKED task directly)
        if task["status"] == "BLOCKED":
            raise InvalidStateTransitionError(
                f"Task '{task_id}' is BLOCKED. An owner or lead must unblock the task before verification."
            )
        if task["status"] != "IN_PROGRESS":
            raise InvalidStateTransitionError(
                f"Task '{task_id}' is in status '{task['status']}' (must be IN_PROGRESS to verify proof)."
            )

        # Load Policy
        policy = await self.repo.get_policy_head(task["policy_id"])
        if not policy:
            raise ValueError(f"Policy '{task['policy_id']}' not found.")

        # Determine allowed GitHub logins
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                "SELECT github_login FROM members WHERE member_id = ?",
                (task["owner_member_id"],),
            )
            row = await cur.fetchone()
            owner_login = row["github_login"] if row and row["github_login"] else None

            delegate_logins = []
            for d_id in delegates:
                cur = await db.execute(
                    "SELECT github_login FROM members WHERE member_id = ?", (d_id,)
                )
                r = await cur.fetchone()
                if r and r["github_login"]:
                    delegate_logins.append(r["github_login"])

        allowed_authors = [l for l in ([owner_login] + delegate_logins) if l]

        # Step 3: Start verification attempt
        attempt_id = f"att_{uuid.uuid4().hex[:12]}"
        attempt_info = await self.repo.start_attempt(
            attempt_id=attempt_id,
            task_id=task_id,
            submitted_by=actor["member_id"],
            pr_url=pr_url,
            source_room_id=room_id,
            source_event_id=source_event_id,
        )

        expected_paths = json.loads(task["expected_paths_json"])
        required_checks = json.loads(policy["required_checks_json"])

        v_input = VerificationInput(
            task_id=task_id,
            pr_url=pr_url,
            expected_paths=expected_paths,
            allowed_authors=allowed_authors,
            policy_id=policy["policy_id"],
            policy_revision=policy["current_revision"],
            policy_hash=policy["current_hash"],
            repo_full_name=policy["repo_full_name"],
            required_checks=required_checks,
        )

        # Step 4: Run GitHub Read-Only Verification
        result = await self.verifier.verify(
            attempt_id=attempt_id,
            task_version=attempt_info["task_version"],
            v_input=v_input,
        )

        # Step 5: Handle Verification Result
        if isinstance(result, VerifiedSnapshot):
            # Check 5-second freshness window from final_read_at
            now_dt = datetime.now(timezone.utc)
            final_read_dt = datetime.fromisoformat(result.final_read_at)
            elapsed_seconds = (now_dt - final_read_dt).total_seconds()

            if elapsed_seconds > 5.0:
                logger.warning("TOCTOU 5-second freshness window expired (elapsed: %.2fs)", elapsed_seconds)
                await self.repo.record_retry(
                    attempt_id=attempt_id,
                    task_id=task_id,
                    reason=f"Freshness window expired ({elapsed_seconds:.2f}s > 5s)",
                    retry_delay_seconds=10,
                )
                return {
                    "status": "RETRY_LATER",
                    "attempt_id": attempt_id,
                    "reason": "Freshness window expired",
                }

            # Atomic CAS Completion Transaction
            commit_res = await self.repo.finalize_success(
                snapshot=result.model_dump(),
                inbox_event_key=inbox_event_key,
            )

            if commit_res == "COMMITTED":
                logger.info("Task %s successfully VERIFIED and COMPLETE!", task_id)
                return {
                    "status": "VERIFIED",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "sha": result.head_sha,
                }
            elif commit_res == "CONFLICT":
                logger.warning("CAS conflict occurred for task %s; attempt superseded", task_id)
                return {
                    "status": "CAS_CONFLICT",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                }
            else:
                return {
                    "status": commit_res,
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                }

        elif isinstance(result, RetryableFailure):
            logger.info("Proof verification transient failure: %s", result.reason)
            await self.repo.record_retry(
                attempt_id=attempt_id,
                task_id=task_id,
                reason=result.reason,
                retry_delay_seconds=result.retry_after_seconds,
            )
            return {
                "status": "RETRY_LATER",
                "attempt_id": attempt_id,
                "reason": result.reason,
            }

        elif isinstance(result, PermanentFailure):
            logger.info("Proof verification permanent rejection: %s", result.reason)
            await self.repo.record_rejection(
                attempt_id=attempt_id,
                task_id=task_id,
                reason=result.reason,
                room_id=room_id,
            )
            return {
                "status": "REJECTED",
                "attempt_id": attempt_id,
                "reason": result.reason,
            }

        return {"status": "UNKNOWN"}


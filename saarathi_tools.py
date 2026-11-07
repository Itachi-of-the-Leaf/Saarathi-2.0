"""Standard tool interface exposing Saarathi 2.0 capabilities.

This root module is a stable bridge for Switch or local LLM agents. It delegates
all state changes to the restructured Saarathi package and never writes task
tables directly.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from saarathi.core.coordinator import (
    AuthorizationError,
    Coordinator,
    DependencyCycleError,
    InvalidStateTransitionError,
)
from saarathi.core.risk_engine import RiskEngine
from saarathi.database import DEFAULT_DB_PATH, TaskRepository, init_db


DB_PATH = os.getenv("SQLITE_DB_PATH", DEFAULT_DB_PATH)


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _deadline_from_minutes(due_in_minutes: Optional[int]) -> Optional[str]:
    if due_in_minutes is None:
        return None
    if not isinstance(due_in_minutes, int) or due_in_minutes < 0:
        raise ValueError("due_in_minutes must be a non-negative integer")
    return (datetime.now(timezone.utc) + timedelta(minutes=due_in_minutes)).isoformat()


class SaarathiToolBridge:
    """Async tool bridge backed by Saarathi's authoritative services."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.repo = TaskRepository(db_path)
        self.coord = Coordinator(db_path)
        self.risk_engine = RiskEngine(db_path)

    async def create_task_with_deadline(
        self,
        room_id: str,
        actor_id: str,
        title: str,
        due_in_minutes: Optional[int] = None,
        owner: Optional[str] = None,
        scope: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a scoped task whose deadline is monitored by the ticker."""
        await init_db(self.db_path)
        room_id = _required_text(room_id, "room_id")
        actor_id = _required_text(actor_id, "actor_id")
        title = _required_text(title, "title")
        due_at = _deadline_from_minutes(due_in_minutes)
        expected_paths = scope or ["src/**", "tests/**"]
        if not expected_paths or any(not isinstance(path, str) or not path.strip() for path in expected_paths):
            raise ValueError("scope must contain at least one non-empty path pattern")

        owner_id = owner.strip() if owner else actor_id
        task_id = await self.coord.create_task(
            room_id=room_id,
            actor_switch_id=actor_id,
            title=title,
            expected_paths=expected_paths,
            owner_member_id=owner_id,
            due_at=due_at,
        )
        return {
            "status": "CREATED",
            "task_id": task_id,
            "title": title,
            "owner": owner_id,
            "due_at": due_at,
            "message": f"Task [{task_id}] '{title}' created. Deadline set for {due_at or 'none'}. Autonomous background hound is monitoring.",
        }

    async def schedule_deadline(
        self,
        room_id: str,
        actor_id: str,
        task_id: str,
        due_in_minutes: int,
    ) -> Dict[str, Any]:
        """Schedule or replace a task deadline through the audited coordinator."""
        await init_db(self.db_path)
        due_at = _deadline_from_minutes(due_in_minutes)
        result = await self.coord.schedule_deadline(
            room_id=_required_text(room_id, "room_id"),
            actor_switch_id=_required_text(actor_id, "actor_id"),
            task_id=_required_text(task_id, "task_id"),
            due_at=due_at or "",
        )
        return {"status": "SCHEDULED", **result}

    async def verify_pr_proof(
        self, room_id: str, actor_id: str, task_id: str, pr_url: str
    ) -> Dict[str, Any]:
        """Run the deterministic Proof Gate for a task completion claim."""
        await init_db(self.db_path)
        return await self.coord.submit_proof(
            room_id=_required_text(room_id, "room_id"),
            actor_switch_id=_required_text(actor_id, "actor_id"),
            task_id=_required_text(task_id, "task_id"),
            pr_url=_required_text(pr_url, "pr_url"),
        )

    async def get_project_status(self, room_id: str) -> Dict[str, Any]:
        """Return the authoritative completed, active, and blocked breakdown."""
        await init_db(self.db_path)
        return await self.repo.get_status_summary(_required_text(room_id, "room_id"))

    async def check_blocker_blast_radius(self, room_id: str, task_id: str) -> Dict[str, Any]:
        """Evaluate downstream impact using the existing risk engine."""
        await init_db(self.db_path)
        return await self.risk_engine.calculate_blocker_blast_radius(
            _required_text(room_id, "room_id"), _required_text(task_id, "task_id")
        )


TOOL_FUNCTIONS: Dict[str, Callable[..., Awaitable[Dict[str, Any]]]] = {
    "create_task_with_deadline": SaarathiToolBridge.create_task_with_deadline,
    "schedule_deadline": SaarathiToolBridge.schedule_deadline,
    "verify_pr_proof": SaarathiToolBridge.verify_pr_proof,
    "get_project_status": SaarathiToolBridge.get_project_status,
    "check_blocker_blast_radius": SaarathiToolBridge.check_blocker_blast_radius,
}


async def call_tool(
    name: str, arguments: Dict[str, Any], db_path: str = DB_PATH
) -> Dict[str, Any]:
    """Dispatch a whitelisted tool call and return an LLM-safe structured result."""
    if name not in TOOL_FUNCTIONS:
        return {"status": "ERROR", "error": f"Unknown Saarathi tool: {name}"}
    try:
        bridge = SaarathiToolBridge(db_path)
        return await TOOL_FUNCTIONS[name](bridge, **arguments)
    except (AuthorizationError, DependencyCycleError, InvalidStateTransitionError, ValueError) as exc:
        return {"status": "ERROR", "error": str(exc), "error_type": type(exc).__name__}


__all__ = ["DB_PATH", "SaarathiToolBridge", "TOOL_FUNCTIONS", "call_tool"]

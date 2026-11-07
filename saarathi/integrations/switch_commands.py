"""Structured Switch-to-Saarathi command protocol.

Commands arrive inside the existing Switch SSE event stream and return through
the existing durable outbox. This module validates and dispatches requests;
task state remains owned by the coordinator and repository layers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..core.coordinator import Coordinator
from ..core.risk_engine import RiskEngine
from ..database import TaskRepository


class SwitchCommandError(ValueError):
    """A client-correctable structured command error."""

    def __init__(self, message: str, code: str = "invalid_command") -> None:
        super().__init__(message)
        self.code = code


class SwitchCommand(BaseModel):
    """Validated command envelope carried by a Switch event."""

    model_config = ConfigDict(extra="forbid")

    action: Literal[
        "create_task",
        "list_tasks",
        "get_task",
        "update_task_status",
        "assign_task",
        "get_dependencies",
        "get_blockers",
        "submit_proof",
    ]
    request_id: str = Field(min_length=1, max_length=128)
    task_id: Optional[str] = Field(default=None, max_length=128)
    title: Optional[str] = Field(default=None, min_length=1, max_length=500)
    expected_paths: Optional[List[str]] = None
    owner_member_id: Optional[str] = Field(default=None, max_length=128)
    status: Optional[Literal["IN_PROGRESS", "BLOCKED"]] = None
    pr_url: Optional[str] = Field(default=None, max_length=2048)
    blocker_reason: Optional[str] = Field(default=None, max_length=2000)
    due_at: Optional[str] = Field(default=None, max_length=128)
    filter_status: Optional[Literal["OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETE"]] = None
    filter_owner_member_id: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_action_fields(self) -> "SwitchCommand":
        requires_task = {
            "get_task",
            "update_task_status",
            "assign_task",
            "get_dependencies",
            "get_blockers",
            "submit_proof",
        }
        if self.action in requires_task and not self.task_id:
            raise ValueError(f"{self.action} requires task_id")
        if self.action == "create_task":
            if not self.title:
                raise ValueError("create_task requires title")
            if not self.expected_paths:
                raise ValueError("create_task requires expected_paths")
        if self.action == "update_task_status":
            if not self.status:
                raise ValueError("update_task_status requires status")
            if self.status == "BLOCKED" and not self.blocker_reason:
                raise ValueError("BLOCKED status requires blocker_reason")
        if self.action == "assign_task" and not self.owner_member_id:
            raise ValueError("assign_task requires owner_member_id")
        if self.action == "submit_proof" and not self.pr_url:
            raise ValueError("submit_proof requires pr_url")
        return self


class SwitchCommandHandler:
    """Execute validated commands using existing authoritative services."""

    def __init__(
        self,
        coordinator: Coordinator,
        repository: TaskRepository,
        risk_engine: RiskEngine,
    ) -> None:
        self.coordinator = coordinator
        self.repository = repository
        self.risk_engine = risk_engine

    async def execute(
        self,
        payload: Dict[str, Any],
        room_id: str,
        actor_switch_id: str,
        source_event_id: Optional[str],
        delivery_target: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            command = SwitchCommand.model_validate(payload)
        except ValidationError as exc:
            raise SwitchCommandError(
                "; ".join(error["msg"] for error in exc.errors())
            ) from exc

        await self.coordinator.authorize_actor(room_id, actor_switch_id)
        action = command.action

        if action == "create_task":
            task_id = await self.coordinator.create_task(
                room_id=room_id,
                actor_switch_id=actor_switch_id,
                title=command.title or "",
                expected_paths=command.expected_paths or [],
                owner_member_id=command.owner_member_id,
                due_at=command.due_at,
                source_event_id=source_event_id,
            )
            return {"request_id": command.request_id, "action": action, "task_id": task_id}

        if action == "list_tasks":
            tasks = await self.repository.list_tasks(
                room_id, command.filter_status, command.filter_owner_member_id
            )
            return {"request_id": command.request_id, "action": action, "tasks": tasks}

        task = await self.repository.get_task(command.task_id or "")
        if not task or task["room_id"] != room_id:
            raise SwitchCommandError(
                f"Task '{command.task_id}' not found in room '{room_id}'.", "not_found"
            )

        if action == "get_task":
            return {"request_id": command.request_id, "action": action, "task": task}

        if action == "update_task_status":
            if command.status == "IN_PROGRESS":
                if task["status"] == "BLOCKED":
                    await self.coordinator.unblock_task(
                        room_id, actor_switch_id, command.task_id or "", source_event_id
                    )
                else:
                    await self.coordinator.start_task(
                        room_id, actor_switch_id, command.task_id or "", source_event_id
                    )
            else:
                await self.coordinator.block_task(
                    room_id,
                    actor_switch_id,
                    command.task_id or "",
                    command.blocker_reason or "",
                    source_event_id,
                )
            return {
                "request_id": command.request_id,
                "action": action,
                "task": await self.repository.get_task(command.task_id or ""),
            }

        if action == "assign_task":
            result = await self.coordinator.assign_task(
                room_id,
                actor_switch_id,
                command.task_id or "",
                command.owner_member_id or "",
                source_event_id,
            )
            return {"request_id": command.request_id, "action": action, "assignment": result}

        if action == "submit_proof":
            result = await self.coordinator.submit_proof(
                room_id=room_id,
                actor_switch_id=actor_switch_id,
                task_id=command.task_id or "",
                pr_url=command.pr_url or "",
                source_event_id=source_event_id,
                inbox_event_key=(room_id, source_event_id) if source_event_id else None,
                outbox_destination=delivery_target,
            )
            return {"request_id": command.request_id, "action": action, "verification": result}

        tasks, dependents, prerequisites = await self.risk_engine.get_task_dependency_graph(room_id)
        if action == "get_dependencies":
            return {
                "request_id": command.request_id,
                "action": action,
                "task_id": command.task_id,
                "prerequisites": [tasks[tid] for tid in prerequisites.get(command.task_id or "", [])],
                "dependents": [tasks[tid] for tid in dependents.get(command.task_id or "", [])],
            }

        blocked_by = [
            tasks[tid]
            for tid in prerequisites.get(command.task_id or "", [])
            if tasks[tid]["status"] != "COMPLETE"
        ]
        blast = await self.risk_engine.calculate_blocker_blast_radius(room_id, command.task_id or "")
        return {
            "request_id": command.request_id,
            "action": action,
            "task_id": command.task_id,
            "blocked_by": blocked_by,
            "reported_blocker": task.get("blocker"),
            "blast_radius": blast,
        }

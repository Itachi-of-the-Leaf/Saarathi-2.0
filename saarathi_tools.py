"""
saarathi_tools.py: Standard tool interface exposing Saarathi 2.0 capabilities
for LLM agents running in Switch or local environments.
"""
from __future__ import annotations
import asyncio
import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from database import TaskRepository, get_db_reader, init_db, DEFAULT_DB_PATH
from coordinator import Coordinator
from risk_engine import RiskEngine

REPO_ROOT = Path(__file__).parent.resolve()
DEFAULT_DB_PATH = os.getenv("SQLITE_DB_PATH") or str(REPO_ROOT / "saarathi.db")
if not os.path.isabs(DEFAULT_DB_PATH):
    DEFAULT_DB_PATH = str(REPO_ROOT / DEFAULT_DB_PATH)
DB_PATH = DEFAULT_DB_PATH


class SaarathiToolBridge:
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
        """
        Tool: Creates a task with strict file scopes and registers a real deadline
        in the SQLite database so the background 60s ticker autonomously monitors it.
        """
        await init_db(self.db_path)
        due_at = None
        if due_in_minutes:
            due_at = (datetime.now(timezone.utc) + timedelta(minutes=due_in_minutes)).isoformat()

        tid = await self.coord.create_task(
            room_id=room_id,
            actor_switch_id=actor_id,
            title=title,
            expected_paths=scope or ["src/**", "tests/**"],
            owner_member_id=owner or actor_id,
            due_at=due_at,
        )
        return {
            "status": "CREATED",
            "task_id": tid,
            "title": title,
            "owner": owner or actor_id,
            "due_at": due_at,
            "message": f"Task [{tid}] '{title}' created. Deadline set for {due_at}. Autonomous background hound is monitoring.",
        }

    async def verify_pr_proof(
        self, room_id: str, actor_id: str, task_id: str, pr_url: str
    ) -> Dict[str, Any]:
        """
        Tool: Deterministic Zero-Trust Proof Gate verification for a submitted PR.
        Verifies author, non-empty diff, POSIX globs, passing CI, and 5s TOCTOU.
        """
        await init_db(self.db_path)
        res = await self.coord.submit_proof(
            room_id=room_id,
            actor_switch_id=actor_id,
            task_id=task_id,
            pr_url=pr_url,
        )
        return res

    async def get_project_status(self, room_id: str) -> Dict[str, Any]:
        """Tool: God's Eye View status breakdown (Completed, In Progress, Blocked)."""
        await init_db(self.db_path)
        return await self.repo.get_status_summary(room_id)

    async def check_blocker_blast_radius(self, room_id: str, task_id: str) -> Dict[str, Any]:
        """Tool: Evaluates downstream impact of blocking a task."""
        await init_db(self.db_path)
        return await self.risk_engine.calculate_blocker_blast_radius(room_id, task_id)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python saarathi_tools.py <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    bridge = SaarathiToolBridge()

    if cmd == "create":
        # python saarathi_tools.py create <room_id> <actor_id> <title> <due_mins>
        room_id = sys.argv[2]
        actor = sys.argv[3]
        title = sys.argv[4]
        mins = int(sys.argv[5]) if len(sys.argv) > 5 else None
        res = asyncio.run(bridge.create_task_with_deadline(room_id, actor, title, mins))
        print(json.dumps(res, indent=2))

    elif cmd == "verify":
        # python saarathi_tools.py verify <room_id> <actor_id> <task_id> <pr_url>
        res = asyncio.run(bridge.verify_pr_proof(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
        print(json.dumps(res, indent=2))

    elif cmd == "status":
        # python saarathi_tools.py status <room_id>
        res = asyncio.run(bridge.get_project_status(sys.argv[2]))
        print(json.dumps(res, indent=2))

    elif cmd == "blast-radius":
        # python saarathi_tools.py blast-radius <room_id> <task_id>
        res = asyncio.run(bridge.check_blocker_blast_radius(sys.argv[2], sys.argv[3]))
        print(json.dumps(res, indent=2))

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


"""
risk_engine.py: Critical path analysis and blocker blast-radius evaluation for Saarathi 2.0.
Implements the Scheduler + Risk Engine component specified in HDL_1_of_1.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any, Dict, List, Set, Tuple

from database import DEFAULT_DB_PATH, get_db_reader

logger = logging.getLogger("saarathi.risk_engine")


class RiskEngine:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path

    async def get_task_dependency_graph(
        self, room_id: str
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Build dependency graph for a room:
        Returns:
            tasks: dict mapping task_id -> task dict
            dependents: dict mapping task_id -> list of tasks that depend on it (downstream)
            prerequisites: dict mapping task_id -> list of tasks it depends on (upstream)
        """
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                "SELECT * FROM tasks WHERE room_id = ?", (room_id,)
            )
            tasks = {r["task_id"]: dict(r) for r in await cur.fetchall()}

            cur = await db.execute(
                "SELECT task_id, depends_on_task_id FROM task_dependencies WHERE room_id = ?",
                (room_id,),
            )
            dep_rows = await cur.fetchall()

        dependents: Dict[str, List[str]] = defaultdict(list)
        prerequisites: Dict[str, List[str]] = defaultdict(list)

        for r in dep_rows:
            tid = r["task_id"]
            dep_id = r["depends_on_task_id"]
            if tid in tasks and dep_id in tasks:
                prerequisites[tid].append(dep_id)
                dependents[dep_id].append(tid)

        return tasks, dependents, prerequisites

    async def calculate_blocker_blast_radius(
        self, room_id: str, blocked_task_id: str
    ) -> Dict[str, Any]:
        """
        Calculate downstream blast radius for a blocked task:
        Finds all tasks directly or transitively waiting on this blocked task.
        """
        tasks, dependents, _ = await self.get_task_dependency_graph(room_id)
        if blocked_task_id not in tasks:
            return {"task_id": blocked_task_id, "downstream_tasks": [], "affected_owners": [], "blast_radius_score": 0}

        visited: Set[str] = set()
        queue = deque([blocked_task_id])
        downstream: List[Dict[str, Any]] = []
        affected_owners: Set[str] = set()

        while queue:
            current = queue.popleft()
            for dep_tid in dependents.get(current, []):
                if dep_tid not in visited:
                    visited.add(dep_tid)
                    queue.append(dep_tid)
                    t_info = tasks[dep_tid]
                    downstream.append({
                        "task_id": dep_tid,
                        "title": t_info["title"],
                        "status": t_info["status"],
                        "owner": t_info["owner_member_id"],
                    })
                    affected_owners.add(t_info["owner_member_id"])

        return {
            "task_id": blocked_task_id,
            "blocked_title": tasks[blocked_task_id]["title"],
            "blast_radius_score": len(visited),
            "downstream_tasks": downstream,
            "affected_owners": sorted(list(affected_owners)),
        }

    async def calculate_critical_path(self, room_id: str) -> List[str]:
        """
        Calculate the longest dependency path (Critical Path) among incomplete tasks.
        A delay on any task on the critical path directly delays the entire project completion.
        """
        tasks, dependents, prerequisites = await self.get_task_dependency_graph(room_id)
        active_tasks = {
            tid: t for tid, t in tasks.items() if t["status"] != "COMPLETE"
        }
        if not active_tasks:
            return []

        # Find in-degrees for active subgraph
        in_degree = {tid: 0 for tid in active_tasks}
        for tid in active_tasks:
            for dep in prerequisites.get(tid, []):
                if dep in active_tasks:
                    in_degree[tid] += 1

        # Longest path dynamic programming
        longest_path_to: Dict[str, List[str]] = {tid: [tid] for tid in active_tasks}
        queue = deque([tid for tid, deg in in_degree.items() if deg == 0])

        while queue:
            curr = queue.popleft()
            curr_path = longest_path_to[curr]

            for downstream_tid in dependents.get(curr, []):
                if downstream_tid in active_tasks:
                    if len(curr_path) + 1 > len(longest_path_to[downstream_tid]):
                        longest_path_to[downstream_tid] = curr_path + [downstream_tid]

                    in_degree[downstream_tid] -= 1
                    if in_degree[downstream_tid] == 0:
                        queue.append(downstream_tid)

        if not longest_path_to:
            return []

        # Return longest path overall
        critical_path = max(longest_path_to.values(), key=len)
        return critical_path


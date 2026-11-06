"""
main.py: Main entrypoint for Saarathi Zero-Trust Auditor.
Runs three concurrent asynchronous loops without external message queues:
1. Inbound Switch SSE listener (GET /rooms/{room_id}/events).
2. Outbox background dispatcher (POST /rooms/{room_id}/messages).
3. Periodic deadline & unblock ticker (runs every 60 seconds).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import signal
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv
from httpx_sse import aconnect_sse

from coordinator import (
    AuthorizationError,
    Coordinator,
    DependencyCycleError,
    InvalidStateTransitionError,
)
from database import (
    DEFAULT_DB_PATH,
    DEFAULT_POLICY_ID,
    TaskRepository,
    get_db_reader,
    get_db_writer,
    init_db,
    utc_now_iso,
)
from proof_gate import GitHubVerifier
from risk_engine import RiskEngine

load_dotenv()

# Setup logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("saarathi.main")

# Environment configuration
SWITCH_BASE_URL = os.getenv("SWITCH_BASE_URL", "https://api.switch.example.com").rstrip("/")
SWITCH_TOKEN = os.getenv("SWITCH_TOKEN", "")
SWITCH_ROOM_ID = os.getenv("SWITCH_ROOM_ID", "room_switch_demo")
AGENT_ID = os.getenv("AGENT_ID", "saarathi-auditor")
DB_PATH = os.getenv("SQLITE_DB_PATH", DEFAULT_DB_PATH)
TICKER_INTERVAL = int(os.getenv("TICKER_INTERVAL_SECONDS", "60"))
OUTBOX_POLL_INTERVAL = float(os.getenv("OUTBOX_POLL_INTERVAL_SECONDS", "2.0"))

# LLM Conversational Intake configuration
OPENAI_API_BASE = os.getenv("OPENAI_API_BASE", os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", os.getenv("LLM_API_KEY", ""))
LLM_BASE_URL = OPENAI_API_BASE
LLM_API_KEY = OPENAI_API_KEY
LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-4o-mini")


def sanitize_public_output(text: str) -> str:
    """
    Scrub sensitive credentials (GitHub PATs, OpenAI/LLM keys, Bearer tokens)
    from public room messages.
    """
    if not text:
        return text
    # 1. GitHub classic & fine-grained PATs
    text = re.sub(r"ghp_[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]", text)
    text = re.sub(r"github_pat_[a-zA-Z0-9_]{20,}", "[REDACTED_API_KEY]", text)
    # 2. OpenAI / OpenRouter sk- keys
    text = re.sub(r"sk-[a-zA-Z0-9_\-]{20,}", "[REDACTED_API_KEY]", text)
    # 3. Bearer tokens
    text = re.sub(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer [REDACTED_API_KEY]", text, flags=re.IGNORECASE)
    return text


def parse_due_date(due_str: Optional[str]) -> Optional[str]:
    """Parse ISO 8601 or relative deadline strings into UTC ISO string."""
    if not due_str or not isinstance(due_str, str):
        return None
    due_str = due_str.strip()
    try:
        dt = datetime.fromisoformat(due_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    m_h = re.search(r"(?:in\s+)?(\d+(?:\.\d+)?)\s*(?:h|hr|hours?)", due_str, re.IGNORECASE)
    if m_h:
        return (now + timedelta(hours=float(m_h.group(1)))).isoformat()
    m_m = re.search(r"(?:in\s+)?(\d+)\s*(?:m|min|mins|minutes?)", due_str, re.IGNORECASE)
    if m_m:
        return (now + timedelta(minutes=int(m_m.group(1)))).isoformat()
    m_d = re.search(r"(?:in\s+)?(\d+)\s*(?:d|days?)", due_str, re.IGNORECASE)
    if m_d:
        return (now + timedelta(days=int(m_d.group(1)))).isoformat()

    return None


class SwitchAdapter:
    """Handles parsing and ingestion of Switch platform events."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.repo = TaskRepository(db_path)

    async def ingest_event(self, event_data: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Deduplicate and store Switch event in switch_inbox.
        Advances room_cursors.received_cursor.
        Returns (is_new, event_id).
        """
        room_id = event_data.get("room_id") or SWITCH_ROOM_ID
        event_id = event_data.get("id") or event_data.get("event_id") or f"evt_{uuid.uuid4().hex[:12]}"
        cursor = event_data.get("cursor") or event_id
        actor_id = event_data.get("user_id") or event_data.get("actor_switch_id") or "anonymous"
        now = utc_now_iso()

        async with get_db_writer(self.db_path) as conn:
            # Check for existing event
            cur = await conn.execute(
                "SELECT state, result_json FROM switch_inbox WHERE room_id = ? AND event_id = ?",
                (room_id, event_id),
            )
            row = await cur.fetchone()
            if row:
                logger.debug("Duplicate event %s in room %s received (state: %s)", event_id, room_id, row["state"])
                return False, event_id

            # Insert inbox row
            await conn.execute(
                """
                INSERT INTO switch_inbox (
                    room_id, event_id, provider_cursor, actor_switch_id,
                    payload_json, state, attempt_count, received_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'RECEIVED', 0, ?, ?)
                """,
                (room_id, event_id, cursor, actor_id, json.dumps(event_data), now, now),
            )

            # Advance received_cursor
            await conn.execute(
                """
                INSERT INTO room_cursors (agent_id, room_id, received_cursor)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id, room_id) DO UPDATE SET received_cursor = excluded.received_cursor
                """,
                (AGENT_ID, room_id, cursor),
            )

        return True, event_id

    async def get_received_cursor(self, room_id: str) -> Optional[str]:
        """Fetch latest received cursor for room."""
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                "SELECT received_cursor FROM room_cursors WHERE agent_id = ? AND room_id = ?",
                (AGENT_ID, room_id),
            )
            row = await cur.fetchone()
            return row["received_cursor"] if row else None


def _normalize_intent_result(res: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Ensure consistent fields across legacy and unified schemas."""
    if not isinstance(res, dict):
        return res
    # Ensure task_id and task_ref are synced
    tid = res.get("task_ref") or res.get("task_id")
    res["task_ref"] = tid
    res["task_id"] = tid

    # Sync first task fields if tasks present
    tasks = res.get("tasks") or []
    if tasks and isinstance(tasks, list) and len(tasks) > 0 and isinstance(tasks[0], dict):
        first = tasks[0]
        if "task_title" not in res or res["task_title"] is None:
            res["task_title"] = first.get("title")
        if "expected_scope" not in res or res["expected_scope"] is None:
            res["expected_scope"] = first.get("scope")
        if "owner" not in res or res["owner"] is None:
            res["owner"] = first.get("owner")
        if "due_at" not in res or res["due_at"] is None:
            res["due_at"] = first.get("due_at")

    return res


def _regex_intent_fallback(clean_text: str) -> Optional[Dict[str, Any]]:
    """Fast regex parser for explicit commands starting with keywords."""
    # Syntax 1: status / overview / dashboard
    if re.search(r"^(?:status|overview|dashboard|summary)\b", clean_text, re.IGNORECASE):
        return {
            "intent": "STATUS_QUERY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 2: reassign <task_id> to <member>
    reassign_match = re.search(
        r"^reassign\s+([a-zA-Z0-9_-]+)\s+to\s+([a-zA-Z0-9_@-]+)", clean_text, re.IGNORECASE
    )
    if reassign_match:
        return {
            "intent": "REASSIGN_TASK",
            "tasks": [],
            "pr_url": None,
            "task_ref": reassign_match.group(1),
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": reassign_match.group(2).lstrip("@"),
        }

    # Syntax 3: afk / unavailable
    afk_match = re.search(
        r"^(?:afk|unavailable|offline)(?:\s+(?:for\s+)?(\d+(?:\.\d+)?)\s*(?:h|hr|hours?))?",
        clean_text,
        re.IGNORECASE,
    )
    if afk_match:
        hrs = float(afk_match.group(1)) if afk_match.group(1) else None
        return {
            "intent": "UPDATE_AVAILABILITY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": {"is_available": False, "duration_hours": hrs},
            "reassign_to": None,
        }

    # Syntax 4: available / back / online
    if re.search(r"^(?:back|available|online)\b", clean_text, re.IGNORECASE):
        return {
            "intent": "UPDATE_AVAILABILITY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": {"is_available": True, "duration_hours": None},
            "reassign_to": None,
        }

    # Syntax 5: start <task_id>
    start_match = re.search(r"^start\s+([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
    if start_match:
        return {
            "intent": "START_TASK",
            "tasks": [],
            "pr_url": None,
            "task_ref": start_match.group(1),
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 6: done / verify / proof <pr_url> [task:<task_id>]
    done_match = re.search(
        r"^(?:done|verify|proof)\s+(https?://github\.com/[^\s]+)(?:\s+(?:for\s+task|task:)?\s*([a-zA-Z0-9_-]+))?",
        clean_text,
        re.IGNORECASE,
    )
    if done_match:
        return {
            "intent": "CLAIM_DONE",
            "tasks": [],
            "pr_url": done_match.group(1),
            "task_ref": done_match.group(2) if done_match.group(2) else None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 7: block <task_id> [reason:<reason>]
    block_match = re.search(
        r"^block\s+([a-zA-Z0-9_-]+)(?:\s+(?:reason:)?(.+))?", clean_text, re.IGNORECASE
    )
    if block_match:
        reason_txt = block_match.group(2).strip() if block_match.group(2) else "Blocked waiting on dependencies"
        return {
            "intent": "REPORT_BLOCKER",
            "tasks": [],
            "pr_url": None,
            "task_ref": block_match.group(1),
            "blocker_target": None,
            "blocker_reason": reason_txt,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 8: unblock <task_id>
    unblock_match = re.search(r"^unblock\s+([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
    if unblock_match:
        return {
            "intent": "CLEAR_BLOCKER",
            "tasks": [],
            "pr_url": None,
            "task_ref": unblock_match.group(1),
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 9: create <title> ...
    create_match = re.search(
        r"^create\s+(.+?)(?:\s+scope:([^\s]+))?(?:\s+owner:([^\s]+))?(?:\s+due:([^\s]+))?(?:\s+depends:([^\s]+))?$",
        clean_text,
        re.IGNORECASE,
    )
    if create_match:
        scopes = create_match.group(2).split(",") if create_match.group(2) else ["src/**", "tests/**"]
        return {
            "intent": "CREATE_OR_CHAIN_TASK",
            "tasks": [
                {
                    "title": create_match.group(1).strip(),
                    "owner": create_match.group(3) if create_match.group(3) else None,
                    "due_at": create_match.group(4) if create_match.group(4) else None,
                    "depends_on_title": create_match.group(5) if create_match.group(5) else None,
                    "scope": scopes,
                }
            ],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Syntax 10: done without PR URL
    if re.search(r"^(?:done|completed|finished)\b", clean_text, re.IGNORECASE):
        pr_m = re.search(r"(https?://github\.com/[^\s]+)", clean_text)
        task_m = re.search(r"(?:task|for\s+task|task:)\s*([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
        return {
            "intent": "CLAIM_DONE",
            "tasks": [],
            "pr_url": pr_m.group(1) if pr_m else None,
            "task_ref": task_m.group(1) if task_m else None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    return None


def _heuristic_intent_fallback(clean_text: str, sender: str) -> Dict[str, Any]:
    """Fallback heuristic classifier when LLM is unavailable or fails."""
    lower = clean_text.lower()
    pr_match = re.search(r"(https?://github\.com/[^\s/]+/[^\s/]+/pull/\d+)", clean_text)
    task_match = re.search(r"(?:for\s+task\b|task:|\bfor\b)\s*[:#]?\s*([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
    task_ref = task_match.group(1) if task_match else None

    # Status query
    if any(k in lower for k in ("status", "overview", "dashboard", "summary", "god's eye", "how are we doing")):
        return {
            "intent": "STATUS_QUERY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Reassign task
    reassign_m = re.search(r"reassign\s+([a-zA-Z0-9_-]+)\s+to\s+([a-zA-Z0-9_@-]+)", clean_text, re.IGNORECASE)
    if reassign_m:
        return {
            "intent": "REASSIGN_TASK",
            "tasks": [],
            "pr_url": None,
            "task_ref": reassign_m.group(1),
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": reassign_m.group(2).lstrip("@"),
        }

    # Availability
    if any(k in lower for k in ("afk", "unavailable", "stepping away", "sick", "offline", "taking a break", "out of office", "ooo")):
        hrs_m = re.search(r"(\d+(?:\.\d+)?)\s*(?:h|hr|hours?)", clean_text, re.IGNORECASE)
        hrs = float(hrs_m.group(1)) if hrs_m else None
        return {
            "intent": "UPDATE_AVAILABILITY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": {"is_available": False, "duration_hours": hrs},
            "reassign_to": None,
        }

    if any(k in lower for k in ("back", "online", "available", "returned")):
        return {
            "intent": "UPDATE_AVAILABILITY",
            "tasks": [],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": {"is_available": True, "duration_hours": None},
            "reassign_to": None,
        }

    # Claim done
    if any(k in lower for k in ("done", "finished", "completed", "pr ready", "submitted pr", "ready for review", "verify")):
        return {
            "intent": "CLAIM_DONE",
            "tasks": [],
            "pr_url": pr_match.group(1) if pr_match else None,
            "task_ref": task_ref,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Clear blocker
    if any(k in lower for k in ("unblock", "resolved blocker", "unblocked", "resumed", "clear blocker")):
        return {
            "intent": "CLEAR_BLOCKER",
            "tasks": [],
            "pr_url": None,
            "task_ref": task_ref,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Report blocker
    if any(k in lower for k in ("block", "blocked", "stuck", "waiting for", "waiting on", "dependency issue", "holding up")):
        target_m = re.search(r"@([a-zA-Z0-9_-]+)", clean_text)
        target = target_m.group(1) if target_m else None
        return {
            "intent": "REPORT_BLOCKER",
            "tasks": [],
            "pr_url": None,
            "task_ref": task_ref,
            "blocker_target": target,
            "blocker_reason": clean_text,
            "availability": None,
            "reassign_to": None,
        }

    # Start task
    if any(k in lower for k in ("start", "working on", "picked up", "begin")):
        return {
            "intent": "START_TASK",
            "tasks": [],
            "pr_url": None,
            "task_ref": task_ref,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    # Create / Chain task
    if any(k in lower for k in ("create", "add task", "new task", "implement", "build", "chain")):
        title_cand = re.sub(
            r"^(?:create|add task|new task|please implement|implement)\s+",
            "",
            clean_text,
            flags=re.IGNORECASE,
        ).strip()
        return {
            "intent": "CREATE_OR_CHAIN_TASK",
            "tasks": [
                {
                    "title": title_cand,
                    "owner": sender,
                    "due_at": None,
                    "depends_on_title": None,
                    "scope": ["src/**", "tests/**"],
                }
            ],
            "pr_url": None,
            "task_ref": None,
            "blocker_target": None,
            "blocker_reason": None,
            "availability": None,
            "reassign_to": None,
        }

    return {
        "intent": "CHAT",
        "tasks": [],
        "pr_url": None,
        "task_ref": None,
        "blocker_target": None,
        "blocker_reason": None,
        "availability": None,
        "reassign_to": None,
    }


async def parse_conversational_intent(
    text: str, sender: str, http_client: Optional[httpx.AsyncClient] = None
) -> Dict[str, Any]:
    """
    Single structured LLM extraction pass for Saarathi 2.0 with fast regex shortcuts.
    Extracts intents:
    CREATE_OR_CHAIN_TASK, CLAIM_DONE, REPORT_BLOCKER, CLEAR_BLOCKER,
    UPDATE_AVAILABILITY, REASSIGN_TASK, STATUS_QUERY, START_TASK, CHAT.
    """
    clean_text = re.sub(r"@saarathi\b", "", text, flags=re.IGNORECASE).strip()

    # 1. Fast regex fallback
    fast_parsed = _regex_intent_fallback(clean_text)
    if fast_parsed is not None:
        logger.debug("Fast regex fallback matched: %s", fast_parsed["intent"])
        return _normalize_intent_result(fast_parsed)

    # If no LLM API key configured, use heuristic fallback immediately
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY") or OPENAI_API_KEY or LLM_API_KEY
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("LLM_BASE_URL") or OPENAI_API_BASE or LLM_BASE_URL
    if not api_key:
        logger.debug("No LLM API key configured; using heuristic intake parser")
        return _normalize_intent_result(_heuristic_intent_fallback(clean_text, sender))

    # 2. Call OpenAI-compatible LLM endpoint
    system_prompt = (
        "You are Saarathi 2.0, a Zero-Trust AI Coordinator for software teams.\n"
        "Analyze team chat messages addressed to you and extract structured intent into JSON.\n\n"
        "Allowed Intents:\n"
        "- CREATE_OR_CHAIN_TASK: Create one or multiple tasks, chain dependencies, specify scope, owner, and deadline.\n"
        "- CLAIM_DONE: User claims a task or PR is complete, ready for review, or done.\n"
        "- REPORT_BLOCKER: User reports being blocked, waiting on another member or task.\n"
        "- CLEAR_BLOCKER: Blocker is resolved, ready to resume.\n"
        "- UPDATE_AVAILABILITY: User is going AFK/unavailable or returning.\n"
        "- REASSIGN_TASK: Team lead reassigns a task to another team member.\n"
        "- STATUS_QUERY: User asks for project status, summary, overview, or God's Eye View.\n"
        "- START_TASK: User begins working on a task.\n"
        "- CHAT: General greetings, chit-chat, or questions.\n\n"
        "Output ONLY a valid JSON object matching this schema:\n"
        "{\n"
        '  "intent": "CREATE_OR_CHAIN_TASK" | "CLAIM_DONE" | "REPORT_BLOCKER" | "CLEAR_BLOCKER" | "UPDATE_AVAILABILITY" | "REASSIGN_TASK" | "STATUS_QUERY" | "START_TASK" | "CHAT",\n'
        '  "tasks": [\n'
        '    {\n'
        '      "title": string,\n'
        '      "owner": string or null,\n'
        '      "due_at": string or null,\n'
        '      "depends_on_title": string or null,\n'
        '      "scope": ["path/glob/**", ...]\n'
        '    }\n'
        '  ],\n'
        '  "pr_url": string or null,\n'
        '  "task_ref": string or null,\n'
        '  "blocker_target": string or null,\n'
        '  "blocker_reason": string or null,\n'
        '  "availability": {"is_available": boolean, "duration_hours": number or null} or null,\n'
        '  "reassign_to": string or null\n'
        "}"
    )

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Sender: {sender}\nMessage: {clean_text}"},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }

    client = http_client or httpx.AsyncClient(timeout=10.0)
    should_close = (http_client is None)
    try:
        resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code == 200:
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            logger.info("LLM conversational intake extracted: %s", parsed)
            return _normalize_intent_result(parsed)
        else:
            logger.warning("LLM API returned %d: %s. Using heuristic fallback.", resp.status_code, resp.text)
    except Exception as e:
        logger.warning("Failed to call LLM API (%s). Using heuristic fallback.", e)
    finally:
        if should_close:
            await client.aclose()

    return _normalize_intent_result(_heuristic_intent_fallback(clean_text, sender))


class AuditorEngine:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.adapter = SwitchAdapter(db_path)
        self.verifier = GitHubVerifier()
        self.coordinator = Coordinator(db_path, verifier=self.verifier)
        self.repo = TaskRepository(db_path)
        self.risk_engine = RiskEngine(db_path)

    # =========================================================================
    # Loop 1: Inbound Switch SSE Listener
    # =========================================================================
    async def run_inbound_sse_listener(self, shutdown_event: asyncio.Event) -> None:
        """
        Task 1: Connect to Switch SSE stream GET /rooms/{room_id}/events.
        Listens for room events, deduplicates in switch_inbox, and processes commands.
        """
        logger.info("Starting Inbound Switch SSE Listener for room: %s", SWITCH_ROOM_ID)
        headers = {
            "Accept": "text/event-stream",
            "User-Agent": f"Saarathi-Auditor/{AGENT_ID}",
        }
        if SWITCH_TOKEN:
            headers["Authorization"] = f"Bearer {SWITCH_TOKEN}"

        url = f"{SWITCH_BASE_URL}/rooms/{SWITCH_ROOM_ID}/events"
        backoff_seconds = 1.0

        while not shutdown_event.is_set():
            cursor = await self.adapter.get_received_cursor(SWITCH_ROOM_ID)
            params = {}
            if cursor:
                params["cursor"] = cursor

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
                    async with aconnect_sse(client, "GET", url, headers=headers, params=params) as event_source:
                        logger.info("Connected to Switch SSE stream at %s", url)
                        backoff_seconds = 1.0

                        async for sse_event in event_source.aiter_sse():
                            if shutdown_event.is_set():
                                break

                            if not sse_event.data:
                                continue

                            try:
                                payload = json.loads(sse_event.data)
                            except json.JSONDecodeError:
                                payload = {"text": sse_event.data, "id": sse_event.id}

                            if sse_event.id and "id" not in payload:
                                payload["id"] = sse_event.id

                            is_new, event_id = await self.adapter.ingest_event(payload)
                            if is_new:
                                asyncio.create_task(self._process_inbox_event(payload))

            except httpx.HTTPError as e:
                if not shutdown_event.is_set():
                    logger.warning("Switch SSE connection lost (%s). Retrying in %.1fs...", e, backoff_seconds)
                    await asyncio.sleep(backoff_seconds)
                    backoff_seconds = min(backoff_seconds * 2, 30.0)
            except Exception as e:
                if not shutdown_event.is_set():
                    logger.error("Unexpected error in SSE listener: %s", e, exc_info=True)
                    await asyncio.sleep(5.0)

    async def _process_inbox_event(self, event_data: Dict[str, Any]) -> None:
        """Parse message text and dispatch to coordinator using conversational intake."""
        room_id = event_data.get("room_id") or SWITCH_ROOM_ID
        event_id = event_data.get("id") or event_data.get("event_id")
        actor_id = event_data.get("user_id") or event_data.get("actor_switch_id")
        text = event_data.get("text") or event_data.get("content") or ""

        # Only process messages addressed to @Saarathi
        if "@saarathi" not in text.lower():
            return

        logger.info("Processing addressed event %s from %s: '%s'", event_id, actor_id, text)

        try:
            # Asynchronous conversational intent parsing
            intent_data = await parse_conversational_intent(text, actor_id)
            intent = intent_data.get("intent", "CHAT")
            logger.info("Parsed intent '%s' for event %s", intent, event_id)

            if intent in ("CREATE_OR_CHAIN_TASK", "CREATE_TASK"):
                tasks_to_create = intent_data.get("tasks") or []
                if not tasks_to_create and intent_data.get("task_title"):
                    tasks_to_create = [
                        {
                            "title": intent_data.get("task_title"),
                            "owner": intent_data.get("owner") or actor_id,
                            "due_at": intent_data.get("due_at"),
                            "depends_on_title": None,
                            "scope": intent_data.get("expected_scope") or ["src/**", "tests/**"],
                        }
                    ]

                if not tasks_to_create:
                    tasks_to_create = [
                        {
                            "title": text,
                            "owner": actor_id,
                            "due_at": None,
                            "depends_on_title": None,
                            "scope": ["src/**", "tests/**"],
                        }
                    ]

                created_tasks = []
                title_to_id = {}

                for spec in tasks_to_create:
                    title = spec.get("title") or "Untitled task"
                    raw_owner = spec.get("owner") or actor_id
                    owner_rec = await self.repo.get_member_by_switch_id(raw_owner)
                    owner = owner_rec["member_id"] if owner_rec else raw_owner.lower().replace("@", "").replace("sw_", "")
                    scopes = spec.get("scope") or ["src/**", "tests/**"]
                    due_at = parse_due_date(spec.get("due_at"))

                    tid = await self.coordinator.create_task(
                        room_id=room_id,
                        actor_switch_id=actor_id,
                        title=title,
                        expected_paths=scopes,
                        owner_member_id=owner,
                        due_at=due_at,
                        source_event_id=event_id,
                    )
                    title_to_id[title.lower()] = tid
                    created_tasks.append(
                        {
                            "task_id": tid,
                            "title": title,
                            "owner": owner,
                            "due_at": due_at,
                            "depends_on_title": spec.get("depends_on_title"),
                            "prereq_id": None,
                        }
                    )

                # Link dependencies and detect cycles
                cycle_detected = False
                cycle_error_msg = ""
                for t_info in created_tasks:
                    dep_title = t_info["depends_on_title"]
                    if dep_title:
                        prereq_id = title_to_id.get(dep_title.lower())
                        if not prereq_id:
                            # Look up in database by title or task_id
                            async with get_db_reader(self.db_path) as db:
                                c = await db.execute(
                                    "SELECT task_id FROM tasks WHERE room_id = ? AND (LOWER(title) LIKE ? OR task_id = ?) LIMIT 1",
                                    (room_id, f"%{dep_title.lower()}%", dep_title),
                                )
                                r = await c.fetchone()
                                if r:
                                    prereq_id = r["task_id"]
                        if prereq_id:
                            t_info["prereq_id"] = prereq_id
                            try:
                                await self.coordinator.set_task_dependencies(
                                    room_id, actor_id, t_info["task_id"], [prereq_id], source_event_id=event_id
                                )
                            except DependencyCycleError as dce:
                                cycle_detected = True
                                cycle_error_msg = str(dce)
                                logger.warning("Dependency cycle detected during chaining: %s", dce)

                if cycle_detected:
                    msg = (
                        f"⚠️ **Deadlock Detected!**\n"
                        f"A cyclic dependency was requested: {cycle_error_msg}\n"
                        f"Saarathi rejected the dependency cycle to protect execution order.\n"
                        f"💡 **Mediation Recommendation**: Team members should define and agree on a temporary mock API contract so both owners can develop in parallel without blocking each other."
                    )
                    await self._queue_room_reply(room_id, msg)
                else:
                    lines = ["📋 **Tasks Created & Chained Successfully:**"]
                    for t_info in created_tasks:
                        due_str = f" [Due: {t_info['due_at'][:16]}]" if t_info["due_at"] else ""
                        dep_str = f"\n  ↳ Depends on: [{t_info['prereq_id']}]" if t_info["prereq_id"] else ""
                        lines.append(f"• [{t_info['task_id']}] '{t_info['title']}' (Owner: @{t_info['owner']}){due_str}{dep_str}")
                    await self._queue_room_reply(room_id, "\n".join(lines))

            elif intent == "CLAIM_DONE":
                pr_url = intent_data.get("pr_url")
                task_ref = intent_data.get("task_ref") or intent_data.get("task_id")

                # Bluff Catcher: user claims done with no GitHub PR URL
                if not pr_url:
                    target_name = f"'{task_ref}'" if task_ref else "work"
                    await self._queue_room_reply(
                        room_id,
                        f"⚠️ @{actor_id}: You claimed {target_name} is complete, but provided no GitHub PR proof (URL)! "
                        f"Proof is required before completion.",
                    )
                    return

                # Resolve task_id
                task_id = None
                if task_ref:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id FROM tasks WHERE task_id = ? OR (room_id = ? AND LOWER(title) LIKE ?) LIMIT 1",
                            (task_ref, room_id, f"%{task_ref.lower()}%"),
                        )
                        r = await c.fetchone()
                        if r:
                            task_id = r["task_id"]

                if not task_id:
                    member = await self.repo.get_member_by_switch_id(actor_id)
                    if member:
                        async with get_db_reader(self.db_path) as db:
                            cur = await db.execute(
                                "SELECT task_id FROM tasks WHERE owner_member_id = ? AND status = 'IN_PROGRESS' ORDER BY updated_at DESC LIMIT 1",
                                (member["member_id"],),
                            )
                            row = await cur.fetchone()
                            if row:
                                task_id = row["task_id"]

                if not task_id:
                    await self._queue_room_reply(
                        room_id,
                        f"⚠️ Please specify which task this PR completes: `@Saarathi done {pr_url} task:<task_id>`",
                    )
                    return

                res = await self.coordinator.submit_proof(
                    room_id=room_id,
                    actor_switch_id=actor_id,
                    task_id=task_id,
                    pr_url=pr_url,
                    source_event_id=event_id,
                    inbox_event_key=(room_id, event_id),
                )
                logger.info("Verification result for event %s: %s", event_id, res)
                if res.get("status") == "VERIFIED":
                    # Check for downstream tasks unblocked by this completion
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            """
                            SELECT t.task_id, t.title, t.owner_member_id
                            FROM task_dependencies d
                            JOIN tasks t ON d.task_id = t.task_id
                            WHERE d.depends_on_task_id = ?
                            """,
                            (task_id,),
                        )
                        downstreams = await c.fetchall()

                    unblocked_msgs = []
                    for d in downstreams:
                        async with get_db_reader(self.db_path) as db:
                            p_cur = await db.execute(
                                """
                                SELECT pt.status
                                FROM task_dependencies td
                                JOIN tasks pt ON td.depends_on_task_id = pt.task_id
                                WHERE td.task_id = ?
                                """,
                                (d["task_id"],),
                            )
                            p_statuses = [row["status"] for row in await p_cur.fetchall()]
                        if all(s == "COMPLETE" for s in p_statuses):
                            unblocked_msgs.append(
                                f"• Downstream task [{d['task_id']}] '{d['title']}' owned by @{d['owner_member_id']} is now UNBLOCKED!"
                            )

                    reply = f"🎉 **Proof Verified!** Task [{task_id}] passed all policy and CI checks and is marked COMPLETE."
                    if unblocked_msgs:
                        reply += "\n" + "\n".join(unblocked_msgs)
                    await self._queue_room_reply(room_id, reply)

                elif res.get("status") == "RETRY_LATER":
                    await self._queue_room_reply(
                        room_id,
                        f"⏳ Proof check pending for task [{task_id}]: {res.get('reason')}. Task remains in progress; will auto-retry.",
                    )
                elif res.get("status") == "REJECTED":
                    await self._queue_room_reply(
                        room_id,
                        f"❌ Proof REJECTED for task [{task_id}]: {res.get('reason')}. Task remains in progress.",
                    )

            elif intent == "START_TASK":
                task_ref = intent_data.get("task_ref") or intent_data.get("task_id")
                task_id = None
                if task_ref:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id FROM tasks WHERE task_id = ? OR (room_id = ? AND LOWER(title) LIKE ?) LIMIT 1",
                            (task_ref, room_id, f"%{task_ref.lower()}%"),
                        )
                        r = await c.fetchone()
                        if r:
                            task_id = r["task_id"]

                if not task_id:
                    member = await self.repo.get_member_by_switch_id(actor_id)
                    if member:
                        async with get_db_reader(self.db_path) as db:
                            cur = await db.execute(
                                "SELECT task_id FROM tasks WHERE owner_member_id = ? AND status = 'OPEN' ORDER BY updated_at DESC LIMIT 1",
                                (member["member_id"],),
                            )
                            row = await cur.fetchone()
                            if row:
                                task_id = row["task_id"]

                if task_id:
                    await self.coordinator.start_task(room_id, actor_id, task_id, source_event_id=event_id)
                    await self._queue_room_reply(room_id, f"🚀 Task [{task_id}] moved to IN_PROGRESS.")
                else:
                    await self._queue_room_reply(room_id, "⚠️ Please specify which task to start: `@Saarathi start <task_id>`")

            elif intent == "REPORT_BLOCKER":
                task_ref = intent_data.get("task_ref") or intent_data.get("task_id")
                target = intent_data.get("blocker_target")
                reason = intent_data.get("blocker_reason") or "Blocked waiting on dependencies/clarification"

                task_id = None
                if task_ref:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id FROM tasks WHERE task_id = ? OR (room_id = ? AND LOWER(title) LIKE ?) LIMIT 1",
                            (task_ref, room_id, f"%{task_ref.lower()}%"),
                        )
                        r = await c.fetchone()
                        if r:
                            task_id = r["task_id"]

                if not task_id:
                    member = await self.repo.get_member_by_switch_id(actor_id)
                    if member:
                        async with get_db_reader(self.db_path) as db:
                            cur = await db.execute(
                                "SELECT task_id FROM tasks WHERE owner_member_id = ? AND status IN ('OPEN', 'IN_PROGRESS') ORDER BY updated_at DESC LIMIT 1",
                                (member["member_id"],),
                            )
                            row = await cur.fetchone()
                            if row:
                                task_id = row["task_id"]

                if not task_id:
                    await self._queue_room_reply(room_id, f"⚠️ Please specify which task is blocked: `@Saarathi block <task_id> {reason}`")
                    return

                full_reason = f"Waiting on @{target}: {reason}" if target else reason
                await self.coordinator.block_task(room_id, actor_id, task_id, full_reason, source_event_id=event_id)

                # Calculate Blast Radius using RiskEngine
                blast = await self.risk_engine.calculate_blocker_blast_radius(room_id, task_id)
                blast_str = ""
                if blast.get("blast_radius_score", 0) > 0:
                    owners_tag = ", ".join(f"@{o}" for o in blast["affected_owners"])
                    blast_str = f"\n💥 **Blast Radius**: {blast['blast_radius_score']} downstream task(s) impacted (Owners: {owners_tag})."

                if target:
                    await self._queue_room_reply(room_id, f"🛑 Task [{task_id}] blocked by @{target}: {reason}{blast_str}")
                else:
                    await self._queue_room_reply(room_id, f"🛑 Task [{task_id}] is now BLOCKED: {reason}{blast_str}")

            elif intent == "CLEAR_BLOCKER":
                task_ref = intent_data.get("task_ref") or intent_data.get("task_id")
                task_id = None
                if task_ref:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id FROM tasks WHERE task_id = ? OR (room_id = ? AND LOWER(title) LIKE ?) LIMIT 1",
                            (task_ref, room_id, f"%{task_ref.lower()}%"),
                        )
                        r = await c.fetchone()
                        if r:
                            task_id = r["task_id"]

                if not task_id:
                    member = await self.repo.get_member_by_switch_id(actor_id)
                    if member:
                        async with get_db_reader(self.db_path) as db:
                            cur = await db.execute(
                                "SELECT task_id FROM tasks WHERE owner_member_id = ? AND status = 'BLOCKED' ORDER BY updated_at DESC LIMIT 1",
                                (member["member_id"],),
                            )
                            row = await cur.fetchone()
                            if row:
                                task_id = row["task_id"]

                if task_id:
                    await self.coordinator.unblock_task(room_id, actor_id, task_id, source_event_id=event_id)
                    await self._queue_room_reply(room_id, f"✅ Task [{task_id}] is UNBLOCKED and IN_PROGRESS.")
                else:
                    await self._queue_room_reply(room_id, "⚠️ Please specify which task to unblock: `@Saarathi unblock <task_id>`")

            elif intent == "UPDATE_AVAILABILITY":
                avail = intent_data.get("availability") or {}
                is_avail = avail.get("is_available", True)
                dur_hours = avail.get("duration_hours")

                member_rec = await self.repo.get_member_by_switch_id(actor_id)
                member_id = member_rec["member_id"] if member_rec else actor_id.lower().replace("@", "").replace("sw_", "")

                if not is_avail:
                    unavail_until = None
                    dur_str = ""
                    if dur_hours:
                        unavail_dt = datetime.now(timezone.utc) + timedelta(hours=dur_hours)
                        unavail_until = unavail_dt.isoformat()
                        dur_str = f" for {dur_hours:g} hour(s)"
                    await self.repo.update_member_availability(member_id, is_available=False, unavailable_until=unavail_until)

                    # Dynamic reallocation of active tasks to lowest-load peer
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id, title FROM tasks WHERE owner_member_id = ? AND room_id = ? AND status IN ('OPEN', 'IN_PROGRESS') ORDER BY updated_at DESC",
                            (member_id, room_id),
                        )
                        active_tasks = await c.fetchall()

                    if active_tasks:
                        lowest_peer = await self.repo.get_lowest_load_member(room_id, exclude_member_ids=[member_id])
                        if lowest_peer:
                            reassigned_notes = []
                            for t in active_tasks:
                                res = await self.repo.reassign_task(
                                    room_id, t["task_id"], lowest_peer, actor_id=AGENT_ID, source_event_id=event_id
                                )
                                reassigned_notes.append(f"• Task [{res['task_id']}] '{res['title']}' $\\to$ @{res['new_owner']}")
                            reassigned_block = "\n".join(reassigned_notes)
                            await self._queue_room_reply(
                                room_id,
                                f"🛌 @{actor_id} is marked unavailable{dur_str}.\n"
                                f"Dynamic Reallocation (Lowest-Load Peer @{lowest_peer}):\n{reassigned_block}\n"
                                f"💡 Note: Team lead @soham can override reassignment if needed.",
                            )
                        else:
                            await self._queue_room_reply(room_id, f"🛌 @{actor_id} is marked unavailable{dur_str}.")
                    else:
                        await self._queue_room_reply(room_id, f"🛌 @{actor_id} is marked unavailable{dur_str}.")
                else:
                    await self.repo.update_member_availability(member_id, is_available=True, unavailable_until=None)
                    await self._queue_room_reply(room_id, f"👋 Welcome back @{actor_id}! Marked as AVAILABLE for task assignments.")

            elif intent == "REASSIGN_TASK":
                # Check authorization: sender must be lead in room_memberships or soham
                member_rec = await self.repo.get_member_by_switch_id(actor_id)
                clean_actor = member_rec["member_id"] if member_rec else actor_id.lower().replace("@", "").replace("sw_", "")

                is_lead = False
                if clean_actor in ("soham", "sw_soham"):
                    is_lead = True
                else:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT role FROM room_memberships WHERE room_id = ? AND member_id = ? AND active = 1",
                            (room_id, clean_actor),
                        )
                        r = await c.fetchone()
                        if r and r["role"] == "lead":
                            is_lead = True

                if not is_lead:
                    await self._queue_room_reply(room_id, "⚠️ Permission Denied: Only team lead @soham can manually reassign tasks.")
                    return

                task_ref = intent_data.get("task_ref") or intent_data.get("task_id")
                target_member = intent_data.get("reassign_to")
                task_id = None
                if task_ref:
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            "SELECT task_id FROM tasks WHERE task_id = ? OR (room_id = ? AND LOWER(title) LIKE ?) LIMIT 1",
                            (task_ref, room_id, f"%{task_ref.lower()}%"),
                        )
                        r = await c.fetchone()
                        if r:
                            task_id = r["task_id"]

                if not task_id or not target_member:
                    await self._queue_room_reply(room_id, "⚠️ Usage: `@Saarathi reassign <task_id> to <member>`")
                    return

                res = await self.repo.reassign_task(room_id, task_id, target_member, actor_id=clean_actor, source_event_id=event_id)
                await self._queue_room_reply(
                    room_id,
                    f"🔄 Team Lead @{actor_id} reassigned task [{task_id}] '{res['title']}' from @{res['old_owner']} to @{res['new_owner']}.",
                )

            elif intent == "STATUS_QUERY":
                summary = await self.repo.get_status_summary(room_id)
                lines = ["📊 **Saarathi God's Eye View:**"]

                lines.append(f"\n🟢 **Completed ({len(summary['completed'])}):**")
                if summary["completed"]:
                    for t in summary["completed"]:
                        lines.append(f"• [{t['task_id']}] '{t['title']}' (Owner: @{t['owner_member_id']})")
                else:
                    lines.append("  (None)")

                lines.append(f"\n🟡 **In Progress / Open ({len(summary['in_progress'])}):**")
                if summary["in_progress"]:
                    for t in summary["in_progress"]:
                        due_info = f" [Due: {t['due_at'][:16]}]" if t.get("due_at") else ""
                        lines.append(
                            f"• [{t['task_id']}] '{t['title']}' (Owner: @{t['owner_member_id']}, Status: {t['status']}){due_info}"
                        )
                else:
                    lines.append("  (None)")

                lines.append(f"\n🔴 **Blocked ({len(summary['blocked'])}):**")
                if summary["blocked"]:
                    for t in summary["blocked"]:
                        lines.append(
                            f"• [{t['task_id']}] '{t['title']}' (Owner: @{t['owner_member_id']}) - Reason: {t['blocker'] or 'Dependencies'}"
                        )
                else:
                    lines.append("  (None)")

                await self._queue_room_reply(room_id, "\n".join(lines))

            elif intent == "CHAT":
                await self._queue_room_reply(
                    room_id,
                    f"👋 Hi @{actor_id}! I am Saarathi, your Zero-Trust Coordinator. I track tasks, verify PR proof, detect deadlocks, and monitor deadlines.",
                )

            # Mark inbox event DONE and advance processed_cursor
            async with get_db_writer(self.db_path) as conn:
                await conn.execute(
                    """
                    UPDATE switch_inbox
                    SET state = 'DONE', updated_at = ?
                    WHERE room_id = ? AND event_id = ? AND state != 'DONE'
                    """,
                    (utc_now_iso(), room_id, event_id),
                )
            await self.repo.advance_processed_cursor(AGENT_ID, room_id)

        except (AuthorizationError, InvalidStateTransitionError, DependencyCycleError) as e:
            logger.warning("User command error for event %s: %s", event_id, e)
            await self._queue_room_reply(room_id, f"⚠️ {e}")
            async with get_db_writer(self.db_path) as conn:
                await conn.execute(
                    """
                    UPDATE switch_inbox
                    SET state = 'ERROR_TERMINAL', last_error = ?, updated_at = ?
                    WHERE room_id = ? AND event_id = ?
                    """,
                    (str(e), utc_now_iso(), room_id, event_id),
                )
            await self.repo.advance_processed_cursor(AGENT_ID, room_id)
        except Exception as e:
            logger.error("Error processing event %s: %s", event_id, e, exc_info=True)
            await self._queue_room_reply(room_id, f"❌ Internal error processing command: {e}")
            async with get_db_writer(self.db_path) as conn:
                await conn.execute(
                    """
                    UPDATE switch_inbox
                    SET state = 'RETRY', last_error = ?, updated_at = ?
                    WHERE room_id = ? AND event_id = ?
                    """,
                    (str(e), utc_now_iso(), room_id, event_id),
                )

    async def _queue_room_reply(self, room_id: str, message: str) -> None:
        """Queue a message in outbox table after sanitizing credentials."""
        sanitized_msg = sanitize_public_output(message)
        async with get_db_writer(self.db_path) as conn:
            out_id = f"out_{uuid.uuid4().hex[:12]}"
            now = utc_now_iso()
            await conn.execute(
                """
                INSERT INTO outbox (
                    outbox_id, idempotency_key, room_id, body,
                    status, attempts, next_attempt_at, created_at
                ) VALUES (?, ?, ?, ?, 'READY', 0, ?, ?)
                """,
                (out_id, f"reply_{out_id}", room_id, sanitized_msg, now, now),
            )

    # =========================================================================
    # Loop 2: Outbox Background Dispatcher
    # =========================================================================
    async def run_outbox_dispatcher(self, shutdown_event: asyncio.Event) -> None:
        """
        Task 2: Outbox background dispatcher with full-jitter exponential backoff and claim leases.
        POST /rooms/{room_id}/messages
        """
        logger.info("Starting Outbox Dispatcher (polling every %.1fs)", OUTBOX_POLL_INTERVAL)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Saarathi-Auditor/{AGENT_ID}",
        }
        if SWITCH_TOKEN:
            headers["Authorization"] = f"Bearer {SWITCH_TOKEN}"

        while not shutdown_event.is_set():
            try:
                claimed_batch = await self._claim_due_outbox_rows()
                if claimed_batch:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        for row in claimed_batch:
                            if shutdown_event.is_set():
                                break
                            await self._dispatch_outbox_message(client, row, headers)

            except Exception as e:
                logger.error("Error in outbox dispatcher loop: %s", e, exc_info=True)

            await asyncio.sleep(OUTBOX_POLL_INTERVAL)

    async def _claim_due_outbox_rows(self) -> List[Dict[str, Any]]:
        """
        Claim READY rows or CLAIMED rows with expired lease inside short writer transaction.
        Writes random claim_token, lease_until = now + 60s, attempts = attempts + 1.
        """
        async with get_db_writer(self.db_path) as conn:
            now_dt = datetime.now(timezone.utc)
            now = now_dt.isoformat()
            lease_until = (now_dt + timedelta(seconds=60)).isoformat()

            cur = await conn.execute(
                """
                SELECT outbox_id, idempotency_key, room_id, body, attempts
                FROM outbox
                WHERE (status = 'READY' AND next_attempt_at <= ?)
                   OR (status = 'CLAIMED' AND lease_until <= ?)
                ORDER BY next_attempt_at ASC
                LIMIT 10
                """,
                (now, now),
            )
            rows = await cur.fetchall()
            claimed = []

            for r in rows:
                token = uuid.uuid4().hex
                new_attempts = r["attempts"] + 1
                await conn.execute(
                    """
                    UPDATE outbox
                    SET status = 'CLAIMED',
                        claim_token = ?,
                        lease_until = ?,
                        attempts = ?
                    WHERE outbox_id = ?
                    """,
                    (token, lease_until, new_attempts, r["outbox_id"]),
                )
                item = dict(r)
                item["claim_token"] = token
                item["attempts"] = new_attempts
                claimed.append(item)

            return claimed

    async def _dispatch_outbox_message(
        self, client: httpx.AsyncClient, row: Dict[str, Any], headers: Dict[str, str]
    ) -> None:
        """Post message to Switch outside transaction, then commit result."""
        room_id = row["room_id"]
        out_id = row["outbox_id"]
        token = row["claim_token"]
        attempts = row["attempts"]
        post_url = f"{SWITCH_BASE_URL}/rooms/{room_id}/messages"
        payload = {
            "body": sanitize_public_output(row["body"]),
            "idempotency_key": row["idempotency_key"],
        }

        try:
            resp = await client.post(post_url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                # Success
                remote_id = resp.json().get("id") if resp.headers.get("content-type") == "application/json" else None
                async with get_db_writer(self.db_path) as conn:
                    await conn.execute(
                        """
                        UPDATE outbox
                        SET status = 'SENT',
                            sent_at = ?,
                            remote_message_id = ?
                        WHERE outbox_id = ? AND claim_token = ?
                        """,
                        (utc_now_iso(), remote_id, out_id, token),
                    )
                logger.info("Delivered outbox message %s to room %s", out_id, room_id)
            elif 400 <= resp.status_code < 500:
                # Permanent failure (bad auth, malformed room)
                async with get_db_writer(self.db_path) as conn:
                    await conn.execute(
                        "UPDATE outbox SET status = 'DEAD', last_error = ? WHERE outbox_id = ?",
                        (f"Client error {resp.status_code}: {resp.text}", out_id),
                    )
                logger.error("Outbox message %s failed permanently: %s", out_id, resp.text)
            else:
                # 5xx Server error -> retry with jitter backoff
                await self._reschedule_outbox_retry(out_id, attempts, f"Server error {resp.status_code}")

        except httpx.HTTPError as e:
            # Network failure -> retry with jitter backoff
            await self._reschedule_outbox_retry(out_id, attempts, str(e))

    async def _reschedule_outbox_retry(self, outbox_id: str, attempts: int, error_msg: str) -> None:
        """Full-jitter exponential backoff: random(0, min(5s * 2^(attempt-1), 15m))."""
        if attempts >= 8:
            async with get_db_writer(self.db_path) as conn:
                await conn.execute(
                    "UPDATE outbox SET status = 'DEAD', last_error = ? WHERE outbox_id = ?",
                    (f"Exhausted 8 attempts. Last error: {error_msg}", outbox_id),
                )
            logger.error("Outbox message %s exceeded max 8 attempts, marked DEAD.", outbox_id)
            return

        max_backoff = min(5.0 * (2.0 ** (attempts - 1)), 900.0)
        delay = random.uniform(0.5, max_backoff)
        next_attempt = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()

        async with get_db_writer(self.db_path) as conn:
            await conn.execute(
                """
                UPDATE outbox
                SET status = 'READY',
                    next_attempt_at = ?,
                    last_error = ?
                WHERE outbox_id = ?
                """,
                (next_attempt, error_msg, outbox_id),
            )
        logger.debug("Rescheduled outbox %s for attempt %d in %.1fs", outbox_id, attempts + 1, delay)

    # =========================================================================
    # Loop 3: Periodic Deadline & Unblock Ticker (runs every 60s)
    # =========================================================================
    async def run_periodic_ticker(self, shutdown_event: asyncio.Event) -> None:
        """
        Task 3: Periodic deadline & dependency unblock ticker (every 60s).
        1. Checks deadline reminders and escalations (3-tier Deadline Hound).
        2. Checks blocked tasks whose prerequisites are now complete.
        3. Retries verification attempts in RETRY_LATER state.
        """
        logger.info("Starting Periodic Deadline & Unblock Ticker (interval: %ds)", TICKER_INTERVAL)

        while not shutdown_event.is_set():
            try:
                await self._check_deadlines()
                await self._check_dependency_unblocks()
                await self._retry_pending_verifications()
            except Exception as e:
                logger.error("Error during periodic ticker run: %s", e, exc_info=True)

            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=float(TICKER_INTERVAL))
            except asyncio.TimeoutError:
                pass

    async def _check_deadlines(self) -> None:
        """
        3-Tier Deadline Hound:
        - Tier 1: T - 1h (within 1 hour of deadline): gentle reminder to owner -> tier 1.
        - Tier 2: T + 0 (past due): overdue alert + downstream peer warnings -> tier 2.
        - Tier 3: T + 1h (1 hour overdue): escalate to team lead @soham -> tier 3.
        """
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                """
                SELECT task_id, room_id, title, owner_member_id, due_at, last_reminded_tier
                FROM tasks
                WHERE status IN ('OPEN', 'IN_PROGRESS') AND due_at IS NOT NULL
                """
            )
            active_tasks = await cur.fetchall()

        now = datetime.now(timezone.utc)

        for t in active_tasks:
            try:
                due_iso = t["due_at"].replace("Z", "+00:00")
                due_dt = datetime.fromisoformat(due_iso)
                if due_dt.tzinfo is None:
                    due_dt = due_dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue

            tid = t["task_id"]
            room = t["room_id"]
            owner = t["owner_member_id"]
            title = t["title"]
            tier = t["last_reminded_tier"]

            # Overdue vs upcoming
            if now > due_dt:
                overdue_secs = (now - due_dt).total_seconds()
                if overdue_secs >= 3600 and tier < 3:
                    logger.warning("Task %s is >1h overdue. Escalating to lead @soham", tid)
                    await self._queue_room_reply(
                        room,
                        f"🔥 **Critical Escalation**: Task [{tid}] '{title}' owned by @{owner} is >1 hour overdue! "
                        f"Notifying team lead @soham for intervention or reallocation.",
                    )
                    await self.repo.update_reminded_tier(tid, 3)
                elif overdue_secs < 3600 and tier < 2:
                    logger.warning("Task %s is past due. Alerting owner and downstream peers.", tid)
                    async with get_db_reader(self.db_path) as db:
                        c = await db.execute(
                            """
                            SELECT DISTINCT pt.owner_member_id
                            FROM task_dependencies d
                            JOIN tasks pt ON d.task_id = pt.task_id
                            WHERE d.depends_on_task_id = ?
                            """,
                            (tid,),
                        )
                        downstream_rows = await c.fetchall()
                    downstream_tags = (
                        ", ".join(f"@{r['owner_member_id']}" for r in downstream_rows)
                        if downstream_rows
                        else "None"
                    )

                    await self._queue_room_reply(
                        room,
                        f"🚨 **Overdue Alert**: Task [{tid}] '{title}' owned by @{owner} is now PAST DUE!\n"
                        f"Heads-up to downstream peers waiting on this task: {downstream_tags}.",
                    )
                    await self.repo.update_reminded_tier(tid, 2)
            else:
                rem_secs = (due_dt - now).total_seconds()
                if rem_secs <= 3600 and tier < 1:
                    mins_left = max(1, int(rem_secs // 60))
                    logger.info("Task %s is due in %d mins. Sending Tier 1 reminder.", tid, mins_left)
                    await self._queue_room_reply(
                        room,
                        f"⏰ **Heads-up** @{owner}: Task [{tid}] '{title}' is due in {mins_left} minutes!",
                    )
                    await self.repo.update_reminded_tier(tid, 1)

    async def _check_dependency_unblocks(self) -> None:
        """
        Inspect BLOCKED tasks. If all prerequisites are now COMPLETE,
        queue an unblock notification so the team lead or owner can resume work.
        """
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                """
                SELECT t.task_id, t.room_id, t.title, t.owner_member_id
                FROM tasks t
                WHERE t.status = 'BLOCKED'
                """
            )
            blocked_tasks = await cur.fetchall()

            for t in blocked_tasks:
                tid = t["task_id"]
                room = t["room_id"]
                # Query prerequisites for this task
                p_cur = await db.execute(
                    """
                    SELECT d.depends_on_task_id, pt.status
                    FROM task_dependencies d
                    JOIN tasks pt ON d.depends_on_task_id = pt.task_id
                    WHERE d.task_id = ?
                    """,
                    (tid,),
                )
                deps = await p_cur.fetchall()
                if not deps:
                    continue

                all_complete = all(d["status"] == "COMPLETE" for d in deps)
                if all_complete:
                    logger.info("All dependencies for blocked task %s are complete!", tid)
                    await self._queue_room_reply(
                        room,
                        f"🔔 Notice: All prerequisites for blocked task [{tid}] '{t['title']}' are COMPLETE! "
                        f"Owner @{t['owner_member_id']} or room lead may now resume work with `@Saarathi unblock {tid}`.",
                    )

    async def _retry_pending_verifications(self) -> None:
        """Check verification_attempts due for retry."""
        now = utc_now_iso()
        async with get_db_reader(self.db_path) as db:
            cur = await db.execute(
                """
                SELECT a.attempt_id, a.task_id, a.pr_url, a.submitted_by, t.room_id
                FROM verification_attempts a
                JOIN tasks t ON a.task_id = t.task_id
                WHERE a.state = 'RETRY_LATER'
                  AND a.next_retry_at <= ?
                  AND t.status = 'IN_PROGRESS'
                  AND t.proof_status = 'PENDING_RETRY'
                LIMIT 5
                """,
                (now,),
            )
            due_attempts = await cur.fetchall()

        for a in due_attempts:
            logger.info("Executing scheduled retry for verification attempt on task %s", a["task_id"])
            asyncio.create_task(
                self.coordinator.submit_proof(
                    room_id=a["room_id"],
                    actor_switch_id=a["submitted_by"],
                    task_id=a["task_id"],
                    pr_url=a["pr_url"],
                )
            )


async def main() -> None:
    """Initialize database and start all three asynchronous tasks."""
    logger.info("Initializing Saarathi Zero-Trust Auditor database...")
    await init_db(DB_PATH)

    engine = AuditorEngine(DB_PATH)
    shutdown_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_event.set)
        except NotImplementedError:
            # Signal handling on Windows
            pass

    logger.info("Starting Saarathi Zero-Trust Auditor engine with 3 async tasks...")
    tasks = [
        asyncio.create_task(engine.run_inbound_sse_listener(shutdown_event), name="SSE_Listener"),
        asyncio.create_task(engine.run_outbox_dispatcher(shutdown_event), name="Outbox_Dispatcher"),
        asyncio.create_task(engine.run_periodic_ticker(shutdown_event), name="Periodic_Ticker"),
    ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Received cancellation, shutting down...")
    finally:
        shutdown_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Saarathi Zero-Trust Auditor stopped cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Terminated by user.")


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
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-4o-mini")


class SwitchAdapter:
    """Handles parsing and ingestion of Switch platform events."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.repo = TaskRepository(db_path)

    async def ingest_event(self, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
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


def _regex_intent_fallback(clean_text: str) -> Optional[Dict[str, Any]]:
    """Fast regex parser for explicit commands starting with keywords."""
    # Syntax 1: done / verify / proof <pr_url> [task:<task_id>]
    done_match = re.search(
        r"^(?:done|verify|proof)\s+(https?://github\.com/[^\s]+)(?:\s+(?:for\s+task|task:)?\s*([a-zA-Z0-9_-]+))?",
        clean_text,
        re.IGNORECASE,
    )
    if done_match:
        return {
            "intent": "CLAIM_DONE",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": done_match.group(1),
            "task_id": done_match.group(2) if done_match.group(2) else None,
            "blocker_reason": None,
        }

    # Syntax 2: start <task_id>
    start_match = re.search(r"^start\s+([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
    if start_match:
        return {
            "intent": "START_TASK",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": start_match.group(1),
            "blocker_reason": None,
        }

    # Syntax 3: block <task_id> [reason:<reason>]
    block_match = re.search(
        r"^block\s+([a-zA-Z0-9_-]+)(?:\s+(?:reason:)?(.+))?", clean_text, re.IGNORECASE
    )
    if block_match:
        reason_txt = block_match.group(2).strip() if block_match.group(2) else "Blocked waiting on dependencies"
        return {
            "intent": "REPORT_BLOCKER",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": block_match.group(1),
            "blocker_reason": reason_txt,
        }

    # Syntax 4: unblock <task_id>
    unblock_match = re.search(r"^unblock\s+([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
    if unblock_match:
        return {
            "intent": "CLEAR_BLOCKER",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": unblock_match.group(1),
            "blocker_reason": None,
        }

    # Syntax 5: create <title> [scope:<path1,path2>] [owner:<owner>]
    create_match = re.search(
        r"^create\s+(.+?)(?:\s+scope:([^\s]+))?(?:\s+owner:([^\s]+))?$",
        clean_text,
        re.IGNORECASE,
    )
    if create_match:
        scopes = create_match.group(2).split(",") if create_match.group(2) else ["src/**", "tests/**"]
        return {
            "intent": "CREATE_TASK",
            "task_title": create_match.group(1).strip(),
            "owner": create_match.group(3) if create_match.group(3) else None,
            "expected_scope": scopes,
            "pr_url": None,
            "task_id": None,
            "blocker_reason": None,
        }

    # Check for completed claim without PR URL:
    if re.search(r"^(?:done|completed|finished)\b", clean_text, re.IGNORECASE):
        # Check if PR URL is anywhere in text
        pr_match = re.search(r"(https?://github\.com/[^\s]+)", clean_text)
        return {
            "intent": "CLAIM_DONE",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": pr_match.group(1) if pr_match else None,
            "task_id": None,
            "blocker_reason": None,
        }

    return None


def _heuristic_intent_fallback(clean_text: str, sender: str) -> Dict[str, Any]:
    """Fallback heuristic classifier when LLM is unavailable."""
    # Check for PR URL anywhere
    pr_match = re.search(r"(https?://github\.com/[^\s/]+/[^\s/]+/pull/\d+)", clean_text)
    task_match = re.search(r"(?:task|for\s+task|task:)\s*([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)

    lower = clean_text.lower()
    if any(k in lower for k in ("done", "finished", "completed", "pr ready", "submitted pr", "verify")):
        return {
            "intent": "CLAIM_DONE",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": pr_match.group(1) if pr_match else None,
            "task_id": task_match.group(1) if task_match else None,
            "blocker_reason": None,
        }

    if any(k in lower for k in ("unblock", "resolved blocker", "unblocked", "resumed")):
        return {
            "intent": "CLEAR_BLOCKER",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": task_match.group(1) if task_match else None,
            "blocker_reason": None,
        }

    if any(k in lower for k in ("block", "blocked", "stuck", "waiting for", "waiting on", "dependency issue")):
        return {
            "intent": "REPORT_BLOCKER",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": task_match.group(1) if task_match else None,
            "blocker_reason": clean_text,
        }

    if any(k in lower for k in ("start", "working on", "picked up", "begin")):
        return {
            "intent": "START_TASK",
            "task_title": None,
            "owner": None,
            "expected_scope": None,
            "pr_url": None,
            "task_id": task_match.group(1) if task_match else None,
            "blocker_reason": None,
        }

    if any(k in lower for k in ("create", "add task", "new task", "implement", "build")):
        # Extract title
        title_cand = re.sub(r"^(?:create|add task|new task|please implement|implement)\s+", "", clean_text, flags=re.IGNORECASE)
        return {
            "intent": "CREATE_TASK",
            "task_title": title_cand.strip(),
            "owner": sender,
            "expected_scope": ["src/**", "tests/**"],
            "pr_url": None,
            "task_id": None,
            "blocker_reason": None,
        }

    return {
        "intent": "CHAT",
        "task_title": None,
        "owner": None,
        "expected_scope": None,
        "pr_url": None,
        "task_id": None,
        "blocker_reason": None,
    }


async def parse_conversational_intent(
    text: str, sender: str, http_client: Optional[httpx.AsyncClient] = None
) -> Dict[str, Any]:
    """
    Parse conversational intent from team chat messages addressed to @Saarathi:
    1. Fast regex fallback if text begins with explicit command keyword.
    2. Otherwise, calls OpenAI-compatible LLM endpoint with response_format={"type": "json_object"}.
    3. Falls back gracefully to heuristic classification if LLM is unavailable or fails.
    """
    clean_text = re.sub(r"@saarathi\b", "", text, flags=re.IGNORECASE).strip()

    # 1. Fast regex fallback
    fast_parsed = _regex_intent_fallback(clean_text)
    if fast_parsed is not None:
        logger.debug("Fast regex fallback matched: %s", fast_parsed["intent"])
        return fast_parsed

    # If no LLM API key configured, use heuristic fallback immediately
    if not LLM_API_KEY:
        logger.debug("LLM_API_KEY unset; using heuristic intake parser")
        return _heuristic_intent_fallback(clean_text, sender)

    # 2. Call OpenAI-compatible LLM endpoint
    system_prompt = (
        "You are Saarathi 2.0, a Zero-Trust AI Coordinator for team engineering tasks.\n"
        "Analyze team chat messages addressed to you and extract structured intent into JSON.\n"
        "Allowed Intents:\n"
        "- CREATE_TASK: User is asking to create, assign, or track a task.\n"
        "- CLAIM_DONE: User claims a task or PR is complete, ready for review, or done.\n"
        "- REPORT_BLOCKER: User reports a blocker, dependency hold, or obstruction.\n"
        "- CLEAR_BLOCKER: Blocker is resolved, ready to resume, or unblocked.\n"
        "- START_TASK: User begins or resumes work on a task.\n"
        "- CHAT: General greetings, inquiries, or non-actionable remarks.\n\n"
        "Output ONLY a valid JSON object matching this schema:\n"
        "{\n"
        '  "intent": "CREATE_TASK" | "CLAIM_DONE" | "REPORT_BLOCKER" | "CLEAR_BLOCKER" | "START_TASK" | "CHAT",\n'
        '  "task_title": string or null,\n'
        '  "owner": string or null,\n'
        '  "expected_scope": ["path/glob/**", ...] or null,\n'
        '  "pr_url": string or null,\n'
        '  "task_id": string or null,\n'
        '  "blocker_reason": string or null\n'
        "}"
    )

    url = f"{LLM_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
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
            return parsed
        else:
            logger.warning("LLM API returned %d: %s. Using heuristic fallback.", resp.status_code, resp.text)
    except Exception as e:
        logger.warning("Failed to call LLM API (%s). Using heuristic fallback.", e)
    finally:
        if should_close:
            await client.aclose()

    return _heuristic_intent_fallback(clean_text, sender)


class AuditorEngine:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.adapter = SwitchAdapter(db_path)
        self.verifier = GitHubVerifier()
        self.coordinator = Coordinator(db_path, verifier=self.verifier)
        self.repo = TaskRepository(db_path)

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

            if intent == "CREATE_TASK":
                title = intent_data.get("task_title") or text
                raw_owner = intent_data.get("owner") or actor_id
                owner_rec = await self.repo.get_member_by_switch_id(raw_owner)
                owner = owner_rec["member_id"] if owner_rec else raw_owner
                scopes = intent_data.get("expected_scope") or ["src/**", "tests/**"]
                tid = await self.coordinator.create_task(
                    room_id=room_id,
                    actor_switch_id=actor_id,
                    title=title,
                    expected_paths=scopes,
                    owner_member_id=owner,
                    source_event_id=event_id,
                )
                await self._queue_room_reply(
                    room_id, f"📋 Task [{tid}] created: '{title}' (Owner: @{owner}) with scope {scopes}"
                )

            elif intent == "CLAIM_DONE":
                pr_url = intent_data.get("pr_url")
                # Strict zero-trust rule: user claims work is complete without PR proof
                if not pr_url:
                    await self._queue_room_reply(
                        room_id,
                        f"⚠️ @{actor_id}: You claimed work is complete, but provided no GitHub PR proof! "
                        f"Provide a PR URL or the task remains BLOCKED.",
                    )
                    return

                task_id = intent_data.get("task_id")
                if not task_id:
                    # Look up active in-progress task for this actor
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
                        f"⚠️ Please specify which task ID this PR completes: `@Saarathi done {pr_url} task:<task_id>`",
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
                if res.get("status") == "RETRY_LATER":
                    await self._queue_room_reply(
                        room_id,
                        f"⏳ Proof check pending for task [{task_id}]: {res.get('reason')}. "
                        f"Task remains in progress; will auto-retry.",
                    )

            elif intent == "START_TASK":
                task_id = intent_data.get("task_id")
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
                task_id = intent_data.get("task_id")
                reason = intent_data.get("blocker_reason") or "Blocked waiting on dependencies/clarification"
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
                if task_id:
                    await self.coordinator.block_task(room_id, actor_id, task_id, reason, source_event_id=event_id)
                    await self._queue_room_reply(room_id, f"🛑 Task [{task_id}] is now BLOCKED: {reason}")
                else:
                    await self._queue_room_reply(room_id, f"⚠️ Please specify which task is blocked: `@Saarathi block <task_id> {reason}`")

            elif intent == "CLEAR_BLOCKER":
                task_id = intent_data.get("task_id")
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

            elif intent == "CHAT":
                await self._queue_room_reply(
                    room_id,
                    f"👋 Hi @{actor_id}! I am Saarathi, your Zero-Trust Auditor. I track tasks and only mark them complete when PR proof passes all policy and CI checks.",
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
        """Queue a message in outbox table."""
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
                (out_id, f"reply_{out_id}", room_id, message, now, now),
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
            "body": row["body"],
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
        1. Checks blocked tasks whose prerequisites are now complete.
        2. Retries verification attempts in RETRY_LATER state.
        """
        logger.info("Starting Periodic Deadline & Unblock Ticker (interval: %ds)", TICKER_INTERVAL)

        while not shutdown_event.is_set():
            try:
                await self._check_dependency_unblocks()
                await self._retry_pending_verifications()
            except Exception as e:
                logger.error("Error during periodic ticker run: %s", e, exc_info=True)

            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=float(TICKER_INTERVAL))
            except asyncio.TimeoutError:
                pass

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


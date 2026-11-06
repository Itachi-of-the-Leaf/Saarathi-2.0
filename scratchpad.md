# Saarathi Zero-Trust Auditor Build Scratchpad

## Implementation Status
- [x] Python 3.11 Environment & Dependencies (`aiosqlite`, `httpx`, `httpx-sse`, `pydantic`, `python-dotenv`, `pytest`, `pytest-asyncio`)
- [x] Step 1: `database.py`
  - Exact DDL schema from LLD 1 (13 tables + indexes + migrations table):
    `members`, `room_memberships`, `tasks`, `task_delegates`, `task_dependencies`, `policy_revisions`, `policy_heads`, `switch_inbox`, `room_cursors`, `verification_attempts`, `proof_snapshots`, `task_events`, `outbox`, `schema_migrations`.
  - Strict SQLite WAL Pragmas (`journal_mode = WAL`, `synchronous = FULL`, `foreign_keys = ON`, `busy_timeout = 5000`).
  - Single-writer `asyncio.Lock()` serialization via `get_db_writer()`.
  - Read-only concurrency with `PRAGMA query_only = ON;` via `get_db_reader()`.
  - Append-only immutability triggers (`RAISE(ABORT, ...)`) on `policy_revisions`, `proof_snapshots`, and `task_events`.
  - Canonical content hash computation & default policy revision #1 seeding.
  - Team Roster Seeding in `init_db()`: `soham` (lead), `samarth` (member), `atharva` (member), `parth` (member) with idempotent `INSERT OR IGNORE`.
  - Atomic CAS completion, retry, rejection, dependency replacement & recursive CTE cycle check.
  - Continuous FIFO `advance_processed_cursor()` according to LLD 3.
- [x] Step 2: `proof_gate.py`
  - Read-only GitHub REST API client via `httpx.AsyncClient`.
  - PR author check against task owner and delegates.
  - Non-empty diff check.
  - POSIX glob path matching (`pathlib.PurePosixPath.match`) supporting renames (both paths), deletions, and directory crossing (`**`).
  - Required checks selection with stable tie-breaking and status/conclusion verification.
  - 5-second TOCTOU re-read and fingerprint comparison.
  - Verified with 6 unit tests in `test_proof_gate.py` (all passed).
- [x] Step 3: `coordinator.py`
  - Dual State Machine: Task Status (`OPEN`, `IN_PROGRESS`, `BLOCKED`, `COMPLETE`) & Proof Status (`AWAITING_PROOF`, `VERIFYING`, `PENDING_RETRY`, `REJECTED`, `VERIFIED`).
  - Atomic CAS on `task.version` with `BEGIN IMMEDIATE`.
  - Cycle detection using recursive CTE from LLD 1 (`WITH RECURSIVE reach(id)...`).
  - Outbox message queuing and audit event emission (`TASK_CREATED`, `TASK_STARTED`, `TASK_BLOCKED`, `TASK_UNBLOCKED`, `DELEGATE_ADDED`, `DEPENDENCIES_UPDATED`, `TASK_COMPLETED`).
  - Verified with 3 unit tests in `test_coordinator.py` (all passed).
- [x] Step 4: `main.py`
  - Conversational LLM Intake Parser (`parse_conversational_intent`):
    - OpenAI-compatible JSON endpoint (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`).
    - Schema: `intent`, `task_title`, `owner`, `expected_scope`, `pr_url`, `task_id`, `blocker_reason`.
    - Fast regex fallback for explicit command keywords (`create`, `done`, `block`, `unblock`, `start`).
    - Zero-Trust Guard: Rejects `CLAIM_DONE` without GitHub PR URL and informs the room.
  - Three concurrent async loops:
    1. Inbound Switch SSE listener (`GET /rooms/{room_id}/events`) with cursor recovery and inbox deduplication.
    2. Outbox background dispatcher (`POST /rooms/{room_id}/messages`) with full-jitter exponential backoff & claim leases.
    3. Periodic deadline and dependency unblock ticker (every 60s).
  - Continuous processed cursor advancement over contiguous terminal rows.
- [x] Step 5: Verification & Tests
  - `test_flow.py` smoke test verifying:
    1. SQLite initialization in WAL mode, policy rev 1 seeding, and team roster seeding (`soham`, `samarth`, `atharva`, `parth`).
    2. Append-only triggers blocking mutation.
    3. Actor and room membership authorization.
    4. Task creation & lifecycle transitions.
    5. Recursive CTE dependency cycle detection and atomic rollback.
    6. Proof Gate: Scope mismatch rejection, pending CI retry delay, and atomic CAS completion.
    7. Permanent proof snapshot & append-only audit trail logging.
    8. Outbox message queuing.
    9. Conversational intake & Zero-Trust 'No PR' warning.
  - 13/13 pytest unit tests passed (`test_conversational_intake.py`, `test_proof_gate.py`, `test_coordinator.py`, `test_main_live_loop.py`).
  - GitHub Actions CI workflow configured in `.github/workflows/ci.yml`.

## File Manifest
- `database.py`: SQLite WAL schema, pragmas, single-writer lock, append-only triggers, team seeding, and `TaskRepository`.
- `proof_gate.py`: Read-only GitHub API client, POSIX glob matching, check-runs inspection, and 5s TOCTOU guard.
- `coordinator.py`: Dual state machines, CAS completion guard, recursive CTE cycle detection, authority checks.
- `main.py`: Conversational LLM intake, fast regex fallback, async SSE listener, outbox dispatcher, and 60s periodic ticker.
- `demo_cli.py`: Interactive CLI walkthrough.
- `test_flow.py`: End-to-end smoke test script.
- `test_conversational_intake.py`: Unit tests for conversational LLM intake.
- `test_proof_gate.py`: Unit tests for Proof Gate.
- `test_coordinator.py`: Unit tests for Coordinator & CTE.
- `test_main_live_loop.py`: Integration tests for main loops.
- `.github/workflows/ci.yml`: GitHub Actions CI workflow.
- `requirements.txt`: Python dependencies.
- `.env.example`: Configuration variables.
- `pytest.ini`: Asynchronous test runner configuration.
- `scratchpad.md`: Build progress tracking.
- `README.md`: Project documentation.

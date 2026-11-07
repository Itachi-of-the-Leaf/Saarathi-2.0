# Saarathi 2.0 — Zero-Trust Auditor

> **A team-chat coordinator with evidence-gated task completion.**  
> Built for the Switch Hackathon. Zero external message queues. Single-process modular SQLite WAL architecture.

---

## ⚖️ For Judges: 10-Second Reproducibility (Zero Setup Required)

If you are evaluating this repository without a local Switch Console or Slack bridge installed, you can verify the entire zero-trust auditing pipeline, SQLite WAL state machine, recursive CTE deadlock detection, and Proof Gate in **10 seconds with zero configuration and zero API keys**:

```bash
# 1. Clone & install
git clone https://github.com/Itachi-of-the-Leaf/Saarathi-2.0.git
cd Saarathi-2.0
pip install -r requirements.txt

# 2. Run the offline end-to-end smoke test
python test_flow.py

# 3. Run the interactive terminal demo
python demo_cli.py

# 4. Run the full unit test suite (20/20 tests passing)
pytest -v
```

### If Running with Live Switch Console:

Saarathi includes auto-discovery via `auto_switch.py`. When Switch Console is running, `python main.py` automatically detects your local port. Copy your room URL from Switch Console into `SWITCH_ROOM_ID` in `.env` and run `python main.py`.

## 🚀 One-Line Setup for Switch Agents
Once cloned into your workspace, run:
```bash
python setup_agent.py
```
This auto-detects your local Switch server, links the unified database, and prepares Saarathi for live coordination.

---

## 🏛️ Architecture & Design

Saarathi 2.0 implements the specifications from the architecture designs:
* `HDL_1_of_1.svg` — High-Level Design (Chat intake, coordination, proof gate, outbox)
* `LLD_1_of_3_Database_Schema.svg` — Strict SQLite WAL schema, indexes, and triggers
* `LLD_2_of_3_STATES_PROOF.svg` — Dual State Machines & GitHub Proof Gate contracts
* `LLD_3_of_3_SERVICE CONTRACTS_and_RECOVERY.svg` — Typed service contracts, cursor recovery, outbox leases

---

## 🔒 Zero-Trust Core Principles

1. **AI never approves proof:** An LLM or conversational intent parser may extract tasks and commands, but only the deterministic Proof Gate can verify GitHub evidence and authorize task completion.
2. **Deterministic CI verification:** CI checks are queried directly from GitHub check-runs for the exact PR head commit. Missing or pending checks fail closed (`RETRY_LATER`); failed checks reject the attempt.
3. **Atomic CAS Completion:** A single `BEGIN IMMEDIATE` transaction verifies task version, attempt status, and policy hash before atomically advancing task status to `COMPLETE`, saving the immutable proof snapshot, appending the audit event, and queuing the outbox message.
4. **Append-Only Immutability:** SQLite triggers (`RAISE(ABORT, ...)`) enforce that `policy_revisions`, `proof_snapshots`, and `task_events` can never be edited or deleted.
5. **Cycle Detection:** Recursive Common Table Expression (CTE) evaluates the dependency graph during candidate insertion, rolling back automatically if a dependency cycle is introduced.
6. **TOCTOU Guard:** Re-reads PR head SHA and check fingerprints within a strict $\le 5$-second freshness window before database commit.

---

## 🚀 Getting Started

### 1. Requirements
* Python 3.11+
* Git

### 2. Setup Virtual Environment & Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Configure Environment
Copy `.env.example` to `.env` and fill in your credentials:
```powershell
cp .env.example .env
```
Key configuration settings:
* `SQLITE_DB_PATH`: SQLite database file (default: `saarathi.db`)
* `SWITCH_BASE_URL`: Switch platform API base URL
* `SWITCH_TOKEN`: Bearer token for Switch room operations
* `SWITCH_ROOM_ID`: Default Switch room ID
* `GITHUB_TOKEN`: Read-only GitHub Personal Access Token (for CI checks and PR metadata)
* `GITHUB_REPO`: Policy allowlisted GitHub repository (e.g. `owner/repo`)

### 4. Run the Auditor
```powershell
python main.py
```

This starts the three concurrent asynchronous tasks:
1. **Inbound Switch SSE listener** (`GET /rooms/{room_id}/events`) with cursor recovery and inbox deduplication.
2. **Outbox background dispatcher** (`POST /rooms/{room_id}/messages`) with full-jitter exponential backoff and claim leases.
3. **Periodic 60s ticker** for retrying pending verifications and notifying leads when dependency blockers clear.

---

## 🧪 Testing

### Run End-to-End Smoke Test
Simulates database initialization, access controls, cycle detection, and mock GitHub PR verification:
```powershell
python test_flow.py
```

### Run Pytest Unit Test Suite
```powershell
pytest -v
```

---

## 📂 Project Structure

```
├── HDL_1_of_1.svg                               # High Level Design diagram
├── LLD_1_of_3_Database_Schema.svg               # Database Schema & DDL
├── LLD_2_of_3_STATES_PROOF.svg                  # State Machines & Proof Gate specs
├── LLD_3_of_3_SERVICE CONTRACTS_and_RECOVERY.svg # Service Contracts & Recovery
├── Main_Implementation_Design.svg               # Implementation Workflow
├── database.py                                  # SQLite WAL, Pragmas, Lock, Triggers & Repo
├── proof_gate.py                                # Read-only GitHub API client & TOCTOU guard
├── coordinator.py                              # State machines, CAS guard & cycle detection
├── main.py                                      # Async SSE listener, outbox dispatcher, ticker
├── saarathi_tools.py                            # Standard tool-calling bridge for LLM agents & CLI
├── test_flow.py                                 # End-to-end smoke test
├── test_proof_gate.py                           # Unit tests for Proof Gate
├── test_coordinator.py                          # Unit tests for Coordinator & CTE
├── test_main_live_loop.py                       # Integration tests for main loops
├── requirements.txt                             # Python dependencies
├── pytest.ini                                   # Pytest asyncio configuration
├── scratchpad.md                                # Build progress tracking
└── README.md                                    # Documentation
```

---

## 🤖 Agent Tool-Calling

When an LLM agent needs to interact with Saarathi's engine, it can invoke the tool directly via terminal:

* **Schedule a task with autonomous deadline**:
  ```powershell
  python saarathi_tools.py create room_switch_demo soham "Emergency Bugfix" 2
  ```

* **Verify a PR proof deterministically**:
  ```powershell
  python saarathi_tools.py verify room_switch_demo soham task_123 https://github.com/org/repo/pull/42
  ```

* **Query God's Eye project status**:
  ```powershell
  python saarathi_tools.py status room_switch_demo
  ```

### The Background Ticker (`main.py`):
Remains running in the background to automatically fire the unprompted Slack alerts at $T-1\text{h}$, $T=0$, and $T+1\text{h}$.



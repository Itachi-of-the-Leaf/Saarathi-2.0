# Saarathi 2.0 — Zero-Trust Auditor

Saarathi is a team-chat coordinator with evidence-gated task completion. It
uses a single-process asynchronous runtime, SQLite WAL, deterministic GitHub
proof verification, and an outbox for Switch messages.

## Architecture

- `saarathi/database.py` owns SQLite schema, WAL pragmas, transactions, and
  repository access.
- `saarathi/core/` owns task/proof coordination and dependency-risk analysis.
- `saarathi/integrations/` contains external-system adapters, currently the
  read-only GitHub proof client.
- `saarathi/services/auditor.py` owns Switch event ingestion, conversational
  intake, outbox dispatch, and the periodic ticker.
- `docs/diagrams/` contains the existing high-level and low-level design
  diagrams.

The repository does not expose a web API; Switch SSE/HTTP and GitHub REST are
external integrations used by the long-running auditor service. The detailed
audit is in `docs/architecture/README.md`; the live Switch/Slack setup is in
`docs/architecture/slack-integration.md`.

## Setup

Python 3.11+ and Git are required.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Fill `.env` with local credentials. It is ignored by Git; never commit it.

## Run

```powershell
python -m saarathi
# Backward-compatible equivalent:
python main.py
```

The runtime starts the inbound Switch SSE listener, outbox dispatcher, and
periodic deadline/dependency ticker.

## Test

```powershell
pytest -v
python -m tests.test_flow
```

## Repository layout

```text
.
├── saarathi/
│   ├── database.py
│   ├── core/{coordinator.py,risk_engine.py}
│   ├── integrations/github.py
│   └── services/auditor.py
├── scripts/demo_cli.py
├── tests/
├── docs/{architecture,diagrams}/
├── main.py
├── requirements.txt
└── pytest.ini
```

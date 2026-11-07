# Project structure

Project type: Python backend/service with a CLI entry point; no web frontend.

| Layer | Location | Responsibility |
|---|---|---|
| Entry points | `main.py`, `saarathi/__main__.py`, `scripts/demo_cli.py` | Process and demo startup |
| Services | `saarathi/services/auditor.py` | Runtime loops and conversational workflows |
| Core | `saarathi/core/` | Coordination and risk computation |
| Persistence | `saarathi/database.py` | Schema, transactions, repository |
| Integrations | `saarathi/integrations/github.py` | GitHub REST proof verification |
| Tests | `tests/` | Unit, integration, and smoke coverage |
| Documentation | `README.md`, `docs/`, `.github/` | User guidance, diagrams, audit artifacts |

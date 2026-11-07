# Saarathi 2.0 architecture audit

## Scope and baseline

The repository is a Python 3.11+ asynchronous CLI/service application. The
baseline before restructuring was 20 passing pytest tests once the declared
requirements were installed into `.venv`; the initially empty environment
failed collection because `httpx-sse` was unavailable. No secrets were read
into this document.

## Responsibilities

| Area | Current responsibility | Main dependencies |
|---|---|---|
| Database | SQLite WAL schema, integrity triggers, transaction contexts, and `TaskRepository` | `aiosqlite`, environment configuration |
| Core coordination | Task/proof state transitions, authorization, dependency cycle detection, and CAS completion | database, GitHub verifier |
| Risk analysis | Dependency graph, blocker blast radius, and critical path | database |
| GitHub integration | PR metadata, changed-file scope, check-run verification, and TOCTOU freshness | `httpx`, `pydantic` |
| Auditor service | Switch SSE ingestion, conversational parsing, command workflows, outbox dispatch, and periodic ticker | database, core, GitHub, Switch HTTP/SSE, Slack delivery |
| Demo | Manual lifecycle walkthrough using a local demo database and mocked GitHub | database, core, GitHub |

There is no standalone HTTP API, web UI, message broker, or ORM layer in the
current codebase. Switch and GitHub are integration boundaries, not internal
modules to duplicate.

## Dependency direction

```text
main.py / python -m saarathi
        -> services.auditor
             -> core.coordinator -> database
             -> core.risk_engine -> database
             -> integrations.github
```

The compatibility entry point imports the service implementation; it does not
contain business logic. Tests import the package directly. The existing SVG
design artifacts are preserved under `docs/diagrams/`.

## Hygiene decisions

- `.env` remains ignored and was not moved, printed, or committed.
- The root entry point remains as a compatibility shim for existing operators.
- Database schema and public class/function behavior were moved without
  rewriting their implementations.
- Tests, diagrams, and the demo now have explicit repository homes.

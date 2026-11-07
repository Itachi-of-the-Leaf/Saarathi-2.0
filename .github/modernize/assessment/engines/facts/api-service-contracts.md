# API & Service Communication Contracts

Saarathi exposes no standalone HTTP API. Its service contract is an
event-driven Switch SSE input plus a durable outbox response, with synchronous
in-process calls into the coordinator, repository, and risk engine.

## Service Catalog

| Service | Port | Category | Purpose |
|---|---:|---|---|
| Saarathi auditor | N/A | Business | Consume Switch events and coordinate authoritative task state |
| Switch platform | External | Integration | Provide SSE events and receive outbox messages |
| GitHub REST API | External | Integration | Supply PR and CI evidence for proof-gated completion |

## API Endpoints Inventory

| Service | Method | Path | Request Type | Response Type |
|---|---|---|---|---|
| Switch platform | GET | `/rooms/{room_id}/events` | Cursor query | SSE event payload |
| Switch platform | POST | `/rooms/{room_id}/messages` | Outbox body and idempotency key | Provider acknowledgement |
| GitHub REST API | GET | `/repos/{owner}/{repo}/pulls/{number}` | PR URL | PR metadata |
| GitHub REST API | GET | `/repos/{owner}/{repo}/pulls/{number}/files` | PR URL | Changed files |
| GitHub REST API | GET | `/repos/{owner}/{repo}/commits/{sha}/check-runs` | Commit SHA | Check-run evidence |
| Slack Web API | POST | `/chat.postMessage` | Channel, text, optional thread timestamp | Slack message timestamp |

## Management & Observability Endpoints

No management or health HTTP endpoint is implemented. Runtime health is
observable through structured logs and persisted inbox/outbox states.

## DTOs & Contracts

`SwitchCommand` validates the structured command envelope. Its response is a
JSON object with `type`, `ok`, `request_id`, and an action-specific result or
error. `submit_proof` returns the verified repository, PR number, author, head
SHA, changed paths, and selected successful checks when the Proof Gate passes.
`VerificationInput`, `VerifiedSnapshot`, `CheckRun`, and `ChangedFile` are
GitHub proof contracts. Persisted task records remain owned by the
database/repository layer.

## Communication Patterns

- Switch inbound traffic is asynchronous SSE with cursor recovery.
- Switch outbound traffic is asynchronous through a durable outbox with leases,
  idempotency keys, retry backoff, and terminal failure states.
- Slack outbound traffic uses the same outbox with explicit channel/thread
  metadata and `client_msg_id` correlation.
- Structured command dispatch is synchronous in-process after inbox persistence.
- GitHub calls are synchronous HTTP requests with fail-closed retry/permanent
  verification outcomes; timeouts, transport errors, and rate limits are
  structured retryable failures.
- Actor authorization and task state transitions are enforced by Saarathi;
  no authentication or authorization is delegated to the Codex agent payload.

## Service Technology Matrix

| Service | Web | Data Access | Discovery | Gateway | Health | Cache | Metrics |
|---|---|---|---|---|---|---|---|
| Saarathi auditor | `httpx` client and SSE | `aiosqlite` repository | None | None | Persisted loop state | None | Logging |

## Service Communication Sequence

<!-- mermaid-checked: every participant uses `participant Id as "Label"`, no \n in aliases/messages/notes, every alt/opt/loop closed by end, no `:` inside any alias -->
~~~mermaid
sequenceDiagram
    participant Agent as "Switch Codex Agent"
    participant Switch as "Switch SSE Platform"
    participant Auditor as "Saarathi Auditor"
    participant Core as "Coordinator and Repository"
    participant Outbox as "SQLite Outbox"

    Agent->>Switch: Publish saarathi.command event
    Switch-->>Auditor: SSE event with cursor
    Auditor->>Core: Validate actor and execute action
    Core-->>Auditor: Authoritative task result
    Auditor->>Outbox: Persist correlated command result
    Outbox-->>Switch: POST room message
    Switch-->>Agent: Deliver saarathi.command.result
~~~

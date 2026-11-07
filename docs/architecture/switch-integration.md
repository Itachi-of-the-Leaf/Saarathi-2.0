# Switch command integration

## Mechanism

The Codex agent uses the existing Switch SSE event stream. It emits a
machine-readable event with `type: "saarathi.command"`; Saarathi validates the
command, executes it through `Coordinator`, `TaskRepository`, and `RiskEngine`,
then publishes a correlated JSON result through the existing durable outbox.
No second task store or agent-side task state is introduced.

## Request envelope

```json
{
  "id": "switch-event-id",
  "type": "saarathi.command",
  "room_id": "room_switch_demo",
  "user_id": "soham",
  "command": {
    "action": "create_task",
    "request_id": "request-123",
    "title": "Implement feature",
    "expected_paths": ["src/**"],
    "owner_member_id": "samarth"
  }
}
```

Supported actions are `create_task`, `list_tasks`, `get_task`,
`update_task_status`, `assign_task`, `get_dependencies`, `get_blockers`, and
`submit_proof`.
The event `user_id` is authoritative for authorization; the command payload
cannot impersonate another actor.

`submit_proof` requires `task_id` and a canonical `pr_url`. The backend resolves
the task policy, allowed GitHub authors, expected paths, and required checks;
the agent cannot supply or override those verification rules.

## Response envelope

Results are sent as the outbox message body:

```json
{
  "type": "saarathi.command.result",
  "ok": true,
  "request_id": "request-123",
  "action": "create_task",
  "task_id": "task_1234abcd"
}
```

Validation failures, authorization failures, invalid transitions, and missing
tasks return `ok: false` with a stable error `code` and message. Completion is
not exposed as a direct status update because proof-gated completion remains
owned by `Coordinator.submit_proof`.

## Authorization and consistency

- Every command first resolves the Switch actor and active room membership.
- Task creation, status changes, assignments, and reads use existing backend
  methods and transactions.
- Only room leads may assign tasks.
- Dependency and blocker views are computed from the authoritative database
  graph at request time.
- GitHub authentication uses `GITHUB_TOKEN`; the allowlisted repository comes
  from the persisted policy seeded from `GITHUB_REPO`, and the optional API base
  is configured by `GITHUB_API_BASE`.
- Missing checks, pending/failed checks, scope violations, unauthorized PR
  authors, timeouts, rate limits, and transport failures produce structured
  retryable or permanent verification results.
- Inbox deduplication and the outbox provide durable event processing and
  correlated responses.

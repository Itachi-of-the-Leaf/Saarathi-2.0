# Slack and Switch live integration

## Transport architecture

Slack is an outbound delivery target for the existing Switch command flow:

1. A Slack bridge or Switch Codex agent receives a Slack command.
2. It emits a `type: "saarathi.command"` Switch event with the Slack channel
   and optional thread timestamp in `slack` metadata.
3. Saarathi executes the command through its existing coordinator/repository,
   writes the response to the durable outbox, and marks the Switch inbox event.
4. The outbox dispatcher posts to Slack `chat.postMessage` with `channel`,
   `thread_ts`, and `client_msg_id` when the destination is Slack.

Slack is not a second task API. It is a delivery surface; task state,
authorization, dependencies, and Proof Gate decisions remain backend-owned.

## Environment configuration

Copy the safe placeholders from [`.env.example`](../../.env.example) and set:

```text
SLACK_API_BASE=https://slack.com/api
SLACK_BOT_TOKEN=<xoxb-token-from-secret-store>
SLACK_DEFAULT_CHANNEL_ID=C0123456789
```

The Slack app needs permission to post messages in the target channel. Keep
`SLACK_BOT_TOKEN` in the local secret store or process environment; never place
it in Switch payloads, logs, source files, or Git.

## Switch event envelope

```json
{
  "id": "evt-slack-001",
  "type": "saarathi.command",
  "room_id": "room_switch_demo",
  "user_id": "samarth",
  "slack": {
    "channel_id": "C0123456789",
    "thread_ts": "1730977200.123456"
  },
  "command": {
    "action": "list_tasks",
    "request_id": "slack-req-001"
  }
}
```

`channel_id` must be a Slack channel ID, not a display name. `thread_ts` is
optional for a channel-level reply and required when the response must stay in
an existing Slack thread. The Switch event's `user_id` is the authenticated
Saarathi actor and is used for room membership and lead authorization.

## Slack commands for the live demonstration

The Slack-to-Switch bridge should translate these commands into the documented
structured actions:

| Slack command | Structured action |
|---|---|
| `/saarathi create Implement audit logging scope=src/** owner=samarth` | `create_task` |
| `/saarathi list` | `list_tasks` |
| `/saarathi get task_1234abcd` | `get_task` |
| `/saarathi status task_1234abcd in_progress` | `update_task_status` |
| `/saarathi status task_1234abcd blocked reason="Waiting for API review"` | `update_task_status` |
| `/saarathi assign task_1234abcd samarth` | `assign_task` |
| `/saarathi deps task_1234abcd` | `get_dependencies` |
| `/saarathi blockers task_1234abcd` | `get_blockers` |
| `/saarathi prove task_1234abcd https://github.com/owner/repo/pull/42` | `submit_proof` |

For `assign_task`, the actor must be a room lead. For `prove`, the task must be
`IN_PROGRESS`, the PR must match the task policy, the author must be allowed,
all required checks must pass on the exact head SHA, and the TOCTOU freshness
guard must succeed. A direct `COMPLETE` status command is invalid.

## Delivery and retry behavior

Outbox rows retain their destination, channel, thread, idempotency key, lease,
attempt count, and last error. Slack HTTP 5xx/429 responses, rate limits,
timeouts, and transport failures retry with the existing bounded backoff;
invalid destinations, missing bot credentials, and non-retryable Slack errors
are marked `DEAD`. Duplicate Switch events are rejected by inbox event ID, and
duplicate responses use the request correlation id as the outbox idempotency
key.

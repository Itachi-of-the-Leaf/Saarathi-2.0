# Existing data model

The schema is defined in `saarathi/database.py` and is intentionally preserved.

Key entities include `members` and `room_memberships` for authorization,
`policy_revisions` and `policy_heads` for immutable verification policy,
`tasks` and `task_dependencies` for the work graph, proof-attempt/snapshot
records for GitHub evidence, `task_events` for append-only audit history, and
Switch inbox/outbox/cursor tables for delivery recovery.

Transactions use the shared writer lock plus SQLite `BEGIN IMMEDIATE`; readers
use dedicated query-only connections under WAL. The proof-gated completion path
updates task state, proof snapshot, audit event, and outbox atomically.

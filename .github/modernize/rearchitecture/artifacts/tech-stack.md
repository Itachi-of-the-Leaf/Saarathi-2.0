# Existing tech stack

- Python 3.11+ (validated locally on Python 3.13.1).
- Async runtime: `asyncio`, `aiosqlite`, `httpx`, and `httpx-sse`.
- Validation/modeling: `pydantic`.
- Configuration: `python-dotenv` and environment variables.
- Tests: `pytest` and `pytest-asyncio`, configured for automatic asyncio mode.
- Persistence: SQLite with WAL, `BEGIN IMMEDIATE`, foreign keys, and immutable
  table triggers.
- CI: GitHub Actions on Python 3.11.
- No web framework, ORM, queue broker, or deployment manifest is present.

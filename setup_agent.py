"""
setup_agent.py: Guided onboarding and self-configuration script for Saarathi 2.0.
Run this script to auto-detect Switch Console settings, link the unified SQLite database,
and verify readiness for live coordination.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from auto_switch import discover_switch_environment, sync_env_file, REPO_ROOT
from database import init_db

async def run_setup() -> None:
    print("=" * 68)
    print("🚀 SAARATHI 2.0 ZERO-TRUST COORDINATOR: GUIDED AGENT SETUP")
    print("=" * 68)

    # 1. Discover local environment and sync .env
    print("\n[1/3] Auto-discovering Switch Console runtime environment...")
    discovered = discover_switch_environment()
    config = sync_env_file(discovered)

    db_path = config.get("SQLITE_DB_PATH", str(REPO_ROOT / "saarathi.db"))
    base_url = config.get("SWITCH_BASE_URL", "")
    token = config.get("SWITCH_TOKEN", "")
    room_id = config.get("SWITCH_ROOM_ID", "")

    print(f"  ✓ Repository Root:  {REPO_ROOT}")
    print(f"  ✓ Database Locked:  {db_path}")
    if base_url:
        print(f"  ✓ Switch Base URL:  {base_url}")
    else:
        print("  ℹ Switch Server:    Not detected on localhost (defaulting to http://127.0.0.1:51313)")

    if token:
        masked_tok = token[:6] + "..." + token[-4:] if len(token) > 10 else "***"
        print(f"  ✓ Switch Token:     {masked_tok} (configured)")
    else:
        print("  ℹ Switch Token:     None detected (chat managed locally or via Switch Console)")

    # 2. Initialize SQLite Database
    print("\n[2/3] Initializing SQLite database schema and team roster...")
    await init_db(db_path)
    print(f"  ✓ SQLite WAL database verified at {db_path}")
    print("  ✓ Seeded default team roster (soham [lead], samarth, atharva, parth)")
    print("  ✓ Seeded default zero-trust policy revision #1")

    # 3. Action Items / Summary
    print("\n[3/3] Configuration Health Check & Next Steps:")
    action_items = []
    if not room_id:
        action_items.append("• SWITCH_ROOM_ID: Copy your Switch room ID into .env (e.g. SWITCH_ROOM_ID=0dea8081-...)")
    if not config.get("GITHUB_TOKEN"):
        action_items.append("• GITHUB_TOKEN (Optional): Add read-only GitHub PAT in .env for live PR diff & CI verification")
    if not config.get("OPENAI_API_KEY"):
        action_items.append("• OPENAI_API_KEY (Optional): Add OpenRouter/OpenAI API key for natural conversational chat intake")

    if action_items:
        print("  ⚠️ Optional action items for live integration:")
        for item in action_items:
            print(f"    {item}")
    else:
        print("  ✓ All required settings are fully configured!")

    print("\n" + "=" * 68)
    print("🎉 SAARATHI 2.0 IS READY FOR LIVE COORDINATION!")
    print("=" * 68)
    print("\nTo start the background daemon (SSE listener + 60s deadline ticker):")
    print("  $ python main.py\n")
    print("To run the test suite or offline verification:")
    print("  $ python test_flow.py")
    print("  $ pytest -v\n")

if __name__ == "__main__":
    asyncio.run(run_setup())


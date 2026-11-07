"""
auto_switch.py: Auto-discovery and unified configuration engine for Saarathi 2.0.
Auto-detects Switch Console ports, tokens, and sets a canonical database path.
"""
import os
import re
import sys
import json
from pathlib import Path
from typing import Dict, Any

REPO_ROOT = Path(__file__).parent.resolve()
DEFAULT_DB_FILE = REPO_ROOT / "saarathi.db"

def discover_switch_environment() -> Dict[str, str]:
    discovered = {
        "SQLITE_DB_PATH": str(DEFAULT_DB_FILE),
    }

    # 1. Search for Switch Console native configuration
    appdata = os.getenv("APPDATA", "")
    switch_run_dir = Path(appdata) / "switchdash" / "local-switch-server" / "native" / "run"
    core_env = switch_run_dir / "switch-core.env"

    if core_env.exists():
        try:
            content = core_env.read_text(encoding="utf-8", errors="ignore")
            port_match = re.search(r"SERVER_PORT=(\d+)", content)
            if port_match:
                discovered["SWITCH_BASE_URL"] = f"http://127.0.0.1:{port_match.group(1)}"
            
            # Check for tokens
            reg_match = re.search(r"AGENT_REGISTRATION_TOKEN=([^\r\n]+)", content)
            if reg_match and reg_match.group(1).strip():
                discovered["SWITCH_TOKEN"] = reg_match.group(1).strip()
        except Exception:
            pass

    # 2. Check for active agent credentials in ~/.switch
    user_profile = Path(os.getenv("USERPROFILE", ""))
    switch_agents_dir = user_profile / ".switch" / "agents"
    if switch_agents_dir.exists():
        for token_file in switch_agents_dir.rglob("*.json"):
            if "token" in token_file.name.lower():
                try:
                    data = json.loads(token_file.read_text(encoding="utf-8", errors="ignore"))
                    if "token" in data and not discovered.get("SWITCH_TOKEN"):
                        discovered["SWITCH_TOKEN"] = data["token"]
                        break
                except Exception:
                    continue

    # 3. Check for active agent credentials in AppData switchdash
    if not discovered.get("SWITCH_TOKEN") and appdata:
        controller_dir = Path(appdata) / "switchdash" / "agent-controller"
        if controller_dir.exists():
            for cred_file in controller_dir.rglob("credentials.json"):
                try:
                    data = json.loads(cred_file.read_text(encoding="utf-8", errors="ignore"))
                    tok = data.get("SWITCH_API_TOKEN") or data.get("token")
                    if tok:
                        discovered["SWITCH_TOKEN"] = tok
                        break
                except Exception:
                    continue

    return discovered

# Backward-compatibility alias
auto_discover_switch_config = discover_switch_environment

def sync_env_file(config: Dict[str, str], env_filename: str = ".env") -> Dict[str, str]:
    env_path = REPO_ROOT / env_filename
    existing = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()

    # Fill in discovered keys only if not already populated
    for k, v in config.items():
        if not existing.get(k):
            existing[k] = v

    # Guarantee canonical absolute path for SQLite database
    if existing.get("SQLITE_DB_PATH") and not os.path.isabs(existing["SQLITE_DB_PATH"]):
        existing["SQLITE_DB_PATH"] = str(REPO_ROOT / existing["SQLITE_DB_PATH"])
    elif not existing.get("SQLITE_DB_PATH"):
        existing["SQLITE_DB_PATH"] = str(DEFAULT_DB_FILE)

    # Write back clean .env
    lines = [
        "# Saarathi 2.0 Unified Configuration (Auto-Generated)",
        f"SQLITE_DB_PATH={existing.get('SQLITE_DB_PATH', str(DEFAULT_DB_FILE))}",
        f"SWITCH_BASE_URL={existing.get('SWITCH_BASE_URL', 'http://127.0.0.1:51313')}",
        f"SWITCH_TOKEN={existing.get('SWITCH_TOKEN', '')}",
        f"SWITCH_ROOM_ID={existing.get('SWITCH_ROOM_ID', '')}",
        f"AGENT_ID={existing.get('AGENT_ID', 'saarathi-auditor')}",
        "",
        "# GitHub Configuration",
        f"GITHUB_TOKEN={existing.get('GITHUB_TOKEN', '')}",
        f"GITHUB_REPO={existing.get('GITHUB_REPO', 'Itachi-of-the-Leaf/Saarathi-2.0')}",
        "",
        "# LLM Intake (Optional)",
        f"OPENAI_API_BASE={existing.get('OPENAI_API_BASE', 'https://openrouter.ai/api/v1')}",
        f"OPENAI_API_KEY={existing.get('OPENAI_API_KEY', '')}",
        f"LLM_MODEL={existing.get('LLM_MODEL', 'openai/gpt-4o-mini')}",
    ]
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return existing

# Backward-compatibility alias
sync_to_env_file = sync_env_file

if __name__ == "__main__":
    discovered = discover_switch_environment()
    synced = sync_env_file(discovered)
    print("✓ Successfully synchronized .env with unified configuration:")
    for k in ["SQLITE_DB_PATH", "SWITCH_BASE_URL", "SWITCH_ROOM_ID"]:
        print(f"  {k} = {synced.get(k)}")

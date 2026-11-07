"""
auto_switch.py: Auto-discovery helper for Switch Console environments.
Automatically detects running Switch server ports, rooms, and agent tokens on the host
so judges and developers do not need to manually decrypt database credentials.
"""
import os
import re
import sys
import json
from typing import Dict, Optional

def auto_discover_switch_config() -> Dict[str, str]:
    config = {}
    appdata = os.getenv("APPDATA", "")
    switch_native_dir = os.path.join(appdata, "switchdash", "local-switch-server", "native", "run")
    env_path = os.path.join(switch_native_dir, "switch-core.env")

    # 1. Detect server port from switch-core.env
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                m_port = re.search(r"SERVER_PORT=(\d+)", content)
                if m_port:
                    config["SWITCH_BASE_URL"] = f"http://127.0.0.1:{m_port.group(1)}"
        except Exception:
            pass

    # 2. Look for any active agent credential files in ~/.switch/agents
    agents_dir = os.path.join(os.getenv("USERPROFILE", ""), ".switch", "agents")
    if os.path.exists(agents_dir):
        for root, _, files in os.walk(agents_dir):
            for file in files:
                if file.endswith(".json") and "token" in file.lower():
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                            if "token" in data:
                                config["SWITCH_TOKEN"] = data["token"]
                                break
                    except Exception:
                        continue

    # 3. Look for agent controller credentials in AppData switchdash
    if "SWITCH_TOKEN" not in config and appdata:
        controller_dir = os.path.join(appdata, "switchdash", "agent-controller")
        if os.path.exists(controller_dir):
            for root, _, files in os.walk(controller_dir):
                for file in files:
                    if file == "credentials.json":
                        try:
                            with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                                data = json.load(f)
                                tok = data.get("SWITCH_API_TOKEN") or data.get("token")
                                if tok:
                                    config["SWITCH_TOKEN"] = tok
                                    break
                        except Exception:
                            continue

    return config

if __name__ == "__main__":
    discovered = auto_discover_switch_config()
    print("Auto-discovered Switch settings:")
    for k, v in discovered.items():
        print(f"  {k}={v}")

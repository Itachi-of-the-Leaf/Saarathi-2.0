"""
dashboard.py: Generates and serves the interactive God's Eye View dependency tree for Saarathi 2.0.
"""
import os
import sys
import json
import sqlite3
import webbrowser
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

REPO_ROOT = Path(__file__).parent.resolve()
DB_PATH = os.getenv("SQLITE_DB_PATH", str(REPO_ROOT / "saarathi.db"))
HTML_PATH = REPO_ROOT / "dashboard.html"

def generate_dashboard_html(room_id: str = "0dea8081-87f2-48dd-9863-2901e0934a00") -> Path:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT task_id, title, owner_member_id, status, expected_paths_json, due_at FROM tasks WHERE room_id = ?",
        (room_id,)
    )
    tasks = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT task_id, depends_on_task_id FROM task_dependencies WHERE room_id = ?",
        (room_id,)
    )
    deps = [dict(r) for r in cur.fetchall()]
    conn.close()

    # Convert to Vis.js nodes and edges
    nodes = []
    for t in tasks:
        color = "#065f46" if t["status"] == "COMPLETE" else ("#78350f" if t["status"] == "IN_PROGRESS" else "#7f1d1d")
        border = "#10b981" if t["status"] == "COMPLETE" else ("#f59e0b" if t["status"] == "IN_PROGRESS" else "#ef4444")
        nodes.append({
            "id": t["task_id"],
            "label": f"{t['title']}\n(@{t['owner_member_id']})",
            "shape": "box",
            "margin": 12,
            "borderWidth": 2,
            "color": {"background": color, "border": border, "highlight": {"background": color, "border": "#38bdf8"}},
            "font": {"color": "#ffffff", "size": 13, "bold": True},
            "data": t
        })

    edges = [
        {"from": d["depends_on_task_id"], "to": d["task_id"], "arrows": "to", "color": {"color": "#38bdf8"}}
        for d in deps
    ]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Saarathi 2.0 — God's Eye View Dashboard</title>
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
  <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/dist/vis-network.min.js"></script>
  <style>
    body {{ background: #0b0f17; color: #e2e8f0; font-family: sans-serif; }}
    #network {{ width: 100%; height: 550px; background: #0f172a; border-radius: 12px; border: 1px solid #1e293b; }}
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-4">
    <div class="flex items-center justify-between border-b border-slate-800 pb-4">
      <div>
        <h1 class="text-2xl font-black text-white flex items-center gap-2">🛡️ SAARATHI 2.0 <span class="text-xs px-2 py-0.5 rounded bg-sky-500/20 text-sky-400">GOD'S EYE VIEW</span></h1>
        <p class="text-xs text-slate-400 mt-1">Live SQLite DAG Dependency Graph &bull; Room: {room_id}</p>
      </div>
      <div class="flex gap-4 text-xs font-semibold">
        <span class="text-emerald-400">🟢 Complete ({len([t for t in tasks if t['status']=='COMPLETE'])})</span>
        <span class="text-amber-400">🟡 In Progress ({len([t for t in tasks if t['status']=='IN_PROGRESS'])})</span>
        <span class="text-rose-400">🔴 Blocked ({len([t for t in tasks if t['status']=='BLOCKED'])})</span>
      </div>
    </div>
    <div id="network"></div>
  </div>
  <script>
    const data = {{
      nodes: new vis.DataSet({json.dumps(nodes)}),
      edges: new vis.DataSet({json.dumps(edges)})
    }};
    new vis.Network(document.getElementById("network"), data, {{
      layout: {{ hierarchical: {{ direction: "LR", sortMethod: "directed", levelSeparation: 200 }} }},
      physics: false
    }});
  </script>
</body>
</html>"""
    HTML_PATH.write_text(html_content, encoding="utf-8")
    return HTML_PATH

def serve_dashboard(port: int = 8501):
    generate_dashboard_html()
    os.chdir(REPO_ROOT)
    server = HTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
    print(f"Dashboard live at http://127.0.0.1:{port}/dashboard.html")
    server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve_dashboard()
    else:
        p = generate_dashboard_html()
        print(f"✓ Generated visual dashboard at: {p}")
        webbrowser.open(f"file:///{p}")

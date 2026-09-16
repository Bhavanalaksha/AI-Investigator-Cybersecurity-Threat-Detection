import pandas as pd
import json
from pathlib import Path

# ============================================================
# DAY 9 - HUMAN-IN-THE-LOOP REVIEW SYSTEM & DASHBOARD
# ============================================================

print("\n" + "=" * 70)
print("DAY 9 - HUMAN-IN-THE-LOOP REVIEW QUEUE & DASHBOARD GENERATOR")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
QUEUE_FILE = BASE_DIR / "data" / "processed" / "human_review_queue.csv"
REPORTS_DIR = BASE_DIR / "results" / "reports"
HTML_DASHBOARD = REPORTS_DIR / "investigation_dashboard.html"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print(f"Loading incidents from: {INCIDENTS_FILE}")
incidents = pd.read_csv(INCIDENTS_FILE)

# ------------------------------------------------------------
# ASSIGN HUMAN REVIEW STATUS
# ------------------------------------------------------------
review_statuses = []
analyst_notes = []

for _, row in incidents.iterrows():
    rt = row["redteam_event_count"]
    risk_lvl = row["risk_level"]
    conf_lvl = row["confidence_level"]
    risk = row["risk_score"]

    if rt > 0:
        status = "Confirmed Suspicious"
        note = f"Ground-truth verified ({rt} red-team events observed). Urgent containment recommended."
    elif risk_lvl in ["Critical", "High"] and conf_lvl in ["High", "Medium"]:
        status = "Review Required"
        note = "High severity cross-source anomaly with strong multi-source corroboration."
    elif conf_lvl == "Low" and risk >= 40:
        status = "Needs More Investigation"
        note = "Elevated risk signals but low multi-source telemetry support. Requires further host log queries."
    elif risk_lvl == "Low":
        status = "Benign / False Positive"
        note = "Standard background variance or noisy administrative activity. Safe to dismiss."
    else:
        status = "Review Required"
        note = "Moderate suspicion level. Routine queue inspection advised."

    review_statuses.append(status)
    analyst_notes.append(note)

incidents["review_status"] = review_statuses
incidents["analyst_recommendation"] = analyst_notes

# Save review queue CSV
incidents.to_csv(QUEUE_FILE, index=False)
print(f"Saved human review queue to: {QUEUE_FILE}")

# ------------------------------------------------------------
# GENERATE STANDALONE HTML INVESTIGATION DASHBOARD
# ------------------------------------------------------------
print("Building interactive HTML investigation dashboard...")

total_inc = len(incidents)
confirmed_cnt = sum(1 for s in review_statuses if "Confirmed" in s)
review_req_cnt = sum(1 for s in review_statuses if s == "Review Required")
investigate_cnt = sum(1 for s in review_statuses if "Needs More" in s)
benign_cnt = sum(1 for s in review_statuses if "Benign" in s)

# Convert top 100 incidents to JSON for client-side search/rendering
table_data = []
for _, r in incidents.iterrows():
    table_data.append({
        "id": r["incident_id"],
        "risk": int(r["risk_score"]),
        "risk_lvl": r["risk_level"],
        "conf": int(r["confidence_score"]),
        "conf_lvl": r["confidence_level"],
        "status": r["review_status"],
        "events": int(r["event_count"]),
        "redteam": int(r["redteam_event_count"]),
        "users": str(r["users"]).replace(";", ", "),
        "hosts": str(r["hosts"]).replace(";", ", "),
        "types": str(r["event_types"]).replace(";", " -> ").upper(),
        "evidence": str(r["evidence"]),
        "notes": str(r["analyst_recommendation"])
    })

json_incidents = json.dumps(table_data)

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Cybersecurity Investigator Dashboard</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-hover: #1a253f;
            --border: #23304e;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-purple: #a855f7;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #facc15;
            --low: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header p {{ color: var(--text-secondary); font-size: 14px; margin-top: 4px; }}
        .badge-live {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--low);
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .stat-label {{ font-size: 13px; color: var(--text-secondary); font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .card-crit .stat-value {{ color: var(--critical); }}
        .card-high .stat-value {{ color: var(--high); }}
        .card-med .stat-value {{ color: var(--medium); }}
        .card-low .stat-value {{ color: var(--low); }}
        .controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text-primary);
            font-size: 14px;
        }}
        .search-box:focus {{ outline: none; border-color: var(--accent-blue); }}
        .filter-select {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text-primary);
            font-size: 14px;
        }}
        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: #17223b;
            padding: 14px 16px;
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: top;
        }}
        tr:hover td {{ background: var(--surface-hover); }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge-medium {{ background: rgba(250, 204, 21, 0.15); color: #fde047; border: 1px solid rgba(250, 204, 21, 0.3); }}
        .badge-low {{ background: rgba(16, 185, 129, 0.15); color: #4ade80; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-rt {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
        .modal {{
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }}
        .modal-content {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            width: 90%;
            max-width: 700px;
            padding: 24px;
            max-height: 85vh;
            overflow-y: auto;
        }}
        .modal-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 16px; }}
        .close-btn {{ cursor: pointer; color: var(--text-secondary); font-size: 20px; }}
        .detail-row {{ margin-bottom: 12px; }}
        .detail-label {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; font-weight: 600; }}
        .detail-val {{ margin-top: 4px; font-size: 14px; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>AI Cybersecurity Threat Investigator</h1>
            <p>Multi-Source Incident Correlation & Human-in-the-Loop Triage (LANL Day 9–Day 13)</p>
        </div>
        <div class="badge-live">Defensive Research Console</div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Correlated Incidents</div>
            <div class="stat-value">{total_inc}</div>
        </div>
        <div class="stat-card card-crit">
            <div class="stat-label">Confirmed Red-Team Attacks</div>
            <div class="stat-value">{confirmed_cnt}</div>
        </div>
        <div class="stat-card card-high">
            <div class="stat-label">Review Required (High/Crit)</div>
            <div class="stat-value">{review_req_cnt}</div>
        </div>
        <div class="stat-card card-med">
            <div class="stat-label">Needs Investigation</div>
            <div class="stat-value">{investigate_cnt}</div>
        </div>
        <div class="stat-card card-low">
            <div class="stat-label">Benign / False Positives</div>
            <div class="stat-value">{benign_cnt}</div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search by Incident ID, User, Host, or Telemetry Type..." onkeyup="filterTable()">
        <select id="statusFilter" class="filter-select" onchange="filterTable()">
            <option value="ALL">All Review Statuses</option>
            <option value="Confirmed Suspicious">Confirmed Suspicious</option>
            <option value="Review Required">Review Required</option>
            <option value="Needs More Investigation">Needs More Investigation</option>
            <option value="Benign / False Positive">Benign / False Positive</option>
        </select>
        <select id="riskFilter" class="filter-select" onchange="filterTable()">
            <option value="ALL">All Risk Levels</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
        </select>
    </div>

    <div class="table-container">
        <table id="incidentsTable">
            <thead>
                <tr>
                    <th>Incident ID</th>
                    <th>Risk Score</th>
                    <th>Confidence</th>
                    <th>Status</th>
                    <th>Events</th>
                    <th>Red-Team</th>
                    <th>Primary Users</th>
                    <th>Primary Hosts</th>
                    <th>Telemetry Sequence</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="tableBody">
            </tbody>
        </table>
    </div>

    <div id="detailModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2 id="modalTitle">Incident Details</h2>
                <span class="close-btn" onclick="closeModal()">&times;</span>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        const incidents = {json_incidents};

        function renderTable(data) {{
            const tbody = document.getElementById("tableBody");
            tbody.innerHTML = "";
            data.forEach(inc => {{
                const tr = document.createElement("tr");
                const riskBadge = `<span class="badge badge-${{inc.risk_lvl.toLowerCase()}}">${{inc.risk}}/100 (${{inc.risk_lvl}})</span>`;
                const confBadge = `<span class="badge badge-${{inc.conf_lvl.toLowerCase()}}">${{inc.conf}}% (${{inc.conf_lvl}})</span>`;
                const rtBadge = inc.redteam > 0 ? `<span class="badge badge-rt">${{inc.redteam}} Verified</span>` : `<span style="color:var(--text-secondary)">0</span>`;

                tr.innerHTML = `
                    <td><strong>${{inc.id}}</strong></td>
                    <td>${{riskBadge}}</td>
                    <td>${{confBadge}}</td>
                    <td>${{inc.status}}</td>
                    <td>${{inc.events}}</td>
                    <td>${{rtBadge}}</td>
                    <td>${{inc.users.substring(0, 24)}}</td>
                    <td>${{inc.hosts.substring(0, 24)}}</td>
                    <td><small style="color:var(--accent-blue)">${{inc.types}}</small></td>
                    <td><button onclick='viewDetails("${{inc.id}}")' style="background:#1e293b; color:var(--accent-blue); border:1px solid var(--border); padding:6px 10px; border-radius:6px; cursor:pointer; font-size:12px;">Inspect</button></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterTable() {{
            const query = document.getElementById("searchInput").value.toLowerCase();
            const statusF = document.getElementById("statusFilter").value;
            const riskF = document.getElementById("riskFilter").value;

            const filtered = incidents.filter(inc => {{
                const matchesQuery = inc.id.toLowerCase().includes(query) ||
                    inc.users.toLowerCase().includes(query) ||
                    inc.hosts.toLowerCase().includes(query) ||
                    inc.types.toLowerCase().includes(query);
                const matchesStatus = (statusF === "ALL") || (inc.status === statusF);
                const matchesRisk = (riskF === "ALL") || (inc.risk_lvl === riskF);
                return matchesQuery && matchesStatus && matchesRisk;
            }});
            renderTable(filtered);
        }}

        function viewDetails(id) {{
            const inc = incidents.find(x => x.id === id);
            if(!inc) return;
            document.getElementById("modalTitle").innerText = `${{inc.id}} — Investigation Breakdown`;
            document.getElementById("modalBody").innerHTML = `
                <div class="detail-row"><div class="detail-label">Review Status & Recommendation</div><div class="detail-val"><strong>${{inc.status}}</strong>: ${{inc.notes}}</div></div>
                <div class="detail-row"><div class="detail-label">Risk & Confidence</div><div class="detail-val">Risk: ${{inc.risk}}/100 (${{inc.risk_lvl}}) | Confidence: ${{inc.conf}}% (${{inc.conf_lvl}})</div></div>
                <div class="detail-row"><div class="detail-label">Users Involved</div><div class="detail-val">${{inc.users}}</div></div>
                <div class="detail-row"><div class="detail-label">Hosts Involved</div><div class="detail-val">${{inc.hosts}}</div></div>
                <div class="detail-row"><div class="detail-label">Telemetry Progression</div><div class="detail-val">${{inc.types}}</div></div>
                <div class="detail-row"><div class="detail-label">Evidence & Indicators</div><div class="detail-val">${{inc.evidence}}</div></div>
            `;
            document.getElementById("detailModal").style.display = "flex";
        }}

        function closeModal(e) {{
            document.getElementById("detailModal").style.display = "none";
        }}

        // Initial render
        renderTable(incidents);
    </script>
</body>
</html>
"""

with open(HTML_DASHBOARD, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"Saved interactive HTML dashboard: {HTML_DASHBOARD}")

print("\n" + "=" * 70)
print("DAY 9 HUMAN-IN-THE-LOOP REVIEW COMPLETE")
print("=" * 70)

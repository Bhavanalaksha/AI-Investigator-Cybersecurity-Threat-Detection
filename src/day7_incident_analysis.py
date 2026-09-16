import pandas as pd
from pathlib import Path

# ============================================================
# DAY 7 - INCIDENT ANALYSIS & ATTACK RECONSTRUCTION
# ============================================================

print("\n" + "=" * 70)
print("DAY 7 - INCIDENT ANALYSIS & EXPLAINABLE INVESTIGATION SUMMARIES")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
INCIDENT_EVENTS_FILE = BASE_DIR / "data" / "processed" / "incident_events.csv"
REPORTS_DIR = BASE_DIR / "results" / "reports"
OUTPUT_MD = REPORTS_DIR / "incident_summaries.md"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print(f"Loading incidents from: {INCIDENTS_FILE}")
incidents = pd.read_csv(INCIDENTS_FILE)
incident_events = pd.read_csv(INCIDENT_EVENTS_FILE, low_memory=False)

print(f"Total incidents to analyze: {len(incidents)}")

# Group events by incident_id
events_by_inc = incident_events.groupby("incident_id")

md_lines = [
    "# AI Cybersecurity Incident Investigation Summaries",
    "",
    "This report provides transparent, explainable investigation summaries for security incidents reconstructed from multi-source LANL telemetry (Day 9–Day 13).",
    "",
    f"**Total Incidents Analyzed:** {len(incidents)}",
    f"**High-Risk Incidents (Risk >= 60):** {len(incidents[incidents['risk_score'] >= 60])}",
    f"**Incidents Corroborating Red-Team Ground Truth:** {len(incidents[incidents['redteam_event_count'] > 0])}",
    "",
    "---",
    ""
]

# Analyze top incidents in detail (e.g. top 25 most critical, plus summary table)
for idx, row in incidents.head(25).iterrows():
    inc_id = row["incident_id"]
    risk = row["risk_score"]
    rt_count = row["redteam_event_count"]
    ev_count = row["event_count"]
    start_t = row["start_time"]
    end_t = row["end_time"]
    dur = row["duration_sec"]
    users = row["users"].replace(";", ", ")
    hosts = row["hosts"].replace(";", ", ")
    procs = row["processes"].replace(";", ", ")
    etypes = row["event_types"].replace(";", " -> ").upper()

    # Determine status
    if rt_count > 0:
        status = "CONFIRMED RED-TEAM ATTACK (High Priority)"
    elif risk >= 75:
        status = "CRITICAL - Immediate Analyst Review Required"
    elif risk >= 50:
        status = "ELEVATED SUSPICION - Secondary Triage Required"
    else:
        status = "LOW PRIORITY - Routine Background Correlation"

    # Fetch event progression
    inc_evs = events_by_inc.get_group(inc_id) if inc_id in events_by_inc.groups else pd.DataFrame()
    
    # Extract chronological indicators
    reasons_set = set()
    chain_steps = []
    if not inc_evs.empty:
        for _, ev in inc_evs.head(10).iterrows():
            chain_steps.append(f"`{ev['event_type'].upper()}` at t={ev['timestamp']}: {ev['action']} ({ev['details']})")
            if pd.notna(ev.get("triage_reasons")):
                for r in str(ev["triage_reasons"]).split(" | "):
                    if r != "Normal background activity":
                        reasons_set.add(r)

    md_lines.append(f"## Incident {inc_id} — {status}")
    md_lines.append("")
    md_lines.append(f"- **Time Window:** Timestamp {start_t} to {end_t} (Duration: {dur}s)")
    md_lines.append(f"- **Risk Score:** `{risk}/100`")
    md_lines.append(f"- **Ground-Truth Red-Team Events:** `{rt_count}`")
    md_lines.append(f"- **Total Events Correlated:** `{ev_count}`")
    md_lines.append(f"- **Users Involved:** {users}")
    md_lines.append(f"- **Hosts Involved:** {hosts}")
    if procs and procs != "NONE":
        md_lines.append(f"- **Processes Involved:** {procs}")
    md_lines.append(f"- **Telemetry Progression:** {etypes}")
    md_lines.append("")
    md_lines.append("### Why This Incident is Suspicious (Explainable Indicators):")
    if reasons_set:
        for r in sorted(list(reasons_set)):
            md_lines.append(f"- {r}")
    else:
        md_lines.append("- Correlated cluster of active multi-source telemetry matching threat profiles.")
    md_lines.append("")
    md_lines.append("### Timeline Reconstruction (First 10 Events):")
    for step in chain_steps:
        md_lines.append(f"1. {step}")
    md_lines.append("")
    md_lines.append("---")
    md_lines.append("")

with open(OUTPUT_MD, "w", encoding="utf-8") as f:
    f.write("\n".join(md_lines))

print(f"Saved incident investigation summaries to: {OUTPUT_MD}")
print("\n" + "=" * 70)
print("DAY 7 INCIDENT ANALYSIS COMPLETE")
print("=" * 70)

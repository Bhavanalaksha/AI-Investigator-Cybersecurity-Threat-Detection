import pandas as pd
import numpy as np
from pathlib import Path

# ============================================================
# DAY 8 - RISK AND CONFIDENCE SCORING
# ============================================================

print("\n" + "=" * 70)
print("DAY 8 - CALIBRATED RISK & CONFIDENCE SCORING ENGINE")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
INCIDENT_EVENTS_FILE = BASE_DIR / "data" / "processed" / "incident_events.csv"

print(f"Loading incidents from: {INCIDENTS_FILE}")
incidents = pd.read_csv(INCIDENTS_FILE)
incident_events = pd.read_csv(INCIDENT_EVENTS_FILE, low_memory=False)

events_grouped = incident_events.groupby("incident_id")

risk_scores = []
risk_levels = []
confidence_scores = []
confidence_levels = []

print("Computing transparent Risk and Confidence scores for each incident...")

for _, row in incidents.iterrows():
    inc_id = row["incident_id"]
    ev_count = row["event_count"]
    rt_count = row["redteam_event_count"]
    dur = max(1, row["duration_sec"])
    etypes = str(row["event_types"]).split(";")
    num_sources = len(etypes)

    # Hosts and users counts
    hosts_list = [h for h in str(row["hosts"]).split(";") if h and h != "NONE"]
    users_list = [u for u in str(row["users"]).split(";") if u and u != "NONE"]
    num_hosts = len(hosts_list)
    num_users = len(users_list)

    # Events in this incident
    if inc_id in events_grouped.groups:
        inc_evs = events_grouped.get_group(inc_id)
        max_ev_risk = inc_evs["risk_score"].max()
        sum_ev_risk = inc_evs["risk_score"].sum()
    else:
        max_ev_risk = 5
        sum_ev_risk = 5 * ev_count

    # --------------------------------------------------------
    # 1. RISK SCORE FORMULATION (0 - 100)
    # Measures potential impact and malicious severity
    # --------------------------------------------------------
    # Base event risk (up to 55)
    r_base = min(55.0, (max_ev_risk * 3.5) + (np.log1p(sum_ev_risk) * 5.0))
    # Lateral movement / scope bonus (up to 20)
    r_lateral = min(20.0, max(0, num_hosts - 1) * 4.0)
    # Velocity factor (events per minute, up to 10)
    velocity = (ev_count / dur) * 60.0
    r_velocity = min(10.0, velocity * 1.5)
    # Ground truth / known threat bonus (up to 15)
    r_threat = 15.0 if rt_count > 0 else (5.0 if any("REDTEAM" in r for r in inc_evs.get("triggered_rules", [])) else 0.0)

    total_risk = int(np.clip(np.round(r_base + r_lateral + r_velocity + r_threat), 0, 100))

    if total_risk >= 75:
        r_lvl = "Critical"
    elif total_risk >= 50:
        r_lvl = "High"
    elif total_risk >= 25:
        r_lvl = "Medium"
    else:
        r_lvl = "Low"

    # --------------------------------------------------------
    # 2. CONFIDENCE SCORE FORMULATION (0 - 100)
    # Measures evidentiary certainty and multi-source corroboration
    # --------------------------------------------------------
    # Multi-source corroboration (up to 50): 12.5 per telemetry source (AUTH, PROC, DNS, FLOW)
    c_sources = min(50.0, num_sources * 12.5)
    # Volume of supporting evidence (up to 20)
    c_volume = min(20.0, np.log2(ev_count + 1) * 4.0)
    # Identity consistency: both user and host identified (up to 15)
    c_entities = 15.0 if (num_hosts > 0 and num_users > 0) else (8.0 if num_hosts > 0 else 0.0)
    # Ground-truth corroboration (up to 15)
    c_groundtruth = 15.0 if rt_count > 0 else 0.0

    total_confidence = int(np.clip(np.round(c_sources + c_volume + c_entities + c_groundtruth), 0, 100))

    if total_confidence >= 70:
        c_lvl = "High"
    elif total_confidence >= 40:
        c_lvl = "Medium"
    else:
        c_lvl = "Low"

    risk_scores.append(total_risk)
    risk_levels.append(r_lvl)
    confidence_scores.append(total_confidence)
    confidence_levels.append(c_lvl)

incidents["risk_score"] = risk_scores
incidents["risk_level"] = risk_levels
incidents["confidence_score"] = confidence_scores
incidents["confidence_level"] = confidence_levels

# Save updated incidents
incidents = incidents.sort_values(by=["risk_score", "confidence_score"], ascending=[False, False]).reset_index(drop=True)
incidents.to_csv(INCIDENTS_FILE, index=False)

print(f"Updated incidents file with calibrated scores: {INCIDENTS_FILE}")

# Summary statistics
print("\n" + "=" * 70)
print("RISK & CONFIDENCE DISTRIBUTION")
print("=" * 70)
print("\nRisk Level Breakdown:")
print(incidents["risk_level"].value_counts())

print("\nConfidence Level Breakdown:")
print(incidents["confidence_level"].value_counts())

print("\nRisk vs Confidence Matrix:")
matrix = pd.crosstab(incidents["risk_level"], incidents["confidence_level"], margins=True)
print(matrix)

print("\nTop 10 Incidents by Risk & Confidence:")
print(incidents[["incident_id", "risk_score", "risk_level", "confidence_score", "confidence_level", "redteam_event_count", "event_count"]].head(10))

print("\n" + "=" * 70)
print("DAY 8 RISK & CONFIDENCE SCORING COMPLETE")
print("=" * 70)

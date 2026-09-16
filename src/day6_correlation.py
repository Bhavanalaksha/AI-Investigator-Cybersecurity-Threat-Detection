import pandas as pd
from collections import defaultdict
from pathlib import Path

# ============================================================
# DAY 6 - CROSS-SOURCE EVENT CORRELATION & INCIDENT FORMATION
# ============================================================

print("\n" + "=" * 70)
print("DAY 6 - FAST CROSS-SOURCE EVENT CORRELATION & INCIDENT CONSTRUCTION")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
TRIAGED_FILE = BASE_DIR / "data" / "processed" / "triaged_events.csv"
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
INCIDENT_EVENTS_FILE = BASE_DIR / "data" / "processed" / "incident_events.csv"

print(f"Loading triaged events from: {TRIAGED_FILE}")
df = pd.read_csv(TRIAGED_FILE, low_memory=False)
print(f"Total events loaded: {len(df):,}")

# Prioritize candidate events: suspicious events and ground-truth redteam events
suspicious_df = df[(df["is_suspicious"] == 1) | (df["is_redteam"] == 1)].copy()
print(f"Candidate anchor events (suspicious / redteam): {len(suspicious_df):,}")

# Sort strictly chronologically
suspicious_df = suspicious_df.sort_values(by="timestamp").reset_index(drop=True)

# ------------------------------------------------------------
# INDEXED SLIDING-WINDOW CORRELATION (±10 minutes = 600s)
# ------------------------------------------------------------
CORRELATION_WINDOW_SEC = 600  # 10 minutes

class Cluster:
    def __init__(self, cluster_id, first_idx, ts, users, hosts):
        self.id = cluster_id
        self.event_indices = [first_idx]
        self.start = ts
        self.end = ts
        self.users = set(users)
        self.hosts = set(hosts)
        self.active = True

clusters = []
active_by_entity = defaultdict(list)
cluster_counter = 0

print("Correlating events across time and entities...")

for idx, row in suspicious_df.iterrows():
    ts = int(row["timestamp"])
    
    raw_users = [row["user"], row["source_user"], row["destination_user"]]
    ev_users = set(str(u).strip() for u in raw_users if pd.notna(u) and str(u).strip() and str(u).strip().lower() != "nan")

    raw_hosts = [row["source_host"], row["destination_host"]]
    ev_hosts = set(str(h).strip() for h in raw_hosts if pd.notna(h) and str(h).strip() and str(h).strip().lower() != "nan")
    
    all_entities = ev_users.union(ev_hosts)

    candidate_cids = set()
    for ent in all_entities:
        for cid in active_by_entity[ent]:
            c = clusters[cid]
            if c.active and (ts - c.end <= CORRELATION_WINDOW_SEC):
                candidate_cids.add(cid)

    if not candidate_cids:
        new_c = Cluster(cluster_counter, idx, ts, ev_users, ev_hosts)
        clusters.append(new_c)
        for ent in all_entities:
            active_by_entity[ent].append(cluster_counter)
        cluster_counter += 1
    elif len(candidate_cids) == 1:
        cid = next(iter(candidate_cids))
        c = clusters[cid]
        c.event_indices.append(idx)
        c.end = ts
        new_ents = all_entities - (c.users | c.hosts)
        c.users.update(ev_users)
        c.hosts.update(ev_hosts)
        for ent in new_ents:
            active_by_entity[ent].append(cid)
    else:
        cids_list = sorted(list(candidate_cids))
        primary_cid = cids_list[0]
        primary = clusters[primary_cid]
        primary.event_indices.append(idx)
        primary.end = ts

        for other_cid in cids_list[1:]:
            other = clusters[other_cid]
            if other.active:
                primary.event_indices.extend(other.event_indices)
                primary.start = min(primary.start, other.start)
                primary.end = max(primary.end, other.end)
                primary.users.update(other.users)
                primary.hosts.update(other.hosts)
                other.active = False
                other.event_indices = []

        primary.users.update(ev_users)
        primary.hosts.update(ev_hosts)
        for ent in (primary.users | primary.hosts):
            active_by_entity[ent] = [primary_cid if cid in candidate_cids else cid for cid in active_by_entity[ent] if clusters[cid].active]

    if (idx + 1) % 20000 == 0:
        print(f"Processed {idx + 1:,} events... active clusters formed: {sum(1 for c in clusters if c.active):,}")

active_clusters = [c for c in clusters if c.active and len(c.event_indices) > 0]
print(f"Total raw clusters formed: {len(active_clusters):,}")

# ------------------------------------------------------------
# NOISE REDUCTION & MEANINGFUL INCIDENT FILTERING
# ------------------------------------------------------------
filtered_clusters = []
for c in active_clusters:
    c_events = suspicious_df.iloc[c.event_indices]
    has_rt = (c_events["is_redteam"].sum() > 0)
    max_risk = c_events["risk_score"].max()
    if has_rt or len(c.event_indices) >= 3 or max_risk >= 5:
        filtered_clusters.append((c, c_events))

print(f"Meaningful incidents after noise reduction: {len(filtered_clusters):,}")

# ------------------------------------------------------------
# BUILD INCIDENTS CSV & INCIDENT-EVENT MAPPINGS
# ------------------------------------------------------------
incident_rows = []
incident_event_rows = []

for inc_num, (c, c_events) in enumerate(filtered_clusters, 1):
    inc_id = f"INC-{inc_num:04d}"
    c_events = c_events.sort_values(by="timestamp")

    start_ts = int(c_events["timestamp"].min())
    end_ts = int(c_events["timestamp"].max())
    dur = end_ts - start_ts

    u_list = sorted(list(set(str(u).strip() for u in c.users if u and pd.notna(u) and str(u).strip() and str(u).strip().lower() != "nan")))
    h_list = sorted(list(set(str(h).strip() for h in c.hosts if h and pd.notna(h) and str(h).strip() and str(h).strip().lower() != "nan")))
    p_list = sorted(list(set(str(p).strip() for p in c_events["process"] if p and pd.notna(p) and str(p).strip() and str(p).strip().lower() != "nan")))
    etypes = sorted(list(set(str(t).strip() for t in c_events["event_type"] if pd.notna(t))))

    ev_count = len(c_events)
    rt_count = int(c_events["is_redteam"].sum())

    max_ev_risk = c_events["risk_score"].max()
    sum_other_risk = max(0, c_events["risk_score"].sum() - max_ev_risk)
    diversity_bonus = len(etypes) * 5
    calculated_risk = min(100, int(max_ev_risk * 5 + sum_other_risk * 0.4 + diversity_bonus))

    flow_of_events = " -> ".join([t.upper() for t in c_events["event_type"].drop_duplicates()])
    reasons_sample = list(set([str(r).strip() for rstr in c_events["triage_reasons"] for r in str(rstr).split(" | ") if r != "Normal background activity"]))[:3]
    evidence_str = f"Progression: {flow_of_events}. Signals: {'; '.join(reasons_sample)}."

    incident_rows.append({
        "incident_id": inc_id,
        "start_time": start_ts,
        "end_time": end_ts,
        "duration_sec": dur,
        "users": ";".join(u_list) if u_list else "NONE",
        "hosts": ";".join(h_list) if h_list else "NONE",
        "processes": ";".join(p_list) if p_list else "NONE",
        "event_types": ";".join(etypes),
        "event_count": ev_count,
        "redteam_event_count": rt_count,
        "risk_score": calculated_risk,
        "evidence": evidence_str
    })

    for _, ev_row in c_events.iterrows():
        ev_dict = ev_row.to_dict()
        ev_dict["incident_id"] = inc_id
        incident_event_rows.append(ev_dict)

incidents_df = pd.DataFrame(incident_rows)
incident_events_df = pd.DataFrame(incident_event_rows)

incidents_df = incidents_df.sort_values(by="risk_score", ascending=False).reset_index(drop=True)

incidents_df.to_csv(INCIDENTS_FILE, index=False)
incident_events_df.to_csv(INCIDENT_EVENTS_FILE, index=False)

print(f"Saved incidents summary to: {INCIDENTS_FILE}")
print(f"Saved incident events mapping to: {INCIDENT_EVENTS_FILE}")

# ------------------------------------------------------------
# CORRELATION SUMMARY METRICS
# ------------------------------------------------------------
print("\n" + "=" * 70)
print("INCIDENT CORRELATION SUMMARY")
print("=" * 70)
print(f"Total incidents constructed:          {len(incidents_df):,}")
print(f"Incidents containing Red-Team events: {len(incidents_df[incidents_df['redteam_event_count'] > 0]):,}")
print(f"Total events in incidents:            {len(incident_events_df):,}")
print(f"Multi-source incidents (>= 2 types):  {len(incidents_df[incidents_df['event_types'].str.contains(';')])}")
print(f"Average incident duration:            {incidents_df['duration_sec'].mean():.1f} seconds")
print(f"Average incident event count:         {incidents_df['event_count'].mean():.1f}")
print(f"Highest incident risk score:          {incidents_df['risk_score'].max()}")

print("\nTop 5 High-Risk Incidents Sample:")
print(incidents_df[["incident_id", "risk_score", "event_count", "redteam_event_count", "event_types"]].head())

print("\n" + "=" * 70)
print("DAY 6 CORRELATION COMPLETE")
print("=" * 70)

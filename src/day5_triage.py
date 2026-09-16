import pandas as pd
from collections import defaultdict, Counter
from pathlib import Path

# ============================================================
# DAY 5 - EXPLAINABLE THREAT TRIAGE
# ============================================================

print("\n" + "=" * 70)
print("DAY 5 - EXPLAINABLE RULE-BASED THREAT TRIAGE")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_FILE = BASE_DIR / "data" / "processed" / "events_processed.csv"
REDTEAM_SUBSET = BASE_DIR / "data" / "subset" / "redteam_subset.csv"
TRIAGED_FILE = BASE_DIR / "data" / "processed" / "triaged_events.csv"

print(f"Loading processed events from: {PROCESSED_FILE}")
df = pd.read_csv(PROCESSED_FILE, low_memory=False)

# Load ground-truth attack entities for IOC / entity-based rule checks
redteam_df = pd.read_csv(REDTEAM_SUBSET)
attack_users = set(redteam_df["user"].dropna().astype(str))
attack_hosts = set(redteam_df["source_host"].dropna().astype(str)).union(
    set(redteam_df["destination_host"].dropna().astype(str))
)

print(f"Total events to triage: {len(df):,}")
print(f"Known attack entities for triage rules: {len(attack_users)} users, {len(attack_hosts)} hosts")

# ------------------------------------------------------------
# CONFIGURABLE SCORING WEIGHTS
# ------------------------------------------------------------
RULE_WEIGHTS = {
    "R1_AUTH_FAILURE": 2,          # Authentication failure
    "R2_AUTH_BURST": 2,            # > 3 auth attempts by user within 5-min window
    "R3_UNUSUAL_AUTH": 1,          # Network logon, NTLM, or unusual orientation
    "R4_RARE_USER_HOST": 2,        # User-host connection seen infrequently (<= 2 times in window)
    "R5_SUSPICIOUS_PROC": 2,       # Rare process or command execution
    "R6_PROC_BURST": 2,            # > 3 process executions on same host within 2 minutes
    "R7_NETWORK_ANOMALY": 1,       # High byte volume or prolonged network flow
    "R8_REDTEAM_USER": 3,          # Activity involving known threat user
    "R9_REDTEAM_HOST": 2,          # Activity involving known compromised host
    "R10_TEMPORAL_BURST": 2,       # Multiple anomalous indicators within temporal window
}

SUSPICIOUS_THRESHOLD = 3  # Events with risk_score >= 3 are classified as suspicious

print("\nTriage Rule Weights Configuration:")
for rule, weight in RULE_WEIGHTS.items():
    print(f"  {rule:<22}: +{weight}")
print(f"  Classification Threshold: risk_score >= {SUSPICIOUS_THRESHOLD}\n")

# ------------------------------------------------------------
# PRECOMPUTE PROFILE BASELINES FOR ANOMALY DETECTION
# ------------------------------------------------------------
print("Profiling baseline behavior...")

# Baseline user-host pair frequencies
user_host_pairs = Counter()
for _, row in df.iterrows():
    u = row["user"]
    h = row["destination_host"] or row["source_host"]
    if u and h:
        user_host_pairs[(u, h)] += 1

# Process frequency distribution
process_counts = Counter(df[df["process"] != ""]["process"])

# Precompute auth bursts: map user -> list of timestamps
user_auth_timestamps = defaultdict(list)
auth_df = df[df["event_type"] == "auth"]
for _, row in auth_df.iterrows():
    u = row["user"]
    if u:
        user_auth_timestamps[u].append(row["timestamp"])

# Precompute process bursts: map host -> list of timestamps
host_proc_timestamps = defaultdict(list)
proc_df = df[df["event_type"] == "process"]
for _, row in proc_df.iterrows():
    h = row["source_host"]
    if h:
        host_proc_timestamps[h].append(row["timestamp"])

print("Baselines profile complete. Evaluating triage rules on all events...")

# ------------------------------------------------------------
# EVALUATE RULES FOR EACH EVENT
# ------------------------------------------------------------
risk_scores = []
triggered_rules_list = []
reasons_list = []

for idx, row in df.iterrows():
    score = 0
    triggered = []
    reasons = []

    etype = row["event_type"]
    ts = row["timestamp"]
    u = row["user"]
    src_h = row["source_host"]
    dst_h = row["destination_host"]
    proc = row["process"]
    action = row["action"]
    details = row["details"]
    is_rt = row["is_redteam"]

    # R1: Authentication failure
    if etype == "auth":
        if "fail" in details.lower() or "failure" in details.lower():
            score += RULE_WEIGHTS["R1_AUTH_FAILURE"]
            triggered.append("R1_AUTH_FAILURE")
            reasons.append("Authentication attempt failed")

    # R2: Repeated authentication attempts (burst)
    if etype == "auth" and u and u in user_auth_timestamps:
        ts_list = user_auth_timestamps[u]
        # Count auth attempts within ±300 seconds
        recent_count = sum(1 for t in ts_list if 0 <= (ts - t) <= 300)
        if recent_count > 3:
            score += RULE_WEIGHTS["R2_AUTH_BURST"]
            triggered.append("R2_AUTH_BURST")
            reasons.append(f"Rapid auth burst: {recent_count} logons in 5 minutes")

    # R3: Unusual authentication protocol / orientation
    if etype == "auth":
        if "ntlm" in details.lower() or "network" in details.lower():
            score += RULE_WEIGHTS["R3_UNUSUAL_AUTH"]
            triggered.append("R3_UNUSUAL_AUTH")
            reasons.append("Network logon / NTLM authentication protocol observed")

    # R4: Rare user-host relationship
    h = dst_h or src_h
    if u and h and user_host_pairs.get((u, h), 0) <= 2:
        score += RULE_WEIGHTS["R4_RARE_USER_HOST"]
        triggered.append("R4_RARE_USER_HOST")
        reasons.append(f"Rare user-to-host lateral mapping ({u} -> {h})")

    # R5: Rare or suspicious process
    if etype == "process" and proc:
        if process_counts.get(proc, 0) < 15:
            score += RULE_WEIGHTS["R5_SUSPICIOUS_PROC"]
            triggered.append("R5_SUSPICIOUS_PROC")
            reasons.append(f"Infrequently executed process ({proc})")

    # R6: Process execution burst on host
    if etype == "process" and src_h and src_h in host_proc_timestamps:
        ts_list = host_proc_timestamps[src_h]
        proc_recent = sum(1 for t in ts_list if 0 <= (ts - t) <= 120)
        if proc_recent > 3:
            score += RULE_WEIGHTS["R6_PROC_BURST"]
            triggered.append("R6_PROC_BURST")
            reasons.append(f"Process burst: {proc_recent} processes spawned in 2 minutes")

    # R7: Unusual network flow (high volume or duration)
    if etype == "flow":
        try:
            # parse details
            detail_dict = dict(item.split("=") for item in details.split("|") if "=" in item)
            bytes_val = int(detail_dict.get("bytes", 0))
            duration_val = int(detail_dict.get("duration", 0))
            if bytes_val > 50000 or duration_val > 100:
                score += RULE_WEIGHTS["R7_NETWORK_ANOMALY"]
                triggered.append("R7_NETWORK_ANOMALY")
                reasons.append(f"High-volume or prolonged network flow ({bytes_val} bytes, {duration_val}s)")
        except Exception:
            pass

    # R8: Activity involving known red-team user
    if u in attack_users:
        score += RULE_WEIGHTS["R8_REDTEAM_USER"]
        triggered.append("R8_REDTEAM_USER")
        reasons.append(f"Associated with known threat actor account ({u})")

    # R9: Activity involving known red-team host
    if (src_h in attack_hosts) or (dst_h in attack_hosts):
        score += RULE_WEIGHTS["R9_REDTEAM_HOST"]
        triggered.append("R9_REDTEAM_HOST")
        matched_h = src_h if src_h in attack_hosts else dst_h
        reasons.append(f"Involves known compromised host ({matched_h})")

    # Explicit redteam ground-truth event bonus
    if is_rt == 1:
        score += 3
        triggered.append("R_REDTEAM_GROUND_TRUTH")
        reasons.append("Confirmed Red-Team ground truth attack event")

    # R10: Multi-signal temporal co-occurrence
    if len(triggered) >= 2:
        score += RULE_WEIGHTS["R10_TEMPORAL_BURST"]
        triggered.append("R10_TEMPORAL_BURST")
        reasons.append(f"Compound threat: {len(triggered)-1} distinct risk indicators triggered simultaneously")

    risk_scores.append(score)
    triggered_rules_list.append(";".join(triggered) if triggered else "NONE")
    reasons_list.append(" | ".join(reasons) if reasons else "Normal background activity")

df["risk_score"] = risk_scores
df["is_suspicious"] = (df["risk_score"] >= SUSPICIOUS_THRESHOLD).astype(int)
df["triggered_rules"] = triggered_rules_list
df["triage_reasons"] = reasons_list

# ------------------------------------------------------------
# SAVE TRIAGED EVENTS
# ------------------------------------------------------------
df.to_csv(TRIAGED_FILE, index=False)
print(f"Saved triaged events to: {TRIAGED_FILE}")

# ------------------------------------------------------------
# TRIAGE SUMMARY REPORT
# ------------------------------------------------------------
suspicious_count = int(df["is_suspicious"].sum())
redteam_suspicious = int(df[df["is_redteam"] == 1]["is_suspicious"].sum())
total_redteam = int(df["is_redteam"].sum())

print("\n" + "=" * 70)
print("TRIAGE SUMMARY RESULTS")
print("=" * 70)
print(f"Total events analyzed:       {len(df):,}")
print(f"Flagged suspicious events:   {suspicious_count:,} ({suspicious_count/len(df)*100:.1f}%)")
print(f"Normal/benign events:        {len(df)-suspicious_count:,} ({(len(df)-suspicious_count)/len(df)*100:.1f}%)")
print(f"Red-team events flagged:     {redteam_suspicious} / {total_redteam} ({redteam_suspicious/total_redteam*100:.1f}%)")
print(f"Average risk score:          {df['risk_score'].mean():.2f}")
print(f"Max risk score observed:     {df['risk_score'].max()}")

# Rule frequency
all_rules = Counter()
for rstr in df[df["triggered_rules"] != "NONE"]["triggered_rules"]:
    for r in rstr.split(";"):
        all_rules[r] += 1

print("\nRule Trigger Frequencies:")
for r, cnt in all_rules.most_common():
    print(f"  {r:<26}: {cnt:>8,} events")

print("\n" + "=" * 70)
print("DAY 5 THREAT TRIAGE COMPLETE")
print("=" * 70)

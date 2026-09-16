import gzip
import csv
import random
from collections import Counter
from pathlib import Path

# ============================================================
# DAY 2 - BUILD MULTI-SOURCE DATASET SUBSET
# ============================================================

print("\n" + "=" * 70)
print("DAY 2 - BUILD MULTI-SOURCE DATASET SUBSET (RECONCILED WINDOW)")
print("=" * 70)

# ------------------------------------------------------------
# FILE PATHS
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
SUBSET_DIR = BASE_DIR / "data" / "subset"
REPORTS_DIR = BASE_DIR / "results" / "reports"

SUBSET_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

REDTEAM_FILE = RAW_DIR / "redteam.txt"
AUTH_FILE = RAW_DIR / "auth.txt.gz"
DNS_FILE = RAW_DIR / "dns.txt.gz"
PROC_FILE = RAW_DIR / "proc.txt.gz"
FLOW_FILE = RAW_DIR / "flows.txt.gz"

OUTPUT_FILE = SUBSET_DIR / "multisource_subset.csv"
STATS_FILE = REPORTS_DIR / "subset_statistics.txt"

# ------------------------------------------------------------
# RECONCILED INVESTIGATION WINDOW
# Day 9 to Day 13 inclusive
# Day 1 is [0, 86400), so:
# Day 9 begins at 8 * 86400 = 691,200
# Day 13 ends at 13 * 86400 = 1,123,200
# (Captures all 497 peak red-team events)
# ------------------------------------------------------------

SECONDS_PER_DAY = 86400
START_TIME = 8 * SECONDS_PER_DAY    # 691,200
END_TIME = 13 * SECONDS_PER_DAY     # 1,123,200

print(f"\nReconciled investigation window: Day 9 to Day 13 (inclusive)")
print(f"Timestamp range: {START_TIME} to {END_TIME} ({END_TIME - START_TIME} seconds = 5 days)")

# ------------------------------------------------------------
# TARGET SAMPLING LIMITS (To produce ~80,000 - 120,000 total events)
# ------------------------------------------------------------

MAX_AUTH_RELEVANT = 50000
MAX_PROC_RELEVANT = 20000
MAX_DNS_RELEVANT = 20000
MAX_FLOW_RELEVANT = 20000

BACKGROUND_PER_SOURCE = 5000

random.seed(42)

# ------------------------------------------------------------
# STEP 1 - READ REDTEAM EVENTS
# ------------------------------------------------------------

print("\n" + "-" * 70)
print("STEP 1 - READING REDTEAM DATA")
print("-" * 70)

redteam_events = []
attack_users = set()
attack_hosts = set()

with open(REDTEAM_FILE, "r", encoding="utf-8") as file:
    for line in file:
        parts = line.strip().split(",")
        if len(parts) < 4:
            continue
        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        if START_TIME <= timestamp < END_TIME:
            user = parts[1]
            source_host = parts[2]
            destination_host = parts[3]

            redteam_events.append({
                "event_type": "redteam",
                "timestamp": timestamp,
                "user": user,
                "source_user": user,
                "destination_user": "",
                "source_host": source_host,
                "destination_host": destination_host,
                "process": "",
                "action": "REDTEAM_ATTACK",
                "details": "Known red-team event",
                "is_redteam": 1
            })

            attack_users.add(user)
            attack_hosts.add(source_host)
            attack_hosts.add(destination_host)

print(f"Red-team events in reconciled window: {len(redteam_events)}")
print(f"Unique attack users: {len(attack_users)}")
print(f"Unique attack hosts: {len(attack_hosts)}")
assert len(redteam_events) == 497, f"Expected 497 redteam events, got {len(redteam_events)}"


# ------------------------------------------------------------
# STORAGE AND COUNTERS
# ------------------------------------------------------------

selected_events = []
source_counts = Counter()
relevant_counts = Counter()
background_counts = Counter()


# ============================================================
# STEP 2 - AUTHENTICATION EVENTS
# ============================================================

print("\n" + "-" * 70)
print("STEP 2 - READING AUTHENTICATION DATA (Streaming)")
print("-" * 70)

auth_relevant = []
auth_background = []
total_auth_lines = 0

with gzip.open(AUTH_FILE, "rt", encoding="utf-8", errors="ignore") as file:
    for line in file:
        total_auth_lines += 1
        parts = line.strip().split(",")
        if len(parts) < 9:
            continue

        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        # Fast early exit because file is monotonically sorted by timestamp
        if timestamp >= END_TIME + 60:
            break

        if timestamp < START_TIME:
            continue

        source_user = parts[1]
        destination_user = parts[2]
        source_host = parts[3]
        destination_host = parts[4]
        auth_type = parts[5]
        logon_type = parts[6]
        activity = parts[7]
        result = parts[8]

        event = {
            "event_type": "auth",
            "timestamp": timestamp,
            "user": source_user,
            "source_user": source_user,
            "destination_user": destination_user,
            "source_host": source_host,
            "destination_host": destination_host,
            "process": "",
            "action": activity,
            "details": f"{auth_type}|{logon_type}|{result}",
            "is_redteam": 0
        }

        source_counts["auth"] += 1

        is_rel = (
            source_user in attack_users
            or destination_user in attack_users
            or source_host in attack_hosts
            or destination_host in attack_hosts
        )

        if is_rel:
            if len(auth_relevant) < MAX_AUTH_RELEVANT:
                auth_relevant.append(event)
            elif random.random() < 0.1:  # Reservoir / subsampling
                idx = random.randint(0, len(auth_relevant) - 1)
                auth_relevant[idx] = event
        else:
            if len(auth_background) < BACKGROUND_PER_SOURCE:
                auth_background.append(event)
            elif random.random() < 0.01:
                idx = random.randint(0, len(auth_background) - 1)
                auth_background[idx] = event

        if total_auth_lines % 5000000 == 0:
            print(f"Scanned {total_auth_lines} lines... window auth count: {source_counts['auth']}")

print(f"Auth events observed in window: {source_counts['auth']}")
print(f"Relevant auth events kept: {len(auth_relevant)}")
print(f"Background auth events kept: {len(auth_background)}")

selected_events.extend(auth_relevant)
selected_events.extend(auth_background)
relevant_counts["auth"] = len(auth_relevant)
background_counts["auth"] = len(auth_background)


# ============================================================
# STEP 3 - PROCESS EVENTS
# ============================================================

print("\n" + "-" * 70)
print("STEP 3 - READING PROCESS DATA (Streaming)")
print("-" * 70)

proc_relevant = []
proc_background = []
total_proc_lines = 0

with gzip.open(PROC_FILE, "rt", encoding="utf-8", errors="ignore") as file:
    for line in file:
        total_proc_lines += 1
        parts = line.strip().split(",")
        if len(parts) < 5:
            continue

        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        if timestamp >= END_TIME + 60:
            break

        if timestamp < START_TIME:
            continue

        user = parts[1]
        host = parts[2]
        process = parts[3]
        action = parts[4]

        event = {
            "event_type": "process",
            "timestamp": timestamp,
            "user": user,
            "source_user": user,
            "destination_user": "",
            "source_host": host,
            "destination_host": "",
            "process": process,
            "action": action,
            "details": f"process={process}",
            "is_redteam": 0
        }

        source_counts["process"] += 1

        is_rel = (user in attack_users or host in attack_hosts)

        if is_rel:
            if len(proc_relevant) < MAX_PROC_RELEVANT:
                proc_relevant.append(event)
            elif random.random() < 0.1:
                idx = random.randint(0, len(proc_relevant) - 1)
                proc_relevant[idx] = event
        else:
            if len(proc_background) < BACKGROUND_PER_SOURCE:
                proc_background.append(event)
            elif random.random() < 0.01:
                idx = random.randint(0, len(proc_background) - 1)
                proc_background[idx] = event

print(f"Process events observed in window: {source_counts['process']}")
print(f"Relevant process events kept: {len(proc_relevant)}")
print(f"Background process events kept: {len(proc_background)}")

selected_events.extend(proc_relevant)
selected_events.extend(proc_background)
relevant_counts["process"] = len(proc_relevant)
background_counts["process"] = len(proc_background)


# ============================================================
# STEP 4 - DNS EVENTS
# ============================================================

print("\n" + "-" * 70)
print("STEP 4 - READING DNS DATA (Streaming)")
print("-" * 70)

dns_relevant = []
dns_background = []

with gzip.open(DNS_FILE, "rt", encoding="utf-8", errors="ignore") as file:
    for line in file:
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue

        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        if timestamp >= END_TIME + 60:
            break

        if timestamp < START_TIME:
            continue

        source_host = parts[1]
        destination = parts[2]

        event = {
            "event_type": "dns",
            "timestamp": timestamp,
            "user": "",
            "source_user": "",
            "destination_user": "",
            "source_host": source_host,
            "destination_host": destination,
            "process": "",
            "action": "DNS_QUERY",
            "details": f"resolved={destination}",
            "is_redteam": 0
        }

        source_counts["dns"] += 1

        is_rel = (source_host in attack_hosts or destination in attack_hosts)

        if is_rel:
            if len(dns_relevant) < MAX_DNS_RELEVANT:
                dns_relevant.append(event)
            elif random.random() < 0.1:
                idx = random.randint(0, len(dns_relevant) - 1)
                dns_relevant[idx] = event
        else:
            if len(dns_background) < BACKGROUND_PER_SOURCE:
                dns_background.append(event)
            elif random.random() < 0.01:
                idx = random.randint(0, len(dns_background) - 1)
                dns_background[idx] = event

print(f"DNS events observed in window: {source_counts['dns']}")
print(f"Relevant DNS events kept: {len(dns_relevant)}")
print(f"Background DNS events kept: {len(dns_background)}")

selected_events.extend(dns_relevant)
selected_events.extend(dns_background)
relevant_counts["dns"] = len(dns_relevant)
background_counts["dns"] = len(dns_background)


# ============================================================
# STEP 5 - NETWORK FLOW EVENTS
# ============================================================

print("\n" + "-" * 70)
print("STEP 5 - READING NETWORK FLOW DATA (Streaming)")
print("-" * 70)

flow_relevant = []
flow_background = []

with gzip.open(FLOW_FILE, "rt", encoding="utf-8", errors="ignore") as file:
    for line in file:
        parts = line.strip().split(",")
        if len(parts) < 9:
            continue

        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        if timestamp >= END_TIME + 60:
            break

        if timestamp < START_TIME:
            continue

        duration = parts[1]
        source_host = parts[2]
        source_port = parts[3]
        destination_host = parts[4]
        destination_port = parts[5]
        protocol = parts[6]
        packets = parts[7]
        bytes_count = parts[8]

        event = {
            "event_type": "flow",
            "timestamp": timestamp,
            "user": "",
            "source_user": "",
            "destination_user": "",
            "source_host": source_host,
            "destination_host": destination_host,
            "process": "",
            "action": "NETWORK_FLOW",
            "details": (
                f"duration={duration}|"
                f"src_port={source_port}|"
                f"dst_port={destination_port}|"
                f"protocol={protocol}|"
                f"packets={packets}|"
                f"bytes={bytes_count}"
            ),
            "is_redteam": 0
        }

        source_counts["flow"] += 1

        is_rel = (source_host in attack_hosts or destination_host in attack_hosts)

        if is_rel:
            if len(flow_relevant) < MAX_FLOW_RELEVANT:
                flow_relevant.append(event)
            elif random.random() < 0.1:
                idx = random.randint(0, len(flow_relevant) - 1)
                flow_relevant[idx] = event
        else:
            if len(flow_background) < BACKGROUND_PER_SOURCE:
                flow_background.append(event)
            elif random.random() < 0.01:
                idx = random.randint(0, len(flow_background) - 1)
                flow_background[idx] = event

print(f"Network flow events observed in window: {source_counts['flow']}")
print(f"Relevant network flow events kept: {len(flow_relevant)}")
print(f"Background network flow events kept: {len(flow_background)}")

selected_events.extend(flow_relevant)
selected_events.extend(flow_background)
relevant_counts["flow"] = len(flow_relevant)
background_counts["flow"] = len(flow_background)


# ============================================================
# STEP 6 - ADD REDTEAM EVENTS
# ============================================================

selected_events.extend(redteam_events)
source_counts["redteam"] = len(redteam_events)
relevant_counts["redteam"] = len(redteam_events)


# ============================================================
# STEP 7 - SORT EVENTS CHRONOLOGICALLY
# ============================================================

print("\n" + "-" * 70)
print("STEP 7 - SORTING EVENTS CHRONOLOGICALLY")
print("-" * 70)

selected_events.sort(key=lambda x: x["timestamp"])

total_events = len(selected_events)
print(f"Total events in final multisource subset: {total_events}")


# ============================================================
# STEP 8 - SAVE CSV
# ============================================================

print("\n" + "-" * 70)
print("STEP 8 - SAVING MULTISOURCE SUBSET CSV")
print("-" * 70)

fieldnames = [
    "event_type",
    "timestamp",
    "user",
    "source_user",
    "destination_user",
    "source_host",
    "destination_host",
    "process",
    "action",
    "details",
    "is_redteam"
]

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(selected_events)

print(f"Saved: {OUTPUT_FILE}")


# ============================================================
# STEP 9 - GENERATE METADATA / STATISTICS REPORT
# ============================================================

print("\n" + "-" * 70)
print("STEP 9 - GENERATING STATISTICS REPORT")
print("-" * 70)

unique_users = set()
unique_hosts = set()
final_counts = Counter()

for ev in selected_events:
    final_counts[ev["event_type"]] += 1
    if ev["user"]:
        unique_users.add(ev["user"])
    if ev["source_user"]:
        unique_users.add(ev["source_user"])
    if ev["destination_user"]:
        unique_users.add(ev["destination_user"])
    if ev["source_host"]:
        unique_hosts.add(ev["source_host"])
    if ev["destination_host"]:
        unique_hosts.add(ev["destination_host"])

stats_content = f"""============================================================
LANL CYBERSECURITY MULTI-SOURCE SUBSET METADATA & STATISTICS
============================================================

1. INVESTIGATION WINDOW DEFINITION & RECONCILIATION
------------------------------------------------------------
Investigation Window: Day 9 to Day 13 (inclusive, 5 days)
Day Indexing: 1-based (day = timestamp // 86400 + 1)
Start Timestamp: {START_TIME} (8 * 86400)
End Timestamp:   {END_TIME} (13 * 86400)
Total Window Duration: {END_TIME - START_TIME} seconds (120 hours)

Window Discrepancy Note:
An earlier script used 777600 to 1209600 (Day 10-14, 305 redteam events).
The reconciled window 691200 to 1123200 correctly corresponds to Day 9-13
and captures all 497 peak rolling 5-day red-team attack events.

2. OVERALL SUBSET TOTALS
------------------------------------------------------------
Total Events in Subset:   {total_events:,}
Red-Team Attack Events:   {len(redteam_events):,}
Unique Users in Subset:   {len(unique_users):,}
Unique Hosts in Subset:   {len(unique_hosts):,}
Timestamp Min:            {min(e['timestamp'] for e in selected_events)}
Timestamp Max:            {max(e['timestamp'] for e in selected_events)}

3. DISTRIBUTION BY EVENT SOURCE
------------------------------------------------------------
"""
for stype, cnt in final_counts.most_common():
    pct = (cnt / total_events) * 100
    stats_content += f"{stype.upper():<12}: {cnt:>8,} events ({pct:>5.1f}%)\n"

stats_content += f"""
4. BREAKDOWN BY TELEMETRY RELEVANCE
------------------------------------------------------------
Source        Relevant Kept      Background Kept     Total In Window
------------------------------------------------------------
"""
for src in ["auth", "process", "dns", "flow", "redteam"]:
    rel = relevant_counts.get(src, 0)
    bg = background_counts.get(src, 0)
    win_tot = source_counts.get(src, 0)
    stats_content += f"{src.upper():<12}  {rel:>12,}  {bg:>17,}  {win_tot:>18,}\n"

stats_content += f"""------------------------------------------------------------
TOTAL         {sum(relevant_counts.values()):>12,}  {sum(background_counts.values()):>17,}  {sum(source_counts.values()):>18,}

5. RED-TEAM GROUND TRUTH ENTITIES
------------------------------------------------------------
Attack Users ({len(attack_users)}): {sorted(list(attack_users))[:15]} ...
Attack Hosts ({len(attack_hosts)}): {sorted(list(attack_hosts))[:15]} ...

6. FILE LOCATION
------------------------------------------------------------
Saved CSV: {OUTPUT_FILE}
File size: {OUTPUT_FILE.stat().st_size / (1024*1024):.2f} MB
============================================================
"""

with open(STATS_FILE, "w", encoding="utf-8") as f:
    f.write(stats_content)

print(f"Saved statistics report: {STATS_FILE}")
print(stats_content)

print("\n" + "=" * 70)
print("DAY 2 MULTI-SOURCE SUBSET CREATION COMPLETE")
print("=" * 70)
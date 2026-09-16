import gzip
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
AUTH_FILE = BASE_DIR / "data" / "raw" / "auth.txt.gz"

print("\n" + "=" * 60)
print("DAY 3 - AUTHENTICATION DATA ANALYSIS")
print("=" * 60)

# Reconciled window: Day 9 to Day 13 inclusive
SECONDS_PER_DAY = 86400
START_TIME = 8 * SECONDS_PER_DAY   # 691,200 (Day 9 start)
END_TIME = 13 * SECONDS_PER_DAY    # 1,123,200 (Day 13 end)

print(f"\nSelected window: Day 9 to Day 13")
print(f"Timestamp range: {START_TIME} to {END_TIME}")

total_records = 0
selected_records = 0

source_users = Counter()
destination_users = Counter()
source_hosts = Counter()
destination_hosts = Counter()
auth_types = Counter()
logon_types = Counter()
activities = Counter()
results = Counter()

print("\nReading authentication data (streaming with early exit)...")

with gzip.open(AUTH_FILE, "rt", encoding="utf-8", errors="ignore") as file:

    for line in file:

        total_records += 1
        parts = line.strip().split(",")

        if len(parts) < 9:
            continue

        try:
            timestamp = int(parts[0])
        except ValueError:
            continue

        # Early exit since LANL files are ordered by timestamp
        if timestamp > END_TIME + 60:
            break

        # Select reconciled suspicious time window
        if START_TIME <= timestamp < END_TIME:

            selected_records += 1

            source_user = parts[1]
            destination_user = parts[2]
            source_host = parts[3]
            destination_host = parts[4]
            auth_type = parts[5]
            logon_type = parts[6]
            activity = parts[7]
            result = parts[8]

            source_users[source_user] += 1
            destination_users[destination_user] += 1
            source_hosts[source_host] += 1
            destination_hosts[destination_host] += 1
            auth_types[auth_type] += 1
            logon_types[logon_type] += 1
            activities[activity] += 1
            results[result] += 1

        if total_records % 5000000 == 0:
            print(f"Scanned {total_records} lines... current timestamp: {timestamp}")

print("\n" + "=" * 60)
print("AUTHENTICATION ANALYSIS RESULTS")
print("=" * 60)

print(f"\nTotal records scanned before window end: {total_records}")
print(f"Records in selected window: {selected_records}")

print("\n===== TOP 10 SOURCE USERS =====")
for user, count in source_users.most_common(10):
    print(f"{user}: {count}")

print("\n===== TOP 10 DESTINATION USERS =====")
for user, count in destination_users.most_common(10):
    print(f"{user}: {count}")

print("\n===== TOP 10 SOURCE HOSTS =====")
for host, count in source_hosts.most_common(10):
    print(f"{host}: {count}")

print("\n===== TOP 10 DESTINATION HOSTS =====")
for host, count in destination_hosts.most_common(10):
    print(f"{host}: {count}")

print("\n===== AUTHENTICATION TYPES =====")
for auth, count in auth_types.most_common():
    print(f"{auth}: {count}")

print("\n===== LOGON TYPES =====")
for logon, count in logon_types.most_common():
    print(f"{logon}: {count}")

print("\n===== ACTIVITIES =====")
for activity, count in activities.most_common():
    print(f"{activity}: {count}")

print("\n===== RESULTS =====")
for result, count in results.most_common():
    print(f"{result}: {count}")

print("\n" + "=" * 60)
print("DAY 3 AUTH ANALYSIS COMPLETE")
print("=" * 60)
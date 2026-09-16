import pandas as pd
from pathlib import Path

# -----------------------------------------
# PROJECT PATHS
# -----------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
SUBSET_DIR = BASE_DIR / "data" / "subset"

SUBSET_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------------------
# RECONCILED INVESTIGATION TIME WINDOW
# Day 9 to Day 13 (inclusive)
# Day 1 is [0, 86400) seconds.
# Day 9 begins at 8 * 86400 = 691,200 seconds.
# Day 13 ends at 13 * 86400 = 1,123,200 seconds.
# This contains the peak rolling 5-day red-team attack activity (497 events).
# -----------------------------------------

SECONDS_PER_DAY = 86400
START_TIME = 8 * SECONDS_PER_DAY   # 691,200 (Day 9 start)
END_TIME = 13 * SECONDS_PER_DAY    # 1,123,200 (Day 13 end)

print("=" * 60)
print("DAY 2 - BUILDING CYBERSECURITY DATA SUBSET")
print("=" * 60)

print(f"\nSelected window: Day 9 to Day 13 (inclusive)")
print(f"Timestamp range: {START_TIME} to {END_TIME}")


# -----------------------------------------
# FUNCTION TO READ REDTEAM DATA
# -----------------------------------------

print("\nReading red-team data...")

redteam_path = RAW_DIR / "redteam.txt"

redteam = pd.read_csv(
    redteam_path,
    header=None,
    names=[
        "timestamp",
        "user",
        "source_host",
        "destination_host"
    ]
)

# Select reconciled Day 9-13 time window
redteam_subset = redteam[
    (redteam["timestamp"] >= START_TIME) &
    (redteam["timestamp"] < END_TIME)
].copy()

print(f"Total red-team events in reconciled window: {len(redteam_subset)}")
assert len(redteam_subset) == 497, f"Expected 497 redteam events, got {len(redteam_subset)}"


# -----------------------------------------
# EXTRACT RELATED USERS AND HOSTS
# -----------------------------------------

attack_users = sorted(list(set(redteam_subset["user"].astype(str))))

attack_hosts = sorted(list(set(
    redteam_subset["source_host"].astype(str)
).union(
    set(redteam_subset["destination_host"].astype(str))
)))

print(f"Unique attack users: {len(attack_users)}")
print(f"Unique attack hosts: {len(attack_hosts)}")


# -----------------------------------------
# SAVE REDTEAM SUBSET
# -----------------------------------------

redteam_subset.to_csv(
    SUBSET_DIR / "redteam_subset.csv",
    index=False
)

print("\nSaved: data/subset/redteam_subset.csv")
print(f"\nAttack users sample ({len(attack_users)} total): {attack_users[:10]}")
print(f"Attack hosts sample ({len(attack_hosts)} total): {attack_hosts[:10]}")

print("\n" + "=" * 60)
print("STEP 1 COMPLETE - RECONCILED RED-TEAM SUBSET CREATED")
print("=" * 60)
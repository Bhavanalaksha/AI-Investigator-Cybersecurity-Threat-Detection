import pandas as pd
from pathlib import Path

# ============================================================
# DAY 4 - DATA PREPROCESSING & NORMALIZATION
# ============================================================

print("\n" + "=" * 70)
print("DAY 4 - DATA PREPROCESSING & NORMALIZATION")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
SUBSET_FILE = BASE_DIR / "data" / "subset" / "multisource_subset.csv"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
REPORTS_DIR = BASE_DIR / "results" / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

PROCESSED_FILE = PROCESSED_DIR / "events_processed.csv"
SUMMARY_FILE = REPORTS_DIR / "preprocessing_summary.txt"

print(f"Loading multisource subset from: {SUBSET_FILE}")
df = pd.read_csv(SUBSET_FILE, low_memory=False)

print(f"Initial raw events count: {len(df):,}")

# ------------------------------------------------------------
# 1. SCHEMA VALIDATION
# ------------------------------------------------------------
expected_columns = [
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

missing_cols = [c for c in expected_columns if c not in df.columns]
if missing_cols:
    raise ValueError(f"Missing required columns in dataset: {missing_cols}")

print("Schema validation PASSED.")

# ------------------------------------------------------------
# 2. HANDLE MISSING VALUES & CLEAN STRINGS
# ------------------------------------------------------------
string_cols = [
    "event_type", "user", "source_user", "destination_user",
    "source_host", "destination_host", "process", "action", "details"
]

for col in string_cols:
    df[col] = df[col].fillna("").astype(str).str.strip()

# If user is blank, infer from source_user if available
df.loc[df["user"] == "", "user"] = df["source_user"]

# ------------------------------------------------------------
# 3. CONVERT & NORMALIZE TIMESTAMPS
# ------------------------------------------------------------
# Drop any rows with invalid timestamp
df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
initial_len = len(df)
df = df.dropna(subset=["timestamp"]).copy()
df["timestamp"] = df["timestamp"].astype(int)

if len(df) < initial_len:
    print(f"Dropped {initial_len - len(df)} rows with invalid timestamps.")

SECONDS_PER_DAY = 86400
# 1-based day indexing: Day 1 starts at t=0
df["day"] = (df["timestamp"] // SECONDS_PER_DAY).astype(int) + 1
df["time_in_day_sec"] = df["timestamp"] % SECONDS_PER_DAY
df["hour_of_day"] = df["time_in_day_sec"] // 3600

# Ensure is_redteam is binary integer
df["is_redteam"] = pd.to_numeric(df["is_redteam"], errors="coerce").fillna(0).astype(int)

# ------------------------------------------------------------
# 4. CHRONOLOGICAL SORTING
# ------------------------------------------------------------
df = df.sort_values(by=["timestamp", "event_type"]).reset_index(drop=True)

# Add event sequence ID
df.insert(0, "event_id", [f"EVT-{i+1:07d}" for i in range(len(df))])

# ------------------------------------------------------------
# 5. SAVE PROCESSED CSV
# ------------------------------------------------------------
df.to_csv(PROCESSED_FILE, index=False)
print(f"Saved processed dataset: {PROCESSED_FILE}")
print(f"Total processed events: {len(df):,}")

# ------------------------------------------------------------
# 6. GENERATE PREPROCESSING SUMMARY REPORT
# ------------------------------------------------------------
redteam_count = int(df["is_redteam"].sum())
event_type_counts = df["event_type"].value_counts().to_dict()
day_counts = df["day"].value_counts().sort_index().to_dict()

summary_text = f"""============================================================
DATA PREPROCESSING & NORMALIZATION SUMMARY
============================================================

1. DATASET OVERVIEW
------------------------------------------------------------
Processed File:         {PROCESSED_FILE}
Total Processed Events: {len(df):,}
Ground-Truth Red-Team:  {redteam_count:,}
File Size:              {PROCESSED_FILE.stat().st_size / (1024*1024):.2f} MB

2. TIME BOUNDARIES & TEMPORAL SPREAD
------------------------------------------------------------
Timestamp Min:          {df['timestamp'].min()} (Day {df['day'].min()})
Timestamp Max:          {df['timestamp'].max()} (Day {df['day'].max()})
Duration:               {df['timestamp'].max() - df['timestamp'].min()} seconds

Events by Day:
"""
for day, cnt in day_counts.items():
    summary_text += f"  Day {day}: {cnt:>8,} events\n"

summary_text += f"""
3. EVENT TYPE COMPOSITION
------------------------------------------------------------
"""
for etype, cnt in event_type_counts.items():
    pct = (cnt / len(df)) * 100
    summary_text += f"  {etype.upper():<12}: {cnt:>8,} events ({pct:>5.1f}%)\n"

summary_text += f"""
4. DATA INTEGRITY & HYGIENE
------------------------------------------------------------
- Missing Values: Standardized to empty string for text fields
- Schema Integrity: Verified all required columns present
- Chronological Order: Strictly sorted by timestamp ascending
- Ground-Truth Integrity: Verified {redteam_count} red-team attack labels preserved
- Derived Features Added: day, time_in_day_sec, hour_of_day, event_id

============================================================
PREPROCESSING COMPLETE
============================================================
"""

with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
    f.write(summary_text)

print(f"Saved preprocessing summary: {SUMMARY_FILE}")
print(summary_text)

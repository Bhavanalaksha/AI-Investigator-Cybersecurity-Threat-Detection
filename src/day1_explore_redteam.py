import pandas as pd

# -------------------------------
# DAY 1: EXPLORE LANL RED-TEAM DATA
# -------------------------------

FILE_PATH = "data/raw/redteam.txt"

# LANL red-team file columns
columns = [
    "timestamp",
    "user",
    "source_host",
    "destination_host"
]

# Read the dataset
redteam = pd.read_csv(
    FILE_PATH,
    names=columns,
    header=None
)

print("\n===== LANL RED-TEAM DATASET ANALYSIS =====\n")

# Basic information
print("Total red-team events:", len(redteam))

print("\nFirst 5 events:")
print(redteam.head())

print("\nTimestamp range:")
print("First timestamp:", redteam["timestamp"].min())
print("Last timestamp:", redteam["timestamp"].max())


# -------------------------------
# CONVERT TIMESTAMPS TO DAYS
# -------------------------------

SECONDS_PER_DAY = 86400

redteam["day"] = (
    redteam["timestamp"] // SECONDS_PER_DAY
).astype(int) + 1


# Count attacks per day
daily_attacks = (
    redteam.groupby("day")
    .size()
    .reset_index(name="redteam_events")
)

print("\n===== RED-TEAM EVENTS PER DAY =====\n")
print(daily_attacks.to_string(index=False))


# -------------------------------
# FIND BEST 3-DAY WINDOW
# -------------------------------

daily_series = daily_attacks.set_index("day")["redteam_events"]

# Make sure missing days have 0 attacks
all_days = range(
    redteam["day"].min(),
    redteam["day"].max() + 1
)

daily_series = daily_series.reindex(all_days, fill_value=0)

rolling_3 = daily_series.rolling(window=3).sum()

best_3_end = rolling_3.idxmax()
best_3_start = best_3_end - 2

print("\n===== BEST 3-DAY WINDOW =====")
print(f"Window: Day {best_3_start} to Day {best_3_end}")
print(f"Total red-team events: {int(rolling_3.max())}")


# -------------------------------
# FIND BEST 5-DAY WINDOW
# -------------------------------

rolling_5 = daily_series.rolling(window=5).sum()

best_5_end = rolling_5.idxmax()
best_5_start = best_5_end - 4

print("\n===== BEST 5-DAY WINDOW =====")
print(f"Window: Day {best_5_start} to Day {best_5_end}")
print(f"Total red-team events: {int(rolling_5.max())}")
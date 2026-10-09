# Final Comprehensive Project Audit

## 1. Discrepancy Investigation: Why Test Population Changed (1,432 vs 289 Windows)
- In the initial clean experiment (`src/clean_experiment.py`), the operational window size was set to **60 seconds (1 minute)**. Spanning Days 13 to 14 (86,400+ seconds), grouping produced exactly **1,432 temporal windows** containing 136 attack windows.
- In the subsequent optimization experiment (`src/model_optimization.py`), window size selection evaluated on validation data selected **300 seconds (5 minutes)** because multi-hop lateral movement and process execution require several minutes to unfold.
- Grouping the exact same Days 13–14 telemetry into 300-second windows produces exactly `86,400 / 300 = 289 temporal windows` (containing 64 attack windows).
- **Conclusion:** The test sample count changed strictly due to the operational window aggregation parameter (60s vs 300s), NOT due to filtering, dropping samples, or data manipulation.

## 2. Dataset Inventory & Raw Telemetry
- LANL Comprehensive Multi-Source Cybersecurity Dataset (Days 9 to 14).
- Total events: 130,497 events across Authentication (55,000), Process (25,000), DNS (25,000), Flow (25,000), and Red-Team (497).
- Timestamps are unix seconds since experiment start.

## 3. Ground-Truth Policy & Window Definitions
- Ground truth is sourced from `redteam.txt`.
- A 300-second window is labeled positive (`y = 1`) if it contains at least one ground-truth Red-Team attack event.
- Non-redteam windows represent background enterprise telemetry under the stated labeling policy.

## 4. Verification of Leakage Removal
- All `is_rt == 1` shortcuts removed from `day5_triage.py`, `auth_agent.py`, `process_agent.py`, and `network_agent.py`.
- No test-derived attack usernames or hostnames seeded into agents.
- Post-hoc ground-truth matching ensures zero target leakage.

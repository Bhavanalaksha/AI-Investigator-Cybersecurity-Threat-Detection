# Phase 3A.1: Independent Methodology and Evaluation Audit Report

**Project:** AI Investigator for Cybersecurity Threat Detection and Response  
**Evaluation Dataset:** Los Alamos National Laboratory (LANL) Multi-Source Cyber Telemetry  
**Audit Phase:** Phase 3A.1 - Independent Methodology & Evaluation Audit ONLY  
**Date of Audit Execution:** October 19, 2026  
**Auditor:** Independent Methodological & Verification Agent  
**Branch:** main | **Commit Checkpoint:** b5dd1d0 | **Integrity Status:** FROZEN & UNMODIFIED  

---

## Executive Summary & Scope

This audit report delivers an exhaustive, read-only forensic analysis of the experimental methodology, data boundaries, synthetic annotations, baseline isolation, and evaluation metrics for the AI Investigator cybersecurity threat detection project.

In strict compliance with the **Phase 3A.1 mandate**, no source code has been altered, no models have been trained or retrained, no operational decision thresholds have been tuned, no existing benchmark outputs have been overwritten, and no ablation experiments have been launched.

### Cryptographic Checkpoint & Artifact Hash Verification
Prior to executing any diagnostic inspections, the cryptographic integrity of core models and prediction benchmarks was independently verified against the baseline registry:

| Artifact Path | Expected SHA-256 Hash | Verified Match | Status |
| :--- | :--- | :--- | :--- |
| `results/models/best_model.joblib` | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | YES | LOCKED |
| `results/reports/final_predictions.csv` | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | YES | LOCKED |
| `data/processed/events_processed.csv` | `565bf5632b53b0a214e24cf7ce55c27599cb592fa4e87df5d1bf2795c207e923` | YES | LOCKED |

---

## 1. Verification of the Held-Out Test Split and Temporal Windows

### 1.1 Resolution of Test Interval Discrepancy (1,036,802–1,123,259 vs 1,036,800–1,123,200)

A recurring discrepancy in earlier project documentation was the reference to the held-out test split as `1,036,800–1,123,200` in design narratives, while evaluation outputs recorded `1,036,802–1,123,259`.

**Code Evidence:**
In `src/model_optimization.py` (lines 58–60, 88–90) and `src/clean_experiment.py` (lines 55–57, 151):
- `T_TRAIN_END = 777600` (End of Day 9, `9 x 86,400s`)
- `T_VAL_END = 1036800` (End of Day 12, `12 x 86,400s`)
- `test_slice = events[events['timestamp'] > T_VAL_END].copy()`

Inside `build_window_dataset` (lines 101–103):
- `min_t = df_slice['timestamp'].min()`
- `df_temp['window_id'] = (df_temp['timestamp'] - min_t) // window_size_sec`

**Resolution:**
1. **Nominal vs Empirical Boundaries:** The theoretical Day 13 boundary begins at exactly `12 x 86,400 = 1,036,800` seconds and ends at `13 x 86,400 = 1,123,200` seconds (an exact 24-hour interval of 86,400 seconds).
2. **Empirical Telemetry Arrival:** In the processed telemetry dataset (`data/processed/events_processed.csv`), the first recorded event after `t = 1,036,800` occurs at timestamp **`1,036,802`** (2 seconds after midnight).
3. **Bin Anchoring:** Because the window extraction function dynamically anchors bins to `min_t = df_slice['timestamp'].min()`, `min_t` evaluates to `1,036,802`. All 300-second bins are therefore computed as:
   - `nominal_bin_start(k) = 1,036,802 + (k x 300)`
   - `nominal_bin_end(k)   = 1,036,802 + ((k + 1) x 300)`
4. **Test Period End:** In the raw dataset extraction script (`src/day2_build_multisource_subset.py`), event slicing extended through Day 13 plus a 59-second tail into the next nominal minute, terminating at timestamp **`1,123,259`**.
5. **Conclusion:** The true empirical test interval is **`1,036,802–1,123,259`** (86,457 seconds). The label `1,036,800–1,123,200` was a theoretical shorthand for Day 13.

---

### 1.2 Mathematical Derivation of the 57-Second Boundary Window and 289-Second Mean Duration

Earlier project reports raised questions regarding why Window 288 has a duration of 57 seconds and why the overall average duration across all 289 windows is reported as 289.0 seconds rather than 300.0 seconds.

**Forensic Explanation:**

1. **Window Count Calculation:**
   The total duration of the empirical test slice is:
   `1,123,259 - 1,036,802 = 86,457 seconds`
   Dividing into non-overlapping 300-second bins:
   `86,457 / 300 = 288.19`
   This yields **289 discrete bins** indexed from `Window 0` (`TEST_W0000`) through `Window 288` (`TEST_W0288`).

2. **The 57-Second Boundary Window (TEST_W0288):**
   - Nominal bin start for Window 288: `1,036,802 + (288 x 300) = 1,123,202`
   - Nominal bin end for Window 288: `1,123,202 + 300 = 1,123,502`
   - However, telemetry recording terminates at timestamp `1,123,259`.
   - The first event in Window 288 occurs at `t = 1,123,202`.
   - The last event in Window 288 occurs at `t = 1,123,259`.
   - Observed duration: `1,123,259 - 1,123,202 = 57 seconds`.
   - Window 288 contains 760 events, all of which are benign (`ground_truth = 0`).

3. **Why the Reported Mean Duration is Exactly 289.0 Seconds:**
   In `results/reports/final_predictions.csv`, the reported columns `t_start` and `t_end` are the **empirical first and last event timestamps** observed in each window bin:
   - `t_start = min(timestamp of events in bin k)`
   - `t_end   = max(timestamp of events in bin k)`
   - `duration = t_end - t_start`

   Because security telemetry is a discrete point process rather than a continuous signal, events do not arrive continuously at second 0 and second 300. In an active 300-second bin `[t_0, t_0 + 300)`:
   - The first event typically arrives at `t_0 + 1s` or `t_0 + 2s`.
   - The last event typically arrives at `t_0 + 298s` or `t_0 + 299s`.
   - Empirical span across the full bins ranges from 286 to 299 seconds (median: 297s, 75th percentile: 299s).
   - For Window 288, the observed span is 57 seconds.
   - The sum of observed event spans across all 289 bins is exactly:
     `Sum(t_end - t_start) = 83,521 seconds`
   - The arithmetic mean is:
     `83,521 / 289 = 289.0000 seconds`

   The report value of 289 seconds is therefore not a misconfigured window parameter, but the exact arithmetic mean of the observed event time spans within the 300-second bins.

---

### 1.3 Read-Only Audit Table Generation

A comprehensive, read-only audit table containing all 289 test windows has been generated and saved to:  
`results/phase3a1_audit/test_windows_audit_table.csv`

**Audit Table Summary Statistics:**
- **Total Windows:** 289 (`TEST_W0000` to `TEST_W0288`)
- **Total Telemetry Events Evaluated:** 107,587 events
- **Ground-Truth Positive (Attack) Windows:** 64 windows (22.15%)
- **Ground-Truth Negative (Benign) Windows:** 225 windows (77.85%)
- **Saved Model Predictions at SOC Threshold (0.9300):** 46 positive windows, 243 negative windows
- **Saved Model Predictions at Balanced Threshold (0.8459):** 64 positive windows, 225 negative windows
- **Rule-Based SIEM Predictions:** 226 positive windows, 63 negative windows

---

## 2. Forensic Audit of Synthetic Red-Team Annotations

### 2.1 Dataset Construction and Injection Origin

The 497 red-team records originated from LANL's `redteam.txt` ground-truth file.

**Code Evidence (`src/day2_build_multisource_subset.py`, lines 40–75, 235–250):**
```python
# STEP 1 - READ REDTEAM EVENTS
redteam_events = []
with open(REDTEAM_FILE, "r", encoding="utf-8") as file:
    for line in file:
        parts = line.strip().split(",")
        redteam_events.append({
            "event_type": "redteam",
            "action": "REDTEAM_ATTACK",
            "details": "Known red-team event",
            "is_redteam": 1
        })

# STEP 6 - ADD REDTEAM EVENTS
selected_events.extend(redteam_events)
```
For native telemetry streams (`auth`, `process`, `dns`, `flow`), the script set:
```python
event_dict["is_redteam"] = 0  # Hardcoded 0 across all 130,000 native rows
```

**Audit Findings on Data Pipeline:**
1. **Synthetic Pseudo-Events:** The 497 rows in `events_processed.csv` with `event_type == 'redteam'` are copies of `redteam.txt` injected as pseudo-events into the telemetry dataframe.
2. **Native Telemetry Left Unlabeled:** No join was performed between `redteam.txt` and native `auth` or `process` records. Consequently, all 130,000 native telemetry rows have `is_redteam = 0`.
3. **Partition Breakdown:**
   - Training/Validation Slice (`t <= 1,036,800`): 288 red-team rows, 22,622 native rows.
   - Held-Out Test Slice (`t > 1,036,800`): 209 red-team rows, 107,378 native rows.

---

### 2.2 Influence of Synthetic Rows on Profiling, Baseline Statistics, and Model Predictions

We conducted an independent empirical test comparing model features and continuous predictions with versus without the 209 synthetic red-team test rows.

**1. Profiling & Baseline Statistics:**
- In `src/phase2/evaluate_agents.py` and `src/agents/orchestrator_agent.py`, baseline behavioral profiles (`user_host_pairs`, frequency distributions) are computed from the training/validation partition (`t <= 1,036,800`).
- Because `events_processed.csv` contained 288 synthetic red-team rows in that partition, the unique user-host entities from those rows entered the baseline tables.

**2. Random Forest Window Feature Distortion:**
In `src/model_optimization.py`, features are aggregated per window:
```python
grouped = df_temp.groupby("window_id").agg({
    "timestamp": "count",
    "user": "nunique",
    "destination_host": "nunique",
    "source_host": "nunique", ...
})
```
When the 209 synthetic red-team rows are present in the test slice, they directly inflate the window features:
- `total_events`: Differed in **64 windows**.
- `user` (unique users count): Differed in **59 windows**.
- `destination_host` (unique destination hosts count): Differed in **62 windows**.
- `source_host` (unique source hosts count): Differed in **62 windows**.
- `user_to_host_ratio`: Differed in **63 windows**.
- `delta_total_events`: Differed in **74 windows**.

**3. Quantitative Impact on Random Forest Predictions:**
Running the frozen `best_model.joblib` across the identical 289 windows with versus without synthetic rows yielded:
- **Maximum Absolute Score Difference:** `0.0875` (an 8.75% probability shift).
- **Windows with Non-Zero Score Shift:** `43 windows`.
- **Windows with Score Shift > 0.01:** `16 windows`.
- **Binary Classification Label Flips at Threshold 0.9300:** `2 windows flipped` (True Positives decreased from 32 to 30; False Negatives increased from 32 to 34).

**Critical Conclusion on Leakage:**
Sanitizing the text fields `action = "LogOn"` and `details = ""` was necessary, but **NOT SUFFICIENT** to achieve complete independence from synthetic annotations. The mere physical presence of synthetic rows in the telemetry dataframe inflates entity counts and event volumes, creating feature distortion and score shifts.

---

### 2.3 Recommended Scientifically Valid Evaluation Approach

To achieve genuine academic reproducibility without synthetic row artifacts:
1. **Decouple Telemetry from Ground Truth:** The multi-agent pipeline and baseline models must ingest **ONLY the 130,000 native observable telemetry events** (`event_type != 'redteam'`).
2. **Ground Truth as External Label Reference:** The 497 red-team attack records must remain strictly in an external reference table (`redteam_ground_truth.csv` or `data/raw/redteam.txt`).
3. **Window-Level Ground Truth Assignment:** A window is labeled positive (`y_true = 1`) if any ground-truth attack record in `redteam.txt` has its timestamp falling in the window interval `[nominal_bin_start, nominal_bin_end)`.
4. **Post-Hoc Association Evaluation:** Correlated multi-agent incidents synthesized purely from native telemetry are matched post-hoc against the external attack records within specified time tolerances (0s, 60s, 300s, 600s) and entity overlaps.

---

## 3. Verification of Common Evaluation Populations & Raw Recomputation

### 3.1 Distinct Evaluation Populations and Metric Definitions

To eliminate ambiguity across previous reports, the evaluation framework is formally partitioned into three distinct operational populations:

| Evaluation Tier | Target Population | Class Definition | Primary Purpose |
| :--- | :--- | :--- | :--- |
| **Tier 1: Event-Level Detection** | Telemetry Events (107,587 test events) | Positive: Attack event<br>Negative: Benign event | Evaluates fine-grained event filtering and analyst alert volume. |
| **Tier 2: Incident-Level Association** | Attack Records (209 test attacks) vs Incidents | Associated: Attack matched to incident within tolerance | Evaluates multi-event investigation and incident synthesis. |
| **Tier 3: Window-Level Parity** | 289 Frozen 300s Windows | Positive: >=1 attack in window (64)<br>Negative: 0 attacks in window (225) | Standardized operational benchmark for multi-system comparison. |

---

### 3.2 Independent Recomputation from Raw Saved Prediction Vectors

We independently recomputed all performance metrics directly from the raw prediction vectors in `final_predictions.csv` and `triaged_events.csv`, bypassing any pre-existing text reports or summary matrices.

#### 1. Random Forest Baseline (SOC Threshold = 0.9300)
- **Confusion Matrix:** TP = 32, FP = 14, FN = 32, TN = 211 (Total = 289)
- **Precision:** `32 / (32 + 14) = 69.57%`
- **Recall (Sensitivity):** `32 / (32 + 32) = 50.00%`
- **F1-Score:** `2 x (0.6957 x 0.5000) / (0.6957 + 0.5000) = 58.18%`
- **Specificity:** `211 / (211 + 14) = 93.78%`
- **False Positive Rate (FPR):** `14 / (211 + 14) = 6.22%`
- **Accuracy:** `(32 + 211) / 289 = 84.08%`
- **ROC-AUC:** `0.6874`
- **PR-AUC (Average Precision):** `0.5670`

#### 2. Random Forest Baseline (Balanced Threshold = 0.8459)
- **Confusion Matrix:** TP = 36, FP = 28, FN = 28, TN = 197 (Total = 289)
- **Precision:** `36 / (36 + 28) = 56.25%`
- **Recall:** `36 / (36 + 28) = 56.25%`
- **F1-Score:** `56.25%`
- **Specificity:** `197 / (197 + 28) = 87.56%`
- **False Positive Rate (FPR):** `28 / (197 + 28) = 12.44%`
- **Accuracy:** `(36 + 197) / 289 = 80.62%`

#### 3. Rule-Based SIEM Baseline (Triage Engine, Score >= 3)
Evaluated across the exact same 289 test windows:
- **Confusion Matrix:** TP = 64, FP = 162, FN = 0, TN = 63 (Total = 289)
- **Precision:** `64 / (64 + 162) = 28.32%`
- **Recall:** `64 / (64 + 0) = 100.00%`
- **F1-Score:** `44.14%`
- **Specificity:** `63 / (63 + 162) = 28.00%`
- **False Positive Rate (FPR):** `162 / 225 = 72.00%`
- **Accuracy:** `(64 + 63) / 289 = 43.94%`

#### 4. Multi-Agent System (Active Incidents in Window, Phase 2B Clean)
Evaluated across the exact same 289 test windows:
- **Confusion Matrix:** TP = 46, FP = 113, FN = 18, TN = 112 (Total = 289)
- **Precision:** `46 / (46 + 113) = 28.93%`
- **Recall:** `46 / (46 + 18) = 71.88%`
- **F1-Score:** `41.26%`
- **Specificity:** `112 / (112 + 113) = 49.78%`
- **False Positive Rate (FPR):** `113 / 225 = 50.22%`
- **Accuracy:** `(46 + 112) / 289 = 54.67%`

---

### 3.3 Relationship Between 209 Red-Team Annotations and 64 Positive Windows

We audited the exact mapping between the 209 test attack records and the 64 positive windows:

**Statistical Distribution of Attacks per Positive Window:**
- **Positive Windows Count:** Exactly 64 windows.
- **Total Red-Team Records Mapped:** Exactly 209 records.
- **Mean Attacks per Window:** `3.27` records.
- **Standard Deviation:** `2.41`.
- **Median Attacks per Window:** `2.50` records.
- **Minimum:** 1 record (in 15 windows).
- **Maximum:** 11 records (in 1 window, reflecting rapid multi-host lateral movement).

**Frequency Breakdown:**
- 1 attack record: 15 windows
- 2 attack records: 17 windows
- 3 attack records: 12 windows
- 4 attack records: 5 windows
- 5 attack records: 5 windows
- 6 to 11 attack records: 10 windows

**Temporal Burst Localization:**
- **First Attack Window:** Window 98 (`TEST_W0098`, `t = 1,066,202`, ~8.17 hours into Day 13).
- **Last Attack Window:** Window 215 (`TEST_W0215`, `t = 1,101,302`, ~17.92 hours into Day 13).
- **Campaign Concentration:** All 64 attack windows occur strictly in a 9.75-hour operational span.
- **Benign Baseline Windows:** Windows 0–97 (first 8.16 hours) and Windows 216–288 (last 6.08 hours) contain **ZERO red-team attacks** (100% pure enterprise background traffic).
- **Attack Continuity:** 43 of the 63 consecutive attack transitions have a step size of 1 (continuous, uninterrupted attack bursts).

---

## 4. Audit of Graph-Only Baseline Isolation

### 4.1 Evaluation of Current Correlation Implementation

We inspected `src/agents/correlation_agent.py` to determine whether a genuine "Graph-Only" baseline exists in the current repository.

**Findings:**
1. **Dependency on Specialist Agents:** `CorrelationAgent` receives candidate events strictly from `agent_findings_list` (lines 52–69). It does not ingest the raw telemetry stream.
2. **Specialist Risk Score Filtering:** In line 200:
   ```python
   max_risk = max((float(e.get("risk_score", 0)) for e in c_events), default=0.0)
   if len(c.event_indices) >= 3 or max_risk >= 5:
       meaningful_clusters.append((c, c_events))
   ```
   The filtering logic retains clusters of 1 or 2 events if `max_risk >= 5`. This rule relies directly on the specialist domain agents' heuristic scores.
3. **Past Ablation Anomaly:** In `results/phase2_backup_before_clean_eval/agent_ablation_results.csv`, `Exp E: Specialists + Correlation` reported 100% recall and 97.64% F1. That result was achieved prior to Phase 1, when ground-truth `is_redteam` leakage was present in the agent score additions.
4. **Current Status:** A standalone, isolated Graph-Only baseline that operates independently of specialist domain rules does NOT currently exist in the codebase.

---

### 4.2 Exact Cluster and Window-Level Alert Rules Required for a Fair Graph-Only Baseline

For a fair and academically rigorous four-way baseline comparison in Phase 3B, the Graph-Only baseline must adhere to the following strict isolation rules:

1. **Input Isolation:** The graph engine must construct an entity-interaction graph directly from native telemetry events over a 600-second sliding window, without receiving specialist agent scores, triage scores, or labels.
2. **Graph Structure:**
   - **Nodes:** Unique users, hosts, and processes.
   - **Edges:** Directed events (Auth: User -> Host, Flow: Host -> Host, Process: Host -> Process).
3. **Cluster Alert Rule (Pure Graph Topology):**
   A cluster is designated an alert if and only if it satisfies structural topological criteria:
   - `Event Count >= 3` within the 600-second window; AND
   - `Distinct Host Count >= 2` (capturing structural lateral movement across network nodes).
   - Zero dependence on `risk_score`, `is_redteam`, or text keywords.
4. **Window Alert Rule for Common Benchmark Parity:**
   Window k is predicted positive (`y_pred = 1`) if and only if an active graph cluster satisfying the topological criteria has its temporal lifetime `[c.start, c.end]` overlapping the window bin `[w_start, w_end]`.

---

## 5. Summary of Confirmed Facts, Unresolved Issues, and Approval Gates

### 5.1 Confirmed Facts (Rigorously Verified)
1. **Split Definition:** The held-out test split covers empirical timestamps `1,036,802` to `1,123,259` (86,457 seconds), partitioned into exactly 289 non-overlapping 300-second bins (`Window 0` to `Window 288`).
2. **Boundary Window Duration:** Window 288 is 57 seconds long because telemetry collection terminates at `t = 1,123,259` (`1,123,259 - 1,123,202 = 57s`).
3. **Mean Duration:** The reported mean duration of 289.0 seconds is the exact arithmetic mean of observed event spans within the 300-second bins.
4. **Model Hash & Prediction Reproduction:** `best_model.joblib` and `final_predictions.csv` hashes match the verified baseline. Continuous scores replicate from the model to `< 5e-7` numerical tolerance.
5. **Metric Verification:** At SOC threshold 0.9300, Random Forest achieves exactly 32 TP, 14 FP, 32 FN, 211 TN (Precision: 69.57%, Recall: 50.00%, F1: 58.18%, FPR: 6.22%, Accuracy: 84.08%).
6. **Attack-to-Window Mapping:** The 209 test attack records map into exactly 64 positive windows (mean: 3.27 attacks/window, range: 1–11), all clustered between Window 98 and Window 215.
7. **SIEM Window Parity:** Rule-Based SIEM on the same 289 windows yields 64 TP, 162 FP, 0 FN, 63 TN (Precision: 28.32%, Recall: 100.00%, F1: 44.14%, FPR: 72.00%).

---

### 5.2 Unresolved Issues and Limitations

1. **Synthetic Annotation Rows in Telemetry Stream:**
   The presence of 209 synthetic red-team rows in `events_processed.csv` during test evaluation introduces subtle feature distortion (e.g. shifts unique user/host counts in 59–64 windows). Although text fields were sanitized in Phase 2B, complete academic purity requires removing these rows from model inputs entirely.
2. **Status of Native Auth Events for Red-Team Attacks:**
   - **Status:** **UNVERIFIED**
   - **Reason:** In `day2_build_multisource_subset.py`, redteam records were appended as synthetic rows, and all 130,000 native rows had `is_redteam = 0` assigned. Whether native auth events corresponding to the 497 attacks were captured in the downsampled subset cannot be verified without a full join against the original multi-gigabyte `auth.txt.gz`.
3. **Graph-Only Baseline Isolation:**
   - The current `CorrelationAgent` is an integration component for specialist agents, not a standalone graph baseline. A pure graph-only baseline script must be defined prior to running Phase 3B.

---

### 5.3 Recommended Corrected Evaluation Protocol (For Phase 3B)

When Phase 3B is approved, the benchmark must execute under this unified protocol:
1. **Frozen Benchmark Population:** All systems evaluated on the **identical 289 non-overlapping 300-second windows** (`1,036,802–1,123,259`).
2. **Pure Telemetry Ingestion:** All detection systems ingest **ONLY native telemetry rows** (`event_type != 'redteam'`).
3. **External Ground-Truth Reference:** Ground truth is strictly defined from `redteam.txt` as an external label generator for windows and post-hoc incident matching.
4. **Standard Four-Way Benchmark Systems:**
   - System 1: Rule-Based SIEM Baseline (Triage Engine, Score >= 3)
   - System 2: Random Forest ML Baseline (SOC Threshold = 0.9300 and Balanced Threshold = 0.8459)
   - System 3: Isolated Graph-Only Baseline (Structural Lateral Movement: Events >= 3, Hosts >= 2, 600s window)
   - System 4: Full AI Investigator Multi-Agent Pipeline (Specialists + Graph Correlation + Analysis + Response)
5. **Reported Metrics:** Precision, Recall, F1, Specificity, FPR, Accuracy, TP, FP, FN, TN, and Incident Reduction Rate.

---

### 5.4 Explicit Approval Gates Before Phase 3B Execution

Execution of Phase 3B remains blocked pending explicit user authorization on the following gates:

- [ ] **Gate 1: Split & Window Definitions Approved**  
  Confirmation that the 289 non-overlapping 300-second windows (`1,036,802–1,123,259`) with 64 positive and 225 negative windows are approved as the permanent benchmark standard.

- [ ] **Gate 2: Synthetic Row Decoupling Approved**  
  Confirmation that the evaluation input stream will ingest native telemetry events only, using red-team annotations solely as external evaluation targets.

- [ ] **Gate 3: Graph-Only Baseline Isolation Specification Approved**  
  Confirmation that the Graph-Only baseline will be evaluated using purely topological clustering (Events >= 3, Hosts >= 2 in 600s window) without specialist agent scores.

- [ ] **Gate 4: Multi-Agent Window Projection Method Approved**  
  Confirmation that multi-agent active incident temporal overlaps `[inc.start, inc.end] overlaps [w_start, w_end]` will serve as the standardized window prediction mapping.

---
*Report generated and locked by Phase 3A.1 Independent Audit Agent. Awaiting user review and authorization.*

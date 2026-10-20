# Phase 3C.3: Corrected Sampling Protocol Design and Leakage Review

**Document Status:** Complete Design & Scientific Review  
**Investigation Scope:** Statistical Protocol Design, Leakage Safeguards, Temporal Isolation, and Reproducibility Specifications  
**Working Directory:** `C:\Users\WELCOME\Desktop\mini_proj`  
**Execution Timestamp:** 2026-10-19T21:20:00+05:30  
**Git Checkpoint:** `checkpoint-phase3c-start`  

---

## Executive Summary

Phase 3C.3 establishes the formal, peer-review-grade protocol design for sampling multi-source telemetry from the raw Los Alamos National Laboratory (LANL) Cyber Telemetry archive (`data/raw/`). 

This document directly addresses the two severe methodological defects identified in the Phase 3C.2 provenance audit of the historical ingestion script [`src/day2_build_multisource_subset.py`](file:///C:/Users/WELCOME/Desktop/mini_proj/src/day2_build_multisource_subset.py):
1. **The Constant-Probability Replacement Flaw:** Setting a fixed 10% replacement rate (`p = 0.1`) across massive gzip streams (85.5 million auth lines) converted the buffer into a leaky sliding window that purged all early telemetry, resulting in 100% DNS in training and relegating all authentication and netflow data to Day 13.
2. **Ground-Truth Entity Sampling Leakage:** In the historical script, `redteam.txt` was parsed *prior to sampling* to extract all `attack_users` and `attack_hosts` across the entire 5-day timeline. The script then prioritized events matching these attack entities (allocating 50,000 slots to attack-associated telemetry vs only 5,000 slots to general enterprise background). This introduced severe retrospective entity selection bias and sampling leakage.

This design protocol establishes an entirely **label-agnostic, temporally stratified streaming reservoir sampling strategy** that:
- Ensures uniform temporal coverage across authentication, process, netflow, and DNS telemetry throughout Days 9 to 13.
- Completely isolates the sampling process from ground-truth attack labels, users, hosts, and timestamps.
- Preserves the frozen Phase 3B/3C historical benchmark unchanged as a distinct scientific baseline.
- Defines comprehensive covariate shift and variance diagnostics.
- Outlines rigorous approval gates before any execution or retraining.

---

## 1. Corrected Sampling Algorithm: Temporally Stratified Reservoir Sampling

### 1.1 Limitations of Global Sampling Across Multi-Gigabyte Streams
A single global reservoir across 120 hours of raw logs suffers from major vulnerabilities:
- High-volume periods (such as business-hour authentication storms containing millions of events) would dominate the reservoir, while quiet off-hours or maintenance periods would be under-represented.
- If replacement probabilities are miscalibrated, chronological order in raw files induces sliding-window distortion.

### 1.2 Mathematical Formulation of Stratified Reservoir Sampling (Algorithm R per Hourly Stratum)
To eliminate chronological bias and preserve diurnal behavioral dynamics, the sampling timeline is partitioned into discrete, non-overlapping **1-hour temporal strata**:

```
Investigation Timeline: Day 9 to Day 13 (inclusive)
Start Time: T_START = 691,200  (Day 9, 00:00:00)
End Time:   T_END   = 1,123,200 (Day 13, 24:00:00)
Total Span: 432,000 seconds = 120 hourly strata (h = 0, 1, ..., 119)

Stratum Boundary:
Stratum h spans [T_START + h * 3600, T_START + (h + 1) * 3600)
```

Within each stratum `h` and for each telemetry modality `m` in `{auth, proc, flow, dns}`, independent **Streaming Reservoir Sampling (Algorithm R)** is executed with a fixed hourly quota `K_m`:

```
Algorithm R within Stratum h for Modality m:
--------------------------------------------------------------------------------
1. Initialize empty reservoir array R_{m, h} of fixed capacity K_m.
2. Initialize stratum event counter n = 0.
3. For each incoming event e from raw file with timestamp t in Stratum h:
     n = n + 1
     if len(R_{m, h}) < K_m:
         Append e to R_{m, h}
     else:
         Generate random integer j uniformly distributed in [0, n - 1]
         if j < K_m:
             R_{m, h}[j] = e   # Replace slot j with event e
4. At boundary t >= T_START + (h + 1) * 3600:
     Flush R_{m, h} to output buffer.
     Reset R_{m, h+1} and reset counter n = 0 for the next stratum.
--------------------------------------------------------------------------------
```

### 1.3 Mathematical Proof of Uniform Survival Within Stratum
Let `N_{m, h}` be the total unknown number of events of modality `m` occurring in stratum `h`.
- For any event `e_i` arriving at index `i <= K_m`, it enters the reservoir with probability 1.
- For each subsequent event `k` (where `K_m < k <= N_{m, h}`), event `k` enters the reservoir with probability `K_m / k`, and replaces a randomly chosen slot with probability `1 / K_m`. The probability that `e_i` is replaced by event `k` is `(K_m / k) * (1 / K_m) = 1 / k`.
- The probability that `e_i` survives step `k` is `1 - 1 / k = (k - 1) / k`.
- By induction across all steps from `K_m + 1` to `N_{m, h}`:
  `P(e_i survives in R_{m, h}) = 1 * (K_m / (K_m + 1)) * ((K_m + 1) / (K_m + 2)) * ... * ((N_{m, h} - 1) / N_{m, h}) = K_m / N_{m, h}`
- For any event `e_k` arriving at index `k > K_m`, it enters the reservoir with probability `K_m / k`, and survives all subsequent steps with probability `k / N_{m, h}`. Its overall survival probability is:
  `P(e_k in R_{m, h}) = (K_m / k) * (k / N_{m, h}) = K_m / N_{m, h}`

**Conclusion:** Every single event within hour `h` has **identically equal probability `K_m / N_{m, h}`** of being included in the sample. Because the reservoir is reset at the start of each hour, events in early hours are **mathematically immune to replacement by events in later hours**.

### 1.4 Sampling Probabilities and Documented Bias
- **Sampling Probability:** In stratum `h`, the selection fraction for modality `m` is:
  `pi_{m, h} = min(1.0, K_m / N_{m, h})`
- **Documented Stratification Bias:**
  - High-volume hours (e.g., peak enterprise workday with 2,000,000 authentications) have a smaller sampling fraction (`pi ~ 500 / 2,000,000 = 0.00025`) than low-volume night hours (`pi ~ 500 / 10,000 = 0.05`).
  - This design deliberately flattens extreme diurnal volume swings to maintain steady telemetry representation across all 120 hours.
  - This is an intentional design choice for machine learning feature stability and is explicitly documented as a stratum-dependent sampling fraction.

---

## 2. Safeguards Against Label-Informed Sampling and Ground-Truth Leakage

### 2.1 The Critical Defect in Historical Practice
The Phase 3C.2 audit revealed that `src/day2_build_multisource_subset.py` parsed `redteam.txt` prior to stream processing, extracted `attack_users` (71 accounts) and `attack_hosts` (240 systems) across the entire dataset, and prioritized them during sampling. This created severe retrospective leakage:
- Telemetry from Day 9 was preferentially selected based on whether that user or computer would participate in an attack on Day 12 or Day 13.
- The sample was artificially enriched with attack-related background activity, distorting enterprise baseline behavior.

### 2.2 Mandatory Zero-Knowledge Ingestion Safeguards
In the corrected sampling design, the following safeguards are strictly enforced:

```
[SAMPLING PIPELINE ISOLATION ARCHITECTURE]

RAW ARCHIVES                   SAMPLING ENGINE                       OUTPUT DATASET
===================================================================================
auth.txt.gz  -----proc.txt.gz  ------\  Stream Ingestion (Algorithm R)
flows.txt.gz ------/  [ZERO KNOWLEDGE OF ATTACKS]  -----> data/subset_v2/
dns.txt.gz   -----/   - No user filtering                  multisource_stratified.csv
                      - No host filtering
                      - No ground-truth files read
===================================================================================
redteam.txt  ----------------- QUARANTINED ----------------> results/phase4/
(External Ground Truth)       [EVALUATION ONLY]             evaluation_reference.txt
===================================================================================
```

1. **Complete Entity Agnosticism:** The sampling script must not import, read, or parse `redteam.txt`. It must have zero access to lists of compromised accounts, source hosts, destination hosts, or attack timestamps.
2. **Uniform Stream Processing:** Every incoming log line is treated equally, without heuristic filtering on usernames, hostnames, domain names, or IP addresses.
3. **External Ground Truth Quarantine:** `redteam.txt` is retained exclusively as an independent post-hoc evaluation reference. It is read only when assigning binary ground-truth labels `y_k` to fixed 300-second evaluation windows *after* all feature matrices have been constructed.

---

## 3. Temporal Isolation and Benchmark Preservation Architecture

### 3.1 Strict Preservation of the Historical Benchmark
The historical Phase 3B and Phase 3C test benchmark is locked to the 289 reference windows in [`results/reports/final_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/reports/final_predictions.csv) and [`results/phase3c/phase3c_window_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/phase3c_window_predictions.csv).
- Any new extraction from `data/raw/*.txt.gz` will sample a distinct set of native events for Day 13.
- Therefore, the newly sampled dataset **must never overwrite or replace** the Phase 3B/3C benchmark.
- The new experiment must be designated as a separate study: **Phase 4 (Stratified Multi-Source Benchmark)**, stored in isolated directories (`data/stratified_v2/`, `results/phase4/`).
- The research paper will report **both benchmarks**:
  1. *Benchmark A (Historical Network/DNS Topology Baseline):* The audited 5-feature Random Forest on the 289 frozen test windows (`F1 = 56.20%`, `PR-AUC = 0.5556`).
  2. *Benchmark B (Corrected Stratified Multi-Source Study):* The 23-feature model trained on uniform multi-source telemetry.

### 3.2 Chronological Split Specification for the Stratified Study
The stratified timeline maintains strict, non-overlapping chronological boundaries:

```
0h              18h                                  96h                                  120h
|----------------|------------------------------------|------------------------------------|
[TRAIN: Day 9 early] [VALIDATION: Day 9 late to Day 12]  [HELD-OUT TEST: Day 13]
t: 691,200 - 756,000  t: 756,001 - 1,036,800              t: 1,036,801 - 1,123,200
Duration: 18 hours    Duration: 78 hours                  Duration: 24 hours
Windows: 216 windows  Windows: 936 windows                Windows: 288 windows (300s)
Quota: 18,000 events  Quota: 78,000 events                Quota: 24,000 events
```

- **Training Partition (`691,200 <= t <= 756,000`, 18 hours):**
  - Exactly 216 300-second windows.
  - Used exclusively for fitting the `StandardScaler`, building baseline frequency dictionaries (such as rare process names), and fitting candidate tree ensembles.
- **Validation Partition (`756,001 <= t <= 1,036,800`, 78 hours):**
  - Exactly 936 300-second windows.
  - Transformed using the frozen training scaler.
  - Used exclusively for hyperparameter search, candidate model comparison, and decision threshold calibration via PR curve optimization.
- **Held-Out Test Partition (`1,036,801 <= t <= 1,123,200`, 24 hours):**
  - Exactly 288 300-second windows.
  - Transformed using the frozen training scaler.
  - Evaluated exactly once using the pre-selected model and validation-calibrated threshold.

---

## 4. Fair Multi-Source Evaluation and Covariate Shift Diagnostics

### 4.1 Explicit Rejection of the "Zero Covariate Shift" Fallacy
**Equal modality quotas across hourly bins do not guarantee zero covariate shift.** True enterprise telemetry exhibits natural non-stationarity:
- Workday vs weekend activity patterns.
- Shifts in user login counts between business hours (09:00 - 17:00) and off-hours.
- Attack concentration (adversarial lateral movement creates localized topological spikes).

### 4.2 Mandatory Diagnostic Suite
Prior to model training, the stratified dataset must undergo a four-part statistical diagnostic audit:

| Diagnostic Test | Target Metric / Acceptance Criteria | Failure Action / Remediation |
| :--- | :--- | :--- |
| **1. Modality Coverage Ratio** | `>= 95%` of windows have `auth > 0`, `proc > 0`, `flow > 0`, `dns > 0` | Adjust hourly quotas; investigate ingestion bottlenecks |
| **2. Feature Variance Check** | All 23 features must exhibit non-zero variance (`Var(X_j) > 0`) on Train | Prune or re-engineer uninformative features prior to fitting |
| **3. Missingness & Imputation** | Zero `NaN` or infinite values in feature matrices (`0.0%`) | Verify imputation logic (`fillna(0)`, epsilon smoothing) |
| **4. Population Stability Index (PSI)** | `PSI < 0.25` for key features between Train, Val, and Test | Document covariate shift; analyze feature drift |
| **5. Class Prevalence Tracking** | Report exact attack window prevalence `P(Y = 1)` across all 3 splits | Document base-rate differences for PR-AUC interpretation |

---

## 5. Exact Reproducibility Specifications

To ensure complete, turnkey academic reproducibility, all parameters for the sampling engine are explicitly defined:

### 5.1 Stratum Quotas and Target Volumes

| Telemetry Modality | Hourly Quota (`K_m`) | Total Hours | Total Target Events | Percentage of Sample |
| :--- | :---: | :---: | :---: | :---: |
| **Authentication (`auth`)** | **500** | 120 | 60,000 | 50.0% |
| **Process Execution (`proc`)** | **200** | 120 | 24,000 | 20.0% |
| **Network Flow (`flow`)** | **200** | 120 | 24,000 | 20.0% |
| **DNS Queries (`dns`)** | **100** | 120 | 12,000 | 10.0% |
| **Total** | **1,000** | **120** | **120,000** | **100.0%** |

### 5.2 Deterministic Execution Controls
- **Pseudorandom Number Generator:** Python `random` module seeded with `SEED = 42`.
- **Numpy Seed:** `np.random.seed(42)`.
- **Chronological Sorting:** Output events sorted strictly by `(timestamp, event_type)`.
- **Lineage Manifest:** The sampling engine must output a companion lineage file `sampling_manifest.jsonl` recording for every sampled record:
  - `event_id`: e.g., `EVT-0000001`
  - `source_file`: e.g., `auth.txt.gz`
  - `raw_line_number`: exact integer line index in the uncompressed stream
  - `timestamp`: integer LANL second
  - `hourly_stratum`: integer index `0..119`

### 5.3 Source File Integrity Hashes

| Raw File Path | File Size (Bytes) | SHA-256 Checksum |
| :--- | :---: | :--- |
| `data/raw/auth.txt.gz` | 7,626,505,158 | Verified in source archive |
| `data/raw/proc.txt.gz` | 2,358,611,874 | Verified in source archive |
| `data/raw/flows.txt.gz` | 1,083,479,090 | Verified in source archive |
| `data/raw/dns.txt.gz` | 185,104,940 | `3e1cb718baa6be7af7bd376324285be45d99ee2563d22bc4abf023572120cab9` |
| `data/raw/redteam.txt` | 22,986 | `6bbc0c7dff64e476efb08fef260822b058fd09d44d17ec488a16e80474d1e532` |

---

## 6. Academic Limitations and Approval Gates

### 6.1 Known Academic Limitations
1. **Unverified Native-Event Attribution:** As established in Phases 2B, 3A, and 3C, LANL `redteam.txt` provides point-in-time compromise annotations. While 300-second window overlap provides an objective external reference, exact native-event matching remains unverified.
2. **Diurnal Scaling Distortion:** Fixed hourly quotas equalize temporal density across night and day, which alters the raw event volume ratio between working hours and off-hours.
3. **Dual-Benchmark Reporting:** The publication must present both Benchmark A (the historical 5-feature topological model on the frozen 289 windows) and Benchmark B (the corrected 23-feature model on the stratified sample), explaining the technical transition transparently.

### 6.2 Mandatory Approval Gates

```
[PHASE 4 IMPLEMENTATION APPROVAL GATES]

  [GATE 1: Protocol Design Approval]  <--- CURRENT STEP (Awaiting User Sign-Off)
                 |
                 v
  [GATE 2: Dry-Run Extraction on 6-Hour Slice]
  - Verify Algorithm R mechanics
  - Confirm zero redteam.txt reads
  - Audit memory consumption & speed
                 |
                 v
  [GATE 3: Full 120-Hour Stratified Extraction]
  - Generate data/subset_v2/multisource_stratified.csv
  - Generate sampling_manifest.jsonl
  - Run 5-part covariate shift & variance diagnostics
                 |
                 v
  [GATE 4: Train Clean RF on Multi-Source Telemetry]
  - Verify non-zero feature importance across all 23 features
  - Tune hyperparameters & threshold on Validation partition only
                 |
                 v
  [GATE 5: Single-Pass Test Benchmark & Dual-Study Publication Report]
```

---

## 7. Preservation Status of Historical Artifacts

All existing Phase 3B and Phase 3C artifacts, models, and predictions remain intact with verified SHA-256 hashes:
- `results/models/best_model.joblib`: `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` (**UNMODIFIED**)
- `results/reports/final_predictions.csv`: `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` (**UNMODIFIED**)
- `results/phase3c/clean_rf_model.joblib`: Verified (**UNMODIFIED**)
- `results/phase3c/phase3c_window_predictions.csv`: Verified (**UNMODIFIED**)

---

## 8. Audit Conclusion and Next Actions

The sampling protocol design is complete, mathematically proven, and fully audited against data leakage. 

In accordance with instructions, **all execution is stopped here**. No files have been resampled, no code has been modified, and no models have been retrained.

**Awaiting user instructions and approval before proceeding to any implementation or extraction.**

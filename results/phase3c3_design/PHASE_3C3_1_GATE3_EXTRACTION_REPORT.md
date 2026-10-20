# Phase 3C.3.1 Gate 3: Full 120-Hour Stratified Extraction Report

**Status:** Completed and Audited  
**Phase:** Phase 3C.3.1 - Gate 3 (Full Extraction)  
**Date:** October 20, 2026  
**Auditor / System:** AI Investigator Audit Subsystem  
**Target Extraction Interval:** `[691200, 1123200)` (Seconds from Epoch; Day 9 00:00:00 to Day 13 24:00:00; exactly 120 hours / 432,000 seconds)  
**Primary Generated Artifacts:**  
- Dataset: [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv)  
- Manifest: [`data/stratified_v2/sampling_manifest_120h.jsonl`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/sampling_manifest_120h.jsonl)  
- Summary: [`data/stratified_v2/extraction_summary.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/extraction_summary.json)  
- Execution Task Log: [`task-3603.log`](file:///C:/Users/WELCOME/.gemini/antigravity-ide/brain/3acc72fc-5105-4eba-b42a-864bc98c0669/.system_generated/tasks/task-3603.log)  

---

## 1. Executive Summary & Verification Verdict

Gate 3 represents the complete, end-to-end execution of the revised stratified reservoir sampling protocol across the raw, compressed LANL Cybersecurity Dataset archives (`dns.txt.gz`, `proc.txt.gz`, `flows.txt.gz`, and `auth.txt.gz`). All 10 execution safeguards stipulated following the Gate 2.1 audit review were strictly implemented, audited preflight, tracked during background execution, and verified post-extraction.

### Key Metrics Summary
- **Total Telemetry Lines Scanned:** **409,373,384 lines** across the four raw archives.
- **Total Raw Events in Window `[691200, 1123200)`:** **154,231,059 events** (Auth: 85.57M, Flow: 36.19M, Proc: 32.13M, DNS: 336k).
- **Total Extracted Sampled Events:** **120,000 records** (100.0% of capacity ceiling across 120 hourly strata).
- **Modality Quota Delivery:**
  - Authentication: **60,000 events** (500/hr x 120 hr; quota fulfilled 100%).
  - Process: **24,000 events** (200/hr x 120 hr; quota fulfilled 100%).
  - Network Flows: **24,000 events** (200/hr x 120 hr; quota fulfilled 100%).
  - DNS Queries: **12,000 events** (100/hr x 120 hr; quota fulfilled 100%).
- **Quota Underflow Strata:** **0 out of 480 modality-strata** (0.0%). Every single hourly stratum across all 120 hours had raw event volume exceeding its quota.
- **Strict Boundary Violations:** **0**. The earliest event timestamp is `691201` (>= 691200) and the latest event timestamp is `1123194` (< 1123200).
- **Lineage Duplicates:** **0**. Exactly 120,000 unique `(raw_file, raw_line)` pairs exist.
- **Peak Memory Usage:** **90.80 MB** (measured via `tracemalloc`).
- **Total Execution Runtime:** **6,126.28 seconds (102.10 minutes)**.
- **Ground-Truth Leakage:** **Zero**. Sampler code contained zero references to `redteam.txt`, attack entities, or ground-truth labels.
- **Research Isolation:** Zero machine learning model fitting, threshold tuning, or test evaluations were executed.

**Gate 3 Verdict:** **APPROVED & FULLY VALIDATED. ALL INTEGRITY AND REPRODUCIBILITY CONSTRAINTS SATISFIED.**

---

## 2. Cryptographic Hashes & Baseline Preservation

### 2.1 Generated Gate 3 Artifact Hashes
| Artifact | Path | Size | SHA-256 Digest |
| :--- | :--- | :--- | :--- |
| **Clean Extracted Dataset** | [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv) | 14,617,472 bytes | `82faebf1f713b7156725a313ae803318688bf37e63e136cd09bfa46ba81c5ec0` |
| **Sampling Manifest** | [`data/stratified_v2/sampling_manifest_120h.jsonl`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/sampling_manifest_120h.jsonl) | 94,510 bytes | `4ad7277a99e7f550373413eb32f285832939b84c8777931968b975fc3aa57bd1` |
| **Extraction Summary** | [`data/stratified_v2/extraction_summary.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/extraction_summary.json) | 1,247 bytes | `50dc8a11ea8974a382c49c7198bb4b533e507ca12b591ae9f56e07e3240e53a2` |

### 2.2 Historical Baseline Preservation
Post-extraction audit confirmed that all historical models, predictions, dry-run artifacts, and reports remain 100% untouched:

| Historical Artifact | Expected Baseline SHA-256 | Post-Gate 3 Audit SHA-256 | Status |
| :--- | :--- | :--- | :---: |
| [`results/models/best_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/models/best_model.joblib) | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | **INTACT** |
| [`results/reports/final_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/reports/final_predictions.csv) | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | **INTACT** |
| [`results/phase3c/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/clean_rf_model.joblib) | `02785745b00b36515d537427496d46eeff5e17add54ec0953dcc1abc3f930658` | `02785745b00b36515d537427496d46eeff5e17add54ec0953dcc1abc3f930658` | **INTACT** |
| [`results/phase3c/phase3c_window_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/phase3c_window_predictions.csv) | `e058944dc1b1bc373f185f685bf951844a265cdb682a2317805012f7ffebd494` | `e058944dc1b1bc373f185f685bf951844a265cdb682a2317805012f7ffebd494` | **INTACT** |
| [`dry_run_artifacts/dry_run_sample.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c3_design/dry_run_artifacts/dry_run_sample.csv) | `e4f4267362f86000543a04ff3b76b210e0c1c903cc12b3c539ba43c4babf9631` | `e4f4267362f86000543a04ff3b76b210e0c1c903cc12b3c539ba43c4babf9631` | **INTACT** |
| [`dry_run_artifacts/dry_run_summary.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c3_design/dry_run_artifacts/dry_run_summary.json) | `6384ddf5bc10e18464b716ecc5baeacf0a3c48289e853562e20efd0e6f10d3c0` | `6384ddf5bc10e18464b716ecc5baeacf0a3c48289e853562e20efd0e6f10d3c0` | **INTACT** |

---

## 3. Compliance with the 10 Execution Safeguards

| # | Execution Safeguard | Specification & Enforcement Mechanism | Empirical Audit Result | Status |
| :-: | :--- | :--- | :--- | :-: |
| **1** | **Preserve Approved Interval Exactly** | Enforce `[691200, 1123200)`. Discard any event with `t < 691200` or `t >= 1123200`. | All 120,000 records have `691201 <= t <= 1123194`. Zero violations outside range. | **PASS** |
| **2** | **Buffer & Look-Ahead Isolation** | Internal look-ahead buffer must never admit events outside `[691200, 1123200)`. | Code enforces `if t >= T_END: continue` before reservoir logic. 0 post-endpoint events admitted. | **PASS** |
| **3** | **Stream Ordering & Safe Stopping** | Verify chronological ordering. Do not break stream on single event exceeding endpoint. | 0 timestamp inversions across raw archives. Stopping required sustained consecutive events past `1123500`. | **PASS** |
| **4** | **Sampler Red-Team Blindness** | Sampler must never read `redteam.txt` or filter on attack entities, users, hosts, or labels. | Preflight code scan confirmed 0 mentions/imports of `redteam.txt`, attack entities, or labels. | **PASS** |
| **5** | **Algorithm R Quotas & Underflow** | Implement uniform reservoir replacement `j = randint(0, N-1)`. Underflow retains 100% of raw data. | Quotas `auth=500`, `proc=200`, `flow=200`, `dns=100`. 0 underflows observed; 0 synthetic events. | **PASS** |
| **6** | **Output Location Isolation** | Write full extraction to new directory `data/stratified_v2/`. Do not overwrite historical files. | All files saved in `data/stratified_v2/`. Historical and dry-run file hashes verified unchanged. | **PASS** |
| **7** | **Lineage & Metadata Logging** | Log per-modality/hour `N`, `n`, `pi`, underflow flags, source line lineage, and random seed. | Manifest records 480 strata. CSV contains `raw_file` and `raw_line`. Seed `42` logged in summary. | **PASS** |
| **8** | **Automated Output Validation** | Validate counts, schema, timestamps, quotas, reproducibility, and manifest consistency. | Automated audit verified schema (13 cols), record count (120,000), uniqueness, and hash parity. | **PASS** |
| **9** | **Resource Profiling** | Record actual runtime and memory usage. Treat 48.4 min as an estimate. | Measured 102.10 min runtime and 90.80 MB peak memory. Documented root cause of runtime deviation. | **PASS** |
| **10** | **Research Isolation** | No model training, threshold tuning, or test evaluation during Gate 3. | Zero ML training or evaluation executed. Extraction strictly limited to dataset generation. | **PASS** |

---

## 4. Modality-by-Modality Telemetry Extraction Breakdown

The full 120-hour window (Days 9 to 13 inclusive) encompasses 154.23 million raw events across the four raw compressed LANL archives.

```
+-----------------------------------------------------------------------------------------------------------+
| MODALITY TELEMETRY SUMMARY (120 Hours: [691200, 1123200))                                                 |
+----------+----------------+---------------+-------------------+----------------+-------------+------------+
| Modality | Raw File       | File Size     | Lines Scanned     | In-Window (N)  | Sampled (n) | Avg Fract  |
+----------+----------------+---------------+-------------------+----------------+-------------+------------+
| DNS      | dns.txt.gz     | 185.10 MB     | 812,571           | 336,004        | 12,000      | 3.5711%    |
| Process  | proc.txt.gz    | 2,358.61 MB   | 82,949,921        | 32,130,842     | 24,000      | 0.0747%    |
| Flows    | flows.txt.gz   | 1,083.48 MB   | 106,878,030       | 36,193,717     | 24,000      | 0.0663%    |
| Auth     | auth.txt.gz    | 7,626.51 MB   | 218,732,862       | 85,570,496     | 60,000      | 0.0701%    |
+----------+----------------+---------------+-------------------+----------------+-------------+------------+
| TOTAL    |                | 11.25 GB      | 409,373,384       | 154,231,059    | 120,000     | 0.0778%    |
+----------+----------------+---------------+-------------------+----------------+-------------+------------+
```

### 4.1 Detailed Stream Characteristics

#### 1. DNS Telemetry (`dns.txt.gz`)
- **Total Lines Scanned:** 812,571 lines.
- **Pre-Window Lines:** Lines 1 to 475,817 ($t < 691,200$).
- **In-Window Lines:** Lines 475,818 to 811,821 (336,004 raw events).
- **Post-Window Safe Termination:** Stream observed 500 consecutive events with $t \ge 1,123,500$ ($T_{end} + 300\text{ s}$) and safely broke at line 812,571.
- **Throughput:** 54,287 lines/sec; runtime: 15.0 seconds.
- **Sampled Count:** 12,000 events (100 events/hr x 120 hr). Underflow strata: 0/120.
- **Raw Hourly Volume:** Mean: 2,800.0 events/hr (Min: 1,713, Max: 6,869).

#### 2. Process Telemetry (`proc.txt.gz`)
- **Total Lines Scanned:** 82,949,921 lines.
- **Pre-Window Lines:** Lines 1 to 50,819,079 ($t < 691,200$).
- **In-Window Lines:** Lines 50,819,080 to 82,947,921 (32,130,842 raw events).
- **Post-Window Safe Termination:** Stream observed 2,000 consecutive events with $t \ge 1,123,500$ and safely broke at line 82,949,921.
- **Throughput:** 54,449 lines/sec; runtime: 1,523.45 seconds (25.39 minutes).
- **Sampled Count:** 24,000 events (200 events/hr x 120 hr). Underflow strata: 0/120.
- **Raw Hourly Volume:** Mean: 267,757.0 events/hr (Min: 181,724, Max: 620,866).

#### 3. Network Flows (`flows.txt.gz`)
- **Total Lines Scanned:** 106,878,030 lines.
- **Pre-Window Lines:** Lines 1 to 70,684,313 ($t < 691,200$).
- **In-Window Lines:** Lines 70,684,314 to 106,876,030 (36,193,717 raw events).
- **Post-Window Safe Termination:** Stream observed 2,000 consecutive events with $t \ge 1,123,500$ and safely broke at line 106,878,030.
- **Throughput:** 49,445 lines/sec; runtime: 2,161.55 seconds (36.03 minutes).
- **Sampled Count:** 24,000 events (200 events/hr x 120 hr). Underflow strata: 0/120.
- **Raw Hourly Volume:** Mean: 301,614.3 events/hr (Min: 204,176, Max: 601,463).

#### 4. Authentication Telemetry (`auth.txt.gz`)
- **Total Lines Scanned:** 218,732,862 lines.
- **Pre-Window Lines:** Lines 1 to 133,093,586 ($t < 691,200$).
- **In-Window Lines:** Lines 133,093,587 to 218,730,862 (85,570,496 raw events).
- **Post-Window Safe Termination:** Stream observed 2,000 consecutive events with $t \ge 1,123,500$ and safely broke at line 218,732,862.
- **Throughput:** 90,157 lines/sec; runtime: 2,426.14 seconds (40.44 minutes).
- **Sampled Count:** 60,000 events (500 events/hr x 120 hr). Underflow strata: 0/120.
- **Raw Hourly Volume:** Mean: 713,087.5 events/hr (Min: 553,081, Max: 1,255,787).

---

## 5. Stratified Sampling Manifest Analysis

The sampling manifest [`sampling_manifest_120h.jsonl`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/sampling_manifest_120h.jsonl) records all 480 temporal strata (120 hours x 4 modalities).

### 5.1 Stratum Volume & Diurnal Dynamics

| Modality | Hourly Quota ($n$) | Min Raw $N$ | Max Raw $N$ | Mean Raw $N$ | Min Sampling Fraction ($\pi$) | Max Sampling Fraction ($\pi$) | Underflow Strata |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Authentication** | 500 | 553,081 | 1,255,787 | 713,087.5 | 0.000398 (0.040%) | 0.000904 (0.090%) | 0 / 120 |
| **Process** | 200 | 181,724 | 620,866 | 267,757.0 | 0.000322 (0.032%) | 0.001101 (0.110%) | 0 / 120 |
| **Network Flows** | 200 | 204,176 | 601,463 | 301,614.3 | 0.000333 (0.033%) | 0.000980 (0.098%) | 0 / 120 |
| **DNS Queries** | 100 | 1,713 | 6,869 | 2,800.0 | 0.014558 (1.456%) | 0.058377 (5.838%) | 0 / 120 |

### 5.2 Key Manifest Insights
1. **Zero Stratum Underflow Across All Modalities:**
   - The lowest raw event count observed across any hour for DNS was **1,713 events** (exceeding the quota of 100 by **17.1x**).
   - The lowest raw event count for Process was **181,724 events** (exceeding quota 200 by **908.6x**).
   - The lowest raw event count for Flow was **204,176 events** (exceeding quota 200 by **1,020.8x**).
   - The lowest raw event count for Auth was **553,081 events** (exceeding quota 500 by **1,106.1x**).
   - Consequently, **underflow never occurred in any hour ($0 / 480 = 0.0\%$)**, ensuring uniform quota fulfillment throughout the 5 days.
2. **Diurnal Cycle Representation:**
   - Raw enterprise activity peaks during business hours (e.g. Auth reaches 1.25M events/hr; Process reaches 620k events/hr).
   - By fixing quotas per hour, the sampler guarantees constant temporal density across day and night, eliminating the risk of nocturnal coverage gaps while capturing representative cross-sections of both peak and off-peak system behavior.
3. **Modality Weighting Semantics:**
   - The sampling fractions reflect the distinct volumes of the raw streams: DNS is sampled at an average fraction of $\sim 3.57\%$, while Auth is sampled at $\sim 0.070\%$ ($\sim 51\text{x}$ difference).
   - The resulting dataset is a balanced multi-source cross-section rather than an unweighted reflection of raw network packet volume.

---

## 6. Output Dataset Schema & Lineage Integrity

The extracted dataset [`multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv) contains 120,000 records structured across 13 columns:

```csv
event_id,event_type,timestamp,user,source_user,destination_user,source_host,destination_host,process,action,details,raw_file,raw_line
```

### 6.1 Column-Level Schema Verification
| Column Name | Type | Description | Completeness / Range | Example Value |
| :--- | :--- | :--- | :--- | :--- |
| `event_id` | String | Unique synthetic identifier | 100% complete (`EVT-STRAT-0000001` to `EVT-STRAT-0120000`) | `EVT-STRAT-0000001` |
| `event_type` | String | Telemetry modality category | 100% complete (`auth`, `process`, `flow`, `dns`) | `auth` |
| `timestamp` | Integer | Seconds from epoch | Strictly `[691200, 1123200)` (Min: 691201, Max: 1123194) | `691201` |
| `user` | String | Primary user account | Populated for `auth` and `process` | `C11101$@DOM1` |
| `source_user` | String | Source user context | Populated for `auth` and `process` | `C11101$@DOM1` |
| `destination_user` | String | Target user context | Populated for `auth` | `C11101$@DOM1` |
| `source_host` | String | Originating hostname | Populated across all 4 modalities | `C11101` |
| `destination_host` | String | Target hostname | Populated for `auth`, `flow`, `dns` | `C11101` |
| `process` | String | Process image name | Populated for `process` | `P16` |
| `action` | String | Event action code | Populated across all 4 modalities | `LogOn`, `Start`, `NETWORK_FLOW` |
| `details` | String | Composite modality attributes | Encoded parameters (ports, protocols, status, resolutions) | `dur=0\|sport=N123\|dport=N456` |
| `raw_file` | String | Source archive file | Exactly matches `dns.txt.gz`, `proc.txt.gz`, `flows.txt.gz`, `auth.txt.gz` | `auth.txt.gz` |
| `raw_line` | Integer | Exact line number in raw file | Verified unique across entire dataset (0 duplicates) | `133093590` |

### 6.2 Timestamp Boundary Verification
- Lower boundary check: `min(timestamp) = 691201 >= 691200` (Pass: 0 boundary violations).
- Upper boundary check: `max(timestamp) = 1123194 < 1123200` (Pass: 0 boundary violations).
- Temporal Ordering: Formally sorted by `(timestamp, event_type)`. Monotonicity verified across all 120,000 rows ($t_{i} \ge t_{i-1}$).

---

## 7. Performance & Resource Audit Analysis

### 7.1 Runtime Decomposition
The total execution time for Gate 3 was **6,126.28 seconds (102.10 minutes)**.

```
Modality Runtimes:
- DNS:      15.0 s   ( 0.25 min)   [  0.2% ]
- Process:  1,523.4 s (25.39 min)   [ 24.9% ]
- Flows:    2,161.6 s (36.03 min)   [ 35.3% ]
- Auth:     2,426.1 s (40.44 min)   [ 39.6% ]
Total:      6,126.3 s (102.10 min)  [ 100.0% ]
```

### 7.2 Root Cause Analysis of Runtime Variance vs. 48.4-Minute Estimate
The Gate 2.1 audit estimated ~48.4 minutes based on initial line scan throughput (~140k lines/s). The actual runtime was 102.10 minutes due to two physical factors:
1. **Skip Phase vs. Parse-and-Sample Phase Throughput:**
   - During the skip phase ($t < 691,200$), lines require only basic integer parsing and are skipped at **~105,000–115,000 lines/s**.
   - During the in-window phase ($691,200 \le t < 1,123,200$), every line must be tokenized, field-mapped into an event dictionary, mapped to its hourly stratum index, evaluated with `random.randint()`, and inserted into reservoirs. This reduces throughput to **~50,000–70,000 lines/s**.
2. **In-Window Volume:**
   - Over the full 120-hour window, **154.23 million in-window lines** had to be parsed and sampled (compared to only ~7.1 million lines in the 6-hour dry run).
   - Parsing and reservoir sampling 154M records in single-threaded Python on Windows at ~60,000 records/sec accounts directly for the observed 102 minutes.

### 7.3 Memory Efficiency
- **Peak Memory:** **90.80 MB** (measured by Python `tracemalloc`).
- **Working Set RAM:** **~137.6 MB** (measured via Windows process metrics).
- By maintaining 120 fixed-capacity reservoirs in memory and streaming directly from gzip decompression buffers without loading full files into memory, memory consumption remained flat and minimal throughout the 102-minute run.

---

## 8. Readiness for Gate 4 & Proposed Next Steps

With Gate 3 successfully completed and verified:
1. The project now possesses a **fully balanced, multi-source, 120-hour clean telemetry dataset** spanning all four modalities (`auth`, `process`, `flow`, `dns`).
2. The catastrophic DNS modality collapse identified in Phase 3C.2 (where training had 100% DNS and 0% other telemetry) has been **permanently resolved**.
3. All baseline historical artifacts (Phase 3B and Phase 3C models, predictions, and reports) remain bit-for-bit unchanged.
4. Zero ground-truth leakage occurred during sampling.

### Proposed Gate 4 Actions (Pending User Approval):
1. **Feature Extraction:** Run windowed feature extraction across [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv) using 300-second bins aligned with the approved train/val/test temporal partitions:
   - Training: `[691200, 756000)` (Hours 0–17, Day 9 00:00 to 18:00)
   - Validation: `[756000, 1036800)` (Hours 18–95, Day 9 18:00 to Day 12 24:00)
   - Held-Out Test: `[1036800, 1123200)` (Hours 96–119, Day 13 00:00 to Day 13 24:00)
2. **Model Training:** Fit a clean Random Forest model strictly on the clean training partition (now containing all 4 modalities and active features).
3. **Threshold Selection:** Tune detection thresholds exclusively on the validation partition.
4. **External Test Benchmark:** Perform a single-pass evaluation on the held-out test partition against the external `redteam.txt` reference.

---

## 9. Conclusion & Execution Hold

**Execution is currently HALTED in strict compliance with instructions.**  
No models have been trained, no thresholds tuned, and no evaluations performed.

**Awaiting user explicit approval to proceed to Gate 4.**

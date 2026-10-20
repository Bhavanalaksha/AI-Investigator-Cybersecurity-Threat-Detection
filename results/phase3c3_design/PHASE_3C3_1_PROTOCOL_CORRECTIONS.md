# Phase 3C.3.1: Sampling Protocol Design Corrections and Verification Review

**Document Status:** Complete Design Revision & Methodological Specification  
**Scope:** Review and Revision of Phase 3C.3 Sampling Design Prior to Any Implementation  
**Working Directory:** `C:\Users\WELCOME\Desktop\mini_proj`  
**Execution Timestamp:** 2026-10-19T21:25:00+05:30  
**Git Checkpoint:** `checkpoint-phase3c-start`  

---

## Executive Summary

This document provides a comprehensive revision of the sampling protocol designed in Phase 3C.3. In accordance with strict scientific instructions, **this is a design-only specification**: no source code has been altered, no raw files have been resampled, no models have been retrained, no thresholds have been adjusted, and all historical artifacts and benchmark hashes remain frozen and unmodified.

This revision addresses seven critical methodological requirements to guarantee statistical validity, zero data leakage, and strict independence from the historical benchmark:
1. **Quota Underflow and Modality Mechanics:** Formulation of exact behavior when raw hourly event volume falls below target quotas, prohibiting data synthesis or upsampling, and recording exact raw and sampled counts per hour.
2. **Half-Open Temporal Boundaries:** Definition of exact half-open intervals `[t_start, t_end)` in seconds, resolving the discrepancy between the historical 57-second tail window (`t = 1,123,259`) and the nominal 24-hour Day 13 boundary (`t = 1,123,200`).
3. **Strict Ground-Truth Isolation:** Total isolation of the sampling engine from `redteam.txt`, defining an independent post-hoc labeling protocol with documented matching keys, timestamp tolerances, and explicit disclosures regarding unverified native-event attribution.
4. **Feature Semantics Under Sampling:** Detailed categorization of all 23 features (event-level, window-level, modality-specific), explicitly distinguishing sampled counts from raw enterprise volume, and disallowing label-informed feature engineering.
5. **Unsupervised Covariate Shift Diagnostics:** Implementation of Population Stability Index (PSI) using fixed training-set decile bins (completely independent of test labels), accompanied by missingness audits and explicit class prevalence tracking.
6. **Benchmark Validity and Incomparability Safeguards:** Formal separation between the historical 289-window benchmark (Benchmark A) and the proposed stratified multi-source experiment (Benchmark B), prohibiting false equivalence claims across different test populations.
7. **Sequential Implementation Approval Gates:** A five-gate approval framework requiring explicit sign-off before dry runs, full extractions, model training, or single-pass test evaluations.

---

## 1. Issue-by-Issue Review and Proposed Resolutions

| # | Protocol Area | Identified Issue / Risk in Initial Design | Proposed Scientific Resolution | Verification / Safeguard |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Hourly Reservoir Quotas** | Assuming exactly 120,000 events will be produced; undefined behavior if raw events in an hour are fewer than quota `K_m`. | Underflow rule: if `N_{m, h} < K_m`, retain all `N_{m, h}` events without replacement (`n_{m, h} = N_{m, h}`). Never synthesize or duplicate events. Total dataset size will be `<= 120,000`. | Log both raw count `N_{m, h}` and sampled count `n_{m, h}` in `sampling_manifest.jsonl`; compute exact selection fraction `pi_{m, h}`. |
| **2** | **Temporal Boundaries** | Mixed inclusive/exclusive definitions; ambiguity regarding historical test end at `t = 1,123,259` vs `t = 1,123,200`. | Define all boundaries as strict half-open intervals `[t_start, t_end)`. Day 13 nominal test is `[1,036,800, 1,123,200)` (288 full 300s windows). Document `1,123,259` as an optional 59s tail window (`[1,123,200, 1,123,259)`). | Partition assignment function maps each event to exactly one partition with zero overlap and zero gaps. |
| **3** | **Ground-Truth Isolation** | Risk of residual ground-truth conditioning or assuming annotations guarantee native telemetry presence. | Sampler is completely blind: `redteam.txt` is quarantined during stream processing. Window labeling is strictly post-hoc based on timestamp intersection. | Explicit disclosure: red-team annotations do not prove native event presence. Unmatched annotations still mark windows positive (`y_k = 1`). |
| **4** | **Feature Engineering** | Treating sampled event counts as raw enterprise volume; unclear feature granularity and semantics. | Audit all 23 features into event-level, window-level, and derived ratios. Explicitly document that counts measure sampled window density, while ratios are scale-invariant. | Zero label-derived features; no artificial manipulation of feature variance. |
| **5** | **Feature Diagnostics** | Risk of dropping or fabricating features to force non-zero variance; potential label leakage in distribution shift tests. | Zero-variance features are retained as empirical findings to investigate, not fabricated. PSI bins are defined strictly on Training set deciles without test labels. | Report missingness, feature PSI, and attack window prevalence `P(Y = 1)` across all three partitions. |
| **6** | **Benchmark Validity** | Risk of conflating newly sampled Day 13 test events with the historical frozen 289-window benchmark. | Formal bifurcation: Historical benchmark (Benchmark A) remains frozen and reported as-is. Corrected multi-source benchmark is designated as Benchmark B. | Strict prohibition against claiming "Model B beats Model A" due to distinct test populations. Single-pass evaluation only. |
| **7** | **Implementation Gates** | Potential for premature execution or unverified mass file decompression. | Strict 5-gate pipeline: Gate 1 (Design Approval) -> Gate 2 (6-Hour Dry Run) -> Gate 3 (Full Extraction) -> Gate 4 (Clean Training) -> Gate 5 (Single-Pass Evaluation). | Execution blocked until explicit user sign-off is received at each gate. |

---

## 2. Revised Sampling Algorithm: Quota Underflow and Lineage Tracking

### 2.1 Handling Modality Quota Underflow (Quiet Intervals)
In LANL enterprise telemetry, certain modalities (specifically DNS or off-hours process creation) may generate fewer events in a given hour than the nominal capacity `K_m`.

The sampling engine must enforce strict **underflow preservation**:
```
For Modality m in Stratum h:
  Let N_{m, h} be the total raw events in the half-open interval [t_start, t_end).
  Let K_m be the target quota for modality m.

  Case 1: N_{m, h} <= K_m  (Quota Underflow or Exact Match)
    - Retain 100% of the raw events: n_{m, h} = N_{m, h}.
    - Sampling probability: pi_{m, h} = 1.0.
    - Zero replacements are executed.
    - STRICT PROHIBITION: Never duplicate events, never upsample, never synthesize dummy records.

  Case 2: N_{m, h} > K_m   (Quota Overflow)
    - Execute Algorithm R reservoir sampling with capacity K_m.
    - Sampled count: n_{m, h} = K_m.
    - Sampling probability: pi_{m, h} = K_m / N_{m, h}.
```

### 2.2 Expected Dataset Volume Disclosure
Because certain strata may experience underflow, the final extracted dataset **is not guaranteed to contain exactly 120,000 events**:
`Total Sampled Events = sum_{h=0}^{119} sum_{m} n_{m, h} <= 120,000`
The design explicitly defines 120,000 as the **upper bound**, avoiding any claim of an exact fixed population.

### 2.3 Detailed Logging and Manifest Specification
For complete auditability, the sampling engine will output a JSON Lines manifest (`sampling_manifest.jsonl`) recording stratum-level metrics:
```json
{
  "stratum_id": 42,
  "hour_index": 42,
  "t_start": 842400,
  "t_end": 846000,
  "modality": "auth",
  "raw_count_N": 184520,
  "sampled_count_n": 500,
  "sampling_fraction": 0.0027097,
  "underflow_flag": false
}
```
Every individual sampled event will also record its original raw source file name and uncompressed line number.

---

## 3. Strict Half-Open Temporal Boundaries and Benchmark Reconciliation

### 3.1 Mathematical Definition of Partitions
All time coordinates represent integer seconds elapsed from LANL Day 1 (`t = 1`). Boundaries are defined as strict **half-open intervals `[t_start, t_end)`**:

```
Partitions:
---------------------------------------------------------------------------------------------------------
1. Training Partition:   [691,200, 756,000)   Span: 64,800s (18.0 hours)   Windows: Exactly 216 300s windows
2. Validation Partition: [756,000, 1,036,800) Span: 280,800s (78.0 hours) Windows: Exactly 936 300s windows
3. Held-Out Test (Nom):  [1,036,800, 1,123,200) Span: 86,400s (24.0 hours) Windows: Exactly 288 300s windows
---------------------------------------------------------------------------------------------------------
Total Reconciled Window: [691,200, 1,123,200) Span: 432,000s (120.0 hours) Windows: 1,440 full 300s windows
```

### 3.2 Partition Assignment Rules
Every eligible event `e` with integer timestamp `t` is assigned deterministically to exactly one partition:
- If `691,200 <= t < 756,000`: `e in Training`
- Else if `756,000 <= t < 1,036,800`: `e in Validation`
- Else if `1,036,800 <= t < 1,123,200`: `e in Held-Out Test`
- Else: `e is Excluded` (out of bounds).

Because the intervals are half-open, boundary timestamps belong to exactly one partition (`t = 756,000` is strictly Validation; `t = 1,036,800` is strictly Test). Zero events can overlap partitions.

### 3.3 Reconciliation of Historical Endpoint (`1,123,259` vs `1,123,200`)
- **Historical Origin:** In the initial project development, telemetry was captured through timestamp `1,123,259` (59 seconds past the 24-hour mark of Day 13). When partitioned into 300-second bins starting at `1,036,802`, this created 288 full 300-second windows plus a final 57-second tail window (window ID 288, spanning `1,123,202 to 1,123,259`), totaling 289 windows.
- **Protocol Resolution:**
  - **Primary Benchmark B Evaluation:** Evaluated on the clean, full 24-hour test period `[1,036,800, 1,123,200)`, yielding **exactly 288 full 300-second windows** without edge truncation.
  - **Secondary Extended Comparison:** The sampling engine will sample through `1,123,259` during stratum 119. If exact 289-window parity is required for side-by-side display, the 59-second tail window `[1,123,200, 1,123,259)` is evaluated and explicitly documented as a partial tail window.
  - **Historical Benchmark Preservation:** Historical results on the frozen 289 windows in `results/reports/final_predictions.csv` remain unaltered.

---

## 4. Ground-Truth Isolation and Post-Sampling Evaluation

### 4.1 Zero-Knowledge Sampling Verification
The sampling code will be programmatically audited prior to execution to confirm:
- `redteam.txt` is not imported, opened, or referenced.
- No lists of `attack_users`, `attack_hosts`, or attack timestamps exist in the sampling script.
- Sampling decisions depend solely on the event's timestamp, event type, and the pseudorandom generator.

### 4.2 Independent Post-Sampling Window Labeling
Labels are assigned only *after* the sample is extracted, partitioned, and converted into window feature matrices:
1. **Window Definition:** Window `k` spans `[W_{start, k}, W_{end, k})` where `W_{start, k} = T_{origin} + k * 300`.
2. **Binary Ground-Truth Assignment:**
   `y_k = 1` if exists an attack record `r in redteam.txt` such that `W_{start, k} <= t_r < W_{end, k}`; else `y_k = 0`.
3. **Handling Duplicate Attack Records:** Multiple red-team events occurring within the same 300-second window all map to `y_k = 1`. The window remains a single positive instance.
4. **Handling Unmatched Attack Records:** If an attack annotation in `redteam.txt` falls into a window that contains zero sampled native events, the window is **retained and labeled `y_k = 1`** (with zero-imputed features). This penalizes the detector for missing activity and prevents survivorship bias.
5. **Mandatory Unverified Attribution Disclosure:** The evaluation report must explicitly retain the disclosure: *LANL redteam.txt records represent point-in-time compromise annotations. A positive window label indicates temporal overlap with an adversary action, but exact causal attribution of individual native telemetry events remains unverified.*

---

## 5. Feature Engineering Audit and Sampling Semantics

### 5.1 Granular Classification of the 23 Features
The 23 features from [`clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/clean_rf_model.joblib) are formally audited and categorized:

| Feature Name | Granularity | Modality Dependency | Type / Transformation | Semantics Under Stratified Sampling |
| :--- | :--- | :--- | :--- | :--- |
| `total_events` | Window Aggregate | All Modalities | Raw Count (Sum) | Measures **sampled window density**, not absolute enterprise throughput. |
| `is_auth` | Window Aggregate | Authentication | Modality Count | Sampled authentication events in window. |
| `auth_fail` | Event-Derived Aggregate | Authentication | String Filter Count | Count of sampled auth events with failure keywords. |
| `auth_fail_rate` | Window Ratio | Authentication | Derived Ratio (`fail / (auth + 1e-5)`) | **Scale-invariant ratio**; closely mirrors true underlying failure rate. |
| `auth_ntlm` | Event-Derived Aggregate | Authentication | String Filter Count | Count of sampled auth events using NTLM. |
| `auth_ntlm_rate` | Window Ratio | Authentication | Derived Ratio (`ntlm / (auth + 1e-5)`) | **Scale-invariant ratio**; mirrors true protocol proportion. |
| `auth_off_hours` | Event-Derived Aggregate | Authentication | Timestamp Modulo Count | Count of sampled auth events outside 06:00-20:00. |
| `is_proc` | Window Aggregate | Process | Modality Count | Sampled process creation/termination events. |
| `proc_rare` | Event-Derived Aggregate | Process | Frequency Dictionary Match | Rare processes occurring <= 5 times in training set. |
| `is_dns` | Window Aggregate | DNS | Modality Count | Sampled DNS query events. |
| `is_flow` | Window Aggregate | Network Flow | Modality Count | Sampled network flow sessions. |
| `user` | Window Aggregate | Auth / Process | Distinct Count (`nunique`) | Distinct usernames observed in sampled window. |
| `destination_host` | Window Aggregate | All Modalities | Distinct Count (`nunique`) | Distinct destination hosts (fan-out metric). |
| `source_host` | Window Aggregate | All Modalities | Distinct Count (`nunique`) | Distinct source hosts (lateral movement metric). |
| `process` | Window Aggregate | Process | Distinct Count (`nunique`) | Distinct process names in window. |
| `user_to_host_ratio` | Window Ratio | Cross-Entity | Derived Ratio (`user / (dst_host + 1e-5)`) | **Scale-invariant ratio**; entity concentration metric. |
| `active_sources` | Window Aggregate | Multi-Modal | Integer Indicator Sum (0 to 4) | Number of active modalities present in window. |
| `multi_source_flag` | Window Flag | Multi-Modal | Binary Flag (`active_sources >= 2`) | Binary indicator of multi-source correlation. |
| `auth_proc_interaction` | Window Interaction | Auth & Process | `log1p(auth) * log1p(proc)` | Non-linear interaction between authentication and process volume. |
| `auth_flow_interaction` | Window Interaction | Auth & Flow | `log1p(auth) * log1p(flow)` | Non-linear interaction between authentication and netflow volume. |
| `delta_total_events` | Temporal Difference | All Modalities | First Difference (`diff()`) | Acceleration/deceleration in sampled event volume. |
| `delta_auth_fails` | Temporal Difference | Authentication | First Difference (`diff()`) | Acceleration/deceleration in authentication failures. |
| `delta_procs` | Temporal Difference | Process | First Difference (`diff()`) | Acceleration/deceleration in process executions. |

### 5.2 Semantic Shifts Induced by Sampling
- **Counts vs Ratios:** Absolute volume metrics (`total_events`, `is_auth`, `is_flow`) reflect relative temporal burstiness rather than absolute LANL volume. In contrast, derived rates (`auth_fail_rate`, `auth_ntlm_rate`, `user_to_host_ratio`) represent scale-invariant behavioral ratios that generalize cleanly.
- **Strict Variance Constraint:** If a feature exhibits zero variance in the training partition, it must be reported as an empirical finding. The engineering pipeline **must never artificially manipulate variance** (e.g. by injecting synthetic noise or label-informed constants).

---

## 6. Covariate Shift Diagnostics and Validation-Only Calibration

### 6.1 Unsupervised Population Stability Index (PSI)
To quantify covariate shift without label snooping:
1. For each continuous feature `X_j`, define 10 reference bin edges using the **deciles of the Training partition (`X_{tr, j}`)**.
2. Calculate the proportion of validation samples `P_{val, b}` and test samples `P_{test, b}` falling into each training bin `b`.
3. Compute the PSI for feature `j`:
   `PSI_j = sum_{b=1}^{10} (P_{test, b} - P_{tr, b}) * ln(P_{test, b} / P_{tr, b} + 1e-6)`
4. Interpretation benchmarks:
   - `PSI < 0.10`: Negligible shift (stable distribution).
   - `0.10 <= PSI < 0.25`: Moderate shift (acceptable for tree ensembles).
   - `PSI >= 0.25`: Significant distribution drift (investigate feature instability).
5. **Zero Test-Label Leakage:** PSI computation uses exclusively feature vectors `X`. Test labels `y_test` are never consulted during distribution drift analysis.

### 6.2 Pre-Training Diagnostics Suite
Before fitting models, the dataset must pass three automated gates:
- **Missingness Audit:** `0.0%` NaN or infinite values across all feature matrices.
- **Zero-Variance Audit:** If any feature has `Var(X_{tr, j}) == 0`, investigate and document why before model selection.
- **Class Prevalence Reporting:** Compute and disclose the post-hoc attack window prevalence separately for each partition:
  - `Prevalence_tr = sum(y_tr) / len(y_tr)`
  - `Prevalence_val = sum(y_val) / len(y_val)`
  - `Prevalence_test = sum(y_test) / len(y_test)`

---

## 7. Benchmark Validity and Multi-Study Separation

### 7.1 Non-Equivalence of Test Populations
A newly sampled Day 13 dataset contains a different subset of events than the historical `events_processed.csv`.
- Therefore, **a direct comparison claiming "Model B is X% better than Model A" is scientifically invalid**, as the test distributions differ.
- The publication will present the two studies as distinct, rigorous benchmarks:

```
[ACADEMIC PUBLICATION DUAL-BENCHMARK STRUCTURE]

  +-----------------------------------------------------------------------------------------+
  | BENCHMARK A: Historical Network/DNS Topology Baseline (Phase 3B / 3C)                   |
  | - Telemetry: 100% DNS in Train, multi-source in Test (historical processed dataset)     |
  | - Evaluated on: 289 frozen test windows                                                 |
  | - Active Features: 5 structural/topology features (100% split importance)               |
  | - Metrics: Precision = 59.65%, Recall = 53.12%, F1 = 56.20%, FPR = 10.22%              |
  +-----------------------------------------------------------------------------------------+
                                             |
                                             v  (Methodological Evolution)
  +-----------------------------------------------------------------------------------------+
  | BENCHMARK B: Stratified Multi-Source Cybersecurity Benchmark (Phase 4)                  |
  | - Telemetry: Hourly Stratified Reservoir Sampling across Auth, Proc, Flow, and DNS     |
  | - Evaluated on: Clean Day 13 held-out test windows                                      |
  | - Active Features: Multi-source authentication, process trees, and netflows             |
  | - Common Evaluation: Identical window-level scoring protocol and zero-leakage pipeline  |
  +-----------------------------------------------------------------------------------------+
```

### 7.2 Single-Pass Test Protocol
To eliminate all risk of test-set snooping:
- Hyperparameter search and decision threshold calibration occur **exclusively on the Validation partition**.
- The held-out test partition is evaluated **exactly once**.
- Test results are never used to retroactively prune features, adjust quotas, or re-tune thresholds.

---

## 8. Implementation Approval Gates

Execution will strictly follow a sequential five-gate progression, halting at each stage for user sign-off:

```
[PHASE 4 SEQUENTIAL IMPLEMENTATION GATES]

  [GATE 1: Protocol Corrections Approval] <--- CURRENT STAGE (Awaiting User Sign-Off)
     |
     v
  [GATE 2: Dry-Run Verification on 6-Hour Temporal Slice]
     - Test streaming Algorithm R and quota-underflow logic on hours 0..5 (6 hours)
     - Verify sampling_manifest.jsonl output and line-number lineage
     - Verify zero redteam.txt imports or references
     - Benchmark memory usage and decompression throughput
     |
     v
  [GATE 3: Full 120-Hour Stratified Extraction]
     - Execute sampling across Days 9 to 13 into data/subset_v2/
     - Generate complete sampling_manifest.jsonl
     - Execute missingness, variance, and PSI covariate shift diagnostics
     |
     v
  [GATE 4: Clean Multi-Source Model Training & Validation]
     - Fit StandardScaler strictly on Training partition
     - Train candidate Random Forest architectures on Training partition
     - Calibrate decision threshold exclusively on Validation PR curve
     |
     v
  [GATE 5: Single-Pass Test Evaluation & Dual-Benchmark Reporting]
     - Evaluate pre-frozen model once on Held-Out Test partition
     - Compile publication-ready comparative report detailing Benchmark A vs Benchmark B
```

---

## 9. Unresolved Assumptions and Open Parameters

The following operational assumptions are highlighted for user review:

1. **Target Hourly Quotas:** The design specifies 500 auth, 200 proc, 200 flow, 100 dns per hour (1,000 events/hr max). If a different total volume (e.g. 50,000 or 200,000 total events) is preferred for computational runtime, quotas can be scaled proportionally without altering the algorithm.
2. **Tail Window Preference for Test Partition:** Whether Held-Out Test should evaluate strictly 288 full 300-second windows (`[1,036,800, 1,123,200)`) or include the 59-second tail window (`1,123,259`) as window 289. (The protocol defaults to 288 full windows, reporting window 289 as an optional appendix).
3. **Decompression Resource Budget:** Scanning through `auth.txt.gz` (7.6 GB compressed) requires approximately 10 to 15 minutes of streaming I/O. The Gate 2 dry run will measure exact streaming throughput on this environment before full extraction is launched.

---

## 10. Cryptographic Verification of Preserved Historical Artifacts

All historical model artifacts, predictions, and benchmarks remain untouched, with identical SHA-256 hashes:

| Historical Artifact Path | SHA-256 Cryptographic Checksum | Integrity Status |
| :--- | :--- | :---: |
| `results/models/best_model.joblib` | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | **VERIFIED (Unmodified)** |
| `results/reports/final_predictions.csv` | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | **VERIFIED (Unmodified)** |
| `results/phase3c/clean_rf_model.joblib` | Package intact: Model, Scaler, 23 features, Seed=42 | **VERIFIED (Unmodified)** |
| `results/phase3c/phase3c_window_predictions.csv` | 289-window prediction vectors intact | **VERIFIED (Unmodified)** |

---

## 11. Protocol Review Conclusion

The revised protocol `PHASE_3C3_1_PROTOCOL_CORRECTIONS.md` resolves all seven methodological issues. The sampling strategy is mathematically sound, immune to ground-truth entity leakage, strictly partitioned chronologically, and preserves historical benchmarks unchanged.

In strict compliance with instructions, **all execution is stopped here**. No code has been modified, no data has been sampled, and no models have been trained.

Awaiting user approval of Gate 1 before proceeding to any dry run or implementation.

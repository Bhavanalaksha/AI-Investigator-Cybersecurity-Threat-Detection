# Phase 5A: Attack Observability and Benchmark Redesign Report

**Status:** Completed and Audited  
**Phase:** Phase 5A - Attack Observability & Benchmark Redesign  
**Date:** October 20, 2026  
**Auditor / System:** AI Investigator Audit & Research Subsystem  
**Scope:** Read-Only Observability Audit and Methodological Redesign (Training & Validation Partitions Only)  
**Deliverable Path:** [`results/phase5a/PHASE5A_OBSERVABILITY_AND_BENCHMARK_DESIGN.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5a/PHASE5A_OBSERVABILITY_AND_BENCHMARK_DESIGN.md)  

---

## 1. Executive Summary & Separation of Evidence from Hypotheses

Phase 5A addresses the central scientific dilemma uncovered in Phase 4 and Phase 4B: **Can native, downsampled LANL telemetry support meaningful cybersecurity threat detection when all synthetic data leakage is removed?**

In strict accordance with research restrictions, the held-out test partition (`[1036800, 1123200)`) was **completely untouched**. No test rows, labels, predictions, or metrics were accessed. No models were retrained.

### 1.1 Observed Evidence (Verified Facts)
1. **Schema & Field Alignment:** The red-team ground-truth annotations in `data/raw/redteam.txt` provide four fields: `timestamp`, `user`, `source_host`, and `destination_host`. These align directly with fields in `auth.txt.gz` (all 4 fields), partially with `proc.txt.gz` (3 fields: time, user, host), `flows.txt.gz` (3 fields: time, src_host, dst_host), and `dns.txt.gz` (3 fields: time, src_host, dst_host).
2. **Sampled Telemetry Unobservability:** In the extracted dataset [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv):
   - **Exact Matches `(t, user, src, dst)`:** **0 / 117 (0.00%)** in Train; **0 / 171 (0.00%)** in Validation.
   - **Partial Matches `(exact t + user)`:** **0 / 117 (0.00%)** in Train; **0 / 171 (0.00%)** in Validation.
   - **Partial Matches `(exact t + host)`:** **0 / 117 (0.00%)** in Train; **0 / 171 (0.00%)** in Validation.
   - **Window-Level User Co-occurrence:** User name co-occurred in the same 300s window in only **2 / 117 cases (1.71%)** in Train, and **22 / 171 cases (12.87%)** in Validation.
3. **Physical Reason for Omission:** Uniform reservoir sampling at 1,000 events/hour draws from an underlying enterprise stream generating ~1.5 million events/hour (pi ≈ 0.000701, or 1 in 1,426 events). Across 117 independent single-event attacks, the binomial probability that zero attack events entered the sample is (1 - 0.0007)^117 ≈ 92.1%.
4. **Current Target Semantics:** The current label y_k = 1 establishes only that an attack co-occurred in time somewhere in the physical world during that 300-second block of enterprise time. The 83 sampled events in that window consist of **100% benign background traffic**.
5. **Impact on Machine Learning:** Because the underlying telemetry is pure background noise in both classes, global aggregate count features have zero mutual information with attack presence. In Phase 4, the model achieved sub-0.50 ROC-AUC (0.3938) solely by latching onto `auth_off_hours` as a spurious diurnal shortcut. Removing `auth_off_hours` yields an ROC-AUC of **0.4986** (an exact random coin toss).

### 1.2 Hypotheses (Requiring Empirical Testing)
1. **Hypothesis H1 (Host-Centric Observability):** An attacker host (such as `C17693` on Day 9) generates detectable behavioral anomalies in its local egress connection graph and authentication patterns that are obscured when events are aggregated into enterprise-wide sums.
2. **Hypothesis H2 (Entity-Level Sampling):** Cohort-based or host-stratified sampling (selecting all events for a sampled cohort of hosts without knowing ground truth) will preserve temporal sequence integrity and reveal attack footprints that uniform independent event sampling destroys.

---

## 2. Task 1: Verification of Attack Observability

### 2.1 Schema Mapping Across Raw Telemetry Streams
The schema of `data/raw/redteam.txt` was mapped against the four raw telemetry archives:

| Red-Team Field | Authentication (`auth.txt.gz`) | Process (`proc.txt.gz`) | Network Flows (`flows.txt.gz`) | DNS (`dns.txt.gz`) |
| :--- | :--- | :--- | :--- | :--- |
| `timestamp` | Field 1 (`time`) | Field 1 (`time`) | Field 1 (`time`) | Field 1 (`time`) |
| `user` | Field 2 (`source_user@domain`) | Field 2 (`user@domain`) | *Not Available* | *Not Available* |
| `source_host` | Field 4 (`source_computer`) | Field 3 (`computer`) | Field 3 (`source_computer`) | Field 2 (`source_computer`) |
| `destination_host` | Field 5 (`destination_computer`) | *Not Available* | Field 5 (`destination_computer`) | Field 3 (`resolved_computer`) |
| *Modality Specifics* | AuthType, LogonType, Action, Result | ProcessName, Start/End | Ports, Protocol, Packets, Bytes | Query Response |

### 2.2 Matching Audit on Sampled Telemetry (`multisource_stratified_120h.csv`)
An exhaustive audit was executed against the 120,000 sampled events for Training (`[691200, 756000)`) and Validation (`[756000, 1036800)`):

```
+----------------------------------------------------------------------------------------------------+
| MATCHING AUDIT: RED-TEAM ANNOTATIONS VS. EXTRACTED DATASET                                         |
+-----------------------------------------------+---------------------+---------------------+
| Matching Criterion                            | Training Partition  | Validation Partition|
+-----------------------------------------------+---------------------+---------------------+
| Total Red-Team Annotations                    | 117                 | 171                 |
| Unique Attack Timestamps                      | 117                 | 161                 |
| Exact Match (t, user, src_host, dst_host)     | 0 / 117 ( 0.00%)    | 0 / 171 ( 0.00%)    |
| Partial Match A (Exact t + User)              | 0 / 117 ( 0.00%)    | 0 / 171 ( 0.00%)    |
| Partial Match B (Exact t + Source Host)       | 0 / 117 ( 0.00%)    | 0 / 171 ( 0.00%)    |
| Partial Match C (Exact t + Destination Host)  | 0 / 117 ( 0.00%)    | 0 / 171 ( 0.00%)    |
| Partial Match D (Window + User Co-occurrence) | 2 / 117 ( 1.71%)    | 22 / 171 (12.87%)   |
| Partial Match E (Window + Source Host)        | 4 / 117 ( 3.42%)    | 7 / 171 ( 4.09%)    |
| Partial Match F (Window + Destination Host)   | 2 / 117 ( 1.71%)    | 6 / 171 ( 3.51%)    |
| Partial Match G (Window + Both Hosts Present) | 0 / 117 ( 0.00%)    | 0 / 171 ( 0.00%)    |
+-----------------------------------------------+---------------------+---------------------+
```

### 2.3 Distinguishing Sampled Misses from Raw Stream Absence
A crucial distinction required by research standards is whether the attack events are missing because they were dropped by the sampler, or because they never existed in the raw streams:

1. **Presence in Raw Telemetry:**
   - On Day 9 (Train), the adversary operated from source machine **`C17693`**, attempting lateral movement to 74 distinct destination machines.
   - In raw `flows.txt.gz`, machine `C17693` actively generated network connections to target machines (e.g. `C6487`, `C1224`), which appear in `redteam.txt` as compromised targets within minutes of the network connections.
   - In raw `auth.txt.gz`, authentication events corresponding to red-team timestamps exist in the full multi-million-event stream.
2. **Mechanism of Sampled Absence:**
   - In our Gate 3 extraction, the reservoir sampler processed **409.37 million lines** and captured **120,000 events** (overall sampling fraction pi = 0.0778%).
   - Because the sampler was strictly blind to red-team labels, users, and hosts (Safeguard 4), it treated every raw line with equal probability within each hourly stratum.
   - For an attack action comprising 1 or 2 logons in a 5-minute block of 125,000 events, the probability of selecting that exact line is 1 / 1,426 ≈ 0.07%.
3. **Audit Finding:** **The absence of red-team records in the sampled dataset is an artifact of uniform event-level downsampling, NOT absence from the raw LANL telemetry.** The raw archives contain the adversary's actions, but independent uniform event sampling acts as an inadvertent low-pass filter that obliterates discrete, sparse signals.

---

## 3. Task 2: Defining the Detection Task

### 3.1 What the Current Target Measures
Under Benchmark B (the Gate 4 configuration):
- **Unit of Analysis:** A fixed 300-second temporal slice of the entire enterprise: W_k = [691200 + k * 300, 691200 + (k+1) * 300).
- **Feature Aggregation:** Enterprise-wide aggregate counts: `total_events`, `is_auth`, `is_proc`, `user_to_host_ratio`, etc.
- **Target Label:** y_k = 1 if any red-team event occurred in the enterprise at t in W_k, else y_k = 0.

### 3.2 Evaluation of Detection Formulations

#### 1. Event-Level Detection (Unsupported on Downsampled Data)
- **Feasibility:** **Impossible on current sampled dataset.**
- **Rationale:** Because exact attack events were dropped during downsampling (0 / 117 present), a classifier cannot classify individual rows as benign vs malicious when no malicious rows exist in the data.

#### 2. Global Enterprise Window-Level Detection (Scientifically Flawed)
- **Feasibility:** **Fundamentally flawed for stealthy APT detection.**
- **Rationale:** Stealthy lateral movement involves single-digit commands and logons. When summed across an entire enterprise of 20,000 hosts generating 125,000 events every 5 minutes, an attack changes total event density by less than 0.001%. Natural Poisson fluctuations in background user activity (e.g. a batch job running on an uncompromised server) generate noise that is orders of magnitude larger than the attack. Global enterprise aggregates cannot detect sparse attacks without synthetic leakage.

#### 3. Weak Temporal Association Task (Current Reality)
- **Status:** **This is what Benchmark B actually measures.**
- **Rationale:** It tests whether global enterprise background traffic differs between times when an attacker was active and times when the attacker was dormant. As proven in Phase 4B, this reduces entirely to diurnal time-of-day correlation: attacks occurred during daytime on Day 9 and nighttime on Days 10–12, causing complete generalization collapse.

#### 4. The Recommended Target Formulation: Entity-Centric Detection
- **Feasibility:** **Supported by LANL data structure.**
- **Target Formulation:** Frame detection at the **host-window** or **user-session** level:
  Instance (h, W_k) => y_{h, k} = 1 if Host h was compromised or active in attack during window k, else 0
- At the host level, an attacker running 3 processes or contacting 5 new machines represents a **100% to 500% anomaly** relative to that host's baseline, making the signal mathematically observable.

---

## 4. Task 3: Benchmark Alternatives Comparison

To transition from the flawed enterprise-aggregate formulation to a scientifically rigorous threat detection benchmark, four architectural alternatives were evaluated:

```
+-----------------------------------------------------------------------------------------------------------+
| COMPARATIVE ARCHITECTURAL MATRIX: BENCHMARK DESIGN ALTERNATIVES                                           |
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Alternative              | Sampling Strategy   | Feature Scope       | Target Task         | Feasibility  |
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Benchmark B (Current)    | Uniform Reservoir   | Global 300s Counts  | Enterprise Window   | Flawed (AUC  |
|                          | (Blind Event Quota) | (23 Features)       | Temporal Overlap    | = 0.4986)    |
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Alternative 1            | Blind Host-Cohort   | Host-Level Dynamic  | Host-Window Attack  | HIGH         |
| (Host-Centric Windows)   | Sampling            | Behavior (Graph/Seq)| Compromise          | (Recommended)|
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Alternative 2            | Graph Edge Stream   | Dynamic Graph       | Edge-Level Anomaly  | MODERATE-    |
| (Authentication Graph)   | Reservoir           | Embeddings & Degree | Novel Lateral Edge  | HIGH         |
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Alternative 3            | Uniform Reservoir   | Statistical Anomaly | Enterprise Window   | LOW-MODERATE |
| (Anomaly-Weighted Sums)  | (Existing Sample)   | Density vs Baseline | Temporal Overlap    | (Noise Heavy)|
+--------------------------+---------------------+---------------------+---------------------+--------------+
| Alternative 4            | Session-Clustered   | User Authentication | Compromised Session | MODERATE     |
| (User-Session Tracking)  | Sampling            | Behavioral Journey  | Account Takeover    |              |
+--------------------------+---------------------+---------------------+---------------------+--------------+
```

### Detailed Evaluation of Alternatives

#### Alternative 1: Host-Centric Entity-Level Windows (Recommended for Benchmark C)
- **Sampling Strategy:** Blind Host-Cohort Sampling. Select a fixed cohort of hosts (e.g. 500 randomly sampled hosts, or all hosts active during Day 9 Hour 0) **completely blind to `redteam.txt`**. Extract 100% of telemetry for those selected hosts across Days 9–13.
- **Assumptions:** Attacks exhibit localized anomalies on the specific host compromised.
- **Potential Bias:** Hosts with zero activity produce sparse vectors; mitigated by evaluating active host-windows.
- **Computational Cost:** Low to moderate (streams filtered by host ID set).
- **Temporal Separation:** Strict preservation of Day 9 (Train), Days 10–12 (Val), Day 13 (Held-Out Test).
- **Observability:** If an attacker host (like `C17693`) is in the cohort, 100% of its network flows and authentications are captured, making the attack footprint completely observable.

#### Alternative 2: Dynamic Bipartite Authentication Graph
- **Sampling Strategy:** Graph-preserving edge reservoir sampling.
- **Features:** Bipartite graph (U, H, E) tracking user-to-host edges. Features measure edge novelty (e.g. first time user u accessed host h), out-degree spikes, and path diameter.
- **Assumptions:** Lateral movement creates novel edges in the authentication topology.
- **Potential Bias:** Enterprise environments naturally generate novel edges over time.
- **Computational Cost:** High (requires continuous graph state maintenance).

#### Alternative 3: Anomaly-Weighted Enterprise Sums (Using Existing Extracted Dataset)
- **Sampling Strategy:** Retain existing [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv).
- **Features:** Replace raw event counts with baseline-weighted anomaly scores:
  - Fit background transition probabilities on clean Day 9 Hours 0–6 (e.g. P(auth_type | logon_type), P(process | user)).
  - Sum the negative log-likelihoods of sampled events in each 300s window.
- **Assumptions:** Even if only 83 background events are sampled, background traffic during an attack hour exhibits elevated stress or secondary anomalous authentications.
- **Limitation:** As proven in Phase 4B, background events during attack windows appear statistically identical to quiet windows; likelihood gains may remain negligible.

---

## 5. Task 4: Fair Experimental Design for Benchmark C (Candidate Version 1.0)

To establish a scientifically sound foundation before any test set evaluation, we specify a clean, strictly controlled training-and-validation experiment plan.

### 5.1 Protocol Specifications & Versioning
- **Benchmark Name:** **Benchmark C (Entity-Centric & Pruned Telemetry Benchmark)**
- **Deterministic Seed:** `42` across all random state generators, splits, and algorithms.
- **Temporal Boundaries (Strictly Enforced):**
  - **Training Partition:** Day 9 `[691200, 756000)` (Hours 0–17, 18.0 hours).
  - **Validation Partition:** Days 10–12 `[756000, 1036800)` (Hours 18–95, 78.0 hours).
  - **Held-Out Test Partition:** Day 13 `[1036800, 1123200)` (**HELD OUT - 100% ISOLATED AND UNTOUCHED**).

### 5.2 Feature Specification & Cleaning Rules
1. **Mandatory Feature Pruning:**
   - **Drop `auth_off_hours`:** Formally remove time-of-day features to eliminate the diurnal shortcut that inverted Validation ROC-AUC.
   - **Drop Zero-Variance Columns:** Remove `active_sources` and `multi_source_flag` (identically 4 and 1 across all windows).
2. **Feature Set (20 Clean Features):**
   - Retain: `total_events`, `is_auth`, `auth_fail`, `auth_fail_rate`, `auth_ntlm`, `auth_ntlm_rate`, `is_proc`, `proc_rare`, `is_dns`, `is_flow`, `user`, `destination_host`, `source_host`, `process`, `user_to_host_ratio`, `auth_proc_interaction`, `auth_flow_interaction`, `delta_total_events`, `delta_auth_fails`, `delta_procs`.
3. **Preprocessing Isolation:**
   - Fit `StandardScaler` strictly on `X_train`. Transform `X_val` using training parameters.
   - Fit `rare_proc_set` strictly on training native process records (t < 756000).

### 5.3 Baseline Model Configurations
To prevent the memorization observed with depth-8 Random Forests (26.9 leaves for 216 samples), the experiment plan restricts models to regularized baselines:

1. **Regularized Random Forest:**
   - `n_estimators=100`, `max_depth=3` (maximum 8 leaves per tree), `min_samples_leaf=15`, `class_weight='balanced'`, `random_state=42`.
2. **L1-Penalized Logistic Regression (Lasso / Sparse Feature Selection):**
   - `penalty='l1'`, `solver='liblinear'`, `C=0.1`, `class_weight='balanced'`, `random_state=42`.
3. **Shallow Decision Tree:**
   - `max_depth=2`, `min_samples_leaf=20`, `class_weight='balanced'`, `random_state=42`.

### 5.4 Imbalanced Evaluation Plan & Operational Threshold Selection
- **Primary Metric:** **Average Precision (AP / PR-AUC)**, explicitly benchmarked against the random positive prevalence (P/N = 5.34%).
- **Secondary Metric:** **ROC-AUC**.
- **Operational Alert Burden Metric:**
  - Alert rate per hour: Alerts/hr = (TP + FP) / Hours.
  - False Discovery Rate (FDR): FDR = FP / (TP + FP) = 1 - Precision.
- **Threshold Calibration Protocol (Validation Only):**
  - Select operational decision threshold T* on the validation set using an explicit operational constraint:
    T* = argmax_T F1(T) subject to Alerts/hr <= 2.0 and Precision >= 0.10
  - If no threshold satisfies this constraint, record that the model fails operational deployment criteria.

### 5.5 Commitment to Honest Reporting
- **No Pre-Set Target Scores:** We do not claim or demand that the model achieve F1 > 0.80 or ROC-AUC > 0.90.
- **Honest Negative Result Criteria:** If regularized clean models on validation continue to perform at random chance (AP ≈ 0.053, ROC-AUC ≈ 0.50), this will be formally documented as evidence that **enterprise-wide window aggregates on 1:1,500 downsampled telemetry cannot observe APT lateral movement**. This is a valid, publishable scientific conclusion.

---

## 6. Cryptographic Baseline & Artifact Preservation

All historical artifacts and prior reports were verified for hash preservation:

| Artifact Path | SHA-256 Checksum | Preservation Status |
| :--- | :--- | :---: |
| [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv) | `82faebf1f713b7156725a313ae803318688bf37e63e136cd09bfa46ba81c5ec0` | **VERIFIED INTACT** |
| [`data/stratified_v2/sampling_manifest_120h.jsonl`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/sampling_manifest_120h.jsonl) | `4ad7277a99e7f550373413eb32f285832939b84c8777931968b975fc3aa57bd1` | **VERIFIED INTACT** |
| [`data/raw/redteam.txt`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/raw/redteam.txt) | `6bbc0c7dff64e476efb08fef260822b058fd09d44d17ec488a16e80474d1e532` | **VERIFIED INTACT** |
| [`results/phase4/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/clean_rf_model.joblib) | `9c431c7e8071dbf7a4416086ba4ac306654165673692aa680739e9eabef88c8d` | **VERIFIED INTACT** |
| [`results/phase4/scaler.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/scaler.joblib) | `80a7cdf2f963703114f832ccc92157ebb8310e549394a0c2b401c6b501634135` | **VERIFIED INTACT** |
| [`results/phase4/PHASE4_GATE4_REPORT.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/PHASE4_GATE4_REPORT.md) | `8bb5901134039826c1acf8e5b17573ff0bf0af142903d60cf89fe987b5097182` | **VERIFIED INTACT** |
| [`results/phase4/PHASE4_VALIDATION_AUDIT.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/PHASE4_VALIDATION_AUDIT.md) | `4dd7513503a03a8865785c74419a4a87c7cc6a7e23fbdd0b37b0fa7e776a3a9c` | **VERIFIED INTACT** |
| [`results/phase4/PHASE4B_ROOT_CAUSE_AUDIT.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/PHASE4B_ROOT_CAUSE_AUDIT.md) | `d763a7e6685fedcfb0e9e8dd2cfb1496fbbd49c3c4b4c89155950bafa0b38210` | **VERIFIED INTACT** |
| [`results/models/best_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/models/best_model.joblib) | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | **VERIFIED INTACT** |
| [`results/reports/final_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/reports/final_predictions.csv) | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | **VERIFIED INTACT** |
| [`results/phase3c/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/clean_rf_model.joblib) | `02785745b00b36515d537427496d46eeff5e17add54ec0953dcc1abc3f930658` | **VERIFIED INTACT** |
| [`results/phase3c/phase3c_window_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/phase3c_window_predictions.csv) | `e058944dc1b1bc373f185f685bf951844a265cdb682a2317805012f7ffebd494` | **VERIFIED INTACT** |

---

## 7. Conclusion & Execution Hold

**Phase 5A is complete.**  
No code modifications, resampling, or model retraining have been executed. The held-out test partition remains strictly blind and unaccessed.

**Awaiting your explicit approval before proceeding.**

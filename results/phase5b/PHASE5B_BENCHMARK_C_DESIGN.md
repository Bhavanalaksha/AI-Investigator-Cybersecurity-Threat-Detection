# Phase 5B: Benchmark C Host-Centric Detection Design Report

**Status:** Completed and Audited  
**Phase:** Phase 5B - Benchmark C Host-Centric Detection  
**Date:** October 20, 2026  
**Auditor / System:** AI Investigator Audit & Research Subsystem  
**Scope:** Design Review, Pilot Verification, and Stop Condition Analysis (Training & Validation Partitions Only)  
**Deliverable Path:** [`results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md)  
**Pilot Manifest Path:** [`results/phase5b/pilot_cohort_audit_manifest.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/pilot_cohort_audit_manifest.json)  

---

## 1. Executive Summary & Stop Condition Activation

In accordance with the directives of Phase 5B, this report delivers the formal pre-implementation design review for **Benchmark C (Host-Centric Entity-Level Detection)**. In strict adherence to Mandatory Safeguards, the held-out test partition (`[1036800, 1123200)`) remains **100% untouched and unaccessed**. Historical Benchmark B artifacts, models, predictions, and reports remain frozen and verified.

### 1.1 Stop Condition Invocation (Section 6 Compliance)
Section 6 of the Phase 5B mandate explicitly establishes the following governance control:
> *"Stop before expensive extraction if the design cannot be implemented without label-informed sampling, test access, unsupported assumptions, or unacceptable resource cost. Report the blocker and await approval."*

Following the completion of our pilot audit on enterprise host coverage and label alignment (`pilot_cohort_audit_manifest.json`), **the AI Investigator has formally triggered this Stop Condition prior to launching the expensive 45-minute raw telemetry extraction**.

### 1.2 Summary of Critical Findings
1. **The Blind Host-Cohort Sampling Dilemma:**
   - Under Mandatory Safeguard 3, red-team annotations must NEVER be used to select hosts or influence sampling probabilities.
   - In the enterprise host population (11,149 active computers observed in the baseline sample), the red-team attacker operated from **exactly ONE source host** (`C17693`) on Day 9 (Train), and **only TWO source hosts** (`C17693`, `C22409`) on Days 10–12 (Validation).
   - In our deterministic pilot audit (seed = 42), drawing random cohorts of size 50, 100, 200, 500, and 1,000 hosts yielded an attacker source-host capture rate of **0.00% across all cohort sizes**.
2. **Extreme Class Imbalance on Destination Hosts:**
   - In a blind cohort of 500 hosts, the source host is completely missing. Only 3 of 74 destination hosts were captured in Train (representing passive recipients of inbound logons), generating exactly **4 positive host-windows out of 108,000 instances** (prevalence = **0.0037%**, or 37 parts per million).
   - For a cohort of 100 hosts, positive host-windows in Train is **0 out of 21,600** (prevalence = **0.0000%**).
3. **Severe Resource Cost for Negligible Signal:**
   - Extracting 100% of telemetry for a 500-host cohort across Days 9–12 requires scanning **327.2 million raw lines** across 4 gzipped archives, taking **44.9 minutes** of continuous streaming.
   - Expending 45 minutes of compute to produce a dataset with 4 positive rows and 107,996 negative rows—where the primary attack vehicle is completely absent—is scientifically unjustifiable without user review and methodological realignment.

---

## 2. Design Review Before Implementation

### 2.1 Entity Definition and Prediction Target
Under Benchmark C, the unit of prediction is shifted from a global enterprise temporal block to a specific **host-window instance**:

Instance (h, W_k)

Where:
- h in H_cohort is an enterprise host (computer identifier).
- W_k = [691200 + k * 300, 691200 + (k+1) * 300) is a non-overlapping 300-second temporal window.
- **Target Label Definition:**
  - y_{h, k} = 1 if host h was actively compromised, used as a lateral movement launch point, or targeted by an unauthorized credentialed logon during window W_k.
  - y_{h, k} = 0 if host h engaged solely in benign background operations during window W_k.

### 2.2 Red-Team Ground Truth Mapping Protocol
The schema of [`data/raw/redteam.txt`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/raw/redteam.txt) provides 4 comma-separated fields: `time, user, source_computer, destination_computer`.

Ground-truth records map to host-windows according to the following strict temporal rule:
- An attack record r = (t_r, u_r, src_r, dst_r) falls into window index k = floor((t_r - 691200) / 300).
- **Source Host Mapping:** The launching computer src_r is labeled positive (y_{src_r, k} = 1). This represents active offensive tradecraft (e.g., executing commands, initiating lateral movement).
- **Destination Host Mapping:** The recipient computer dst_r receives an inbound authentication logon. Under host-level threat detection, receiving an unauthorized red-team authentication marks the target as compromised (y_{dst_r, k} = 1).
- **Multi-Event Deduplication:** If multiple red-team actions occur on host h within the same 300-second window, they collapse to a single binary label y_{h, k} = 1.

```
+----------------------------------------------------------------------------------------------------+
| GROUND-TRUTH ANNOTATION SUMMARY: TRAIN VS. VALIDATION                                              |
+----------------------------------------------------+-----------------------+-----------------------+
| Metric                                             | Training Partition    | Validation Partition  |
|                                                    | [691200, 756000)      | [756000, 1036800)     |
+----------------------------------------------------+-----------------------+-----------------------+
| Total Red-Team Records                             | 117                   | 171                   |
| Temporal Duration                                  | 18.0 hours (216 win)  | 78.0 hours (936 win)  |
| Unique Source Hosts (Attack Launchers)             | 1 ('C17693')          | 2 ('C17693', 'C22409')|
| Unique Destination Hosts (Compromised Targets)     | 74 hosts              | 114 hosts             |
| Earliest Red-Team Timestamp                        | 725488 (Hour 9.5)     | 759247 (Hour 18.9)    |
| Unique Attack 300s Windows (Enterprise-Wide)       | 21 windows            | 49 windows            |
+----------------------------------------------------+-----------------------+-----------------------+
```

### 2.3 Selection of Benign Host-Windows Without Test Contamination
- **Temporal Half-Open Partitions:**
  - Training Partition: t in [691200, 756000) (Day 9, Hours 0–17).
  - Validation Partition: t in [756000, 1036800) (Days 10–12, Hours 18–95).
  - Held-Out Test Partition: t in [1036800, 1123200) (Day 13, Hours 96–119). **Strictly untouched.**
- **Benign Windows:** Any window (h, W_k) where no red-team annotation in `data/raw/redteam.txt` touches host h (either as source or destination) is labeled y_{h, k} = 0.
- **Zero Test Contamination:** No timestamps, events, or host states from t >= 1036800 are inspected or used to define negative examples in Train or Validation.

### 2.4 Independent Cohort Selection (The Blind Sampling Dilemma)
To comply with Mandatory Safeguard 3 (*"Do not use redteam.txt to select hosts, events, sampling probabilities, features, or training examples"*), the host cohort H_cohort must be chosen using an unsupervised, label-blind selection function f(D_unlabeled, seed).

We evaluated uniform random sampling with fixed seed `42` across 11,149 enterprise hosts observed in the pre-extracted sample. The mathematical results of this audit are summarized below:

```
+-------------------------------------------------------------------------------------------------------------------+
| PILOT COHORT AUDIT: BLIND DETERMINISTIC HOST SELECTION (SEED = 42)                                                |
+--------+---------------------------------------+---------------------------------------+--------------------------+
| Cohort | Training Partition [691200, 756000)   | Validation Partition [756000, 1036800)| Attack Source Capture    |
| Size K | Src Hits | Dst Hits | Pos/Total Win   | Src Hits | Dst Hits | Pos/Total Win   | Rate (C17693 / C22409)   |
+--------+----------+----------+-----------------+----------+----------+-----------------+--------------------------+
| 50     | 0 / 1    | 0 / 74   | 0 / 10,800      | 0 / 2    | 0 / 114  | 0 / 46,800      | 0.0% (Both Partitions)   |
| 100    | 0 / 1    | 0 / 74   | 0 / 21,600      | 0 / 2    | 1 / 114  | 1 / 93,600      | 0.0% (Both Partitions)   |
| 200    | 0 / 1    | 0 / 74   | 0 / 43,200      | 0 / 2    | 2 / 114  | 2 / 187,200     | 0.0% (Both Partitions)   |
| 500    | 0 / 1    | 3 / 74   | 4 / 108,000     | 0 / 2    | 7 / 114  | 8 / 468,000     | 0.0% (Both Partitions)   |
| 1000   | 0 / 1    | 9 / 74   | 14 / 216,000    | 0 / 2    | 14 / 114 | 14 / 936,000    | 0.0% (Both Partitions)   |
+--------+----------+----------+-----------------+----------+----------+-----------------+--------------------------+
```

#### Mathematical Analysis of the Sampling Dilemma
Let N_ent ≈ 11,149 be the total enterprise host population, and let K be the cohort size.
1. The probability that the single adversary source host `C17693` is selected in a blind uniform random sample is:
   P(C17693 in H_cohort) = K / N_ent
   - For K = 100: P = 100 / 11,149 = 0.897%.
   - For K = 500: P = 500 / 11,149 = 4.485%.
   - In over **95.5%** of random cohort selections, the adversary launcher is entirely absent.
2. If `C17693` is not captured, the training set contains **zero instances of malicious command execution, offensive network reconnaissance, or outbound lateral movement**.
3. The only positive labels that enter the cohort are rare destination hosts that happen to be hit by lateral movement. In a 500-host cohort, exactly 3 destination hosts are captured (`C583`, `C1484`, `C3521`), generating 4 positive host-windows out of 108,000 instances (prevalence = 37 parts per million).
4. Machine learning models cannot learn generalized representations of cyber threats from 4 positive examples embedded in 107,996 negative examples, especially when those 4 examples capture only the receiving end of a network handshake.

### 2.5 Host Identity, Generalization, and Categorical Leakage
A critical question in entity-level detection is how to prevent models from memorizing specific host identifiers:
1. **Host Identity Leakage:** If the categorical identifier (e.g. `host_id = C17693`) is provided to the classifier, the model trivially memorizes that `C17693` is malicious and achieves near-perfect training accuracy. In deployment on unseen hosts, this model has zero predictive capability.
2. **Mandatory Prohibition:** Categorical host identifiers must be **strictly excluded** from the feature matrix. All features must be purely behavioral, topological, or statistical.
3. **Temporal Cross-Partition Host Overlap:** If `C17693` is present in both Train and Validation, even purely behavioral features risk overfitting to the specific diurnal habits and software profile of user `U748` on `C17693`. True generalization requires testing whether a model trained on attacker actions from machine A can detect an unknown adversary operating on machine B.

---

## 3. Feature Engineering Specification (Host-Centric)

To support entity-level behavioral modeling, 9 host-centric temporal features were formally specified and verified against raw stream schemas:

```
+-----------------------------------------------------------------------------------------------------------+
| HOST-CENTRIC FEATURE SPECIFICATION (BENCHMARK C)                                                          |
+--------------------------+---------------------+-----------------------------------+----------------------+
| Feature Name             | Modality Source     | Mathematical Definition           | Raw Field Support    |
+--------------------------+---------------------+-----------------------------------+----------------------+
| host_event_count         | Multisource         | Total events touching host h in W | Supported (All 4)    |
| host_auth_count          | Authentication      | Count of auth events on host h    | auth.txt.gz (col 4,5)|
| host_proc_count          | Process Execution   | Count of process starts on host h | proc.txt.gz (col 3)  |
| host_flow_count          | Network Flows       | Count of flow records for host h  | flows.txt.gz (col 3) |
| host_dns_count           | DNS Queries         | Count of DNS lookups by host h    | dns.txt.gz (col 2)   |
| host_auth_fail_count     | Authentication      | Count of failed auths on host h   | auth.txt.gz (col 8)  |
| host_auth_fail_rate      | Authentication      | Failed auths / Total auths on h   | auth.txt.gz (col 8)  |
| host_distinct_peers      | Auth / Flows        | Unique remote hosts contacted     | auth & flows (col 5) |
| delta_host_events        | Multisource         | Count(W_k) - Count(W_{k-1})       | Lag-1 Difference     |
+--------------------------+---------------------+-----------------------------------+----------------------+
```

### Feature Construction & Leakage Controls
- **Temporal Isolation:** All window features are computed strictly from events within window W_k and prior window W_{k-1}. Future window information (W_{k+1}) is strictly inaccessible.
- **Diurnal Ablation Protocol:** Feature `auth_off_hours` will not be removed arbitrarily; it will be evaluated in a documented ablation on host-windows to determine whether diurnal bias persists at the entity level.
- **Transformation Isolation:** Preprocessing (e.g., standard scaling, imputation) is fit strictly on Training host-windows and applied out-of-sample to Validation.

---

## 4. Computational Feasibility & Resource Controls

### 4.1 Estimated Scan Volume and Streaming Throughput
From our Gate 3 extraction logs, the physical scan costs across Days 9–12 (96 hours: Train 18h + Validation 78h) were verified:

```
+----------------------------------------------------------------------------------------------------+
| RAW STREAM DECOMPRESSION AND FILTERING PROJECTIONS (DAYS 9-12 / 96 HOURS)                          |
+-------------------+---------------------+---------------------+------------------------------------+
| Telemetry Stream  | Raw Compressed Size | Total Lines (96h)   | Streaming Throughput | Est Runtime |
+-------------------+---------------------+---------------------+----------------------+-------------+
| dns.txt.gz        | 185 MB              | 33,200,000 lines    | 494,000 lines/sec    | 1.1 minutes |
| proc.txt.gz       | 2,358 MB            | 54,000,000 lines    | 432,000 lines/sec    | 2.1 minutes |
| flows.txt.gz      | 1,083 MB            | 104,000,000 lines   | 120,000 lines/sec    | 14.4 minutes|
| auth.txt.gz       | 7,626 MB            | 136,000,000 lines   | 83,000 lines/sec     | 27.3 minutes|
+-------------------+---------------------+---------------------+----------------------+-------------+
| TOTALS            | 11,252 MB (~11.2 GB)| 327,200,000 lines   | ~121,000 lines/sec   | 44.9 minutes|
+-------------------+---------------------+---------------------+----------------------+-------------+
```

### 4.2 Storage and Memory Projections
- **Raw Filtered Output:** Extracting 100% of events for 500 hosts across 96 hours yields approximately 4.5 million records (~450 MB uncompressed CSV).
- **Feature Matrix Size:** 500 hosts * 1,152 windows = 576,000 rows * 10 columns ≈ 46 MB.
- **Runtime Bottleneck:** Scanning 327.2 million raw lines across 11.2 GB of gzipped text requires **44.9 minutes of continuous disk streaming**.

---

## 5. Strategic Evaluation and Decision Matrix

Because executing the 45-minute extraction for a blind 500-host cohort yields a dataset with **zero source attacker presence and an extreme prevalence of 0.0037% on destination hosts**, proceeding directly to large-scale extraction would constitute a failure of scientific diligence.

We present three defensible pathways for user decision:

```
+-------------------------------------------------------------------------------------------------------------------+
| STRATEGIC DECISION MATRIX: BENCHMARK C DEVELOPMENT PATHWAYS                                                       |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
| Pathway                  | Sampling Strategy   | Signal Observability| Compute Cost        | Scientific Rigor     |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
| Pathway A                | Active Host-Window  | High on Active      | Zero raw extraction | HIGH (Recommended)   |
| (Stratified Sample       | Featurization on    | Windows             | (Uses existing 120k | Validates host-level |
| Host-Window Benchmark)   | Existing 120k Extr. | (Prevalence ~1.2%)  | dataset)            | features immediately |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
| Pathway B                | Blind 500-Host      | Near-Zero           | High (~45 min raw   | FLAWED               |
| (Blind Cohort from       | Extraction from Raw | (Src=0%, Dst=4 win  | stream; 327M lines) | (Prevalence 37 ppm;  |
| Raw Archives)            | Archives            | Prevalence = 37 ppm)|                     | zero source signal)  |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
| Pathway C                | Two-Stage Forensic  | High                | Moderate            | HIGH                 |
| (Candidate Host Triage   | Triage (Anomaly     | (Captures anomalous | (2-stage extraction | (Reflects modern     |
| + Entity Featurization)  | Filter -> Feature)  | hosts blindly)      | protocol)           | SOC architecture)    |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
| Pathway D                | Conclude Benchmark B| Complete Baseline   | Zero (Read-only     | CRITICAL MILESTONE   |
| (Gate 5 Baseline         | Lifecycle (Held-Out | Documentation       | single pass on Day  | (Freezes historical  |
| Evaluation)              | Test Set Evaluation)|                     | 13 test set)        | baseline)            |
+--------------------------+---------------------+---------------------+---------------------+----------------------+
```

### Detailed Evaluation of Strategic Pathways:

#### Pathway A: Active Host-Window Benchmark on Extracted Dataset (Recommended)
- Instead of scanning 327 million raw lines for a blind cohort that misses the attacker, construct host-window instances (h, W_k) directly from the verified 120,000-event extraction ([`multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv)).
- Filter to active host-windows (windows where host h had at least one sampled event).
- Host coverage: In the 120k sample, `C17693` has 9 sampled events spanning 9 windows across Days 9–12.
- Enables instant verification of regularized models, precision, recall, and feature importances with zero resource waste.

#### Pathway C: Two-Stage Blind Forensic Triage
- Stage 1: Compute a global entropy or novelty score on all hosts during Day 9 Hour 0–6 without reading `redteam.txt`.
- Stage 2: Select the top 1,000 hosts with the highest baseline anomaly or egress diversity (completely blind to labels).
- Test whether `C17693` is naturally selected by unsupervised anomaly triage.

#### Pathway D: Execute Gate 5 Baseline Test Evaluation
- Formally run the single-pass evaluation of the frozen Benchmark B model on the held-out test partition (`[1036800, 1123200)`).
- Complete the documentation of Benchmark B's performance on unseen test data before building Benchmark C.

---

## 6. Cryptographic Baseline & Artifact Preservation

All historical artifacts and model weights remain strictly preserved with verified SHA-256 hashes:

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
| [`results/phase5a/PHASE5A_OBSERVABILITY_AND_BENCHMARK_DESIGN.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5a/PHASE5A_OBSERVABILITY_AND_BENCHMARK_DESIGN.md) | `11A631BE0319CA444B88C0E0CF539E689464065178FE1D35AEA55C09B5BE6123` | **VERIFIED INTACT** |
| [`results/phase5b/pilot_cohort_audit_manifest.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/pilot_cohort_audit_manifest.json) | `dab0b18a6adde17e4fb1d6c9344eec0d6c6e449ca082b3ca42f4f182e9b9ca7a` | **CREATED & VERIFIED** |

---

## 7. Stop Condition & Governance Hold

In accordance with Phase 5B instructions:
- **No expensive extraction has been initiated.**
- **No models have been trained.**
- **The held-out test partition (`[1036800, 1123200)`) remains strictly blind, isolated, and untouched.**
- **The blocker is fully documented with reproducible empirical evidence.**

**Awaiting user decision on which strategic pathway to pursue.**

# Phase 5B: Benchmark C Implementation and Pilot Audit Report

**Status:** Implementation On Hold (Section 6 Stop Condition Triggered)  
**Phase:** Phase 5B - Benchmark C Host-Centric Detection  
**Date:** October 20, 2026  
**Auditor / System:** AI Investigator Audit & Research Subsystem  
**Scope:** Pilot Implementation, Empirical Feasibility Audit, and Execution Hold  
**Deliverable Path:** [`results/phase5b/PHASE5B_IMPLEMENTATION_REPORT.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/PHASE5B_IMPLEMENTATION_REPORT.md)  
**Companion Design Doc:** [`results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md)  
**Pilot Manifest Path:** [`results/phase5b/pilot_cohort_audit_manifest.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/pilot_cohort_audit_manifest.json)  

---

## 1. Executive Summary & Governance Status

Phase 5B authorizes the development of Benchmark C (host-centric threat detection using blind cohort sampling). Prior to executing an expensive 45-minute streaming extraction across 327.2 million raw lines, a comprehensive pilot audit was implemented to verify:
1. Enterprise host coverage and adversary presence under label-blind sampling.
2. Ground-truth label alignment across Training (`[691200, 756000)`) and Validation (`[756000, 1036800)`).
3. Telemetry schema feasibility for 9 host-centric temporal features.
4. Physical compute, runtime, and memory requirements.

### 1.1 Governance Status: Execution On Hold
Pursuant to Phase 5B Section 6 (*"Stop before expensive extraction if the design cannot be implemented without label-informed sampling, test access, unsupported assumptions, or unacceptable resource cost. Report the blocker and await approval"*), **full raw extraction and model training are formally PAUSED**.

The pilot audit revealed a fatal methodological blocker: **under blind sampling, the adversary launcher is captured in 0.00% of tested cohorts, resulting in an extreme positive prevalence of 0 to 37 parts per million (ppm)**. Proceeding to full extraction without user review would violate empirical research principles.

---

## 2. Pilot Implementation Details

### 2.1 Pilot Pipeline Architecture
The pilot pipeline was implemented via [`scripts/phase5b/pilot_host_cohort_audit.py`](file:///C:/Users/WELCOME/.gemini/antigravity-ide/brain/3acc72fc-5105-4eba-b42a-864bc98c0669/scratch/pilot_host_cohort_audit.py) with the following controls:
- **Blind Cohort Generator:** Samples K unique hosts uniformly at random from 11,149 enterprise computers using deterministic seed `42`.
- **Ground-Truth Auditor:** Evaluates attack presence strictly in Train (t in [691200, 756000)) and Validation (t in [756000, 1036800)). The held-out test partition (t >= 1036800) was **never loaded or inspected**.
- **Manifest Logger:** Emits full empirical audit metrics to [`results/phase5b/pilot_cohort_audit_manifest.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/pilot_cohort_audit_manifest.json).

### 2.2 Empirical Audit Findings

```
+-------------------------------------------------------------------------------------------------------------------+
| PILOT AUDIT RESULTS: HOST COHORT COVERAGE ACROSS PARTITIONS (SEED = 42)                                          |
+--------+---------------------------------------+---------------------------------------+--------------------------+
| Cohort | Training Partition [691200, 756000)   | Validation Partition [756000, 1036800)| Attacker Source Host     |
| Size K | Src Hits | Dst Hits | Pos/Total Win   | Src Hits | Dst Hits | Pos/Total Win   | Capture Rate (C17693)    |
+--------+----------+----------+-----------------+----------+----------+-----------------+--------------------------+
| 50     | 0 / 1    | 0 / 74   | 0 / 10,800      | 0 / 2    | 0 / 114  | 0 / 46,800      | 0.00% (0 / 1)            |
| 100    | 0 / 1    | 0 / 74   | 0 / 21,600      | 0 / 2    | 1 / 114  | 1 / 93,600      | 0.00% (0 / 1)            |
| 200    | 0 / 1    | 0 / 74   | 0 / 43,200      | 0 / 2    | 2 / 114  | 2 / 187,200     | 0.00% (0 / 1)            |
| 500    | 0 / 1    | 3 / 74   | 4 / 108,000     | 0 / 2    | 7 / 114  | 8 / 468,000     | 0.00% (0 / 1)            |
| 1000   | 0 / 1    | 9 / 74   | 14 / 216,000    | 0 / 2    | 14 / 114 | 14 / 936,000    | 0.00% (0 / 1)            |
+--------+----------+----------+-----------------+----------+----------+-----------------+--------------------------+
```

### 2.3 The Three Core Blockers Identified

#### Blocker 1: Total Absence of Offensive Activity in Blind Cohorts
- In the LANL red-team exercise, lateral movement and malicious commands originate from a single source computer (`C17693`).
- Because blind cohort selection cannot peek at `redteam.txt`, the probability of selecting `C17693` in a 500-host cohort is 500 / 11,149 ≈ 4.48%.
- In our deterministic audit, `C17693` was **NOT selected in any cohort up to 1,000 hosts**.
- Consequently, the extracted training dataset contains **zero malicious processes, zero outbound network scans, and zero lateral movement initiation events**.

#### Blocker 2: Ultra-Low Prevalence of Passive Destination Records
- The only attack records present in a 500-host cohort are 3 destination hosts (`C583`, `C1484`, `C3521`) that received an inbound authentication logon.
- These 3 hosts generate exactly **4 positive windows out of 108,000 total instances** in Train (prevalence = **0.0037%**, or 37 ppm).
- In Validation, 7 destination hosts generate **8 positive windows out of 468,000 instances** (prevalence = **0.0017%**, or 17 ppm).
- Supervised classifiers cannot train or calibrate operational decision thresholds on 4 positive examples against 107,996 negative examples without severe degeneration.

#### Blocker 3: Extreme Compute Expenditure for Null Signal
- Scanning 327.2 million lines across 11.2 GB of gzipped text requires **44.9 minutes of continuous disk streaming**:
  - `auth.txt.gz`: 136M lines, ~27.3 minutes.
  - `flows.txt.gz`: 104M lines, ~14.4 minutes.
  - `proc.txt.gz`: 54M lines, ~2.1 minutes.
  - `dns.txt.gz`: 33.2M lines, ~1.1 minutes.
- Expending 45 minutes of system resources to extract a dataset with 4 positive rows and zero attacker source records is an unacceptable resource cost under Section 6.

---

## 3. Verified Host-Centric Feature Definitions

The schema feasibility check verified that native fields support 9 host-centric temporal features:

1. `host_event_count`: Total events involving host h in window W_k.
2. `host_auth_count`: Authentication volume for host h.
3. `host_proc_count`: Process creations on host h.
4. `host_flow_count`: Network flow initiations by host h.
5. `host_dns_count`: DNS queries issued by host h.
6. `host_auth_fail_count`: Failed authentications involving host h.
7. `host_auth_fail_rate`: Ratio of failed authentications to total authentications.
8. `host_distinct_peers`: Count of distinct destination computers contacted.
9. `delta_host_events`: Temporal lag difference: Count(W_k) - Count(W_{k-1}).

---

## 4. Proposed Solution Pathways for User Approval

To resolve the blind sampling dilemma without compromising scientific integrity, we present three concrete pathways:

### Pathway A: Active Host-Window Benchmark on Existing Extracted Dataset (Recommended)
- **Concept:** Construct host-window instances (h, W_k) directly from the verified 120,000-event extraction ([`multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv)).
- **Mechanism:** Filter to active host-windows (windows where a host had at least one sampled event).
- **Observability:** In the 120k sample, `C17693` is present with 9 sampled flow events across Days 9–12.
- **Compute:** Zero raw extraction needed; immediate feature matrix construction and model evaluation.

### Pathway B: Supervised Forensic Case-Control Benchmark (Explicitly Acknowledged)
- **Concept:** Formulate a forensic case-control benchmark that includes the adversary host `C17693` and an equal/controlled cohort of benign enterprise hosts.
- **Documentation:** Explicitly document that host inclusion is informed by retrospective incident response knowledge (case-control study design).
- **Evaluation:** Evaluates whether host-centric features can distinguish compromised hosts from peer workstations during active hours.

### Pathway C: Conclude Benchmark B Baseline on Held-Out Test Set (Gate 5)
- **Concept:** Execute the frozen Benchmark B model on the held-out test partition (`[1036800, 1123200)`).
- **Outcome:** Formally document the baseline failure on unseen test data before re-engineering.

---

## 5. Cryptographic Baseline & Artifact Preservation

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
| [`results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/PHASE5B_BENCHMARK_C_DESIGN.md) | `b4256675006e17a332fbc914016099c5a39c07d8b6776d526c56df0076578d3f` | **CREATED & VERIFIED** |
| [`results/phase5b/pilot_cohort_audit_manifest.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase5b/pilot_cohort_audit_manifest.json) | `dab0b18a6adde17e4fb1d6c9344eec0d6c6e449ca082b3ca42f4f182e9b9ca7a` | **CREATED & VERIFIED** |

---

## 6. Conclusion & Stop Condition Hold

**The Phase 5B design review and pilot audit are complete.**  
In accordance with Section 6, the system has paused before expensive raw extraction.

**Awaiting your explicit guidance on which pathway to pursue.**

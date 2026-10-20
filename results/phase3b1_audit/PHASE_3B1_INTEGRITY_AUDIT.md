# Phase 3B.1: Independent Results Integrity and Scientific Claims Audit Report

**Project:** AI Investigator for Cybersecurity Threat Detection and Response  
**Evaluation Dataset:** Los Alamos National Laboratory (LANL) Multi-Source Cyber Telemetry  
**Audit Phase:** Phase 3B.1 - Independent Results Integrity & Scientific Claims Audit  
**Date of Audit Execution:** October 19, 2026  
**Auditor:** Independent Methodological & Verification Agent  
**Branch:** main | **Commit Checkpoint:** b5dd1d0 | **Integrity Status:** FROZEN & UNMODIFIED  

---

## Executive Summary & Scope

This audit report provides an independent, rigorous, read-only scientific evaluation of the Phase 3B experimental outcomes, model training integrity, comparative claims, incident matching logic, and performance terminology for the AI Investigator cybersecurity threat detection project.

In strict compliance with the **Phase 3B.1 mandate**, no source code has been altered, no models have been retrained, no operational decision thresholds have been tuned, no existing benchmark outputs have been overwritten, and no further benchmarking runs have been executed.

---

## Section A: Independent Verification of All Reported Metrics

All window-level metrics were independently recalculated directly from the saved 289-row prediction table in [`results/phase3/phase3b_window_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3/phase3b_window_predictions.csv) using `ground_truth` as the reference target vector.

### 1. Recalculation Results Table (289 Frozen Windows)

| Detection System | Target Prediction Column | Reference Ground Truth Column | TP | FP | FN | TN | Precision (%) | Recall (%) | F1-Score (%) | Specificity (%) | False Positive Rate (%) | Accuracy (%) | Total Alert Windows | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule-Based SIEM** | `siem_pred` | `ground_truth` | 64 | 162 | 0 | 63 | 28.32% | 100.00% | 44.14% | 28.00% | 72.00% | 43.94% | 226 | N/A | N/A |
| **Isolated Graph-Only** | `graph_pred` | `ground_truth` | 64 | 225 | 0 | 0 | 22.15% | 100.00% | 36.26% | 0.00% | 100.00% | 22.15% | 289 | N/A | N/A |
| **Random Forest Balanced** | `rf_pred_0_8459` | `ground_truth` | 36 | 28 | 28 | 197 | 56.25% | 56.25% | 56.25% | 87.56% | 12.44% | 80.62% | 64 | 0.6830 | 0.5314 |
| **Random Forest SOC Mode** | `rf_pred_0_9300` | `ground_truth` | 30 | 14 | 34 | 211 | 68.18% | 46.88% | 55.56% | 93.78% | 6.22% | 83.39% | 44 | 0.6830 | 0.5314 |
| **Multi-Agent Incidents** | `multiagent_inc_pred` | `ground_truth` | 64 | 168 | 0 | 57 | 27.59% | 100.00% | 43.24% | 25.33% | 74.67% | 41.87% | 232 | N/A | N/A |

### 2. Investigation of Any Numerical Discrepancies
- **Confusion Matrices & Binary Metrics:** 100% exact match across all four systems and both Random Forest thresholds.
- **ROC-AUC & PR-AUC:**
  - Evaluated on continuous raw scores (`raw_probs`), Random Forest achieves `ROC-AUC = 0.6830` and `PR-AUC = 0.5314`.
  - In `results/phase3/phase3b_window_predictions.csv`, the continuous scores were saved rounded to four decimal places (`rf_native_prob = round(p, 4)`). Recalculating PR-AUC from the 4-decimal rounded column yields `0.5311` (a minor 0.0003 discretization variance).
  - ROC-AUC remains exactly identical at `0.6830` on both raw and 4-decimal rounded representations.

---

## Section B: Verification of Random Forest Training Integrity

We conducted a forensic code and data trace of the frozen model [`results/models/best_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/models/best_model.joblib) back to its training origin in [`src/model_optimization.py`](file:///C:/Users/WELCOME/Desktop/mini_proj/src/model_optimization.py).

### 1. Training and Validation Partition Composition
The underlying telemetry dataset [`data/processed/events_processed.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/processed/events_processed.csv) contains 130,497 total rows, divided temporally as follows:

| Dataset Partition | Timestamp Range | Native Telemetry Rows | Synthetic Red-Team Rows | Total Partition Rows | Synthetic Contamination Ratio |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Training Partition** | `t <= 777,600` (Days 1–9) | 15,777 | **273** | 16,050 | 1.70% of partition |
| **Validation Partition** | `777,600 < t <= 1,036,800` (Days 10–12) | 6,845 | **15** | 6,860 | 0.22% of partition |
| **Held-Out Test Partition** | `t > 1,036,800` (Days 13–14) | 107,378 | **209** | 107,587 | 0.19% of partition |
| **Total** | Full Dataset Span | 130,000 | **497** | 130,497 | 0.38% of dataset |

### 2. Methodological Distinctions
To maintain strict scientific transparency, three separate dimensions of the evaluation pipeline must be distinguished:

1. **Clean Test-Time Inference (VERIFIED):**
   In Phase 3B, the test-time feature extraction strictly ingested **only the 107,378 native telemetry events** (`event_type != 'redteam'`). Zero synthetic red-team rows were present in `X_test_native`.
2. **Training and Validation Contamination (CONFIRMED LIMITATION):**
   In [`src/model_optimization.py`](file:///C:/Users/WELCOME/Desktop/mini_proj/src/model_optimization.py#L88-L150), `StandardScaler` was fitted on `X_train`, which was aggregated from `train_slice` containing 273 synthetic red-team pseudo-events. Model architecture selection and threshold optimization were performed on `val_slice`, which contained 15 synthetic rows. Thus, the trained weights in `best_model.joblib` were trained on feature distributions partially shaped by synthetic annotations in the training split.
3. **Ground-Truth Evaluation (INDEPENDENT):**
   The ground truth vector for the 289 test windows was derived independently from `redteam.txt` based on attack timestamps occurring within each window bin.

**Scientific Assessment:**
Excluding synthetic rows during test-time inference removed test-time feature manipulation. However, because the historical `best_model.joblib` was trained on data containing 273 training-partition synthetic rows, **the model training process itself cannot be claimed to be 100% free of synthetic row influence**. Subsequent phases must retrain the benchmark on a dataset where training and validation partitions also strictly exclude synthetic pseudo-events.

---

## Section C: Audit of Comparative Claims (SIEM vs Multi-Agent)

### 1. Comparative Verification
A direct side-by-side comparison between the Rule-Based SIEM baseline and the clean Multi-Agent pipeline on the 289 test windows reveals:

| Metric | Rule-Based SIEM Baseline | AI Investigator Multi-Agent | Relative Comparison |
| :--- | :---: | :---: | :--- |
| **True Positives (TP)** | 64 | 64 | Identical (Both 100.0% Recall) |
| **False Positives (FP)** | 162 | 168 | **Multi-Agent produces 6 MORE false alarm windows** |
| **True Negatives (TN)** | 63 | 57 | Multi-Agent correctly clears 6 fewer benign windows |
| **Precision** | 28.32% | 27.59% | **Multi-Agent is 0.73% LOWER** |
| **Recall (Sensitivity)** | 100.00% | 100.00% | Tied |
| **F1-Score** | 44.14% | 43.24% | **Multi-Agent is 0.90% LOWER** |
| **Specificity** | 28.00% | 25.33% | **Multi-Agent is 2.67% LOWER** |
| **False Positive Rate (FPR)** | 72.00% | 74.67% | **Multi-Agent has a 2.67% HIGHER false positive rate** |
| **Overall Accuracy** | 43.94% | 41.87% | **Multi-Agent is 2.07% LOWER** |
| **Alert Window Count** | 226 | 232 | Multi-Agent alerts in 6 more operational shifts |

### 2. Scientific Claim Audit
- **Unsupported Claim:** Any claim that the Multi-Agent system achieved a "detection improvement", "superior triage accuracy", or "false-positive reduction compared to SIEM" at the window level is **EMPIRICALLY FALSE and UNSUPPORTED**.
- **Supported Fact:** Both the SIEM and the Multi-Agent systems achieved 100.0% recall across the 64 attack windows, but SIEM slightly outperformed the Multi-Agent system on precision (28.32% vs 27.59%), accuracy (43.94% vs 41.87%), and false-positive suppression (72.00% vs 74.67%).
- **Accurate Academic Characterization:**
  - The Multi-Agent system should NOT be presented as a superior binary window detector compared to SIEM.
  - The Multi-Agent system's true academic value lies in **qualitative incident synthesis and multi-source correlation**: transforming thousands of disconnected behavioral alerts into structured investigation cases with entity timelines, provenance tracking, and MITRE ATT&CK contextualization.
  - The **Random Forest model** remains the only evaluated system that provides genuine quantitative false-positive suppression (reducing FPR from 72.00% to 6.22% while maintaining 68.18% precision).

---

## Section D: Audit of Incident-Level Evaluation Logic

We audited the matching implementation in `evaluate_tier2_association` ([`src/phase3/evaluate_phase3b.py`](file:///C:/Users/WELCOME/Desktop/mini_proj/src/phase3/evaluate_phase3b.py#L125-L175)):

```python
for inc in incidents:
    inc_start = inc["time_start"] - tol
    inc_end   = inc["time_end"] + tol
    for rt_idx, rt in redteam_test_df.iterrows():
        if inc_start <= rt["timestamp"] <= inc_end:
            user_match = (rt["user"] in inc["users"])
            host_match = (rt["source_host"] in inc["hosts"] or rt["destination_host"] in inc["hosts"])
            if user_match or host_match:
                matched_attacks.add(rt_idx)
                tp_incidents.add(inc["incident_id"])
```

### 1. Resolution: Why Captured Attacks (60) Differ from TP Incidents (5)
In the Tier 2 results at 0s tolerance:
- **Total Attack Records Captured:** 60 records (28.71% attack coverage).
- **Confirmed TP Incidents:** 5 incidents (0.29% incident precision).

**Explanation:**
1. **Many-to-One Spatio-Temporal Concentration:**
   - Forensic inspection of `test_redteam` reveals extreme entity concentration: **206 out of the 209 test attack records originated from a single host: `C17693`**, and 69 originated from user `U66@DOM1`.
   - The red-team campaign executed rapid, multi-stage actions within short time windows.
   - When the Multi-Agent pipeline synthesized an active incident covering `C17693` during an attack burst, that **single incident subsumed dozens of discrete attack records** (averaging 12 attack records per confirmed incident).
2. **Strict Deduplication:**
   - Both `matched_attacks` and `tp_incidents` are Python `set()` objects. Each attack record is counted at most once toward attack recall, and each incident is counted at most once toward incident precision.
3. **Precision Dilution:**
   - The multi-agent pipeline synthesized 1,754 incidents across the held-out test day.
   - Because only 5 of those incidents overlapped with ground-truth attack records, **1,749 incidents (99.71%) are benign false-alarm incidents**, resulting in an incident precision of `0.29%`.

### 2. Verified vs Unverified Status
- **VERIFIED:** The spatio-temporal matching loop, deduplication logic, and mathematical formulas for attack coverage and incident precision are correct and verified.
- **UNVERIFIED:** Whether the native events inside the 5 matching incidents reflect genuine malicious execution telemetry or coincidental benign activity from the same user/host at that timestamp cannot be definitively proven without full ground-truth provenance tracing.

---

## Section E: Audit of Compression Terminology

In earlier reports, the ratio between the 57,825 flagged specialist alerts and the 1,754 synthesized incidents (`57,825 / 1,754 = 32.97x`) was described as "alert reduction" or "compression".

### 1. Conceptual & Dimensional Audit
- **Dimensional Mismatch:**
  - The numerator (`57,825`) counts **atomic telemetry events** (individual log lines).
  - The denominator (`1,754`) counts **composite incident clusters** (multi-event temporal groupings).
  - Comparing atomic events to composite incident cases is a dimensional mismatch.
- **Clustering vs False-Positive Suppression:**
  - An average incident cluster contains ~33 events by construction.
  - Converting 57,825 raw alerts into 1,754 incident cases groups raw alerts into investigation tickets.
  - However, because **1,749 of those 1,754 incidents are false alarms**, this clustering **did NOT eliminate false positives**; it merely aggregated them into fewer, larger tickets.

### 2. Recommended Corrected Terminology
To prevent misleading readers or peer reviewers:
- **Do NOT use:** "33x false positive reduction" or "33x alert suppression".
- **DO use:** **"33x Incident Aggregation Factor"** or **"Event-to-Case Structuring Ratio"** (`32.97 raw alerts per investigation case`).
- Explicitly state that aggregation structures raw telemetry for human review but does not substitute for quantitative false-positive suppression.

---

## Section F: Summary of Verified Facts, Concerns, and Recommendations

### 1. Summary of Confirmed Facts
1. All 289 window-level predictions and metrics in [`results/phase3/phase3b_four_way_comparison.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3/phase3b_four_way_comparison.csv) recalculate with 100% precision from raw saved prediction vectors.
2. In the four-way benchmark, the **Random Forest ML Baseline** is the top-performing quantitative triage gate:
   - SOC Mode (`0.9300`): Precision: 68.18%, Recall: 46.88%, F1: 55.56%, **FPR: 6.22%**, Accuracy: 83.39%.
   - Balanced Mode (`0.8459`): Precision: 56.25%, Recall: 56.25%, F1: 56.25%, **FPR: 12.44%**, Accuracy: 80.62%.
3. The **Isolated Graph-Only Baseline** saturates completely (`100% FPR`, `0% Specificity`), demonstrating that topological connectivity without domain scoring cannot filter enterprise traffic.
4. The **Rule-Based SIEM** achieves 100% recall but suffers from a **72.00% FPR** (226 alert windows).
5. The **AI Investigator Multi-Agent** achieves 100% recall but has a **74.67% FPR** (232 alert windows), with lower F1 (43.24%) and lower accuracy (41.87%) than the SIEM baseline.

### 2. Unresolved Concerns
1. **Training Partition Contamination:** The historical `best_model.joblib` was trained on data containing 273 synthetic red-team rows in the training split. While test inference is clean, full methodological purity requires retraining on native telemetry only.
2. **High Incident False Alarm Rate:** Synthesizing 1,754 incidents with only 5 to 21 confirmed attack incidents across tolerances indicates that specialist agent thresholding is overly sensitive on native background telemetry.

### 3. Actionable Recommendations for Subsequent Phases
1. **Adopt Accurate Paper Claims:**
   - Frame Random Forest as the **Quantitative Operational Triage Gate** (6.22% FPR, 83.39% accuracy).
   - Frame Multi-Agent as the **Qualitative Forensic Investigator** (synthesizing evidence timelines and MITRE tactics after an alert is gated).
   - Acknowledge that naive graph topology on raw telemetry fails in enterprise networks.
2. **Model Retraining Gate (Phase 4):**
   - Retrain Random Forest strictly on native telemetry training/validation partitions to ensure zero synthetic row influence across the entire model lifecycle.

---
*Report generated and locked by Phase 3B.1 Independent Audit Agent. Awaiting user review and authorization.*

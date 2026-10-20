# FINAL VISUAL AND RESULTS AUDIT REPORT

## Executive Summary
This document provides an exhaustive, forensic verification of all numerical results, figures, charts, diagrams, and operational threshold claims across the AI Investigator project.

Every claim and visual was traced to its authoritative underlying data artifacts:
1. Benchmark B Validation: 
esults/phase4/validation_predictions.csv (N = 936, Positives = 50, Prevalence = 0.0534).
2. Benchmark C Candidate Validation: 
esults/phase5b/active_host_window/validation_predictions.csv (N = 82,254, Positives = 13, Prevalence = 0.000158).
3. Benchmark C L1 Logistic Regression Validation: Evaluated directly from candidate feature matrices al_active_host_windows.csv.

---

## 1. Mandatory Operational Threshold 0.58 Audit

### 1.1 The Discrepancy Caught
- **Historical Draft Claim:** Setting decision threshold T = 0.58 curtails alert volume to **14.10 alerts/hour**.
- **Audit Requirement:** Recompute directly from the authoritative validation prediction scores across the exact 78.0-hour validation partition ([756000, 1036800)).
- **Audit Findings:**
  - Validation duration: 1036800 - 756000 = 280,800 seconds = **78.0 hours**.
  - Total validation instances: **82,254 active host-windows**.
  - Total ground-truth attack instances: **13 host-windows** (prevalence = 158.05 ppm).

### 1.2 Exact Recalculated Threshold Metrics Table
The table below details the exact empirical performance of the two candidate models at threshold 0.58 and adjacent thresholds:

| Model | Threshold | Alerts (78h) | Alerts / Hour | TP | FP | FN | TN | Precision | Recall | Specificity | FPR | F1-Score | FDR (1-Prec) | Status / Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Historical Claim** | 0.58 | ~1,100 | **14.10** | Unrep. | Unrep. | Unrep. | Unrep. | 0.00091 | Unrep. | Unrep. | Unrep. | Unrep. | Unrep. | **FAIL (Unreproducible)** |
| **Candidate RF (Audited)** | 0.50 | 57,780 | 740.77 | 9 | 57,771 | 4 | 24,470 | 0.000156 | 0.6923 | 0.2975 | 0.7025 | 0.000311 | 0.99984 | Verified Empirical |
| **Candidate RF (Audited)** | 0.55 | 6,406 | 82.13 | 1 | 6,405 | 12 | 75,836 | 0.000156 | 0.0769 | 0.9221 | 0.0779 | 0.000312 | 0.99984 | Verified Empirical |
| **Candidate RF (Audited)** | **0.58** | **6,406** | **82.13** | **1** | **6,405** | **12** | **75,836** | **0.000156** | **0.0769** | **0.9221** | **0.0779** | **0.000312** | **0.99984** | **CORRECTED AUDIT BASELINE** |
| **Candidate RF (Audited)** | 0.583 | 6,406 | 82.13 | 1 | 6,405 | 12 | 75,836 | 0.000156 | 0.0769 | 0.9221 | 0.0779 | 0.000312 | 0.99984 | Sharp cliff boundary |
| **Candidate RF (Audited)** | >=0.585 | 0 | 0.00 | 0 | 0 | 13 | 82,241 | 0.000000 | 0.0000 | 1.0000 | 0.0000 | 0.000000 | N/A | Predicts zero positives |
| **Candidate L1-LR** | 0.50 | 43,355 | 555.83 | 8 | 43,347 | 5 | 38,894 | 0.000185 | 0.6154 | 0.4729 | 0.5271 | 0.000369 | 0.99981 | Verified Empirical |
| **Candidate L1-LR** | **0.58** | **32,645** | **418.53** | **7** | **32,638** | **6** | **49,603** | **0.000214** | **0.5385** | **0.6031** | **0.3969** | **0.000429** | **0.99979** | L1 Logistic Model |
| **Candidate L1-LR** | 0.65 | 6,815 | 87.37 | 1 | 6,814 | 12 | 75,427 | 0.000147 | 0.0769 | 0.9171 | 0.0829 | 0.000293 | 0.99985 | High-threshold L1 |

### 1.3 Forensic Determination
The previously quoted alert rate of 14.10 alerts/hour was an unverified heuristic estimate. The true empirical rate of the candidate Random Forest at T = 0.58 is **82.13 alerts/hour** (6,406 alerts across 78 hours).
All reports, papers, and submission documents have been updated to reflect the true empirical alert rate of 82.13 alerts/hour.

---

## 2. Complete Visual and Graphical Assets Audit

A total of 42 image assets were inspected across 
esults/figures/, 
esults/figures/verified/, presentation_mockup/figures/, and 
esults/figures/verified_benchmark_c/.

| Visual Filename | Location | Document Referenced | Source Data / Origin | Displayed Values | Expected Verified Values | Verification Status | Action / Correction |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| ig01_confusion_matrix.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype N=289 test run (historical) | TN=211, FP=14, FN=32, TP=32; Prec=69.57%, Rec=50% | Benchmark B: TN=598, FP=288, FN=38, TP=12 | **FAIL** | Marked as superseded historical mockup; excluded from final paper. |
| ig02_roc_curve.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype N=289 test run (historical) | ROC-AUC = 0.6874 | Benchmark B: 0.3938; Benchmark C: 0.5561 | **FAIL** | Superseded. Replaced by erified_benchmark_c/fig01_verified_roc_curves.png. |
| ig03_precision_recall_curve.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype N=289 test run (historical) | AP = 0.5670 | Benchmark B: 0.0454; Benchmark C: 0.000247 | **FAIL** | Superseded. Replaced by erified_benchmark_c/fig02_verified_pr_curves.png. |
| ig04_model_comparison.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype comparative mockups | RF: 69.57% Prec, 50% Rec | RF Benchmark B: 4.0% Prec, 24% Rec; RF Benchmark C: 0.02% Prec, 69.2% Rec | **FAIL** | Superseded prototype graphic. Not included in submission DOCX/PDF. |
| ig05_threshold_tradeoff.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype threshold sweep | Threshold sweep 0.50-0.98 on N=289 | Threshold sweep on 82,254 instances; T=0.58 yields 82.13 alerts/hr | **FAIL** | Superseded. Replaced by erified_benchmark_c/fig03_verified_alert_burden_threshold.png. |
| ig06_feature_importance.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype 23 features | uth_fail_count (18.4%), dmin_user_logons (15.2%) | Candidate top features: delta_events (+1.1965), is_src (+1.0297) | **FAIL** | Superseded prototype graphic. |
| ig07_attack_detection_summary.png | 
esults/figures/verified/ | Superseded Phase 2 report | Red-team timeline mockup | Timeline of attacks across days 1-14 | Days 9-12 timeline (Day 9 Train: 60 pos, Days 10-12 Val: 50 pos) | **FAIL** | Superseded prototype graphic. |
| ig08_score_distribution.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype risk scores | Illustrative score distribution | Benchmark B inverted score distribution | **FAIL** | Superseded prototype graphic. |
| ig09_dataset_summary.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype event counters | Event breakdown | 120,000 stratified samples (480 hourly strata) | **FAIL** | Superseded prototype graphic. |
| ig10_threshold_cm_comparison.png | 
esults/figures/verified/ | Superseded Phase 2 report | Prototype threshold comparison | N=289 comparisons | 82,254 host-window comparisons | **FAIL** | Superseded prototype graphic. |
| system_architecture.png | presentation_mockup/figures/ | Architecture Overview | Engineering design | 7-stage architectural workflow | Matches code structure in src/agents/ | **PASS (Conceptual)** | Valid architectural schematic. |
| dataset_feature_pipeline.png | presentation_mockup/figures/ | Architecture Overview | Engineering design | 4-family feature extraction pipeline | Matches pipeline in src/day4_preprocess.py | **PASS (Conceptual)** | Valid pipeline schematic. |
| multi_agent_workflow.png | presentation_mockup/figures/ | Architecture Overview | Engineering design | Multi-agent specialist investigation layer | Matches multi-agent design in src/agents/ | **PASS (Conceptual)** | Valid design schematic. |
| ig01_verified_roc_curves.png | 
esults/figures/verified_benchmark_c/ | Submission Artifacts | phase4 & phase5b CSVs | Benchmark B AUC = 0.3938; Benchmark C AUC = 0.5398 | Exactly matches audited validation predictions | **PASS (Verified)** | Generated from verified predictions. |
| ig02_verified_pr_curves.png | 
esults/figures/verified_benchmark_c/ | Submission Artifacts | phase4 & phase5b CSVs | Benchmark B AP = 0.0454; Benchmark C AP = 0.000224 | Exactly matches audited validation predictions | **PASS (Verified)** | Generated from verified predictions. |
| ig03_verified_alert_burden_threshold.png | 
esults/figures/verified_benchmark_c/ | Submission Artifacts | phase5b CSV | Alert rate curve; T=0.58 = 82.13 alerts/hr | Exactly matches audited validation predictions | **PASS (Verified)** | Generated from verified predictions. |

---

## 3. Fair Model Comparison & Evaluation Units Audit

| Dimension | Benchmark B (Baseline) | Benchmark C (Candidate) | Scientifically Defensible Conclusion |
| :--- | :--- | :--- | :--- |
| **Prediction Unit** | Global 300-second Enterprise Window | Active Host-Window instance (h, W_k) | **Different prediction units.** Cannot be compared without normalizing base rates. |
| **Validation Sample Size (N)** | 936 windows | 82,254 active host-windows | Benchmark C evaluates 87.8x more discrete decision instances. |
| **Validation Attacks (P)** | 50 windows | 13 host-windows | Low attack count in Benchmark C makes evaluation highly sensitive. |
| **Class Prevalence (P/N)** | **0.0534 (5.34%)** | **0.000158 (0.0158% / 158 ppm)** | Extreme disparity (338x difference in positive concentration). |
| **Raw Average Precision** | 0.0454 | 0.000247 (L1-LR) / 0.000224 (RF) | Direct numerical AP comparison is invalid (0.000247 < 0.0454). |
| **Normalized AP / Base Rate** | **0.85x base rate** (Below Chance) | **1.56x base rate** (Above Chance) | Benchmark C candidate achieves genuine above-chance discrimination. |
| **ROC-AUC** | 0.3938 (Severe Inversion) | 0.5561 (L1-LR) / 0.5398 (RF) | Removing diurnal shortcut eliminates ranking inversion. |
| **Attack Recall** | 24.0% (at default T=0.5) | **61.5% - 69.2%** (at default T=0.5) | Host-window features capture 8-9 of 13 true attacks on unseen data. |
| **Alert Burden (T=0.58)** | 0.00 alerts/hour | **82.13 alerts/hour** (6,406 alerts / 78h) | Real-world deployment requires second-stage graph correlation. |

---

## 4. Final Verification Summary
- **Benchmark B Metrics:** 100% REPRODUCED AND VERIFIED (ROC-AUC = 0.3938, AP = 0.0454).
- **Benchmark C Metrics:** 100% REPRODUCED AND VERIFIED (ROC-AUC = 0.5561, AP = 0.000247, Recall = 61.54%).
- **Threshold 0.58 Discrepancy:** RESOLVED AND CORRECTED to 82.13 alerts/hour.
- **Obsolete Visual Assets:** Fully identified, cataloged, marked FAIL/SUPERSEDED, and excluded from final papers.
- **New Verified Visual Assets:** Regenerated directly from authoritative prediction files and stored under 
esults/figures/verified_benchmark_c/.

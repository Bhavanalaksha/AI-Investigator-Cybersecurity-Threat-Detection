# Final Clean, Leakage-Free LANL Threat Detection Evaluation Report

## 1. Previous Leaked Methodology
In the original implementation:
- Evaluation was conducted on a flat event-by-event triage heuristic threshold (`risk_score >= 3`).
- Over 58,885 background events crossed this threshold, resulting in an unviable Precision of 0.84% and F1-Score of 1.66% on the raw event level.
- Despite low Precision, an artificially high ROC-AUC of 0.999356 was observed due to direct label and entity contamination.

---

## 2. Leakage Sources Identified
A comprehensive code audit identified four critical flaws:
1. **Target Label Injection in Triage Engine:** In `src/day5_triage.py`, `if is_rt == 1: score += 3` added 3 risk points directly to any event marked as Red-Team.
2. **Evaluation Bypass in Agents:** In `auth_agent.py`, `process_agent.py`, and `network_agent.py`, the condition `if ev_score >= 3 or is_rt == 1:` automatically flagged ground-truth attacks regardless of behavioral evidence.
3. **Target Entity Contamination:** Attack usernames and hostnames extracted from the ground-truth test file (`redteam.txt`) were passed into agents as pre-seeded IOC rules (`R8_REDTEAM_USER`, `R9_REDTEAM_HOST`).
4. **Lack of Chronological Partitioning:** Telemetry from Days 9 to 13 was evaluated as a single un-partitioned batch.

---

## 3. Leakage Removal
Every leakage pathway has been permanently eliminated:
- Removed all `if is_rt == 1` scoring and classification bypasses across all agent files.
- Emptied all pre-seeded test threat entity lists (`attack_users = set()`, `attack_hosts = set()`). Agents must identify anomalies strictly from learned behavioral distributions.
- Red-Team labels (`redteam.txt`) are utilized **strictly after predictions are generated** for independent metric calculation.

---

## 4. Dataset Overview
- **Source:** Los Alamos National Laboratory (LANL) Comprehensive Cyber Security Dataset.
- **Scope:** 130,497 total events spanning Days 9 to 14 across Authentication (AUTH), Process Lineage (PROCESS), Domain Name System (DNS), and Network Flow (FLOW).
- **Ground Truth:** 497 validated Red-Team adversarial actions occurring on Day 9 (273 events), Day 10 (15 events), and Day 13 (209 events).

---

## 5. Chronological Train / Validation / Test Split
To guarantee zero future information leakage, the timeline is partitioned into three non-overlapping chronological segments:
- **TRAIN PERIOD (Day 9, timestamp <= 777,600):**
  - Raw Events: 16,049
  - Window Vectors: 1,387 windows (207 attack windows, 14.92% prevalence)
  - Purpose: Behavioral baseline construction, frequency distributions, and model training.
- **VALIDATION PERIOD (Days 10-12, 777,600 < timestamp <= 1,036,800):**
  - Raw Events: 6,861
  - Window Vectors: 3,303 windows (2 attack windows, 0.06% prevalence)
  - Purpose: Window size evaluation, hyperparameter tuning, and decision threshold optimization.
- **TEST PERIOD (Days 13-14, timestamp > 1,036,800):**
  - Raw Events: 107,587
  - Window Vectors: 1,432 windows (136 attack windows, 9.50% prevalence)
  - Purpose: Single-pass final evaluation. **Untouched during training and tuning.**

---

## 6. Label Construction & Window-Level Methodology
- **Temporal Windows:** Events are grouped into non-overlapping temporal windows.
- **Window Size Selection:** Evaluated window sizes of 10s, 30s, 60s, and 300s on validation data. Selected and **frozen at 60 seconds (1 minute)** to balance temporal precision with cross-source feature density.
- **Target Variable:** `y = 1` if a window contains at least one ground-truth Red-Team event (`redteam.txt`); `y = 0` otherwise.

---

## 7. Feature Engineering
Each 60-second window is converted into a structured vector using only information observable up to the prediction time:
1. **Authentication:** Total auth count, failed authentication count, fail ratio, NTLM count, off-hours authentication count, unique users, unique destination hosts.
2. **Process Execution:** Total process spawn count, unique process names, rare process count (frequency <= 5 in train baseline), unique hosts, process burst max.
3. **DNS & Flow:** DNS query count, unique DNS destinations, flow connection count, unique source/destination IPs.
4. **Cross-Source Corroboration:** Total event count across sources, count of active telemetry sources (1 to 4), multi-source corroboration indicator.

---

## 8. Models Evaluated
Four standard machine learning architectures were trained:
1. **Logistic Regression:** Linear baseline with balanced class weights (`class_weight='balanced'`).
2. **Random Forest Classifier:** Ensemble of 100 decision trees (`max_depth=8`, balanced subsample weights).
3. **HistGradientBoosting Classifier:** Gradient-boosted decision trees handling class imbalance.
4. **Isolation Forest:** Unsupervised anomaly detector fit strictly on benign training windows (`contamination=0.05`).

---

## 9. Hyperparameters & Threshold Selection
- Models were trained strictly on the **Train set**.
- Probability predictions were generated on the **Validation set**.
- Thresholds were swept from 0.01 to 0.99 to maximize the Validation F1-Score.
- The resulting optimal thresholds were **frozen**:
  - Logistic Regression: 0.98
  - Random Forest: 0.99
  - HistGradientBoosting: 0.01
  - Isolation Forest: 0.68

---

## 10. Final Test Set Benchmark Results (Unseen Days 13-14)

| Model | TP | TN | FP | FN | Precision (%) | Recall (%) | F1 (%) | Accuracy (%) | Specificity (%) | FPR (%) | ROC-AUC | PR-AUC | Frozen Threshold |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 136 | 159 | 1137 | 0 | 10.68 | 100.00 | 19.30 | 20.60 | 12.27 | 87.73 | 0.6522 | 0.1312 | 0.98 |
| **Random Forest (Best)** | **63** | **1110** | **186** | **73** | **25.30** | **46.32** | **32.73** | **81.91** | **85.65** | **14.35** | **0.7596** | **0.2517** | **0.99** |
| **HistGradientBoosting** | 136 | 49 | 1247 | 0 | 9.83 | 100.00 | 17.91 | 12.92 | 3.78 | 96.22 | 0.5189 | 0.0983 | 0.01 |
| **Isolation Forest** | 54 | 409 | 887 | 82 | 5.74 | 39.71 | 10.03 | 32.33 | 31.56 | 68.44 | 0.3232 | 0.0680 | 0.68 |

### Model Selection Rationale:
**Random Forest** is selected as the top detector because it achieves the highest F1-Score (32.73%), highest PR-AUC (0.2517), highest ROC-AUC (0.7596), and lowest False Positive Rate (14.35%), maintaining an Accuracy of 81.91%.

---

## 11. Confusion Matrix Verification (Best Model: Random Forest)

| | Predicted Benign | Predicted Attack | Total |
|---|---|---|---|
| **Actual Benign Windows** | **TN = 1,110** | **FP = 186** | 1,296 |
| **Actual Attack Windows** | **FN = 73** | **TP = 63** | 136 |
| **Total** | 1,183 | 249 | 1,432 |

- **Precision:** 63 / (63 + 186) = 25.30%
- **Recall:** 63 / (63 + 73) = 46.32%
- **F1-Score:** 2 * (0.2530 * 0.4632) / (0.2530 + 0.4632) = 32.73% (0.3273)
- **Accuracy:** (63 + 1110) / 1432 = 81.91%
- **Specificity:** 1110 / (1110 + 186) = 85.65%
- **FPR:** 186 / (1110 + 186) = 14.35%
- **FNR:** 73 / (63 + 73) = 53.68%
- **Prevalence:** 136 / 1432 = 9.50%

---

## 12. Investigation into ROC-AUC Drop
- **Previous Leaked Score:** ROC-AUC = 0.999356
- **Clean Genuine Score:** ROC-AUC = 0.7596, PR-AUC = 0.2517
- **Root Cause Analysis:** The previous ROC-AUC was near 1.0 because the ground-truth label bonus (`if is_rt == 1: score += 3`) and pre-seeded Red-Team user/host lists systematically gave attack events higher scores than background traffic. Once all label and entity leakages were removed, the clean ROC-AUC dropped to 0.7596. This is a realistic, defensible result reflecting genuine generalization on unseen adversarial telemetry.

---

## 13. Incremental Architectural Ablation Study

| Stage | Evaluated Components | Precision (%) | Recall (%) | F1 (%) | PR-AUC | FPR (%) |
|---|---|---|---|---|---|---|
| **Stage A** | Basic Event & Auth Counts Baseline | 3.41 | 10.29 | 5.12 | 0.0862 | 30.63 |
| **Stage B** | + Behavioral Features (Off-Hours, Rare Procs) | 3.41 | 10.29 | 5.12 | 0.0862 | 30.63 |
| **Stage C** | + Multi-Source Features (DNS, Flow, Diversity) | 25.30 | 46.32 | 32.73 | 0.2517 | 14.35 |
| **Stage D** | + Temporal Correlation (Sliding Window Graph) | 18.56 | 68.38 | 29.20 | 0.2467 | 31.48 |
| **Stage E** | **Full Multi-Agent Pipeline (Specialists + Corroboration)** | **19.61** | **66.91** | **30.33** | **0.2467** | **28.78** |

### Insights:
- Multi-source features (Stage C) provide the single largest boost in precision (jumping from 3.41% to 25.30%) and cut false positive rates by more than half (30.63% to 14.35%).
- Temporal correlation and multi-agent corroboration (Stages D & E) elevate recall to 66.91%, capturing two-thirds of all adversarial windows.

---

## 14. Controlled Synthetic Attack Demonstration (`test_attack.csv`)
- **Telemetry File:** `test_attack.csv` (39 raw events, 15 60-second windows)
- **Status:** Unseen during all training, validation, and feature development.
- **Results:**
  - Suspicious Windows Detected: 1 / 15
  - Peak Model Risk Score: 100.0 / 100
  - Contributing Specialist Agents: AuthenticationAgent, ProcessAgent, CorrelationAgent
  - Detected Pattern: Lateral Kerberos credential hopping followed by anomalous process invocation.
  - Recommended Advisory Response: Host endpoint isolation, session invalidation, and Tier-3 SOC analyst escalation.

---

## 15. Limitations
1. **Extreme Class Imbalance:** Adversarial actions constitute a small fraction of real enterprise telemetry (0.38% of events, 9.50% of test windows).
2. **Behavioral Normalcy Overlap:** Living-off-the-land techniques use legitimate admin tools, causing background admin activity to trigger false positives.
3. **Absence of Host Payload Inspection:** LANL provides anonymized connection and process metadata without command-line arguments or payload text.

---

## 16. Reproducibility
The clean, leakage-free experiment can be reproduced with a single command:
```powershell
python src/clean_experiment.py
```
Outputs are automatically written to:
- `results/reports/final_model_comparison.csv`
- `results/reports/clean_ablation_results.csv`
- `results/reports/leakage_fixed.md`
- `results/reports/final_clean_evaluation.md`

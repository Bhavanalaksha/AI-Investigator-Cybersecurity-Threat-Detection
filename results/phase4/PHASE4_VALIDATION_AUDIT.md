# Phase 3C.3.1 Gate 4: Independent Validation Audit Report

**Status:** Completed and Audited  
**Phase:** Phase 3C.3.1 - Gate 4 Independent Validation Audit  
**Date:** October 20, 2026  
**Auditor / System:** AI Investigator Independent Audit Subsystem  
**Audit Scope:** Read-Only Audit of Stage B Model Training and Validation Artifacts under [`results/phase4/`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4)  
**Evaluated Data Artifact:** [`results/phase4/validation_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/validation_predictions.csv)  
**Evaluated Model Artifact:** [`results/phase4/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/clean_rf_model.joblib)  

---

## 1. Executive Summary & Audit Verdict

In accordance with strict research directives, an independent, read-only audit of the Phase 4 clean model training and validation artifacts was conducted before Gate 5 approval. 

### Key Audit Findings
1. **Metric Verification (Item 1):** Directly recalculated all metrics from [`results/phase4/validation_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/validation_predictions.csv). The reported Validation ROC-AUC (**0.3938**), PR-AUC (**0.0454**), and all four operating point confusion matrices match the serialized logs bit-for-bit.
2. **PR-AUC Baseline & Area Metric (Item 2):** In the validation partition, there are 50 positive windows out of 936 total windows, establishing an exact random guessing baseline prevalence of **0.053419 (5.34%)**. The reported PR-AUC of **0.045414** is derived using Scikit-Learn's default `average_precision_score` (step-function interpolation). Trapezoidal area under the PR curve (`auc(recalls, precisions)`) yields **0.043537**. Both area metrics are below the random baseline (~0.85x) because the model assigns lower probability scores to attack windows than to benign windows.
3. **Score Distribution & Inversion Audit (Item 3):** The sub-0.50 ROC-AUC (0.3938) reflects a **statistically significant, genuine ranking inversion** (Mann-Whitney U = 17,446.0, p = 0.0114), not a software bug, not a score-column inversion, and not a label assignment error. In the validation set:
   - Attack windows received a mean predicted probability of **0.2843** (median: **0.1801**).
   - Benign windows received a mean predicted probability of **0.3646** (median: **0.3821**).
   - `model.classes_` was verified as `[0, 1]`, and column 1 ($P(Y=1|X)$) was correctly ingested throughout.
4. **Training Overfitting (Item 4):** The reported Train ROC-AUC of **1.0000** and PR-AUC of **1.0000** were verified on `X_train_scaled`. The ensemble of 100 trees with `max_depth=8` averages 26.9 leaves per tree, effectively memorizing the 216 training instances (8 samples per leaf). The resulting generalization gap is massive: $\Delta\text{ROC-AUC} = 1.0000 - 0.3938 = \mathbf{0.6062}$.
5. **Diurnal Correlation Inversion (`auth_off_hours`) (Item 5):** The root cause of the ranking inversion was empirically isolated to diurnal feature dynamics:
   - In Train (Day 9, 00:00–18:00), all 60 attacks occurred during daytime business hours (mean `auth_off_hours` = **0.00**; 0.0% > 0), whereas benign night windows had high off-hours auth (mean = **19.23**; 46.2% > 0). The model assigned `auth_off_hours` **21.4% of total feature importance**, learning that off-hours activity was benign.
   - In Validation (Days 10–12), attacks shifted to night hours (mean `auth_off_hours` = **27.56**; 66.0% > 0). When attack windows arrived with high off-hours volume, the model suppressed attack probabilities, causing inverted rankings.
6. **Pipeline Consistency (Item 6):** Feature ordering (23 columns), scaler mean/variance alignment, contiguous non-overlapping temporal boundaries, and post-hoc label matching are 100% mathematically consistent between Train and Validation.
7. **Zero-Variance Features (Item 7):** `active_sources` (= 4) and `multi_source_flag` (= 1) are constant across all 1,152 windows because uniform stratified sampling guarantees that all 4 modalities are represented in every single 300s window. They contribute 0.00% split information and should be pruned.
8. **Held-Out Test Partition Isolation (Item 8):** **Verified 100% untouched.** Zero test data rows, features, labels, predictions, or metrics were loaded, computed, or evaluated.

**Audit Verdict:** **PHASE 4 VALIDATION RESULTS ARE RIGOROUSLY VERIFIED AND METHODOLOGICALLY HONEST. THE SUB-0.50 GENERALIZATION ARISES FROM GENUINE TEMPORAL COVARIATE SHIFT AND DIURNAL SHORTCUT INVERSION, NOT METHODOLOGICAL ERROR.**

---

## 2. Item 1: Verification of Validation Metrics directly from CSV

All validation evaluation metrics were independently recomputed directly from the 936 rows of [`results/phase4/validation_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/validation_predictions.csv) and cross-checked against [`results/phase4/training_validation_log.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/training_validation_log.json):

```python
# Validation ground truth: is_attack (50 positives, 886 negatives)
# Validation predicted probability: y_prob
calc_roc_auc = roc_auc_score(y_true, y_prob)  # Result: 0.393815
calc_pr_auc = average_precision_score(y_true, y_prob)  # Result: 0.045414
```

### 2.1 Confusion Matrix & Threshold Re-Verification
| Operating Point | Threshold ($T$) | TP | FP | TN | FN | Precision | Recall | F1-Score | Accuracy | Audit Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Default Threshold** | **0.5000** | 12 | 288 | 598 | 38 | 0.0400 | 0.2400 | 0.0686 | 0.6517 | **VERIFIED EXACT** |
| **Optimal F1 Point** | **0.0409** | 50 | 886 | 0 | 0 | 0.0534 | 1.0000 | 0.1014 | 0.0534 | **VERIFIED EXACT** |
| **High Precision Point** | **0.8000** | 0 | 2 | 884 | 50 | 0.0000 | 0.0000 | 0.0000 | 0.9444 | **VERIFIED EXACT** |
| **High Recall Point** | **0.0409** | 50 | 886 | 0 | 0 | 0.0534 | 1.0000 | 0.1014 | 0.0534 | **VERIFIED EXACT** |

**Audit Finding:** All metrics, confusion counts, and thresholds in the Phase 4 report are 100% reproducible directly from the saved CSV.

---

## 3. Item 2: PR-AUC Baseline & Area Metric Definitions

In binary classification with imbalanced datasets, the area under the Precision-Recall curve must always be interpreted against the positive class prevalence baseline:

### 2.1 Empirical Parameters
- Validation window count ($N$): **936 windows**
- Validation attack window count ($P$): **50 windows**
- Baseline Random Guessing Prevalence ($P / N$): **0.053419 (5.34%)**

### 2.2 Mathematical PR Area Definitions
Two standard definitions of PR area exist in literature:
1. **Average Precision (AP) (Scikit-Learn `average_precision_score`):**
   $$\text{AP} = \sum_{n} (R_n - R_{n-1}) P_n$$
   Evaluated on `validation_predictions.csv`, $\text{AP} = \mathbf{0.045414}$.
2. **Trapezoidal PR-AUC (`sklearn.metrics.auc(recalls, precisions)`):**
   Calculated by trapezoidal integration of the piecewise linear interpolation between PR curve points.
   Evaluated on `validation_predictions.csv`, $\text{AUC}_{\text{PR, trap}} = \mathbf{0.043537}$.

### 2.3 Interpretation
- A non-informative random classifier achieves an expected Average Precision equal to the prevalence: $\text{AP}_{\text{random}} = 0.053419$.
- The trained clean model achieves $\text{AP} = 0.045414$, which is **$0.008005$ below the random baseline ($0.850\text{x}$ random)**.
- This sub-baseline PR performance is mathematically expected whenever ROC-AUC is below 0.50: the highest probability thresholds select disproportionately more benign windows than attack windows, pulling precision at the top of the ranked list below random chance.

---

## 4. Item 3: Inspection of Predicted Probability Distribution & Inversion Check

To investigate whether the ROC-AUC of 0.3938 was caused by an implementation error (such as reading the wrong probability column, inverting ground truth labels, or an indexing bug), the distribution of predicted probabilities was analyzed by class:

### 3.1 Probability Distributions by Class
```
+----------------------------------------------------------------------------------------------------+
| VALIDATION PREDICTED PROBABILITY DISTRIBUTION (N = 936)                                            |
+--------------------------+---------------------+---------------------+---------------------+
| Distribution Parameter   | Attack Windows (Y=1)| Benign Windows (Y=0)| Full Validation Set |
+--------------------------+---------------------+---------------------+---------------------+
| Sample Count (N)         | 50 windows          | 886 windows         | 936 windows         |
| Mean Probability         | 0.2843              | 0.3646              | 0.3603              |
| Standard Deviation       | 0.2057              | 0.2024              | 0.2033              |
| Minimum Probability      | 0.0409              | 0.0439              | 0.0409              |
| 25th Percentile (Q1)     | 0.1280              | 0.1636              | 0.1584              |
| Median Probability (Q2)  | 0.1801              | 0.3821              | 0.3704              |
| 75th Percentile (Q3)     | 0.4762              | 0.5379              | 0.5375              |
| Maximum Probability      | 0.7009              | 0.8617              | 0.8617              |
+--------------------------+---------------------+---------------------+---------------------+
```

### 3.2 Non-Parametric Rank-Sum Verification (Mann-Whitney U Test)
The non-parametric Mann-Whitney U test between positive and negative predictions was evaluated:
- **Mann-Whitney U Statistic:** $U = 17,446.0$
- **Total Possible Pairs:** $n_1 \times n_0 = 50 \times 886 = 44,300$
- **Empirical ROC-AUC:**
  $$\text{AUC} = \frac{U}{n_1 n_0} = \frac{17,446.0}{44,300} = \mathbf{0.393815}$$
- **Two-Sided P-Value:** $p = \mathbf{0.01144}$ ($p < 0.05$)

### 3.3 Integrity Check of Potential Bugs
1. **Did `predict_proba` select the wrong column?**
   - Direct inspection of [`results/phase4/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/clean_rf_model.joblib) reveals `rf_model.classes_ = array([0, 1])`.
   - The code accessed `rf_model.predict_proba(X_val_scaled)[:, 1]`. Column 1 strictly represents $P(Y=1|X)$. There is no score-column inversion.
2. **Was ground truth flipped?**
   - Direct inspection of `is_attack` in `validation_predictions.csv` shows 50 positive windows and 886 negative windows. This matches the 50 attack intervals in `data/raw/redteam.txt`. Labels were not flipped.
3. **Conclusion:** The sub-0.50 ROC-AUC is a **genuine empirical ranking inversion**. On average, benign windows received higher threat scores than actual attack windows. If scores were inverted ($1 - P$), ROC-AUC would be $1 - 0.3938 = \mathbf{0.6062}$.

---

## 5. Item 4: Training Performance & Overfitting Audit

### 4.1 Training Metric Re-Verification
The model was re-evaluated on the 216 training windows (`X_train_scaled`, `y_train`):
- **Train Sample Count:** 216 windows (60 attack windows, 156 benign windows; prevalence = 27.78%)
- **Re-Evaluated Train ROC-AUC:** **1.0000**
- **Re-Evaluated Train PR-AUC:** **1.0000**
- **Train Confusion Matrix at T=0.50:** $\text{TP} = 60, \text{FP} = 0, \text{TN} = 156, \text{FN} = 0$ (Zero training errors).

### 4.2 Structural Tree Complexity Analysis
To determine how the ensemble achieved 100% training accuracy:
- **Number of Estimators:** 100 decision trees.
- **Configured Maximum Depth:** 8.
- **Empirical Tree Depths:** All 100 trees reached the maximum allowed depth of **8.0** ($\min=8, \max=8, \text{std}=0.0$).
- **Number of Leaves per Tree:** Mean = **26.9 leaves** ($\min=21, \max=33$).
- **Sample Density per Leaf:** Across 216 training instances, 26.9 leaves per tree means each leaf node contains an average of only **8.0 training instances** ($216 / 26.9$).
- **Finding:** With 23 continuous features and `class_weight='balanced'`, unpruned depth-8 trees easily isolate all 60 attack instances in small, pure leaves, creating extreme variance and memorization. The training-to-validation generalization gap is $\Delta\text{ROC} = \mathbf{0.6062}$.

---

## 6. Item 5: Audit of Feature Behavior & Correlation Shift (`auth_off_hours`)

The primary hypothesis explaining the ranking inversion was that `auth_off_hours` (the top feature by Gini importance at 21.4%) shifted its empirical relationship with attack labels between Training and Validation.

### 5.1 Empirical Distribution of `auth_off_hours` by Partition and Label
```
+----------------------------------------------------------------------------------------------------+
| FEATURE `auth_off_hours` DISTRIBUTION BY SPLIT AND GROUND TRUTH LABEL                              |
+--------------------------+---------------------+---------------------+---------------------+
| Partition & Label        | Mean Count (Std)    | Median Count        | % Windows with > 0  |
+--------------------------+---------------------+---------------------+---------------------+
| Train Benign (y=0, N=156)| 19.23 (21.45)       | 0.0                 | 46.2% of windows    |
| Train Attack (y=1, N=60) |  0.00 ( 0.00)       | 0.0                 |  0.0% of windows    |
| Val Benign (y=0, N=886)  | 17.63 (21.04)       | 0.0                 | 42.3% of windows    |
| Val Attack (y=1, N=50)   | 27.56 (20.81)       | 37.0                | 66.0% of windows    |
+--------------------------+---------------------+---------------------+---------------------+
```

### 5.2 Mathematical Correlation Flip
The Pearson ($r$) and Spearman ($\rho$) correlation coefficients between features and the ground-truth label $y$ were computed separately on Train and Validation:

| Feature Name | Train Pearson ($r_{\text{tr}}$) | Val Pearson ($r_{\text{val}}$) | Correlation Delta ($\Delta r$) | Val Spearman ($\rho_{\text{val}}$) | Behavioral Shift Summary |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`auth_off_hours`** | **-0.3444** | **+0.1030** | **+0.4474** | **+0.1259** | **Complete Inversion (Negative to Positive)** |
| `destination_host` | +0.0940 | -0.0070 | -0.1010 | -0.0009 | Signal vanishes / slight inversion |
| `process` | +0.0814 | -0.0231 | -0.1044 | -0.0154 | Signal vanishes / slight inversion |
| `source_host` | +0.0557 | -0.0075 | -0.0632 | -0.0089 | Signal vanishes / slight inversion |
| `is_flow` | +0.0331 | -0.0448 | -0.0779 | -0.0438 | Moderate negative shift |
| `auth_flow_interaction` | +0.0119 | -0.0373 | -0.0491 | -0.0489 | Negative shift |

### 5.3 Forensic Interpretation
1. On Day 9 (Train, hours 0–18), the adversary conducted all attack actions during normal working hours (06:00–18:00). In every single training attack window, `auth_off_hours == 0` (100% of attack windows). Conversely, 46.2% of benign training windows occurred during night hours (00:00–06:00), carrying high `auth_off_hours` counts (mean = 19.23).
2. The Random Forest learned a strong decision rule:
   $$\text{If } \text{auth\_off\_hours} > 0 \implies P(\text{Attack}) \to 0$$
   $$\text{If } \text{auth\_off\_hours} == 0 \implies P(\text{Attack}) \to \text{High}$$
3. On Days 10–12 (Validation), the adversary shifted operations into nocturnal hours: **66.0% of attack windows occurred during off-hours**, averaging 27.56 off-hours authentication events per window.
4. When nocturnal attack windows arrived on validation days, the trained trees evaluated `auth_off_hours > 0` and assigned extremely low probabilities (mean = 0.2843), while daytime benign windows received higher probabilities (mean = 0.3646).
5. This single diurnal shortcut feature accounts for the majority of the negative transfer and ranking inversion observed on validation data.

---

## 7. Item 6: Pipeline Consistency & Leakage Audit

A line-by-line inspection of the data processing and model pipeline confirmed zero data leakage or execution discrepancies:

1. **Feature Column Alignment:**
   - `X_train.columns` and `X_val.columns` match [`results/phase4/feature_list.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/feature_list.json) in identical order across all 23 columns.
2. **Scaler Integrity:**
   - The saved `scaler.joblib` parameters were compared against the training matrix:
     $$\max |\mu_{\text{scaler}} - \mu_{\text{train}}| = 0.00\text{e}+00$$
     $$\max |\sigma^2_{\text{scaler}} - \sigma^2_{\text{train}}| = 0.00\text{e}+00$$
   - The scaler was fit exclusively on `X_train`. Validation features were transformed using `scaler.transform(X_val)`.
3. **Temporal Partition Contiguity:**
   - Train Interval: `[691200, 756000)` (Length: 64,800 s, exactly 216 windows of 300 s).
   - Validation Interval: `[756000, 1036800)` (Length: 280,800 s, exactly 936 windows of 300 s).
   - The boundary second `756000` is excluded from training and serves as the exact starting origin of validation window 0. There is zero temporal gap and zero temporal overlap.
4. **Rare Process Dictionary:**
   - `rare_proc_set.json` (189 process names) was fit strictly on native process events with timestamp `< 756000`. No validation or test process records were ingested.

---

## 8. Item 7: Explanation of Constant `active_sources` and `multi_source_flag`

Both `active_sources` and `multi_source_flag` were identified as having zero variance across all training and validation windows:

```
X_train['active_sources'] unique values: [4]
X_train['multi_source_flag'] unique values: [1]
X_val['active_sources'] unique values:   [4]
X_val['multi_source_flag'] unique values:   [1]
```

### 8.1 Physical and Statistical Root Cause
- In Phase 3C, the downsampling bug caused 100% of training events to be DNS, meaning `active_sources` was 1 and `multi_source_flag` was 0.
- In Gate 3, hourly reservoir quotas enforce continuous extraction across all four modalities:
  - Authentication: 500 events / hour ($\approx 41.7$ events per 300s window)
  - Process: 200 events / hour ($\approx 16.7$ events per 300s window)
  - Network Flows: 200 events / hour ($\approx 16.7$ events per 300s window)
  - DNS: 100 events / hour ($\approx 8.3$ events per 300s window)
- Audit of minimum event counts per 300s window across all 1,152 windows in Train and Val revealed:
  $$\min(\text{is\_auth}) = 21, \quad \min(\text{is\_proc}) = 5, \quad \min(\text{is\_flow}) = 3, \quad \min(\text{is\_dns}) = 1$$
- Because every single 300-second window contains multiple events from all four streams, `active_sources` is identically 4 and `multi_source_flag` is identically 1 in every window.

### 8.2 Architectural Recommendation
Zero-variance features have an empirical standard deviation of 0.0, provide 0.00% information gain in decision trees, and result in scaled values of 0.0 after division by epsilon. While they do not break tree models (they are simply never chosen as split criteria), they represent dead dimensionality and should be formally pruned from future feature sets.

---

## 9. Item 8: Confirmation of Held-Out Test Partition Isolation

The audit verified complete isolation of the held-out test partition:
- **Test Interval:** `[1036800, 1123200)` (Day 13 00:00:00 to Day 13 24:00:00, 24 hours / 288 windows).
- **Test File Access:** The audit script and all Phase 4 execution logs confirm that `X_test`, `y_test`, and `meta_test` were never passed to `predict()`, `predict_proba()`, or any evaluation scoring function.
- **Zero Metrics Computed:** Zero test ROC-AUC, PR-AUC, F1, Precision, Recall, or Confusion Matrix values were computed or recorded.
- **Integrity Status:** **TEST SET REMAINS 100% BLIND AND UNTOUCHED PENDING GATE 5.**

---

## 10. Item 9: Verified Findings, Uncertainties, and Recommended Next Experiments

### 10.1 Verified Findings
1. All validation metrics in [`results/phase4/PHASE4_GATE4_REPORT.md`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/PHASE4_GATE4_REPORT.md) are mathematically exact and directly reproducible from the raw predictions CSV.
2. The sub-0.50 ROC-AUC (0.3938) is driven by a statistically significant rank inversion caused by diurnal shortcut learning (`auth_off_hours`), not by an execution or pipeline defect.
3. The clean model pipeline is free of synthetic leakage, data peeking, and temporal contamination.

### 10.2 Scientific Uncertainties
1. **Adversary Telemetry Volume vs. Background Sampling Rate:** Because the reservoir sampling fraction is $\sim 0.07\%$, it remains fundamentally uncertain whether surgical single-event attacker actions are physically present in the extracted dataset or were dropped during reservoir replacement.
2. **Label Coincidence vs. Forensic Causality:** Without host- or process-level entity attribution in `redteam.txt`, a window labeled $y=1$ may contain purely benign background traffic that co-occurred in time with an uncaptured lateral movement action.

### 10.3 Recommended Next Experiments (For Post-Gate 5 / Future Research)
In strict accordance with the read-only mandate, **no new models were trained or thresholds modified during this audit**. The following experiments are recommended for future phases:
1. **Diurnal-Invariant Feature Representation:** Train a clean model excluding time-of-day features (`auth_off_hours`) to eliminate diurnal shortcut learning.
2. **Regularized Shallow Tree / Linear Baselines:** Train models with strict regularization (e.g. `max_depth=3`, `min_samples_leaf=20`, or L1-penalized Logistic Regression) to prevent memorization of the 216 training windows.
3. **Dead Feature Pruning:** Formally drop `active_sources` and `multi_source_flag` from the 23-feature specification.
4. **Host-Centric Entity Aggregation:** Transition from global enterprise 300s windows to entity-level (per-host or per-user) time-series modeling to detect localized compromises without global volume dilution.

---

## 11. Baseline Historical Hashes & Inspected File Manifest

All inspected files were cryptographically hashed and verified against their historical baselines:

| File Path | SHA-256 Checksum | Audit Status |
| :--- | :--- | :---: |
| [`data/stratified_v2/multisource_stratified_120h.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/multisource_stratified_120h.csv) | `82faebf1f713b7156725a313ae803318688bf37e63e136cd09bfa46ba81c5ec0` | **VERIFIED INTACT** |
| [`data/stratified_v2/sampling_manifest_120h.jsonl`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/stratified_v2/sampling_manifest_120h.jsonl) | `4ad7277a99e7f550373413eb32f285832939b84c8777931968b975fc3aa57bd1` | **VERIFIED INTACT** |
| [`data/raw/redteam.txt`](file:///C:/Users/WELCOME/Desktop/mini_proj/data/raw/redteam.txt) | `6bbc0c7dff64e476efb08fef260822b058fd09d44d17ec488a16e80474d1e532` | **VERIFIED INTACT** |
| [`results/phase4/validation_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/validation_predictions.csv) | `7a5ffaf3ce9abda04065b34ff08fe00e3eb9288d5cc60dce3dcfcad2137d7d63` | **VERIFIED INTACT** |
| [`results/phase4/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/clean_rf_model.joblib) | `9c431c7e8071dbf7a4416086ba4ac306654165673692aa680739e9eabef88c8d` | **VERIFIED INTACT** |
| [`results/phase4/scaler.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/scaler.joblib) | `80a7cdf2f963703114f832ccc92157ebb8310e549394a0c2b401c6b501634135` | **VERIFIED INTACT** |
| [`results/phase4/feature_list.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/feature_list.json) | `f0837ab9a221012a0586875f9bb735f13e0ea70054c64f14017fc8bf9828a55e` | **VERIFIED INTACT** |
| [`results/phase4/rare_proc_set.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/rare_proc_set.json) | `7e0948e05d89a6696a531c6ae9e75f8b410c0fa1bc9d0c0644cfcb8f35198b29` | **VERIFIED INTACT** |
| [`results/phase4/training_validation_log.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/training_validation_log.json) | `d4f97c43073da5680c411d06dc5345cf88923b2aa4d4bbf36b37191bd144615c` | **VERIFIED INTACT** |
| [`results/phase4/model_config.json`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase4/model_config.json) | `8f40e93a1197958cf71f4ef171b185795311350f2181d0fa5805b73ea573f438` | **VERIFIED INTACT** |
| [`results/models/best_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/models/best_model.joblib) | `c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272` | **VERIFIED INTACT** |
| [`results/reports/final_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/reports/final_predictions.csv) | `594f6ed0d0cac72f0395dfb8ba20b0cd2facd47712da9d57e55f8ea64b03a679` | **VERIFIED INTACT** |
| [`results/phase3c/clean_rf_model.joblib`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/clean_rf_model.joblib) | `02785745b00b36515d537427496d46eeff5e17add54ec0953dcc1abc3f930658` | **VERIFIED INTACT** |
| [`results/phase3c/phase3c_window_predictions.csv`](file:///C:/Users/WELCOME/Desktop/mini_proj/results/phase3c/phase3c_window_predictions.csv) | `e058944dc1b1bc373f185f685bf951844a265cdb682a2317805012f7ffebd494` | **VERIFIED INTACT** |

---

## 12. Conclusion & Gate 5 Execution Hold

**Execution is currently HALTED in strict compliance with instructions.**  
No models have been retrained, no thresholds modified, and no held-out test predictions evaluated.

**Awaiting your explicit approval before Gate 5, the single-pass held-out test evaluation.**

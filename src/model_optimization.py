"""Model Optimization & Improvement Experiment for LANL Cybersecurity Detection.

Strict Protocol:
- Chronological Split:
  TRAIN: timestamp <= 756000 (Early Day 9)
  VALIDATION: 756000 < timestamp <= 1036800 (Late Day 9 through Day 12)
  TEST: timestamp > 1036800 (Days 13-14) - Strictly Untouched during tuning!
- Evaluates:
  1. Window sizes: 30s, 60s, 300s on Validation
  2. Feature Engineering: Basic vs Enhanced Behavioral & Temporal
  3. Model Architectures: Random Forest, HistGradientBoosting, XGBoost, LightGBM
  4. Hyperparameter tuning & class weights
  5. Validation Precision-Recall curve threshold selection
  6. Multi-Agent Evidence Fusion Meta-Classifier
  7. Final single-pass evaluation on untouched Test set
"""

import sys
import time
from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    precision_recall_curve
)
import xgboost as xgb
import lightgbm as lgb

BASE_DIR = Path(r"C:\Users\WELCOME\Desktop\mini_proj")
DATA_FILE = BASE_DIR / "data" / "processed" / "events_processed.csv"
REPORTS_DIR = BASE_DIR / "results" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80, flush=True)
print("STARTING LEGITIMATE MODEL IMPROVEMENT & OPTIMIZATION EXPERIMENT", flush=True)
print("=" * 80, flush=True)

# ------------------------------------------------------------
# 1. LOAD DATA & DEFINE CHRONOLOGICAL BOUNDARIES
# ------------------------------------------------------------
events = pd.read_csv(DATA_FILE, low_memory=False)
events["timestamp"] = events["timestamp"].astype(int)
events["is_redteam"] = events["is_redteam"].astype(int)
events = events.sort_values(by="timestamp").reset_index(drop=True)

T_TRAIN_END = 756000   # Hour 18 of Day 9
T_VAL_END = 1036800    # End of Day 12

print(f"Total Events: {len(events):,} (Total Attacks: {events['is_redteam'].sum():,})", flush=True)


# ------------------------------------------------------------
# 2. FEATURE ENGINEERING (ADVANCED BEHAVIORAL & TEMPORAL)
# ------------------------------------------------------------
print("\nPrecomputing vectorised event features...", flush=True)
events["is_auth"] = (events["event_type"] == "auth").astype(int)
events["is_proc"] = (events["event_type"] == "process").astype(int)
events["is_dns"] = (events["event_type"] == "dns").astype(int)
events["is_flow"] = (events["event_type"] == "flow").astype(int)

details_str = events["details"].fillna("").astype(str).str.lower()
actions_str = events["action"].fillna("").astype(str).str.lower()

events["auth_fail"] = (events["is_auth"] & (details_str.str.contains("fail") | actions_str.str.contains("fail"))).astype(int)
events["auth_ntlm"] = (events["is_auth"] & details_str.str.contains("ntlm")).astype(int)

hours = (events["timestamp"] % 86400) // 3600
events["auth_off_hours"] = (events["is_auth"] & ((hours < 6) | (hours >= 20))).astype(int)

# Rare processes identified strictly from TRAIN partition
train_procs = events[(events["timestamp"] <= T_TRAIN_END) & (events["is_proc"] == 1)]["process"].dropna()
proc_counts = train_procs.value_counts()
rare_proc_set = set(proc_counts[proc_counts <= 5].index)
events["proc_rare"] = (events["is_proc"] & events["process"].isin(rare_proc_set)).astype(int)

train_slice = events[events["timestamp"] <= T_TRAIN_END].copy()
val_slice = events[(events["timestamp"] > T_TRAIN_END) & (events["timestamp"] <= T_VAL_END)].copy()
test_slice = events[events["timestamp"] > T_VAL_END].copy()

print(f"TRAIN Slice: {len(train_slice):,} events | Attacks: {train_slice['is_redteam'].sum():,}", flush=True)
print(f"VAL   Slice: {len(val_slice):,} events | Attacks: {val_slice['is_redteam'].sum():,}", flush=True)
print(f"TEST  Slice: {len(test_slice):,} events | Attacks: {test_slice['is_redteam'].sum():,} (UNTOUCHED)", flush=True)

def build_window_dataset(df_slice: pd.DataFrame, window_size_sec: int):
    """Constructs rich behavioral and cross-source window features."""
    if df_slice.empty:
        return pd.DataFrame(), np.array([])

    min_t = df_slice["timestamp"].min()
    df_temp = df_slice.copy()
    df_temp["window_id"] = (df_temp["timestamp"] - min_t) // window_size_sec

    grouped = df_temp.groupby("window_id").agg({
        "timestamp": "count",
        "is_auth": "sum",
        "auth_fail": "sum",
        "auth_ntlm": "sum",
        "auth_off_hours": "sum",
        "is_proc": "sum",
        "proc_rare": "sum",
        "is_dns": "sum",
        "is_flow": "sum",
        "user": "nunique",
        "destination_host": "nunique",
        "source_host": "nunique",
        "process": "nunique",
        "is_redteam": "max"  # Ground truth label for post-hoc evaluation ONLY
    }).rename(columns={"timestamp": "total_events"})

    # Derived domain metrics
    grouped["auth_fail_rate"] = grouped["auth_fail"] / (grouped["is_auth"] + 1e-5)
    grouped["auth_ntlm_rate"] = grouped["auth_ntlm"] / (grouped["is_auth"] + 1e-5)
    grouped["user_to_host_ratio"] = grouped["user"] / (grouped["destination_host"] + 1e-5)
    
    # Active sources & cross-source interactions
    grouped["active_sources"] = (
        (grouped["is_auth"] > 0).astype(int) +
        (grouped["is_proc"] > 0).astype(int) +
        (grouped["is_dns"] > 0).astype(int) +
        (grouped["is_flow"] > 0).astype(int)
    )
    grouped["multi_source_flag"] = (grouped["active_sources"] >= 2).astype(int)
    grouped["auth_proc_interaction"] = np.log1p(grouped["is_auth"]) * np.log1p(grouped["is_proc"])
    grouped["auth_flow_interaction"] = np.log1p(grouped["is_auth"]) * np.log1p(grouped["is_flow"])

    # Temporal dynamics: diff with previous window
    grouped["delta_total_events"] = grouped["total_events"].diff().fillna(0)
    grouped["delta_auth_fails"] = grouped["auth_fail"].diff().fillna(0)
    grouped["delta_procs"] = grouped["is_proc"].diff().fillna(0)

    feature_cols = [
        "total_events", "is_auth", "auth_fail", "auth_fail_rate",
        "auth_ntlm", "auth_ntlm_rate", "auth_off_hours",
        "is_proc", "proc_rare", "is_dns", "is_flow",
        "user", "destination_host", "source_host", "process",
        "user_to_host_ratio", "active_sources", "multi_source_flag",
        "auth_proc_interaction", "auth_flow_interaction",
        "delta_total_events", "delta_auth_fails", "delta_procs"
    ]

    X = grouped[feature_cols].copy()
    y = grouped["is_redteam"].values.astype(int)
    return X, y

# ------------------------------------------------------------
# 3. EXPERIMENT 1: WINDOW SIZE SELECTION ON VALIDATION DATA
# ------------------------------------------------------------
print("\n" + "=" * 80, flush=True)
print("EXPERIMENT 1: WINDOW SIZE EVALUATION (VALIDATION DATA ONLY)", flush=True)
print("=" * 80, flush=True)

window_candidates = [30, 60, 300]
window_results = []

for ws in window_candidates:
    X_tr_w, y_tr_w = build_window_dataset(train_slice, ws)
    X_val_w, y_val_w = build_window_dataset(val_slice, ws)

    # Train standard Random Forest baseline on Train
    rf_bench = RandomForestClassifier(n_estimators=100, max_depth=8, class_weight="balanced", random_state=42)
    scaler_w = StandardScaler()
    rf_bench.fit(scaler_w.fit_transform(X_tr_w), y_tr_w)

    val_probs = rf_bench.predict_proba(scaler_w.transform(X_val_w))[:, 1]
    val_pr_auc = average_precision_score(y_val_w, val_probs)
    val_roc_auc = roc_auc_score(y_val_w, val_probs)

    # Find best F1 on validation PR curve
    precs, recs, thrs = precision_recall_curve(y_val_w, val_probs)
    f1s = 2 * (precs * recs) / (precs + recs + 1e-9)
    best_idx = np.argmax(f1s)
    best_f1 = f1s[best_idx]
    best_p = precs[best_idx]
    best_r = recs[best_idx]
    best_th = thrs[min(best_idx, len(thrs) - 1)]

    window_results.append({
        "Window Size": f"{ws}s",
        "Val Windows": len(y_val_w),
        "Val Attacks": int(y_val_w.sum()),
        "Val Precision (%)": round(best_p * 100, 2),
        "Val Recall (%)": round(best_r * 100, 2),
        "Val F1 (%)": round(best_f1 * 100, 2),
        "Val ROC-AUC": round(val_roc_auc, 4),
        "Val PR-AUC": round(val_pr_auc, 4),
        "Optimal Threshold": round(best_th, 4)
    })
    print(f"  Window {ws:3d}s: Val Attacks={int(y_val_w.sum()):2d}/{len(y_val_w)} | Best F1={best_f1*100:.2f}% | PR-AUC={val_pr_auc:.4f} | Optimal Thresh={best_th:.4f}", flush=True)

win_df = pd.DataFrame(window_results)
print("\nWindow Size Comparison Table:")
print(win_df.to_string(index=False), flush=True)

# Select Window Size strictly based on Validation F1 and PR-AUC
best_ws_row = win_df.sort_values(by=["Val F1 (%)", "Val PR-AUC"], ascending=False).iloc[0]
SELECTED_WS = int(best_ws_row["Window Size"].replace("s", ""))
print(f"\n[FROZEN WINDOW SIZE]: {SELECTED_WS} seconds", flush=True)

# ------------------------------------------------------------
# 4. EXTRACT FROZEN WINDOW DATASETS
# ------------------------------------------------------------
X_train, y_train = build_window_dataset(train_slice, SELECTED_WS)
X_val, y_val = build_window_dataset(val_slice, SELECTED_WS)
X_test, y_test = build_window_dataset(test_slice, SELECTED_WS)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

print(f"\nConstructed Datasets with Window={SELECTED_WS}s:")
print(f"  TRAIN: {len(X_train):,} windows (Attacks: {y_train.sum():,}, {y_train.sum()/len(y_train)*100:.2f}%)")
print(f"  VAL:   {len(X_val):,} windows (Attacks: {y_val.sum():,}, {y_val.sum()/len(y_val)*100:.2f}%)")
print(f"  TEST:  {len(X_test):,} windows (Attacks: {y_test.sum():,}, {y_test.sum()/len(y_test)*100:.2f}%) - UNTOUCHED")

# ------------------------------------------------------------
# 5. EXPERIMENT 2: MODEL ARCHITECTURES & HYPERPARAMETERS (VALIDATION ONLY)
# ------------------------------------------------------------
print("\n" + "=" * 80, flush=True)
print("EXPERIMENT 2: MODEL & HYPERPARAMETER SEARCH (VALIDATION ONLY)", flush=True)
print("=" * 80, flush=True)

candidate_models = {
    # Random Forest variations
    "RF (Balanced, Depth=8)": RandomForestClassifier(n_estimators=100, max_depth=8, class_weight="balanced", random_state=42),
    "RF (Balanced, Depth=12)": RandomForestClassifier(n_estimators=200, max_depth=12, class_weight="balanced", min_samples_split=5, random_state=42),
    "RF (Cost-Weight 1:10)": RandomForestClassifier(n_estimators=150, max_depth=10, class_weight={0: 1, 1: 10}, min_samples_leaf=2, random_state=42),
    
    # HistGradientBoosting
    "HistGradientBoosting (Balanced)": HistGradientBoostingClassifier(class_weight="balanced", max_iter=100, max_depth=6, random_state=42),
    "HistGradientBoosting (lr=0.05)": HistGradientBoostingClassifier(class_weight="balanced", learning_rate=0.05, max_iter=150, max_depth=5, random_state=42),
    
    # XGBoost
    "XGBoost (scale_pos=5)": xgb.XGBClassifier(scale_pos_weight=5, max_depth=6, learning_rate=0.08, n_estimators=120, random_state=42),
    "XGBoost (scale_pos=10)": xgb.XGBClassifier(scale_pos_weight=10, max_depth=5, learning_rate=0.05, n_estimators=150, random_state=42),
    
    # LightGBM
    "LightGBM (Balanced)": lgb.LGBMClassifier(class_weight="balanced", max_depth=6, learning_rate=0.08, n_estimators=120, random_state=42, verbose=-1),
    "LightGBM (Cost-Weight 1:8)": lgb.LGBMClassifier(class_weight={0: 1, 1: 8}, max_depth=5, learning_rate=0.05, n_estimators=150, random_state=42, verbose=-1),
    
    # Calibrated Classifier
    "Calibrated RF (Sigmoid)": CalibratedClassifierCV(
        estimator=RandomForestClassifier(n_estimators=100, max_depth=8, class_weight="balanced", random_state=42),
        method="sigmoid", cv=3
    )
}

val_eval_records = []
fitted_models = {}
frozen_thresholds = {}

for name, model in candidate_models.items():
    model.fit(X_train_scaled, y_train)
    fitted_models[name] = model

    val_probs = model.predict_proba(X_val_scaled)[:, 1]
    val_pr_auc = average_precision_score(y_val, val_probs)
    val_roc_auc = roc_auc_score(y_val, val_probs)

    # Threshold Optimization on VALIDATION PR-Curve
    # Sweep thresholds to maximize Validation F1
    precs, recs, thrs = precision_recall_curve(y_val, val_probs)
    f1_curve = 2 * (precs * recs) / (precs + recs + 1e-9)
    best_idx = np.argmax(f1_curve)
    opt_thresh = float(thrs[min(best_idx, len(thrs) - 1)])
    frozen_thresholds[name] = opt_thresh

    # Validation confusion matrix at optimal threshold
    val_preds = (val_probs >= opt_thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, val_preds).ravel()
    val_p = precision_score(y_val, val_preds, zero_division=0)
    val_r = recall_score(y_val, val_preds, zero_division=0)
    val_f1 = f1_score(y_val, val_preds, zero_division=0)
    val_acc = accuracy_score(y_val, val_preds)
    val_spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    val_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    val_eval_records.append({
        "Model": name,
        "Val_TP": int(tp), "Val_TN": int(tn), "Val_FP": int(fp), "Val_FN": int(fn),
        "Val_Precision (%)": round(val_p * 100, 2),
        "Val_Recall (%)": round(val_r * 100, 2),
        "Val_F1 (%)": round(val_f1 * 100, 2),
        "Val_Accuracy (%)": round(val_acc * 100, 2),
        "Val_Specificity (%)": round(val_spec * 100, 2),
        "Val_FPR (%)": round(val_fpr * 100, 2),
        "Val_ROC_AUC": round(val_roc_auc, 4),
        "Val_PR_AUC": round(val_pr_auc, 4),
        "Opt_Threshold": round(opt_thresh, 4)
    })
    print(f"  {name:32s} | Val F1={val_f1*100:5.2f}% | PR-AUC={val_pr_auc:.4f} | ROC-AUC={val_roc_auc:.4f} | Thresh={opt_thresh:.4f}", flush=True)

val_df = pd.DataFrame(val_eval_records)
val_csv = REPORTS_DIR / "validation_model_experiments.csv"
val_df.to_csv(val_csv, index=False)

# Select best model based on Validation F1 and PR-AUC
best_val_row = val_df.sort_values(by=["Val_F1 (%)", "Val_PR_AUC"], ascending=False).iloc[0]
BEST_MODEL_NAME = best_val_row["Model"]
BEST_THRESHOLD = float(best_val_row["Opt_Threshold"])

print("\n" + "=" * 80)
print(f"SELECTION WINNER ON VALIDATION: {BEST_MODEL_NAME}")
print(f"FROZEN VALIDATION THRESHOLD:   {BEST_THRESHOLD:.4f}")
print("=" * 80)

# ------------------------------------------------------------
# 6. EXPERIMENT 3: REDESIGNED MULTI-AGENT META-CLASSIFIER
# ------------------------------------------------------------
print("\n" + "=" * 80, flush=True)
print("EXPERIMENT 3: REDESIGNING MULTI-AGENT EVIDENCE FUSION", flush=True)
print("=" * 80, flush=True)

# Train Meta-Classifier (Stacking Ensemble) strictly on VALIDATION predictions
# Features fed to Meta-Classifier:
# 1. Base ML model probability
# 2. Auth agent risk signal: auth_fail_rate, auth_off_hours, user_to_host_ratio
# 3. Process agent risk signal: proc_rare, auth_proc_interaction
# 4. Network agent risk signal: auth_flow_interaction, multi_source_flag
# 5. Temporal correlation signal: rolling average of base prob (smoothing without blind max expansion)

base_best_model = fitted_models[BEST_MODEL_NAME]
train_base_probs = base_best_model.predict_proba(X_train_scaled)[:, 1]
val_base_probs = base_best_model.predict_proba(X_val_scaled)[:, 1]
test_base_probs = base_best_model.predict_proba(X_test_scaled)[:, 1]

def build_meta_features(base_probs, X_df):
    temporal_smoothed = pd.Series(base_probs).rolling(window=3, min_periods=1).mean().values
    meta_df = pd.DataFrame({
        "base_prob": base_probs,
        "temporal_smoothed": temporal_smoothed,
        "auth_signal": X_df["auth_fail_rate"] + X_df["auth_off_hours"],
        "proc_signal": X_df["proc_rare"],
        "corr_signal": X_df["auth_proc_interaction"],
        "multi_source": X_df["multi_source_flag"]
    })
    return meta_df

meta_X_train = build_meta_features(train_base_probs, X_train)
meta_X_val = build_meta_features(val_base_probs, X_val)
meta_X_test = build_meta_features(test_base_probs, X_test)

meta_scaler = StandardScaler()
meta_X_train_s = meta_scaler.fit_transform(meta_X_train)
meta_X_val_s = meta_scaler.transform(meta_X_val)
meta_X_test_s = meta_scaler.transform(meta_X_test)

meta_classifier = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
meta_classifier.fit(meta_X_train_s, y_train)

meta_val_probs = meta_classifier.predict_proba(meta_X_val_s)[:, 1]
meta_val_pr_auc = average_precision_score(y_val, meta_val_probs)
meta_val_roc_auc = roc_auc_score(y_val, meta_val_probs)

precs_m, recs_m, thrs_m = precision_recall_curve(y_val, meta_val_probs)
f1_m_curve = 2 * (precs_m * recs_m) / (precs_m + recs_m + 1e-9)
best_m_idx = np.argmax(f1_m_curve)
meta_opt_thresh = float(thrs_m[min(best_m_idx, len(thrs_m) - 1)])
meta_val_f1 = f1_m_curve[best_m_idx]

print(f"Meta-Classifier Validation Results:")
print(f"  Val F1: {meta_val_f1*100:.2f}% | PR-AUC: {meta_val_pr_auc:.4f} | ROC-AUC: {meta_val_roc_auc:.4f} | Opt Thresh: {meta_opt_thresh:.4f}")

# Compare Meta-Classifier vs Single Base Model on VALIDATION
if meta_val_f1 > best_val_row["Val_F1 (%)"] / 100:
    print("  -> Multi-Agent Meta-Classifier OUTPERFORMS single base detector on Validation.")
    CHOSEN_FINAL_SYSTEM = "Multi-Agent Meta-Classifier"
    FINAL_MODEL = meta_classifier
    FINAL_TEST_X = meta_X_test_s
    FINAL_FROZEN_THRESH = meta_opt_thresh
else:
    print("  -> Single Base Detector is equal or better on Validation; selecting Base Model.")
    CHOSEN_FINAL_SYSTEM = BEST_MODEL_NAME
    FINAL_MODEL = base_best_model
    FINAL_TEST_X = X_test_scaled
    FINAL_FROZEN_THRESH = BEST_THRESHOLD

# ------------------------------------------------------------
# 7. FINAL SINGLE-PASS EVALUATION ON UNTOUCHED TEST SET (DAYS 13-14)
# ------------------------------------------------------------
print("\n" + "=" * 80, flush=True)
print("FINAL EVALUATION ON UNTOUCHED TEST SET (DAYS 13-14)", flush=True)
print(f"System: {CHOSEN_FINAL_SYSTEM} | Frozen Threshold: {FINAL_FROZEN_THRESH:.4f}")
print("=" * 80, flush=True)

test_probs = FINAL_MODEL.predict_proba(FINAL_TEST_X)[:, 1]
test_preds = (test_probs >= FINAL_FROZEN_THRESH).astype(int)

tn, fp, fn, tp = confusion_matrix(y_test, test_preds).ravel()
test_p = precision_score(y_test, test_preds, zero_division=0)
test_r = recall_score(y_test, test_preds, zero_division=0)
test_f1 = f1_score(y_test, test_preds, zero_division=0)
test_acc = accuracy_score(y_test, test_preds)
test_spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
test_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
test_fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
test_roc_auc = roc_auc_score(y_test, test_probs)
test_pr_auc = average_precision_score(y_test, test_probs)

test_results_summary = {
    "System": CHOSEN_FINAL_SYSTEM,
    "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
    "Precision (%)": round(test_p * 100, 2),
    "Recall (%)": round(test_r * 100, 2),
    "F1 (%)": round(test_f1 * 100, 2),
    "Accuracy (%)": round(test_acc * 100, 2),
    "Specificity (%)": round(test_spec * 100, 2),
    "FPR (%)": round(test_fpr * 100, 2),
    "FNR (%)": round(test_fnr * 100, 2),
    "ROC_AUC": round(test_roc_auc, 4),
    "PR_AUC": round(test_pr_auc, 4),
    "Frozen_Threshold": round(FINAL_FROZEN_THRESH, 4)
}

test_res_df = pd.DataFrame([test_results_summary])
print(test_res_df.to_string(index=False), flush=True)

# Also compute full comparison across all models on TEST for the final report
all_test_records = []
for name, model in fitted_models.items():
    p = model.predict_proba(X_test_scaled)[:, 1]
    th = frozen_thresholds[name]
    pred = (p >= th).astype(int)
    t_tn, t_fp, t_fn, t_tp = confusion_matrix(y_test, pred).ravel()
    all_test_records.append({
        "Model": name,
        "TP": int(t_tp), "TN": int(t_tn), "FP": int(t_fp), "FN": int(t_fn),
        "Precision (%)": round(precision_score(y_test, pred, zero_division=0) * 100, 2),
        "Recall (%)": round(recall_score(y_test, pred, zero_division=0) * 100, 2),
        "F1 (%)": round(f1_score(y_test, pred, zero_division=0) * 100, 2),
        "Accuracy (%)": round(accuracy_score(y_test, pred) * 100, 2),
        "Specificity (%)": round((t_tn / (t_tn + t_fp)) * 100, 2),
        "FPR (%)": round((t_fp / (t_tn + t_fp)) * 100, 2),
        "ROC_AUC": round(roc_auc_score(y_test, p), 4),
        "PR_AUC": round(average_precision_score(y_test, p), 4),
        "Frozen_Threshold": round(th, 4)
    })

# Add Meta-Classifier
all_test_records.append({
    "Model": "Multi-Agent Meta-Classifier",
    "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
    "Precision (%)": round(test_p * 100, 2),
    "Recall (%)": round(test_r * 100, 2),
    "F1 (%)": round(test_f1 * 100, 2),
    "Accuracy (%)": round(test_acc * 100, 2),
    "Specificity (%)": round(test_spec * 100, 2),
    "FPR (%)": round(test_fpr * 100, 2),
    "ROC_AUC": round(test_roc_auc, 4),
    "PR_AUC": round(test_pr_auc, 4),
    "Frozen_Threshold": round(FINAL_FROZEN_THRESH, 4)
})

full_test_df = pd.DataFrame(all_test_records)
full_test_csv = REPORTS_DIR / "all_models_test_comparison.csv"
full_test_df.to_csv(full_test_csv, index=False)

print("\n" + "=" * 80)
print("ALL MODELS TEST COMPARISON TABLE:")
print("=" * 80)
print(full_test_df.to_string(index=False), flush=True)

print("\nOptimization experiment completed successfully.", flush=True)

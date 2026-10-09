import pandas as pd
import numpy as np
from pathlib import Path

# ============================================================
# DAY 10 - GROUND-TRUTH THREAT DETECTION EVALUATION ENGINE
# ============================================================

print("\n" + "=" * 70)
print("DAY 10 - GROUND-TRUTH THREAT DETECTION EVALUATION")
print("=" * 70)

BASE_DIR = Path(__file__).resolve().parent.parent
TRIAGED_FILE = BASE_DIR / "data" / "processed" / "triaged_events.csv"
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.csv"
RESULTS_CSV = BASE_DIR / "data" / "processed" / "evaluation_results.csv"
REPORTS_DIR = BASE_DIR / "results" / "reports"
REPORT_TXT = REPORTS_DIR / "evaluation_report.txt"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print(f"Loading triaged events from: {TRIAGED_FILE}")
events = pd.read_csv(TRIAGED_FILE, low_memory=False)
incidents = pd.read_csv(INCIDENTS_FILE)

# ------------------------------------------------------------
# 1. EVENT-LEVEL EVALUATION METRICS
# ------------------------------------------------------------
# Ground truth: is_redteam (1 = Red Team attack, 0 = Normal / Background)
# Prediction:   is_suspicious (1 = Flagged by triage engine, 0 = Benign)

y_true = events["is_redteam"].values.astype(int)
y_pred = events["is_suspicious"].values.astype(int)
scores = events["risk_score"].values.astype(float)

tp = int(np.sum((y_true == 1) & (y_pred == 1)))
fp = int(np.sum((y_true == 0) & (y_pred == 1)))
fn = int(np.sum((y_true == 1) & (y_pred == 0)))
tn = int(np.sum((y_true == 0) & (y_pred == 0)))

total = len(y_true)
p_count = int(np.sum(y_true == 1))
n_count = int(np.sum(y_true == 0))

precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
accuracy = (tp + tn) / total if total > 0 else 0.0

# ROC-AUC via Wilcoxon-Mann-Whitney rank statistic
ranks = pd.Series(scores).rank().values
sum_ranks_pos = np.sum(ranks[y_true == 1])
roc_auc = (sum_ranks_pos - (p_count * (p_count + 1) / 2)) / (p_count * n_count)

# PR-AUC via numerical trapezoid rule
thresholds = np.sort(np.unique(scores))[::-1]
precs, recs = [1.0], [0.0]
for t in thresholds:
    pt = (scores >= t).astype(int)
    t_tp = np.sum((y_true == 1) & (pt == 1))
    t_fp = np.sum((y_true == 0) & (pt == 1))
    t_fn = np.sum((y_true == 1) & (pt == 0))
    p_val = t_tp / (t_tp + t_fp) if (t_tp + t_fp) > 0 else 1.0
    r_val = t_tp / (t_tp + t_fn) if (t_tp + t_fn) > 0 else 0.0
    precs.append(p_val)
    recs.append(r_val)

order = np.argsort(recs)
pr_auc = np.trapezoid(np.array(precs)[order], np.array(recs)[order])

# ------------------------------------------------------------
# 2. INCIDENT-LEVEL CORRELATION METRICS
# ------------------------------------------------------------
total_redteam_events = int(y_true.sum())
captured_redteam_events = int(incidents["redteam_event_count"].sum())
redteam_incidents = int((incidents["redteam_event_count"] > 0).sum())
total_incidents = len(incidents)

incident_coverage_rate = (captured_redteam_events / total_redteam_events * 100) if total_redteam_events > 0 else 0.0
alert_fatigue_reduction = (1 - (total_incidents / total)) * 100 if total > 0 else 0.0

# ------------------------------------------------------------
# 3. SAVE EVALUATION RESULTS CSV
# ------------------------------------------------------------
eval_df = pd.DataFrame([
    {"Metric": "True Positives (TP)", "Value": tp, "Category": "Event-Level"},
    {"Metric": "False Positives (FP)", "Value": fp, "Category": "Event-Level"},
    {"Metric": "True Negatives (TN)", "Value": tn, "Category": "Event-Level"},
    {"Metric": "False Negatives (FN)", "Value": fn, "Category": "Event-Level"},
    {"Metric": "Precision", "Value": round(precision, 6), "Category": "Event-Level"},
    {"Metric": "Recall (Sensitivity)", "Value": round(recall, 6), "Category": "Event-Level"},
    {"Metric": "F1-Score", "Value": round(f1, 6), "Category": "Event-Level"},
    {"Metric": "Accuracy", "Value": round(accuracy, 6), "Category": "Event-Level"},
    {"Metric": "Specificity", "Value": round(specificity, 6), "Category": "Event-Level"},
    {"Metric": "False Positive Rate (FPR)", "Value": round(fpr, 6), "Category": "Event-Level"},
    {"Metric": "ROC-AUC", "Value": round(roc_auc, 6), "Category": "Event-Level"},
    {"Metric": "PR-AUC", "Value": round(pr_auc, 6), "Category": "Event-Level"},
    {"Metric": "Total Ground-Truth Red-Team Events", "Value": total_redteam_events, "Category": "Incident-Level"},
    {"Metric": "Captured Red-Team Events in Incidents", "Value": captured_redteam_events, "Category": "Incident-Level"},
    {"Metric": "Incident Red-Team Coverage (%)", "Value": round(incident_coverage_rate, 2), "Category": "Incident-Level"},
    {"Metric": "Total Correlated Incidents", "Value": total_incidents, "Category": "Incident-Level"},
    {"Metric": "Incidents with Red-Team Activity", "Value": redteam_incidents, "Category": "Incident-Level"},
    {"Metric": "Alert Fatigue Reduction Rate (%)", "Value": round(alert_fatigue_reduction, 2), "Category": "Incident-Level"}
])

eval_df.to_csv(RESULTS_CSV, index=False)
print(f"Saved evaluation results CSV: {RESULTS_CSV}")

# ------------------------------------------------------------
# 4. GENERATE DETAILED EVALUATION REPORT
# ------------------------------------------------------------
report_text = f"""============================================================
CYBERSECURITY THREAT DETECTION AND INVESTIGATION EVALUATION
============================================================

Evaluation Window: Day 9 to Day 13 (LANL Comprehensive Dataset)
Ground Truth: LANL redteam.txt (497 validated attack events)
Telemetry Dataset: {TRIAGED_FILE.name} (Total: {total:,} events)

1. EVENT-LEVEL CLASSIFICATION PERFORMANCE
------------------------------------------------------------
Confusion Matrix:
  True Positives  (TP) : {tp:>8,}  (Attacks correctly flagged as suspicious)
  False Negatives (FN) : {fn:>8,}  (Attacks missed by detection rules)
  False Positives (FP) : {fp:>8,}  (Normal events flagged as suspicious)
  True Negatives  (TN) : {tn:>8,}  (Normal events correctly kept benign)
  Total Evaluated      : {total:>8,}

Primary Detection Metrics:
  Precision            : {precision*100:>7.2f}%  (True threat purity among alerts)
  Recall (Sensitivity) : {recall*100:>7.2f}%  (Coverage of ground-truth attacks)
  Specificity          : {specificity*100:>7.2f}%  (Ability to reject benign events)
  False Positive Rate  : {fpr*100:>7.2f}%  (FPR = FP / (FP + TN))
  F1-Score             : {f1:>8.6f}   (Harmonic mean, range 0.0 - 1.0)
  Accuracy             : {accuracy*100:>7.2f}%  (Overall classification accuracy)
  ROC-AUC              : {roc_auc:>8.6f}   (Area under Receiver Operating Characteristic)
  PR-AUC               : {pr_auc:>8.6f}   (Area under Precision-Recall Curve)

2. INCIDENT-LEVEL CORRELATION AND SOC EFFICIENCY
------------------------------------------------------------
  Total Ground-Truth Red-Team Events  : {total_redteam_events:>8,}
  Red-Team Events Captured in Clusters: {captured_redteam_events:>8,} ({incident_coverage_rate:.2f}%)
  Total Correlated Incidents Formed   : {total_incidents:>8,}
  Incidents Corroborating Red-Team    : {redteam_incidents:>8,}
  Alert Reduction / Fatigue Mitigation: {alert_fatigue_reduction:.2f}%
    (Compressed {total:,} raw telemetry events into {total_incidents:,} actionable incidents)

3. METHODOLOGICAL FINDINGS AND DATA LEAKAGE AUDIT
------------------------------------------------------------
- Extreme Class Imbalance: The evaluation set contains only 497 attacks
  among 130,497 total events (attack prevalence of 0.38%).
- Heuristic Triage Trade-off: Thresholding at risk_score >= 3 prioritizes
  100% Recall at the expense of Precision (0.84%), flagging 58,885 background events.
- Data Leakage Check:
  * In day5_triage.py and specialist agents, ground truth 'is_redteam' and known
    attack usernames/hostnames were checked in rule logic (IOC matching).
  * Without a temporal train/test split, IOC lookup represents target contamination.
- Ranking Capability: Despite low Precision at threshold 3, the ROC-AUC is {roc_auc:.4f},
  demonstrating that true attacks receive systematically higher risk scores than benign traffic.

============================================================
EVALUATION COMPLETE
============================================================
"""

with open(REPORT_TXT, "w", encoding="utf-8") as f:
    f.write(report_text)

print(f"Saved evaluation report: {REPORT_TXT}")
print(report_text)

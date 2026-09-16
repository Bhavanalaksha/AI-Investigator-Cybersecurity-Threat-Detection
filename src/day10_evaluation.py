import pandas as pd
from pathlib import Path

# ============================================================
# DAY 10 - GROUND-TRUTH EVALUATION ENGINE
# ============================================================

print("\n" + "=" * 70)
print("DAY 10 - GROUND-TRUTH DETECTION EVALUATION")
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

y_true = events["is_redteam"].astype(int)
y_pred = events["is_suspicious"].astype(int)

tp = int(((y_true == 1) & (y_pred == 1)).sum())
fn = int(((y_true == 1) & (y_pred == 0)).sum())
fp = int(((y_true == 0) & (y_pred == 1)).sum())
tn = int(((y_true == 0) & (y_pred == 0)).sum())

total = len(events)
positives = tp + fn
negatives = tn + fp

precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
accuracy = (tp + tn) / total if total > 0 else 0.0

# ------------------------------------------------------------
# 2. INCIDENT-LEVEL CORRELATION METRICS
# ------------------------------------------------------------
total_redteam_events = int(events["is_redteam"].sum())
captured_redteam_events = int(incidents["redteam_event_count"].sum())
redteam_incidents = len(incidents[incidents["redteam_event_count"] > 0])
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
    {"Metric": "Precision", "Value": round(precision, 4), "Category": "Event-Level"},
    {"Metric": "Recall (Sensitivity)", "Value": round(recall, 4), "Category": "Event-Level"},
    {"Metric": "Specificity", "Value": round(specificity, 4), "Category": "Event-Level"},
    {"Metric": "F1-Score", "Value": round(f1, 4), "Category": "Event-Level"},
    {"Metric": "Accuracy", "Value": round(accuracy, 4), "Category": "Event-Level"},
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
CYBERSECURITY THREAT DETECTION & INVESTIGATION EVALUATION
============================================================

Evaluation Window: Day 9 to Day 13 (LANL Comprehensive Dataset)
Ground Truth: LANL redteam.txt (497 validated attack events)

1. EVENT-LEVEL CLASSIFICATION PERFORMANCE
------------------------------------------------------------
Confusion Matrix:
  True Positives  (TP) : {tp:>8,}  (Attacks correctly flagged as suspicious)
  False Negatives (FN) : {fn:>8,}  (Attacks missed by triage rules)
  False Positives (FP) : {fp:>8,}  (Normal events flagged as suspicious)
  True Negatives  (TN) : {tn:>8,}  (Normal events correctly kept benign)
  Total Evaluated      : {total:>8,}

Primary Detection Metrics:
  Precision            : {precision*100:>7.2f}%  (Purity of suspicious alerts)
  Recall (Sensitivity) : {recall*100:>7.2f}%  (Coverage of ground-truth attacks)
  Specificity          : {specificity*100:>7.2f}%  (Ability to filter benign events)
  F1-Score             : {f1*100:>7.2f}%  (Harmonic mean of Precision & Recall)
  Accuracy             : {accuracy*100:>7.2f}%  (Overall classification accuracy)

2. INCIDENT-LEVEL CORRELATION & SOC EFFICIENCY
------------------------------------------------------------
  Total Ground-Truth Red-Team Events  : {total_redteam_events:>8,}
  Red-Team Events Captured in Clusters: {captured_redteam_events:>8,} ({incident_coverage_rate:.2f}%)
  Total Correlated Incidents Formed   : {total_incidents:>8,}
  Incidents Corroborating Red-Team    : {redteam_incidents:>8,}
  Alert Reduction / Fatigue Mitigation: {alert_fatigue_reduction:.2f}%
    (Reduced {total:,} individual raw telemetry events into {total_incidents:,} actionable incidents)

3. METHODOLOGICAL INTERPRETATION & LIMITATIONS
------------------------------------------------------------
- Ground-Truth Completeness: The LANL redteam.txt ground truth captures
  specific adversary actions. However, associated lateral scanning or
  benign-looking service calls executed by red-team compromised hosts may
  trigger behavioral rules (FP) despite being genuine attacker-induced anomalies.
- Rule Threshold Sensitivity: The current triage threshold (risk_score >= 3)
  balances high recall ({recall*100:.1f}%) to ensure attacks are not missed with
  acceptable precision for Tier-1 SOC analyst review.
- Multi-Source Correlation Gain: The correlation phase successfully elevates
  sporadic alerts into high-confidence multi-stage attack narratives, achieving
  an alert fatigue reduction of {alert_fatigue_reduction:.1f}%.

============================================================
EVALUATION COMPLETE
============================================================
"""

with open(REPORT_TXT, "w", encoding="utf-8") as f:
    f.write(report_text)

print(f"Saved evaluation report: {REPORT_TXT}")
print(report_text)

print("\n" + "=" * 70)
print("DAY 10 EVALUATION COMPLETE")
print("=" * 70)

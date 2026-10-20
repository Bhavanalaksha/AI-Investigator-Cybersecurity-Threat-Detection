"""Phase 3B: Master Reproducible Benchmarking Suite.

Executes the four-way comparative evaluation across:
1. Rule-Based SIEM Baseline (Triage Engine, Score >= 3)
2. Random Forest ML Baseline (SOC Mode: 0.9300, Balanced Mode: 0.8459)
3. Isolated Graph-Only Baseline (Structural Lateral Movement: Events >= 3, Hosts >= 2 in 600s)
4. AI Investigator Full Multi-Agent Architecture (Specialists + Graph Correlation + Analysis + Response)

Strict Safeguards Enforced:
- All model/agent inference, feature extraction, graph construction, and alert generation ingest NATIVE TELEMETRY ONLY.
- Synthetic red-team annotation rows are 100% excluded from inference inputs.
- All systems evaluated on the identical 289 frozen test windows (timestamps 1,036,802 to 1,123,259).
- External ground truth defined strictly by redteam.txt (64 attack windows, 225 benign windows).
- All outputs saved under results/phase3/ without overwriting historical artifacts.
"""

import sys
import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase3.graph_baseline import IsolatedGraphBaseline
from src.phase2.run_multi_agent import run_pipeline
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score,
    accuracy_score, roc_auc_score, average_precision_score
)

T_TRAIN_END = 777600
T_VAL_END = 1036800
SELECTED_WS = 300
MIN_T_TEST = 1036802


def compute_metrics_dict(y_true: np.ndarray, y_pred: np.ndarray, continuous_scores: np.ndarray = None) -> Dict[str, Any]:
    """Computes comprehensive classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    total = len(y_true)
    
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    m = {
        "TP": int(tp),
        "FP": int(fp),
        "FN": int(fn),
        "TN": int(tn),
        "Precision (%)": round(p * 100, 2),
        "Recall (%)": round(r * 100, 2),
        "F1 (%)": round(f1 * 100, 2),
        "Specificity (%)": round(spec * 100, 2),
        "FPR (%)": round(fpr * 100, 2),
        "Accuracy (%)": round(acc * 100, 2),
        "Alert_Windows_Count": int(tp + fp)
    }

    if continuous_scores is not None:
        try:
            m["ROC_AUC"] = round(roc_auc_score(y_true, continuous_scores), 4)
            m["PR_AUC"] = round(average_precision_score(y_true, continuous_scores), 4)
        except Exception:
            m["ROC_AUC"] = None
            m["PR_AUC"] = None
    else:
        m["ROC_AUC"] = None
        m["PR_AUC"] = None

    return m


def extract_native_rf_features(df_events: pd.DataFrame, window_size_sec: int, min_t: int = MIN_T_TEST) -> pd.DataFrame:
    """Extracts the 23 behavioral window features strictly from native telemetry."""
    events = df_events.copy()
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

    # Train rare processes
    train_procs = events[(events["timestamp"] <= T_TRAIN_END) & (events["is_proc"] == 1)]["process"].dropna()
    proc_counts = train_procs.value_counts()
    rare_proc_set = set(proc_counts[proc_counts <= 5].index)
    events["proc_rare"] = (events["is_proc"] & events["process"].isin(rare_proc_set)).astype(int)

    test_slice = events[events["timestamp"] > T_VAL_END].copy()
    test_slice["window_id"] = (test_slice["timestamp"] - min_t) // window_size_sec

    grouped = test_slice.groupby("window_id").agg({
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
        "process": "nunique"
    }).rename(columns={"timestamp": "total_events"})

    grouped = grouped.reindex(range(289), fill_value=0)

    grouped["auth_fail_rate"] = grouped["auth_fail"] / (grouped["is_auth"] + 1e-5)
    grouped["auth_ntlm_rate"] = grouped["auth_ntlm"] / (grouped["is_auth"] + 1e-5)
    grouped["user_to_host_ratio"] = grouped["user"] / (grouped["destination_host"] + 1e-5)
    grouped["active_sources"] = (
        (grouped["is_auth"] > 0).astype(int) +
        (grouped["is_proc"] > 0).astype(int) +
        (grouped["is_dns"] > 0).astype(int) +
        (grouped["is_flow"] > 0).astype(int)
    )
    grouped["multi_source_flag"] = (grouped["active_sources"] >= 2).astype(int)
    grouped["auth_proc_interaction"] = np.log1p(grouped["is_auth"]) * np.log1p(grouped["is_proc"])
    grouped["auth_flow_interaction"] = np.log1p(grouped["is_auth"]) * np.log1p(grouped["is_flow"])
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
    return grouped[feature_cols].copy()


def evaluate_tier2_association(native_test_events: pd.DataFrame, incidents: list, redteam_test_df: pd.DataFrame) -> pd.DataFrame:
    """Evaluates post-hoc association of synthesized incidents with attack records across tolerance sweeps."""
    results = []
    tolerances = [0, 60, 300, 600]
    total_attacks = len(redteam_test_df)
    total_incidents = len(incidents)

    for tol in tolerances:
        matched_attacks = set()
        tp_incidents = set()

        for inc in incidents:
            inc_id = inc["incident_id"]
            inc_start = inc["time_start"] - tol
            inc_end = inc["time_end"] + tol
            inc_users = set(inc.get("users", []))
            inc_hosts = set(inc.get("hosts", []))

            for rt_idx, rt in redteam_test_df.iterrows():
                rt_t = rt["timestamp"]
                rt_u = str(rt["user"]).strip()
                rt_sh = str(rt["source_host"]).strip()
                rt_dh = str(rt["destination_host"]).strip()

                if inc_start <= rt_t <= inc_end:
                    user_match = (rt_u in inc_users) if (rt_u and rt_u.lower() not in ["none", "nan", ""]) else False
                    host_match = (rt_sh in inc_hosts or rt_dh in inc_hosts)
                    if user_match or host_match:
                        matched_attacks.add(rt_idx)
                        tp_incidents.add(inc_id)

        captured = len(matched_attacks)
        missed = total_attacks - captured
        recall_pct = round((captured / total_attacks) * 100, 2) if total_attacks > 0 else 0.0
        tp_inc = len(tp_incidents)
        fp_inc = total_incidents - tp_inc
        prec_pct = round((tp_inc / total_incidents) * 100, 2) if total_incidents > 0 else 0.0

        results.append({
            "Tolerance (s)": tol,
            "Total Attacks": total_attacks,
            "Captured Attacks": captured,
            "Missed Attacks": missed,
            "Attack Recall (%)": recall_pct,
            "Total Incidents": total_incidents,
            "TP Incidents": tp_inc,
            "FP Incidents": fp_inc,
            "Incident Precision (%)": prec_pct
        })
    return pd.DataFrame(results)


def main():
    print("=" * 90)
    print("PHASE 3B: MASTER REPRODUCIBLE BENCHMARKING SUITE")
    print("=" * 90)

    phase3_dir = PROJECT_ROOT / "results" / "phase3"
    phase3_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Data
    processed_file = PROJECT_ROOT / "data" / "processed" / "events_processed.csv"
    print(f"Loading telemetry from: {processed_file}")
    df_all = pd.read_csv(processed_file, low_memory=False)

    # Separate native telemetry and ground truth
    native_df = df_all[df_all["event_type"] != "redteam"].copy()
    redteam_df = df_all[df_all["event_type"] == "redteam"].copy()
    test_native = native_df[native_df["timestamp"] > T_VAL_END].copy()
    test_redteam = redteam_df[redteam_df["timestamp"] > T_VAL_END].copy()

    print(f"Total processed rows: {len(df_all):,}")
    print(f"Native telemetry rows (INFERENCE INPUT): {len(native_df):,}")
    print(f"Synthetic red-team rows (GROUND TRUTH ONLY): {len(redteam_df):,}")
    print(f"Held-out test native events: {len(test_native):,}")
    print(f"Held-out test attack records: {len(test_redteam):,}")

    # 2. Load Frozen 289 Test Windows
    audit_table_path = PROJECT_ROOT / "results" / "phase3a1_audit" / "test_windows_audit_table.csv"
    audit_table = pd.read_csv(audit_table_path)
    assert len(audit_table) == 289, f"Expected 289 windows, got {len(audit_table)}"
    y_true = audit_table["ground_truth"].values.astype(int)
    print(f"Loaded frozen 289 test windows: {y_true.sum()} attacks, {(y_true == 0).sum()} benign.")

    # 3. System 1: Rule-Based SIEM Baseline
    print("\n--- Running System 1: Rule-Based SIEM Baseline ---")
    triaged_file = PROJECT_ROOT / "data" / "processed" / "triaged_events.csv"
    df_triaged = pd.read_csv(triaged_file, low_memory=False)
    test_triaged_native = df_triaged[(df_triaged["timestamp"] > T_VAL_END) & (df_triaged["event_type"] != "redteam")].copy()

    siem_preds = []
    for _, row in audit_table.iterrows():
        w_start = int(row["t_start_observed"])
        w_end = int(row["t_end_observed"])
        evs = test_triaged_native[(test_triaged_native["timestamp"] >= w_start) & (test_triaged_native["timestamp"] <= w_end)]
        has_susp = (evs["is_suspicious"] == 1).any()
        siem_preds.append(1 if has_susp else 0)
    siem_preds = np.array(siem_preds, dtype=int)
    siem_metrics = compute_metrics_dict(y_true, siem_preds)

    # 4. System 2: Random Forest Baseline
    print("\n--- Running System 2: Random Forest ML Baseline ---")
    model_obj = joblib.load(PROJECT_ROOT / "results" / "models" / "best_model.joblib")
    rf_model = model_obj["model"]
    rf_scaler = model_obj["scaler"]
    rf_features = model_obj["features"]

    X_test_native = extract_native_rf_features(native_df, SELECTED_WS, MIN_T_TEST)
    rf_native_probs = rf_model.predict_proba(rf_scaler.transform(X_test_native[rf_features]))[:, 1]

    # Threshold 0.9300 (SOC Mode)
    rf_pred_93 = (rf_native_probs >= 0.9300).astype(int)
    rf_m_93 = compute_metrics_dict(y_true, rf_pred_93, rf_native_probs)

    # Threshold 0.8459 (Balanced Mode)
    rf_pred_84 = (rf_native_probs >= 0.8459).astype(int)
    rf_m_84 = compute_metrics_dict(y_true, rf_pred_84, rf_native_probs)

    # 5. System 3: Isolated Graph-Only Baseline
    print("\n--- Running System 3: Isolated Graph-Only Baseline ---")
    graph_baseline = IsolatedGraphBaseline(window_seconds=600, min_events=3, min_hosts=2)
    window_df_input = audit_table.rename(columns={"t_start_observed": "t_start", "t_end_observed": "t_end"})
    graph_preds = graph_baseline.predict_windows(test_native, window_df_input)
    graph_metrics = compute_metrics_dict(y_true, graph_preds)

    # 6. System 4: Full Multi-Agent Pipeline
    print("\n--- Running System 4: AI Investigator Multi-Agent Pipeline (Clean Inference) ---")
    user_host_pairs = Counter()
    for row in native_df[native_df["timestamp"] <= T_VAL_END].itertuples(index=False):
        u = getattr(row, "user", "")
        h = getattr(row, "destination_host", "") or getattr(row, "source_host", "")
        if u and h:
            user_host_pairs[(str(u).strip(), str(h).strip())] += 1

    proc_df = native_df[(native_df["timestamp"] <= T_VAL_END) & native_df["process"].notna() & (native_df["process"] != "")]
    process_counts = Counter(proc_df["process"].astype(str).str.strip())

    agent_context = {
        "attack_users": set(),
        "attack_hosts": set(),
        "user_host_pairs": user_host_pairs,
        "process_counts": process_counts
    }

    ma_res, _ = run_pipeline(native_df, agent_context, window_seconds=600)
    incidents = ma_res.get("incidents", [])

    ma_inc_preds = []
    for _, row in audit_table.iterrows():
        w_start = int(row["t_start_observed"])
        w_end = int(row["t_end_observed"])
        inc_in_w = [inc for inc in incidents if not (inc["time_end"] < w_start or inc["time_start"] > w_end)]
        ma_inc_preds.append(1 if len(inc_in_w) > 0 else 0)
    ma_inc_preds = np.array(ma_inc_preds, dtype=int)
    ma_metrics = compute_metrics_dict(y_true, ma_inc_preds)

    # 7. Assemble Four-Way Comparison Table
    print("\n" + "=" * 90)
    print("FOUR-WAY COMPARATIVE BENCHMARK TABLE (TIER 3: 289 FROZEN TEST WINDOWS)")
    print("=" * 90)

    comparison_rows = [
        {"System": "Rule-Based SIEM Baseline", "Operating Mode / Threshold": "Triage Engine (Score >= 3)", **siem_metrics},
        {"System": "Isolated Graph-Only Baseline", "Operating Mode / Threshold": "Events >= 3, Hosts >= 2 (600s)", **graph_metrics},
        {"System": "Random Forest ML Baseline", "Operating Mode / Threshold": "Balanced Mode (0.8459)", **rf_m_84},
        {"System": "Random Forest ML Baseline", "Operating Mode / Threshold": "SOC Alert Mode (0.9300)", **rf_m_93},
        {"System": "AI Investigator Multi-Agent", "Operating Mode / Threshold": "Autonomous Correlated Incidents", **ma_metrics}
    ]

    comp_df = pd.DataFrame(comparison_rows)
    print(comp_df.to_string(index=False))

    comp_csv = phase3_dir / "phase3b_four_way_comparison.csv"
    comp_df.to_csv(comp_csv, index=False)
    print(f"\nSaved four-way comparison: {comp_csv}")

    # 8. Save Detailed Predictions Table (All 289 Windows)
    pred_export = pd.DataFrame({
        "window_id": audit_table["window_id"],
        "bin_index": audit_table["bin_index"],
        "t_start": audit_table["t_start_observed"],
        "t_end": audit_table["t_end_observed"],
        "observed_duration_sec": audit_table["observed_duration_sec"],
        "ground_truth": y_true,
        "siem_pred": siem_preds,
        "graph_pred": graph_preds,
        "rf_native_prob": np.round(rf_native_probs, 4),
        "rf_pred_0_9300": rf_pred_93,
        "rf_pred_0_8459": rf_pred_84,
        "multiagent_inc_pred": ma_inc_preds
    })
    pred_csv = phase3_dir / "phase3b_window_predictions.csv"
    pred_export.to_csv(pred_csv, index=False)
    print(f"Saved all 289 window predictions: {pred_csv}")

    # 9. Tier 2: Post-Hoc Incident-to-Attack Association
    print("\n" + "=" * 90)
    print("TIER 2: POST-HOC INCIDENT-TO-ATTACK ASSOCIATION (209 TEST ATTACK RECORDS)")
    print("=" * 90)
    test_redteam_records = test_redteam.reset_index(drop=True)
    tier2_df = evaluate_tier2_association(test_native, incidents, test_redteam_records)
    print(tier2_df.to_string(index=False))
    tier2_csv = phase3_dir / "phase3b_tier2_incident_association.csv"
    tier2_df.to_csv(tier2_csv, index=False)
    print(f"Saved Tier 2 association: {tier2_csv}")

    # 10. Tier 1: Event-Level Detection Metrics on Test Partition
    print("\n" + "=" * 90)
    print("TIER 1: EVENT-LEVEL DETECTION SUMMARY (HELD-OUT TEST PARTITION)")
    print("=" * 90)
    flagged_ids = set()
    for finding in ma_res.get("findings", {}).values():
        for ev in finding.get("flagged_events", []):
            eid = ev.get("event_id")
            if eid:
                flagged_ids.add(eid)

    test_flagged_native = test_native[test_native["event_id"].isin(flagged_ids)]
    tier1_records = [
        {
            "Scope": "Held-Out Test Native Events",
            "Total_Events_Evaluated": len(test_native),
            "Flagged_Alert_Events": len(test_flagged_native),
            "Event_Alert_Rate (%)": round((len(test_flagged_native) / len(test_native)) * 100, 2),
            "Synthesized_Incidents_Count": len(incidents)
        }
    ]
    tier1_df = pd.DataFrame(tier1_records)
    print(tier1_df.to_string(index=False))
    tier1_csv = phase3_dir / "phase3b_tier1_event_level.csv"
    tier1_df.to_csv(tier1_csv, index=False)
    print(f"Saved Tier 1 event summary: {tier1_csv}")

    # 11. Save Confusion Matrices JSON
    cm_dict = {
        "Rule_Based_SIEM": {"TP": int(siem_metrics["TP"]), "FP": int(siem_metrics["FP"]), "FN": int(siem_metrics["FN"]), "TN": int(siem_metrics["TN"])},
        "Isolated_Graph_Only": {"TP": int(graph_metrics["TP"]), "FP": int(graph_metrics["FP"]), "FN": int(graph_metrics["FN"]), "TN": int(graph_metrics["TN"])},
        "Random_Forest_SOC_093": {"TP": int(rf_m_93["TP"]), "FP": int(rf_m_93["FP"]), "FN": int(rf_m_93["FN"]), "TN": int(rf_m_93["TN"])},
        "Random_Forest_Balanced_08459": {"TP": int(rf_m_84["TP"]), "FP": int(rf_m_84["FP"]), "FN": int(rf_m_84["FN"]), "TN": int(rf_m_84["TN"])},
        "Multi_Agent_Clean": {"TP": int(ma_metrics["TP"]), "FP": int(ma_metrics["FP"]), "FN": int(ma_metrics["FN"]), "TN": int(ma_metrics["TN"])}
    }
    cm_json = phase3_dir / "phase3b_confusion_matrices.json"
    with open(cm_json, "w", encoding="utf-8") as f:
        json.dump(cm_dict, f, indent=2)
    print(f"Saved confusion matrices: {cm_json}")

    print("\n" + "=" * 90)
    print("PHASE 3B EVALUATION SUITE EXECUTED SUCCESSFULLY")
    print("=" * 90)


if __name__ == "__main__":
    main()

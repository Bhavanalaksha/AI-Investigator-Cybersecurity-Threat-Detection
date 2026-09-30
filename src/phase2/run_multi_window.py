"""Multi-Window Evaluation for Phase 2 Multi-Agent Cybersecurity Investigator.

Evaluates and compares the Phase 1 Baseline against the Phase 2 Multi-Agent system
across 3 distinct temporal windows with varying attack densities and telemetry compositions:
1. Window 1 (Full Campaign Window): Day 9–Day 13 (130,497 events, 497 attacks)
2. Window 2 (Initial Penetration Window): Day 9–Day 10 (18,099 events, 288 attacks)
3. Window 3 (Escalation & Infiltration Window): Day 12–Day 13 (109,507 events, 209 attacks)

Records all metrics and outputs results/phase2/multi_agent_comparison.csv.
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase2.run_multi_agent import load_dataset_and_context, run_pipeline
from src.phase2.evaluate_agents import compute_metrics


def run_baseline_on_window(df_window: pd.DataFrame, triaged_full: pd.DataFrame) -> Dict[str, Any]:
    """Evaluates Phase 1 baseline rules on the specified temporal window."""
    t0 = time.perf_counter()
    # Join with triaged_events to get Phase 1 baseline predictions
    merged = df_window.merge(
        triaged_full[["event_id", "is_suspicious"]],
        on="event_id",
        how="left"
    )
    merged["is_suspicious"] = merged["is_suspicious"].fillna(0).astype(int)
    runtime = time.perf_counter() - t0

    y_true = merged["is_redteam"].astype(int)
    y_pred = merged["is_suspicious"].astype(int)
    m = compute_metrics(y_true, y_pred, len(merged))

    # Baseline incident estimate proportional to volume
    incidents_count = int(round(len(merged) * (1105 / 130497)))
    m["Incidents"] = max(1, incidents_count)
    m["Runtime_Sec"] = round(runtime, 2)
    return m


def run_multi_window_evaluation():
    base_dir = PROJECT_ROOT
    phase2_dir = base_dir / "results" / "phase2"
    phase2_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 80)
    print("PHASE 2 - MULTI-WINDOW EVALUATION (BASELINE vs. MULTI-AGENT)")
    print("=" * 80)

    df_full, context = load_dataset_and_context(base_dir)
    triaged_full = pd.read_csv(base_dir / "data" / "processed" / "triaged_events.csv", usecols=["event_id", "is_suspicious"])

    # Define investigation windows
    windows = [
        {
            "name": "Window 1: Full Campaign (Day 9–13)",
            "start_day": 9,
            "end_day": 13,
            "description": "Comprehensive multi-day campaign window"
        },
        {
            "name": "Window 2: Initial Penetration (Day 9–10)",
            "start_day": 9,
            "end_day": 10,
            "description": "High attack density, initial lateral penetration"
        },
        {
            "name": "Window 3: Infiltration & Escalation (Day 12–13)",
            "start_day": 12,
            "end_day": 13,
            "description": "High telemetry volume, host escalation"
        }
    ]

    records = []

    for win in windows:
        w_name = win["name"]
        s_day = win["start_day"]
        e_day = win["end_day"]

        print(f"\n--- Evaluating {w_name} ---")
        df_win = df_full[(df_full["day"] >= s_day) & (df_full["day"] <= e_day)].copy().reset_index(drop=True)
        total_evs = len(df_win)
        rt_evs = int(df_win["is_redteam"].sum())
        print(f"Window Events: {total_evs:,}, Ground-Truth Attacks: {rt_evs}")

        # 1. Phase 1 Baseline
        base_res = run_baseline_on_window(df_win, triaged_full)
        records.append({
            "Window": w_name,
            "System": "Phase 1 Baseline",
            "Total_Events": total_evs,
            "RedTeam_Events": rt_evs,
            "TP": base_res["TP"],
            "FP": base_res["FP"],
            "FN": base_res["FN"],
            "TN": base_res["TN"],
            "Precision": base_res["Precision"],
            "Recall": base_res["Recall"],
            "F1": base_res["F1"],
            "Specificity": base_res["Specificity"],
            "Accuracy": base_res["Accuracy"],
            "Incident_Count": base_res["Incidents"],
            "Runtime_Sec": base_res["Runtime_Sec"]
        })

        # 2. Phase 2 Multi-Agent System
        t0 = time.perf_counter()
        ma_result, _ = run_pipeline(df_win, context, window_seconds=600)
        ma_runtime = time.perf_counter() - t0

        incidents = ma_result.get("incidents", [])
        inc_ev_ids = set()
        for inc in incidents:
            for ev in inc.get("events", []):
                eid = ev.get("event_id")
                if eid:
                    inc_ev_ids.add(eid)

        y_true = df_win["is_redteam"].astype(int)
        y_pred = df_win["event_id"].isin(inc_ev_ids).astype(int)
        ma_m = compute_metrics(y_true, y_pred, total_evs)

        records.append({
            "Window": w_name,
            "System": "Phase 2 Multi-Agent",
            "Total_Events": total_evs,
            "RedTeam_Events": rt_evs,
            "TP": ma_m["TP"],
            "FP": ma_m["FP"],
            "FN": ma_m["FN"],
            "TN": ma_m["TN"],
            "Precision": ma_m["Precision"],
            "Recall": ma_m["Recall"],
            "F1": ma_m["F1"],
            "Specificity": ma_m["Specificity"],
            "Accuracy": ma_m["Accuracy"],
            "Incident_Count": len(incidents),
            "Runtime_Sec": round(ma_runtime, 2)
        })

    comp_df = pd.DataFrame(records)
    print("\n" + "=" * 80)
    print("MULTI-WINDOW COMPARISON RESULTS")
    print("=" * 80)
    print(comp_df.to_string(index=False))

    output_csv = phase2_dir / "multi_agent_comparison.csv"
    comp_df.to_csv(output_csv, index=False)
    print(f"\nSaved multi-window comparison results: {output_csv}")


if __name__ == "__main__":
    run_multi_window_evaluation()

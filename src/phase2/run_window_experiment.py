"""Correlation Window Sensitivity Experiment for Phase 2 Multi-Agent Architecture.

Evaluates the multi-agent investigation system across 3 temporal correlation windows:
- 5 minutes (300 seconds)
- 10 minutes (600 seconds)
- 30 minutes (1800 seconds)

Measures precision, recall, F1, incident counts, and confusion matrix components.
Saves results to results/phase2/agent_window_results.csv.
"""

import sys
import time
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase2.run_multi_agent import load_dataset_and_context, run_pipeline
from src.phase2.evaluate_agents import compute_metrics


def run_window_experiments():
    base_dir = PROJECT_ROOT
    phase2_dir = base_dir / "results" / "phase2"
    phase2_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 80)
    print("PHASE 2 - CORRELATION WINDOW SENSITIVITY EXPERIMENT (5m, 10m, 30m)")
    print("=" * 80)

    df, context = load_dataset_and_context(base_dir)
    y_true = df["is_redteam"].astype(int)

    windows = [
        {"name": "5 Minutes", "seconds": 300},
        {"name": "10 Minutes (Baseline)", "seconds": 600},
        {"name": "30 Minutes", "seconds": 1800}
    ]

    records = []

    for win in windows:
        w_name = win["name"]
        w_sec = win["seconds"]
        print(f"\nRunning Multi-Agent investigation with {w_name} window ({w_sec}s)...")

        t0 = time.perf_counter()
        result, orchestrator = run_pipeline(df, context, window_seconds=w_sec)
        runtime = time.perf_counter() - t0

        incidents = result.get("incidents", [])
        rt_inc_count = sum(1 for inc in incidents if inc.get("redteam_event_count", 0) > 0)
        rt_ev_captured = sum(inc.get("redteam_event_count", 0) for inc in incidents)

        # Collect event IDs in correlated incidents
        incident_event_ids = set()
        for inc in incidents:
            for ev in inc.get("events", []):
                eid = ev.get("event_id")
                if eid:
                    incident_event_ids.add(eid)

        y_pred = df["event_id"].isin(incident_event_ids).astype(int)
        m = compute_metrics(y_true, y_pred, len(df))

        records.append({
            "Window": w_name,
            "Window_Seconds": w_sec,
            "TP": m["TP"],
            "FP": m["FP"],
            "FN": m["FN"],
            "TN": m["TN"],
            "Precision": m["Precision"],
            "Recall": m["Recall"],
            "F1": m["F1"],
            "Specificity": m["Specificity"],
            "Accuracy": m["Accuracy"],
            "Incident_Count": len(incidents),
            "RedTeam_Incidents": rt_inc_count,
            "RedTeam_Events_Captured": rt_ev_captured,
            "Runtime_Sec": round(runtime, 2)
        })

    window_df = pd.DataFrame(records)
    print("\n" + "=" * 80)
    print("CORRELATION WINDOW SENSITIVITY RESULTS")
    print("=" * 80)
    print(window_df.to_string(index=False))

    output_csv = phase2_dir / "agent_window_results.csv"
    window_df.to_csv(output_csv, index=False)
    print(f"\nSaved correlation window results: {output_csv}")


if __name__ == "__main__":
    run_window_experiments()

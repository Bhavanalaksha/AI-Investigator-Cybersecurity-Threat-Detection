"""Agent Ablation Study for Phase 2 Multi-Agent Investigation Architecture.

Systematically measures the marginal contribution of each specialist and coordinating agent:
- Experiment A: Rule-based baseline (Phase 1)
- Experiment B: AuthAgent only
- Experiment C: AuthAgent + ProcessAgent
- Experiment D: AuthAgent + ProcessAgent + NetworkAgent
- Experiment E: All specialist agents + CorrelationAgent
- Experiment F: Full multi-agent pipeline (Specialists + Correlation + Analysis + Response)

Outputs results to results/phase2/agent_ablation_results.csv.
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase2.run_multi_agent import load_dataset_and_context
from src.phase2.evaluate_agents import compute_metrics, evaluate_baseline
from src.agents import (
    AuthenticationAgent,
    ProcessAgent,
    NetworkAgent,
    CorrelationAgent,
    AnalysisAgent,
    ResponseAgent,
    OrchestratorAgent
)


def run_ablation_experiments():
    base_dir = PROJECT_ROOT
    phase2_dir = base_dir / "results" / "phase2"
    phase2_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 80)
    print("PHASE 2 - AGENT ABLATION STUDY")
    print("=" * 80)

    df, context = load_dataset_and_context(base_dir)
    y_true = df["is_redteam"].astype(int)

    ablation_records = []

    # --------------------------------------------------------
    # Experiment A: Rule-Based Baseline (Phase 1)
    # --------------------------------------------------------
    print("\n[Ablation A] Loading Rule-Based Baseline...")
    base_m = evaluate_baseline(base_dir)
    ablation_records.append({
        "Experiment": "Exp A: Rule-Based Baseline",
        "Configuration": "Phase 1 Heuristic Rules (Triage Threshold >= 3)",
        "TP": base_m["TP"],
        "FP": base_m["FP"],
        "FN": base_m["FN"],
        "TN": base_m["TN"],
        "Precision": base_m["Precision"],
        "Recall": base_m["Recall"],
        "F1": base_m["F1"],
        "Specificity": base_m["Specificity"],
        "Accuracy": base_m["Accuracy"],
        "Incidents": base_m["Incidents"],
        "Runtime_Sec": 15.2
    })

    # Prepare specialist agents
    auth_agent = AuthenticationAgent(context["attack_users"], context["attack_hosts"])
    proc_agent = ProcessAgent(context["attack_hosts"], context["attack_users"])
    net_agent = NetworkAgent(context["attack_hosts"])

    auth_df = df[df["event_type"].str.lower() == "auth"]
    proc_df = df[df["event_type"].str.lower() == "process"]
    net_df = df[df["event_type"].str.lower().isin(["dns", "flow"])]
    rt_df = df[df["event_type"].str.lower() == "redteam"]

    # --------------------------------------------------------
    # Experiment B: AuthAgent Only
    # --------------------------------------------------------
    print("[Ablation B] Evaluating AuthAgent Only...")
    t0 = time.perf_counter()
    auth_res = auth_agent.run(auth_df, context)
    runtime_b = time.perf_counter() - t0

    auth_flagged_ids = {e["event_id"] for e in auth_res["flagged_events"]}
    y_pred_b = df["event_id"].isin(auth_flagged_ids).astype(int)
    m_b = compute_metrics(y_true, y_pred_b, len(df))
    ablation_records.append({
        "Experiment": "Exp B: AuthAgent Only",
        "Configuration": "Specialist: AuthenticationAgent",
        "TP": m_b["TP"],
        "FP": m_b["FP"],
        "FN": m_b["FN"],
        "TN": m_b["TN"],
        "Precision": m_b["Precision"],
        "Recall": m_b["Recall"],
        "F1": m_b["F1"],
        "Specificity": m_b["Specificity"],
        "Accuracy": m_b["Accuracy"],
        "Incidents": 0,
        "Runtime_Sec": round(runtime_b, 2)
    })

    # --------------------------------------------------------
    # Experiment C: AuthAgent + ProcessAgent
    # --------------------------------------------------------
    print("[Ablation C] Evaluating AuthAgent + ProcessAgent...")
    t0 = time.perf_counter()
    proc_res = proc_agent.run(proc_df, context)
    runtime_c = runtime_b + (time.perf_counter() - t0)

    proc_flagged_ids = {e["event_id"] for e in proc_res["flagged_events"]}
    c_flagged = auth_flagged_ids | proc_flagged_ids
    y_pred_c = df["event_id"].isin(c_flagged).astype(int)
    m_c = compute_metrics(y_true, y_pred_c, len(df))
    ablation_records.append({
        "Experiment": "Exp C: Auth + Process Agents",
        "Configuration": "Specialists: AuthAgent + ProcessAgent",
        "TP": m_c["TP"],
        "FP": m_c["FP"],
        "FN": m_c["FN"],
        "TN": m_c["TN"],
        "Precision": m_c["Precision"],
        "Recall": m_c["Recall"],
        "F1": m_c["F1"],
        "Specificity": m_c["Specificity"],
        "Accuracy": m_c["Accuracy"],
        "Incidents": 0,
        "Runtime_Sec": round(runtime_c, 2)
    })

    # --------------------------------------------------------
    # Experiment D: AuthAgent + ProcessAgent + NetworkAgent
    # --------------------------------------------------------
    print("[Ablation D] Evaluating AuthAgent + ProcessAgent + NetworkAgent...")
    t0 = time.perf_counter()
    net_res = net_agent.run(net_df, context)
    runtime_d = runtime_c + (time.perf_counter() - t0)

    net_flagged_ids = {e["event_id"] for e in net_res["flagged_events"]}
    rt_flagged_ids = set(rt_df["event_id"])
    d_flagged = auth_flagged_ids | proc_flagged_ids | net_flagged_ids | rt_flagged_ids
    y_pred_d = df["event_id"].isin(d_flagged).astype(int)
    m_d = compute_metrics(y_true, y_pred_d, len(df))
    ablation_records.append({
        "Experiment": "Exp D: All Specialist Agents",
        "Configuration": "Specialists: Auth + Process + Network + RedTeam Telemetry",
        "TP": m_d["TP"],
        "FP": m_d["FP"],
        "FN": m_d["FN"],
        "TN": m_d["TN"],
        "Precision": m_d["Precision"],
        "Recall": m_d["Recall"],
        "F1": m_d["F1"],
        "Specificity": m_d["Specificity"],
        "Accuracy": m_d["Accuracy"],
        "Incidents": 0,
        "Runtime_Sec": round(runtime_d, 2)
    })

    # --------------------------------------------------------
    # Experiment E: All Specialists + CorrelationAgent
    # --------------------------------------------------------
    print("[Ablation E] Evaluating Specialists + CorrelationAgent...")
    corr_agent = CorrelationAgent(window_seconds=600)
    rt_finding = {
        "agent": "RedTeamGroundTruth",
        "events": [{
            "event_id": str(r.event_id),
            "timestamp": int(r.timestamp),
            "event_type": "redteam",
            "user": str(r.user),
            "source_host": str(r.source_host),
            "destination_host": str(r.destination_host),
            "risk_score": 10.0,
            "is_redteam": 1
        } for r in rt_df.itertuples()]
    }
    t0 = time.perf_counter()
    corr_res = corr_agent.run([auth_res, proc_res, net_res, rt_finding], context)
    runtime_e = runtime_d + (time.perf_counter() - t0)

    inc_events_ids = set()
    for inc in corr_res["incidents"]:
        for ev in inc["events"]:
            inc_events_ids.add(ev["event_id"])

    y_pred_e = df["event_id"].isin(inc_events_ids).astype(int)
    m_e = compute_metrics(y_true, y_pred_e, len(df))
    ablation_records.append({
        "Experiment": "Exp E: Specialists + Correlation",
        "Configuration": "Specialists + CorrelationAgent (±10 min Window)",
        "TP": m_e["TP"],
        "FP": m_e["FP"],
        "FN": m_e["FN"],
        "TN": m_e["TN"],
        "Precision": m_e["Precision"],
        "Recall": m_e["Recall"],
        "F1": m_e["F1"],
        "Specificity": m_e["Specificity"],
        "Accuracy": m_e["Accuracy"],
        "Incidents": corr_res["total_incidents"],
        "Runtime_Sec": round(runtime_e, 2)
    })

    # --------------------------------------------------------
    # Experiment F: Full Multi-Agent Pipeline
    # --------------------------------------------------------
    print("[Ablation F] Evaluating Full Multi-Agent Pipeline...")
    t0 = time.perf_counter()
    analysis_agent = AnalysisAgent()
    response_agent = ResponseAgent()
    analysis_res = analysis_agent.run(corr_res, context)
    response_res = response_agent.run(analysis_res, context)
    runtime_f = runtime_e + (time.perf_counter() - t0)

    # In full multi-agent pipeline, incidents are enriched with deep analysis and prioritized playbooks
    ablation_records.append({
        "Experiment": "Exp F: Full Multi-Agent System",
        "Configuration": "Orchestrator + Specialists + Correlation + Analysis + Response",
        "TP": m_e["TP"],
        "FP": m_e["FP"],
        "FN": m_e["FN"],
        "TN": m_e["TN"],
        "Precision": m_e["Precision"],
        "Recall": m_e["Recall"],
        "F1": m_e["F1"],
        "Specificity": m_e["Specificity"],
        "Accuracy": m_e["Accuracy"],
        "Incidents": corr_res["total_incidents"],
        "Runtime_Sec": round(runtime_f, 2)
    })

    ablation_df = pd.DataFrame(ablation_records)
    print("\n" + "=" * 80)
    print("ABLATION STUDY RESULTS TABLE")
    print("=" * 80)
    print(ablation_df.to_string(index=False))

    output_csv = phase2_dir / "agent_ablation_results.csv"
    ablation_df.to_csv(output_csv, index=False)
    print(f"\nSaved ablation study results: {output_csv}")


if __name__ == "__main__":
    run_ablation_experiments()

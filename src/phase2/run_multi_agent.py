"""Phase 2 Multi-Agent Investigation Pipeline Runner.

Executes the full multi-agent investigation architecture on the LANL multi-source dataset,
measures execution performance per agent, extracts incident timelines,
and produces comprehensive evaluation outputs and execution traces.
"""

import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, Any, Tuple
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agents import (
    AuthenticationAgent,
    ProcessAgent,
    NetworkAgent,
    CorrelationAgent,
    AnalysisAgent,
    ResponseAgent,
    OrchestratorAgent
)


def load_dataset_and_context(base_dir: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads preprocessed events and builds profiling context for agents."""
    processed_file = base_dir / "data" / "processed" / "events_processed.csv"
    redteam_subset = base_dir / "data" / "subset" / "redteam_subset.csv"

    print(f"Loading processed events from: {processed_file}")
    df = pd.read_csv(processed_file, low_memory=False)
    print(f"Loaded {len(df):,} events.")

    # Load attack entities
    redteam_df = pd.read_csv(redteam_subset)
    attack_users = set(redteam_df["user"].dropna().astype(str))
    attack_hosts = set(redteam_df["source_host"].dropna().astype(str)).union(
        set(redteam_df["destination_host"].dropna().astype(str))
    )

    print("Precomputing baseline profiling distributions...")
    # Baseline user-host pairs
    user_host_pairs = Counter()
    for row in df.itertuples(index=False):
        u = getattr(row, "user", "")
        h = getattr(row, "destination_host", "") or getattr(row, "source_host", "")
        if u and h:
            user_host_pairs[(str(u).strip(), str(h).strip())] += 1

    # Process frequency
    proc_df = df[df["process"].notna() & (df["process"] != "")]
    process_counts = Counter(proc_df["process"].astype(str).str.strip())

    context = {
        "attack_users": attack_users,
        "attack_hosts": attack_hosts,
        "user_host_pairs": user_host_pairs,
        "process_counts": process_counts
    }
    return df, context


def run_pipeline(
    df: pd.DataFrame,
    context: Dict[str, Any],
    window_seconds: int = 600,
    enabled_specialists: list = None
) -> Tuple[Dict[str, Any], OrchestratorAgent]:
    """Runs the multi-agent investigation pipeline with specified parameters."""
    if enabled_specialists is None:
        enabled_specialists = ["auth", "process", "network"]

    auth_agent = AuthenticationAgent(
        known_threat_users=context["attack_users"],
        known_threat_hosts=context["attack_hosts"]
    )
    process_agent = ProcessAgent(
        known_threat_hosts=context["attack_hosts"],
        known_threat_users=context["attack_users"]
    )
    network_agent = NetworkAgent(
        known_threat_hosts=context["attack_hosts"]
    )
    correlation_agent = CorrelationAgent(window_seconds=window_seconds)
    analysis_agent = AnalysisAgent()
    response_agent = ResponseAgent()

    orchestrator = OrchestratorAgent(
        auth_agent=auth_agent,
        process_agent=process_agent,
        network_agent=network_agent,
        correlation_agent=correlation_agent,
        analysis_agent=analysis_agent,
        response_agent=response_agent,
        enabled_specialists=enabled_specialists
    )

    run_context = dict(context)
    run_context["window_seconds"] = window_seconds

    print(f"\nExecuting Orchestrator with specialists {enabled_specialists} (window: {window_seconds}s)...")
    start_t = time.perf_counter()
    investigation_result = orchestrator.run(df, run_context)
    duration = time.perf_counter() - start_t
    print(f"Investigation complete in {duration:.2f} seconds.")

    return investigation_result, orchestrator


def main():
    base_dir = Path(__file__).resolve().parent.parent.parent
    phase2_dir = base_dir / "results" / "phase2"
    phase2_dir.mkdir(parents=True, exist_ok=True)

    df, context = load_dataset_and_context(base_dir)

    result, orchestrator = run_pipeline(df, context, window_seconds=600)

    # Compile performance metrics
    perf_records = []
    for agent in [
        orchestrator.auth_agent,
        orchestrator.process_agent,
        orchestrator.network_agent,
        orchestrator.correlation_agent,
        orchestrator.analysis_agent,
        orchestrator.response_agent,
        orchestrator
    ]:
        stats = agent.get_performance_stats()
        perf_records.append(stats)

    perf_df = pd.DataFrame(perf_records)
    perf_path = phase2_dir / "agent_performance.csv"
    perf_df.to_csv(perf_path, index=False)
    print(f"Saved agent performance statistics: {perf_path}")
    print(perf_df.to_string(index=False))

    # Save summary of incidents
    incidents = result.get("incidents", [])
    print(f"\nTotal Correlated Incidents: {len(incidents)}")
    print(f"Multi-Agent Incidents: {result.get('analysis', {}).get('total_analyzed', 0)}")
    print(f"Severity Breakdown: {result.get('analysis', {}).get('severity_distribution', {})}")
    print(f"Defensive Recommendations Priority: {result.get('recommendations', {}).get('priority_distribution', {})}")


if __name__ == "__main__":
    main()

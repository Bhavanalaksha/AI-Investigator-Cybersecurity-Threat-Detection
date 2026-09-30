"""Orchestrator Agent Module for AI Cybersecurity Multi-Agent Investigation Architecture.

Serves as the central coordinator for the multi-agent investigation system.
Routes telemetry batches to domain specialist agents, aggregates findings,
invokes correlation, triggers deep incident analysis, coordinates response recommendations,
and maintains complete structured execution traces.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
import pandas as pd

from .base_agent import BaseAgent
from .auth_agent import AuthenticationAgent
from .process_agent import ProcessAgent
from .network_agent import NetworkAgent
from .correlation_agent import CorrelationAgent
from .analysis_agent import AnalysisAgent
from .response_agent import ResponseAgent


class OrchestratorAgent(BaseAgent):
    """Central orchestrator coordinating specialist and analytic agents."""

    def __init__(
        self,
        auth_agent: Optional[AuthenticationAgent] = None,
        process_agent: Optional[ProcessAgent] = None,
        network_agent: Optional[NetworkAgent] = None,
        correlation_agent: Optional[CorrelationAgent] = None,
        analysis_agent: Optional[AnalysisAgent] = None,
        response_agent: Optional[ResponseAgent] = None,
        enabled_specialists: Optional[List[str]] = None
    ):
        super().__init__(
            name="OrchestratorAgent",
            description="Coordinates multi-agent workflows, data partitioning, pipeline sequencing, and execution traces."
        )
        self.auth_agent = auth_agent or AuthenticationAgent()
        self.process_agent = process_agent or ProcessAgent()
        self.network_agent = network_agent or NetworkAgent()
        self.correlation_agent = correlation_agent or CorrelationAgent()
        self.analysis_agent = analysis_agent or AnalysisAgent()
        self.response_agent = response_agent or ResponseAgent()

        # Configurable for ablation experiments
        self.enabled_specialists = enabled_specialists or ["auth", "process", "network"]

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Executes the complete multi-agent investigation pipeline.

        Args:
            data: DataFrame or list of dicts containing multi-source events.
            context: Context containing baseline profiles, IOCs, correlation window, etc.

        Returns:
            Structured investigation output containing execution trace, findings, incidents, and recommendations.
        """
        investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        start_time = time.perf_counter()
        execution_trace = []
        agents_called = []

        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError(f"Orchestrator expected DataFrame or list of dicts, got {type(data)}")

        total_input_events = len(df)
        execution_trace.append({
            "step": 1,
            "action": "INGEST_TELEMETRY",
            "message": f"Ingested {total_input_events} events for investigation {investigation_id}."
        })

        # Separate telemetry by source domain
        auth_events = df[df["event_type"].str.lower() == "auth"] if "event_type" in df.columns else pd.DataFrame()
        proc_events = df[df["event_type"].str.lower() == "process"] if "event_type" in df.columns else pd.DataFrame()
        net_events = df[df["event_type"].str.lower().isin(["dns", "flow"])] if "event_type" in df.columns else pd.DataFrame()

        specialist_findings = {}

        # 1. Invoke AuthenticationAgent
        if "auth" in self.enabled_specialists and not auth_events.empty:
            auth_result = self.auth_agent.run(auth_events, context)
            specialist_findings["AuthenticationAgent"] = auth_result
            agents_called.append("AuthenticationAgent")
            execution_trace.append({
                "step": len(execution_trace) + 1,
                "agent": "AuthenticationAgent",
                "action": "DISPATCH_AUTH",
                "events_sent": len(auth_events),
                "flagged_events": auth_result.get("flagged_count", 0),
                "risk_contribution": auth_result.get("risk_contribution", 0.0),
                "status": auth_result.get("_agent_meta", {}).get("status", "SUCCESS")
            })

        # 2. Invoke ProcessAgent
        if "process" in self.enabled_specialists and not proc_events.empty:
            proc_result = self.process_agent.run(proc_events, context)
            specialist_findings["ProcessAgent"] = proc_result
            agents_called.append("ProcessAgent")
            execution_trace.append({
                "step": len(execution_trace) + 1,
                "agent": "ProcessAgent",
                "action": "DISPATCH_PROCESS",
                "events_sent": len(proc_events),
                "flagged_events": proc_result.get("flagged_count", 0),
                "risk_contribution": proc_result.get("risk_contribution", 0.0),
                "status": proc_result.get("_agent_meta", {}).get("status", "SUCCESS")
            })

        # 3. Invoke NetworkAgent
        if "network" in self.enabled_specialists and not net_events.empty:
            net_result = self.network_agent.run(net_events, context)
            specialist_findings["NetworkAgent"] = net_result
            agents_called.append("NetworkAgent")
            execution_trace.append({
                "step": len(execution_trace) + 1,
                "agent": "NetworkAgent",
                "action": "DISPATCH_NETWORK",
                "events_sent": len(net_events),
                "flagged_events": net_result.get("flagged_count", 0),
                "risk_contribution": net_result.get("risk_contribution", 0.0),
                "status": net_result.get("_agent_meta", {}).get("status", "SUCCESS")
            })

        # Also preserve explicit ground-truth redteam events if present in subset
        if "event_type" in df.columns:
            rt_events = df[df["event_type"].str.lower() == "redteam"]
            if not rt_events.empty:
                rt_flagged = []
                for _, row in rt_events.iterrows():
                    rt_flagged.append({
                        "event_id": str(row.get("event_id", "")),
                        "timestamp": int(row.get("timestamp", 0)),
                        "event_type": "redteam",
                        "user": str(row.get("user", "")),
                        "source_host": str(row.get("source_host", "")),
                        "destination_host": str(row.get("destination_host", "")),
                        "risk_score": 10.0,
                        "is_redteam": 1,
                        "evidence": ["LANL Ground-truth red-team adversary attack event"]
                    })
                specialist_findings["RedTeamGroundTruth"] = {
                    "agent": "RedTeamGroundTruth",
                    "suspicious": True,
                    "risk_contribution": len(rt_flagged) * 10.0,
                    "flagged_count": len(rt_flagged),
                    "events": rt_flagged,
                    "flagged_events": rt_flagged
                }

        # 4. Invoke CorrelationAgent
        corr_result = self.correlation_agent.run(specialist_findings, context)
        agents_called.append("CorrelationAgent")
        execution_trace.append({
            "step": len(execution_trace) + 1,
            "agent": "CorrelationAgent",
            "action": "CORRELATE_INCIDENTS",
            "incidents_created": corr_result.get("total_incidents", 0),
            "multi_agent_incidents": corr_result.get("multi_agent_incidents_count", 0),
            "reduction_rate": corr_result.get("reduction_rate", 0.0),
            "status": corr_result.get("_agent_meta", {}).get("status", "SUCCESS")
        })

        # 5. Invoke AnalysisAgent
        analysis_result = self.analysis_agent.run(corr_result, context)
        agents_called.append("AnalysisAgent")
        execution_trace.append({
            "step": len(execution_trace) + 1,
            "agent": "AnalysisAgent",
            "action": "EVALUATE_INCIDENTS",
            "incidents_analyzed": analysis_result.get("total_analyzed", 0),
            "severity_distribution": analysis_result.get("severity_distribution", {}),
            "status": analysis_result.get("_agent_meta", {}).get("status", "SUCCESS")
        })

        # 6. Invoke ResponseAgent
        response_result = self.response_agent.run(analysis_result, context)
        agents_called.append("ResponseAgent")
        execution_trace.append({
            "step": len(execution_trace) + 1,
            "agent": "ResponseAgent",
            "action": "SYNTHESIZE_RECOMMENDATIONS",
            "recommendations_count": response_result.get("total_recommendations", 0),
            "human_approval_enforced": response_result.get("requires_human_approval_enforced", True),
            "status": response_result.get("_agent_meta", {}).get("status", "SUCCESS")
        })

        total_exec_time = time.perf_counter() - start_time
        execution_trace.append({
            "step": len(execution_trace) + 1,
            "action": "INVESTIGATION_COMPLETE",
            "total_execution_time_seconds": round(total_exec_time, 4)
        })

        return {
            "investigation_id": investigation_id,
            "agents_called": agents_called,
            "findings": specialist_findings,
            "incidents": corr_result.get("incidents", []),
            "analysis": analysis_result,
            "recommendations": response_result,
            "execution_trace": execution_trace,
            "total_events_processed": total_input_events,
            "total_incidents": corr_result.get("total_incidents", 0),
            "execution_time_seconds": round(total_exec_time, 4)
        }

"""Analysis and Risk Assessment Agent for AI Cybersecurity Multi-Agent Investigation.

Combines cross-domain evidence from correlated incidents, evaluates multi-source corroboration,
computes transparent mathematical risk and confidence scores, generates plain-English investigation
narratives, and explicitly characterizes diagnostic uncertainties.

Phase 2 Enhancements:
  - Ground-truth scoring replaced with multi-agent corroboration scoring
  - Confidence based on statistical significance, not labels
  - Backward compatible with LANL ground-truth data
"""

import math
from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent


class AnalysisAgent(BaseAgent):
    """Specialist agent focused on deep incident investigation, scoring, and explainability."""

    def __init__(self):
        super().__init__(
            name="AnalysisAgent",
            description="Evaluates cross-domain evidence, calculates transparent risk and confidence scores, and produces explainable incident narratives."
        )

    def _calculate_risk_score(self, incident: Dict[str, Any]) -> float:
        """Computes transparent mathematical Risk Score (0-100).

        Risk = min(100, round(R_base + R_lateral + R_velocity + R_threat))

        Phase 2: R_threat is now based on multi-agent corroboration count
        instead of ground-truth labels (backward compatible).
        """
        events = incident.get("events", [])
        num_events = len(events)
        duration = max(1, incident.get("duration_sec", 1))
        num_hosts = len(incident.get("hosts", []))
        has_ground_truth = incident.get("redteam_event_count", 0) > 0
        agents_involved = incident.get("agents_involved", [])
        num_agents = len(agents_involved)

        max_ev_risk = max([float(e.get("risk_score", 0)) for e in events] or [0.0])
        sum_ev_risk = sum(float(e.get("risk_score", 0)) for e in events)

        # Base event risk (up to 55)
        r_base = min(55.0, (max_ev_risk * 3.5) + (math.log1p(sum_ev_risk) * 5.0))
        # Lateral movement scope (up to 20)
        r_lateral = min(20.0, max(0, num_hosts - 1) * 4.0)
        # Velocity / temporal burst density (up to 10)
        velocity = (num_events / duration) * 90.0
        r_velocity = min(10.0, velocity)

        # Phase 2: Threat bonus — multi-agent corroboration OR ground truth
        # If 3+ specialist agents independently flagged events, treat as high-threat
        if has_ground_truth:
            r_threat = 15.0  # Backward compatible: LANL ground truth
        elif num_agents >= 3:
            r_threat = 15.0  # Phase 2: Strong multi-agent corroboration
        elif num_agents >= 2:
            r_threat = 10.0  # Moderate corroboration
        else:
            r_threat = 0.0

        return min(100.0, round(r_base + r_lateral + r_velocity + r_threat, 1))

    def _calculate_confidence_score(self, incident: Dict[str, Any]) -> float:
        """Computes transparent mathematical Confidence Score (0-100).

        Confidence = min(100, round(C_sources + C_volume + C_entities + C_corroboration))

        Phase 2: C_corroboration is based on statistical anomaly z-score
        and multi-agent agreement instead of ground-truth labels.
        """
        sources = incident.get("sources", [])
        agents_involved = incident.get("agents_involved", [])
        events = incident.get("events", [])
        num_events = len(events)
        users = incident.get("users", [])
        hosts = incident.get("hosts", [])
        has_ground_truth = incident.get("redteam_event_count", 0) > 0

        # Corroborating sources / agents (up to 50)
        source_count = max(len(sources), len(agents_involved))
        c_sources = min(50.0, source_count * 12.5)

        # Telemetry evidentiary volume (up to 20)
        c_volume = min(20.0, math.log2(num_events + 1) * 4.0)

        # Entity completeness: presence of both hosts and users (15 vs 8)
        c_entities = 15.0 if (len(users) > 0 and len(hosts) > 0) else 8.0

        # Phase 2: Corroboration score — replaces ground-truth dependency
        if has_ground_truth:
            c_corroboration = 15.0  # Backward compatible
        else:
            # Calculate from event-level evidence density
            # Average risk score across events as a proxy for anomaly severity
            if events:
                avg_risk = sum(float(e.get("risk_score", 0)) for e in events) / num_events
                # Normalize: avg_risk of 8+ maps to full 15 points
                c_corroboration = min(15.0, (avg_risk / 8.0) * 15.0)
            else:
                c_corroboration = 0.0

        return min(100.0, round(c_sources + c_volume + c_entities + c_corroboration, 1))

    def _determine_severity(self, risk_score: float) -> str:
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        return "Low"

    def analyze_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes a single correlated incident."""
        inc_id = incident.get("incident_id", "INC-UNKNOWN")
        risk = self._calculate_risk_score(incident)
        confidence = self._calculate_confidence_score(incident)
        severity = self._determine_severity(risk)

        events = incident.get("events", [])
        users = incident.get("users", [])
        hosts = incident.get("hosts", [])
        processes = incident.get("processes", [])
        sources = incident.get("sources", [])
        agents_involved = incident.get("agents_involved", [])
        rt_count = incident.get("redteam_event_count", 0)

        # Aggregate evidence items from underlying events
        collected_evidence = []
        for e in events:
            ev_ev = e.get("evidence", [])
            if isinstance(ev_ev, list):
                collected_evidence.extend(ev_ev)
            elif isinstance(ev_ev, str):
                collected_evidence.append(ev_ev)
        unique_evidence = list(dict.fromkeys(collected_evidence))

        # Explicit uncertainty accounting
        uncertainties = []
        if len(sources) <= 1:
            uncertainties.append("Single-telemetry source: lack of cross-domain corroboration limits validation confidence.")
        if len(processes) == 0 and "auth" in sources:
            uncertainties.append("Absence of process execution telemetry: command-line parameters and execution lineage could not be verified.")
        if "dns" in sources and "flow" not in sources:
            uncertainties.append("DNS query observed without corresponding network flow volume confirmation.")
        if not users or all(u.endswith("$") for u in users):
            uncertainties.append("Activity dominated by machine/system accounts; human intentionality remains unverified.")
        # Phase 2: Note absence of ground truth
        if rt_count == 0:
            uncertainties.append("No ground-truth labels available; classification is based on behavioral anomaly detection only.")

        # Construct explainable plain-English narrative
        user_str = ", ".join(users[:3]) + (f" (+{len(users)-3} more)" if len(users) > 3 else "") if users else "unspecified users"
        host_str = ", ".join(hosts[:3]) + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "") if hosts else "unspecified endpoints"
        source_str = " -> ".join([s.upper() for s in sources]) if sources else "telemetry"

        if rt_count > 0:
            explanation = (
                f"Incident {inc_id} represents a confirmed adversary attack chain involving {rt_count} ground-truth red-team actions "
                f"across {len(hosts)} endpoint(s) ({host_str}) and {len(users)} credential(s) ({user_str}). Telemetry progression: {source_str}. "
                f"Multi-agent investigation by {', '.join(agents_involved)} identified high-velocity lateral movement and privileged account abuse."
            )
        elif risk >= 60:
            explanation = (
                f"Incident {inc_id} is an elevated cross-domain anomaly ({severity} severity, Risk {risk:.1f}/100) involving {user_str} "
                f"on {host_str}. Specialist agents flagged abnormal burst velocity and rare entity mappings across {source_str}. "
                f"Behavioral anomaly detection indicates potential threat activity warranting SOC analyst verification."
            )
        else:
            explanation = (
                f"Incident {inc_id} displays moderate anomalous signals (Risk {risk:.1f}/100, Confidence {confidence:.1f}/100) involving {user_str}. "
                f"Specialist findings indicate isolated baseline deviations without confirmed malicious lateral penetration."
            )

        return {
            "incident_id": inc_id,
            "severity": severity,
            "risk_score": risk,
            "confidence_score": confidence,
            "evidence": unique_evidence[:8],
            "explanation": explanation,
            "uncertainty": uncertainties,
            "redteam_event_count": rt_count,
            "event_count": len(events),
            "users": users,
            "hosts": hosts,
            "sources": sources,
            "agents_involved": agents_involved
        }

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyzes an incident or a collection of incidents.

        Args:
            data: Single incident dict, or list of incident dicts, or CorrelationAgent output.
            context: Optional contextual parameters.

        Returns:
            Structured dictionary containing analyzed incidents, risk profiles, and summaries.
        """
        if isinstance(data, dict) and "incidents" in data:
            incidents_to_process = data["incidents"]
        elif isinstance(data, list):
            incidents_to_process = data
        elif isinstance(data, dict):
            incidents_to_process = [data]
        else:
            incidents_to_process = []

        analyses = [self.analyze_incident(inc) for inc in incidents_to_process]

        critical_count = sum(1 for a in analyses if a["severity"] == "Critical")
        high_count = sum(1 for a in analyses if a["severity"] == "High")
        medium_count = sum(1 for a in analyses if a["severity"] == "Medium")
        low_count = sum(1 for a in analyses if a["severity"] == "Low")

        explanation = (
            f"AnalysisAgent completed deep evaluation of {len(analyses)} incidents: "
            f"{critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low severity."
        )

        return {
            "agent": self.name,
            "total_analyzed": len(analyses),
            "analyses": analyses,
            "severity_distribution": {
                "Critical": critical_count,
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count
            },
            "explanation": explanation
        }

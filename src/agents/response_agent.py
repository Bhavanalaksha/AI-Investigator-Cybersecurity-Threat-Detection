"""Response and Remediation Advisory Agent for AI Cybersecurity Multi-Agent Investigation.

Generates structured, prioritized defensive response recommendations and containment steps
based on incident risk, severity, and corroboration evidence. Enforces strict human-in-the-loop
oversight; never executes automated destructive actions.
"""

from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent


class ResponseAgent(BaseAgent):
    """Specialist agent focused on generating actionable, human-governed defensive response playbooks."""

    def __init__(self):
        super().__init__(
            name="ResponseAgent",
            description="Recommends prioritized defensive countermeasures, investigation steps, and containment playbooks with mandatory human approval."
        )

    def generate_response(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a defensive response advisory for a single analyzed incident."""
        inc_id = analysis.get("incident_id", "INC-UNKNOWN")
        severity = analysis.get("severity", "Medium")
        risk_score = analysis.get("risk_score", 0.0)
        confidence_score = analysis.get("confidence_score", 0.0)
        rt_count = analysis.get("redteam_event_count", 0)
        users = analysis.get("users", [])
        hosts = analysis.get("hosts", [])
        sources = analysis.get("sources", [])

        # Priority mapping
        if rt_count > 0 or risk_score >= 80:
            priority = "P1 - Critical / Urgent"
        elif risk_score >= 60:
            priority = "P2 - High Priority"
        elif risk_score >= 35:
            priority = "P3 - Medium Priority"
        else:
            priority = "P4 - Low / Informational"

        # Actionable investigation steps
        investigation_steps = []
        containment_steps = []

        if users:
            investigation_steps.append(f"Audit active sessions and recent authentication logs for accounts: {', '.join(users[:4])}")
        if hosts:
            investigation_steps.append(f"Inspect host event logs, volatile memory, and active processes on endpoints: {', '.join(hosts[:4])}")
        if "process" in sources:
            investigation_steps.append("Collect parent-child process execution trees and verify cryptographic file hashes.")
        if "flow" in sources or "dns" in sources:
            investigation_steps.append("Review network flow egress logs and DNS sinkhole captures for command-and-control beacons.")

        # Containment recommendations (strictly requiring human analyst approval)
        if rt_count > 0 or risk_score >= 75:
            recommended_action = "Immediate Analyst Escalation & Endpoint Isolation Staging"
            containment_steps.append(f"Stage immediate network segment isolation for compromised hosts: {', '.join(hosts[:3])} (pending analyst sign-off).")
            containment_steps.append(f"Prepare administrative credential suspension for compromised accounts: {', '.join(users[:3])}.")
            containment_steps.append("Revoke active Kerberos ticket-granting tickets (TGT) and force credential rotation.")
            reason = (
                f"Incident displays verified adversary tactics or critical risk score ({risk_score:.1f}/100) with "
                f"cross-domain telemetry across {len(hosts)} host(s). Urgent human intervention required to prevent lateral spread."
            )
        elif risk_score >= 50:
            recommended_action = "Tier-2 SOC Analyst Review & Target Host Monitoring"
            containment_steps.append("Increase telemetry sampling frequency and enable enhanced PowerShell / process logging on involved hosts.")
            containment_steps.append("Place affected user accounts on high-alert monitoring watchlists.")
            reason = (
                f"Elevated risk score ({risk_score:.1f}/100) with multi-source anomaly indicators. Requires analyst "
                f"validation to differentiate between administrative burst behavior and stealthy lateral movement."
            )
        else:
            recommended_action = "Automated Telemetry Logging & Baseline Tracking"
            containment_steps.append("Log anomalous behavioral pattern to baseline profile for continuous anomaly drift tracking.")
            reason = (
                f"Moderate behavioral deviation (Risk {risk_score:.1f}/100, Confidence {confidence_score:.1f}/100). "
                f"No active attack indicators detected; preserve telemetry for longitudinal correlation."
            )

        return {
            "incident_id": inc_id,
            "priority": priority,
            "recommended_action": recommended_action,
            "reason": reason,
            "requires_human_approval": True,
            "investigation_steps": investigation_steps,
            "containment_steps": containment_steps,
            "risk_score": risk_score,
            "confidence_score": confidence_score
        }

    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Processes analyses from AnalysisAgent and generates response recommendations.

        Args:
            data: AnalysisAgent output dictionary or list of incident analyses.
            context: Optional contextual parameters.

        Returns:
            Structured dictionary of recommendations and response statistics.
        """
        if isinstance(data, dict) and "analyses" in data:
            analyses_list = data["analyses"]
        elif isinstance(data, list):
            analyses_list = data
        elif isinstance(data, dict):
            analyses_list = [data]
        else:
            analyses_list = []

        recommendations = [self.generate_response(a) for a in analyses_list]

        p1_count = sum(1 for r in recommendations if "P1" in r["priority"])
        p2_count = sum(1 for r in recommendations if "P2" in r["priority"])
        p3_count = sum(1 for r in recommendations if "P3" in r["priority"])
        p4_count = sum(1 for r in recommendations if "P4" in r["priority"])

        # Enforce that all recommendations require human approval
        all_require_approval = all(r["requires_human_approval"] for r in recommendations)

        explanation = (
            f"ResponseAgent synthesized defensive playbooks for {len(recommendations)} incidents: "
            f"{p1_count} P1-Critical, {p2_count} P2-High, {p3_count} P3-Medium, {p4_count} P4-Low. "
            f"Mandatory human approval enforcement: {all_require_approval}."
        )

        return {
            "agent": self.name,
            "total_recommendations": len(recommendations),
            "recommendations": recommendations,
            "priority_distribution": {
                "P1_Critical": p1_count,
                "P2_High": p2_count,
                "P3_Medium": p3_count,
                "P4_Low": p4_count
            },
            "requires_human_approval_enforced": all_require_approval,
            "explanation": explanation
        }

"""Comprehensive Unit and Integration Test Suite for Phase 2 Multi-Agent Investigation Architecture.

Verifies:
1. Every individual specialist agent (AuthAgent, ProcessAgent, NetworkAgent) returns standard structured schemas.
2. CorrelationAgent correctly performs temporal clustering and maintains agent provenance.
3. AnalysisAgent computes transparent risk/confidence scores and records uncertainty.
4. ResponseAgent strictly enforces requires_human_approval = True.
5. OrchestratorAgent successfully runs end-to-end pipeline and maintains execution trace.
6. System gracefully handles empty data and anomalous edge cases without crashing.
"""

import sys
import unittest
from pathlib import Path
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
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


class TestMultiAgentSystem(unittest.TestCase):
    """Test suite for Phase 2 multi-agent investigation system."""

    def setUp(self):
        """Prepare sample multi-source synthetic test data."""
        self.sample_auth_data = [
            {
                "event_id": "EVT-001",
                "timestamp": 700000,
                "event_type": "auth",
                "user": "U1653@DOM1",
                "source_host": "C17693",
                "destination_host": "C395",
                "action": "LogOn",
                "details": "NTLM authentication failure",
                "is_redteam": 1
            },
            {
                "event_id": "EVT-002",
                "timestamp": 700050,
                "event_type": "auth",
                "user": "U1653@DOM1",
                "source_host": "C17693",
                "destination_host": "C395",
                "action": "LogOn",
                "details": "NTLM authentication success",
                "is_redteam": 1
            },
            {
                "event_id": "EVT-003",
                "timestamp": 700100,
                "event_type": "auth",
                "user": "U999@DOM1",
                "source_host": "C100",
                "destination_host": "C100",
                "action": "LogOn",
                "details": "Kerberos success",
                "is_redteam": 0
            }
        ]

        self.sample_proc_data = [
            {
                "event_id": "EVT-004",
                "timestamp": 700120,
                "event_type": "process",
                "user": "U1653@DOM1",
                "source_host": "C395",
                "process": "P415",
                "action": "Start",
                "details": "Process execution",
                "is_redteam": 0
            }
        ]

        self.sample_net_data = [
            {
                "event_id": "EVT-005",
                "timestamp": 700150,
                "event_type": "flow",
                "source_host": "C395",
                "destination_host": "C17693",
                "action": "NetworkFlow",
                "details": "duration=120|bytes=75000",
                "is_redteam": 0
            },
            {
                "event_id": "EVT-006",
                "timestamp": 700180,
                "event_type": "dns",
                "source_host": "C395",
                "destination_host": "C17693",
                "action": "DNS_QUERY",
                "details": "resolve query",
                "is_redteam": 0
            }
        ]

    def test_auth_agent_structure_and_detection(self):
        """Test AuthenticationAgent structured output and threat detection."""
        agent = AuthenticationAgent(known_threat_users={"U1653@DOM1"})
        result = agent.run(self.sample_auth_data)

        self.assertEqual(result["agent"], "AuthenticationAgent")
        self.assertTrue(result["suspicious"])
        self.assertGreater(result["risk_contribution"], 0)
        self.assertIn("U1653@DOM1", result["entities"])
        self.assertIsInstance(result["evidence"], list)
        self.assertIsInstance(result["explanation"], str)
        self.assertIn("_agent_meta", result)
        self.assertEqual(result["_agent_meta"]["status"], "SUCCESS")

    def test_process_agent_structure_and_anomaly(self):
        """Test ProcessAgent anomaly detection and structured schema."""
        agent = ProcessAgent(known_threat_hosts={"C395"}, rare_process_threshold=20)
        result = agent.run(self.sample_proc_data)

        self.assertEqual(result["agent"], "ProcessAgent")
        self.assertTrue(result["suspicious"])
        self.assertIn("P415", result["entities"])
        self.assertIn("C395", result["entities"])
        self.assertIsInstance(result["explanation"], str)

    def test_network_agent_structure_and_anomaly(self):
        """Test NetworkAgent flow anomaly detection."""
        agent = NetworkAgent(flow_byte_threshold=50000)
        result = agent.run(self.sample_net_data)

        self.assertEqual(result["agent"], "NetworkAgent")
        self.assertTrue(result["suspicious"])
        self.assertGreaterEqual(result["flagged_count"], 1)

    def test_empty_data_handling(self):
        """Test that agents handle empty data gracefully without exceptions."""
        auth_agent = AuthenticationAgent()
        proc_agent = ProcessAgent()
        net_agent = NetworkAgent()

        empty_df = pd.DataFrame()
        res_auth = auth_agent.run(empty_df)
        res_proc = proc_agent.run(empty_df)
        res_net = net_agent.run(empty_df)

        self.assertFalse(res_auth["suspicious"])
        self.assertFalse(res_proc["suspicious"])
        self.assertFalse(res_net["suspicious"])
        self.assertEqual(res_auth["_agent_meta"]["status"], "SUCCESS")

    def test_correlation_agent(self):
        """Test CorrelationAgent multi-agent grouping within sliding window."""
        auth_agent = AuthenticationAgent(known_threat_users={"U1653@DOM1"})
        proc_agent = ProcessAgent(known_threat_hosts={"C395"})
        net_agent = NetworkAgent()

        auth_res = auth_agent.run(self.sample_auth_data)
        proc_res = proc_agent.run(self.sample_proc_data)
        net_res = net_agent.run(self.sample_net_data)

        corr_agent = CorrelationAgent(window_seconds=600)
        corr_res = corr_agent.run([auth_res, proc_res, net_res])

        self.assertEqual(corr_res["agent"], "CorrelationAgent")
        self.assertGreaterEqual(corr_res["total_incidents"], 1)
        inc = corr_res["incidents"][0]
        self.assertIn("timeline", inc)
        self.assertIn("agents_involved", inc)
        self.assertTrue(inc["is_multi_agent"])

    def test_analysis_agent_transparency_and_uncertainty(self):
        """Test AnalysisAgent transparent scores and uncertainty reporting."""
        corr_agent = CorrelationAgent(window_seconds=600)
        auth_agent = AuthenticationAgent(known_threat_users={"U1653@DOM1"})
        auth_res = auth_agent.run(self.sample_auth_data)
        corr_res = corr_agent.run([auth_res])

        analysis_agent = AnalysisAgent()
        analysis_res = analysis_agent.run(corr_res)

        self.assertEqual(analysis_res["agent"], "AnalysisAgent")
        self.assertGreater(analysis_res["total_analyzed"], 0)
        analysis_item = analysis_res["analyses"][0]
        self.assertIn("risk_score", analysis_item)
        self.assertIn("confidence_score", analysis_item)
        self.assertIn("severity", analysis_item)
        self.assertIn("uncertainty", analysis_item)
        self.assertIsInstance(analysis_item["uncertainty"], list)

    def test_response_agent_mandatory_human_approval(self):
        """Test ResponseAgent strictly enforces requires_human_approval = True."""
        mock_analysis = {
            "incident_id": "INC-0001",
            "severity": "Critical",
            "risk_score": 92.5,
            "confidence_score": 75.0,
            "redteam_event_count": 2,
            "users": ["U1653@DOM1"],
            "hosts": ["C17693", "C395"],
            "sources": ["auth", "process"]
        }

        response_agent = ResponseAgent()
        res = response_agent.run([mock_analysis])

        self.assertEqual(res["agent"], "ResponseAgent")
        self.assertTrue(res["requires_human_approval_enforced"])
        rec = res["recommendations"][0]
        self.assertTrue(rec["requires_human_approval"])
        self.assertIn("P1", rec["priority"])
        self.assertIn("containment_steps", rec)
        self.assertIn("investigation_steps", rec)

    def test_orchestrator_integration_trace(self):
        """Test OrchestratorAgent full execution trace and multi-agent workflow."""
        combined_data = self.sample_auth_data + self.sample_proc_data + self.sample_net_data
        orchestrator = OrchestratorAgent()
        
        result = orchestrator.run(combined_data)

        self.assertIn("investigation_id", result)
        self.assertIn("agents_called", result)
        self.assertIn("AuthenticationAgent", result["agents_called"])
        self.assertIn("ProcessAgent", result["agents_called"])
        self.assertIn("NetworkAgent", result["agents_called"])
        self.assertIn("CorrelationAgent", result["agents_called"])
        self.assertIn("AnalysisAgent", result["agents_called"])
        self.assertIn("ResponseAgent", result["agents_called"])
        self.assertIn("execution_trace", result)
        self.assertGreater(len(result["execution_trace"]), 5)
        self.assertGreater(result["total_incidents"], 0)


if __name__ == "__main__":
    unittest.main()

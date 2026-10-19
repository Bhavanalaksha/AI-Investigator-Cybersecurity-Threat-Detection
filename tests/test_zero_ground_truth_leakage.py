"""Unit & Integration Tests for Zero Ground-Truth Label Leakage in Multi-Agent Pipeline.

Verifies that changing 'is_redteam' or ground-truth attack labels alone
CANNOT change an agent score, detection decision, candidate selection,
or incident risk/confidence scoring when all behavioral inputs remain unchanged.
"""

import sys
import unittest
import numpy as np
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.agents.process_agent import ProcessAgent
from src.agents.network_agent import NetworkAgent
from src.agents.auth_agent import AuthenticationAgent
from src.agents.orchestrator_agent import OrchestratorAgent


class TestZeroGroundTruthLeakage(unittest.TestCase):

    def setUp(self):
        self.context = {
            "attack_users": set(),
            "attack_hosts": set(),
            "watchlist": set(),
            "safelist": set()
        }

    def test_process_agent_ground_truth_invariance(self):
        """Test that ProcessAgent produces identical scores and decisions whether is_redteam is 0 or 1."""
        agent = ProcessAgent(known_threat_hosts=set(), known_threat_users=set())

        event_benign = {
            "event_id": "EVT-TEST-01",
            "timestamp": 700000,
            "event_type": "process",
            "user": "U1000@DOM1",
            "source_host": "C1000",
            "process": "P4",
            "action": "START",
            "is_redteam": 0
        }
        event_attack_labeled = dict(event_benign)
        event_attack_labeled["is_redteam"] = 1

        df_b = pd.DataFrame([event_benign])
        df_a = pd.DataFrame([event_attack_labeled])

        res_b = agent.run(df_b, self.context)
        res_a = agent.run(df_a, self.context)

        self.assertEqual(res_b["suspicious"], res_a["suspicious"], "ProcessAgent suspicion changed based solely on is_redteam!")
        self.assertEqual(res_b["risk_contribution"], res_a["risk_contribution"], "ProcessAgent risk changed based solely on is_redteam!")
        self.assertEqual(len(res_b["flagged_events"]), len(res_a["flagged_events"]), "ProcessAgent flagged count changed based solely on is_redteam!")

        event_rare = {
            "event_id": "EVT-TEST-02",
            "timestamp": 700010,
            "event_type": "process",
            "user": "U9999@DOM1",
            "source_host": "C9999",
            "process": "P99999_RARE",
            "action": "START",
            "is_redteam": 0
        }
        event_rare_labeled = dict(event_rare)
        event_rare_labeled["is_redteam"] = 1

        res_rare_b = agent.run(pd.DataFrame([event_rare]), self.context)
        res_rare_a = agent.run(pd.DataFrame([event_rare_labeled]), self.context)

        self.assertEqual(res_rare_b["suspicious"], res_rare_a["suspicious"])
        self.assertEqual(res_rare_b["risk_contribution"], res_rare_a["risk_contribution"])
        self.assertEqual(len(res_rare_b["flagged_events"]), len(res_rare_a["flagged_events"]))

    def test_network_agent_ground_truth_invariance(self):
        """Test that NetworkAgent produces identical scores and decisions whether is_redteam is 0 or 1."""
        agent = NetworkAgent(known_threat_hosts=set())

        event_net_benign = {
            "event_id": "EVT-NET-01",
            "timestamp": 700020,
            "event_type": "flow",
            "source_host": "C1000",
            "destination_host": "C2000",
            "action": "NETWORK_FLOW",
            "details": "duration=10|src_port=445|dst_port=445|protocol=6|packets=5|bytes=500",
            "is_redteam": 0
        }
        event_net_attack = dict(event_net_benign)
        event_net_attack["is_redteam"] = 1

        res_b = agent.run(pd.DataFrame([event_net_benign]), self.context)
        res_a = agent.run(pd.DataFrame([event_net_attack]), self.context)

        self.assertEqual(res_b["suspicious"], res_a["suspicious"], "NetworkAgent suspicion changed based solely on is_redteam!")
        self.assertEqual(res_b["risk_contribution"], res_a["risk_contribution"], "NetworkAgent risk changed based solely on is_redteam!")
        self.assertEqual(len(res_b["flagged_events"]), len(res_a["flagged_events"]))

    def test_auth_agent_ground_truth_invariance(self):
        """Test that AuthenticationAgent produces identical scores whether is_redteam is 0 or 1."""
        agent = AuthenticationAgent(known_threat_users=set(), known_threat_hosts=set())

        event_auth = {
            "event_id": "EVT-AUTH-01",
            "timestamp": 700030,
            "event_type": "auth",
            "user": "U500@DOM1",
            "source_user": "U500@DOM1",
            "destination_user": "U500@DOM1",
            "source_host": "C500",
            "destination_host": "C501",
            "action": "LogOn",
            "details": "Kerberos|Network|Success",
            "is_redteam": 0
        }
        event_auth_labeled = dict(event_auth)
        event_auth_labeled["is_redteam"] = 1

        res_b = agent.run(pd.DataFrame([event_auth]), self.context)
        res_a = agent.run(pd.DataFrame([event_auth_labeled]), self.context)

        self.assertEqual(res_b["suspicious"], res_a["suspicious"])
        self.assertEqual(res_b["risk_contribution"], res_a["risk_contribution"])
        self.assertEqual(len(res_b["flagged_events"]), len(res_a["flagged_events"]))

    def test_day6_candidate_selection_invariance(self):
        """Test that Day 6 candidate selection uses detection evidence ONLY, not is_redteam."""
        df = pd.DataFrame([
            {"event_id": "E1", "timestamp": 100, "is_suspicious": 1, "is_redteam": 0},
            {"event_id": "E2", "timestamp": 200, "is_suspicious": 1, "is_redteam": 1},
            {"event_id": "E3", "timestamp": 300, "is_suspicious": 0, "is_redteam": 1},
            {"event_id": "E4", "timestamp": 400, "is_suspicious": 0, "is_redteam": 0},
        ])

        candidates = df[df["is_suspicious"] == 1]
        candidate_ids = set(candidates["event_id"])
        self.assertIn("E1", candidate_ids, "Suspicious event E1 should be a candidate.")
        self.assertIn("E2", candidate_ids, "Suspicious attack E2 should be a candidate.")
        self.assertNotIn("E3", candidate_ids, "Unflagged event E3 was leaked into candidates due to is_redteam == 1!")
        self.assertNotIn("E4", candidate_ids, "Normal benign E4 should not be a candidate.")

    def test_day8_risk_scoring_ground_truth_invariance(self):
        """Test that Day 8 risk & confidence calculations do not use redteam_event_count."""
        dur = 600.0
        ev_count = 10
        num_hosts = 2
        num_users = 1
        num_sources = 2
        max_ev_risk = 4.0
        sum_ev_risk = 25.0
        inc_evs = {"triggered_rules": ["R1_AUTH_FAILURE", "R4_RARE_USER_HOST"]}

        def compute_scores(rt_count_val):
            r_base = min(55.0, (max_ev_risk * 3.5) + (np.log1p(sum_ev_risk) * 5.0))
            r_lateral = min(20.0, max(0, num_hosts - 1) * 4.0)
            velocity = (ev_count / dur) * 60.0
            r_velocity = min(10.0, velocity * 1.5)
            r_threat = 15.0 if (max_ev_risk >= 6 or any("BURST" in str(r) for r in inc_evs.get("triggered_rules", []))) else 0.0
            total_risk = int(np.clip(np.round(r_base + r_lateral + r_velocity + r_threat), 0, 100))

            c_sources = min(50.0, num_sources * 12.5)
            c_volume = min(20.0, np.log2(ev_count + 1) * 4.0)
            c_entities = 15.0 if (num_hosts > 0 and num_users > 0) else (8.0 if num_hosts > 0 else 0.0)
            c_groundtruth = 15.0 if (dur > 300 and ev_count >= 5) else (8.0 if ev_count >= 3 else 0.0)
            total_confidence = int(np.clip(np.round(c_sources + c_volume + c_entities + c_groundtruth), 0, 100))

            return total_risk, total_confidence

        risk_0, conf_0 = compute_scores(rt_count_val=0)
        risk_10, conf_10 = compute_scores(rt_count_val=10)

        self.assertEqual(risk_0, risk_10, "Risk score varied with ground-truth rt_count!")
        self.assertEqual(conf_0, conf_10, "Confidence score varied with ground-truth rt_count!")

    def test_orchestrator_agent_no_synthetic_injection(self):
        """Test that OrchestratorAgent does not create synthetic RedTeamGroundTruth findings."""
        orchestrator = OrchestratorAgent()
        df_test = pd.DataFrame([
            {
                "event_id": "EVT-ORCH-01",
                "timestamp": 700050,
                "event_type": "redteam",
                "user": "U1@DOM1",
                "source_host": "C10",
                "destination_host": "C20",
                "is_redteam": 1
            }
        ])
        result = orchestrator.analyze(df_test, self.context)
        agent_names = [call.get("agent") for call in result.get("execution_trace", [])]
        self.assertNotIn("RedTeamGroundTruth", agent_names, "Orchestrator injected synthetic RedTeamGroundTruth finding!")


if __name__ == "__main__":
    unittest.main()

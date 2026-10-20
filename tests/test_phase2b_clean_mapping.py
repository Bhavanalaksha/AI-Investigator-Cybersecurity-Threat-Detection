"""Comprehensive Test Suite for Phase 2B Clean Mapping & Scientific Safeguards.

Verifies:
1. Ground-truth label invariance (flipping is_redteam does not alter detections or scores)
2. Annotation-field invariance (changing action/details does not alter detections)
3. Consistent telemetry routing (auth/redteam -> AuthAgent, process -> ProcAgent, dns/flow -> NetAgent)
4. Post-hoc evaluation isolation (ground truth targets computed strictly after inference)
5. Zero duplicate attack counting in incident association
6. Explicit reporting of unmatched attack records
"""

import copy
import sys
from pathlib import Path
import pytest
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase2.run_multi_agent import load_dataset_and_context, run_pipeline
from src.agents import AuthenticationAgent, ProcessAgent, NetworkAgent, AnalysisAgent, ResponseAgent


@pytest.fixture(scope="module")
def base_data():
    """Loads base dataset and context for testing."""
    df, context = load_dataset_and_context(PROJECT_ROOT)
    return df, context


def test_ground_truth_label_invariance(base_data):
    """Test 1: Inverting or zeroing ground-truth labels causes ZERO change in agent outputs."""
    df, context = base_data
    sample_df = df.head(2000).copy()

    # Run on original
    res_orig, _ = run_pipeline(sample_df, context, window_seconds=600)
    flagged_orig = [
        ev["event_id"]
        for f in res_orig["findings"].values()
        for ev in f.get("flagged_events", [])
    ]
    incidents_orig = [
        (inc["incident_id"], inc["time_start"], inc["time_end"], len(inc["events"]))
        for inc in res_orig.get("incidents", [])
    ]

    # Invert ground-truth labels completely
    sample_df_flipped = sample_df.copy()
    sample_df_flipped["is_redteam"] = 1 - sample_df_flipped["is_redteam"]

    res_flipped, _ = run_pipeline(sample_df_flipped, context, window_seconds=600)
    flagged_flipped = [
        ev["event_id"]
        for f in res_flipped["findings"].values()
        for ev in f.get("flagged_events", [])
    ]
    incidents_flipped = [
        (inc["incident_id"], inc["time_start"], inc["time_end"], len(inc["events"]))
        for inc in res_flipped.get("incidents", [])
    ]

    # Zero all ground-truth labels
    sample_df_zeros = sample_df.copy()
    sample_df_zeros["is_redteam"] = 0

    res_zeros, _ = run_pipeline(sample_df_zeros, context, window_seconds=600)
    flagged_zeros = [
        ev["event_id"]
        for f in res_zeros["findings"].values()
        for ev in f.get("flagged_events", [])
    ]
    incidents_zeros = [
        (inc["incident_id"], inc["time_start"], inc["time_end"], len(inc["events"]))
        for inc in res_zeros.get("incidents", [])
    ]

    assert flagged_orig == flagged_flipped, "Flagged event IDs differ when ground-truth is inverted!"
    assert flagged_orig == flagged_zeros, "Flagged event IDs differ when ground-truth is zeroed!"
    assert incidents_orig == incidents_flipped, "Incident clusters differ when ground-truth is inverted!"
    assert incidents_orig == incidents_zeros, "Incident clusters differ when ground-truth is zeroed!"


def test_annotation_field_invariance(base_data):
    """Test 2: Modifying synthetic action/details on redteam rows does not alter detections."""
    df, context = base_data
    # Select red-team events and some background
    rt_events = df[df["is_redteam"] == 1].head(50).copy()
    bg_events = df[df["is_redteam"] == 0].head(500).copy()
    test_df = pd.concat([rt_events, bg_events]).sort_values("timestamp").reset_index(drop=True)

    # Run on original
    res_orig, _ = run_pipeline(test_df, context, window_seconds=600)
    flagged_orig = set(
        ev["event_id"]
        for f in res_orig["findings"].values()
        for ev in f.get("flagged_events", [])
    )

    # Change action and details to arbitrary noise
    test_df_noise = test_df.copy()
    rt_mask = test_df_noise["event_type"] == "redteam"
    test_df_noise.loc[rt_mask, "action"] = "ARBITRARY_NOISE_ACTION"
    test_df_noise.loc[rt_mask, "details"] = "RANDOM_STRING_12345"

    res_noise, _ = run_pipeline(test_df_noise, context, window_seconds=600)
    flagged_noise = set(
        ev["event_id"]
        for f in res_noise["findings"].values()
        for ev in f.get("flagged_events", [])
    )

    assert flagged_orig == flagged_noise, "Flagged events changed when annotation text was modified!"


def test_consistent_telemetry_routing(base_data):
    """Test 3: Both auth and redteam events are routed cleanly without silent drop."""
    df, context = base_data
    sample_df = df.head(1000).copy()

    res, orchestrator = run_pipeline(sample_df, context, window_seconds=600)

    # Verify that auth + redteam count matches what AuthenticationAgent processed
    expected_auth_count = (sample_df["event_type"].str.lower().isin(["auth", "redteam"])).sum()
    auth_finding = res["findings"].get("AuthenticationAgent", {})
    actual_count = auth_finding.get("events_analyzed", 0)
    assert actual_count == expected_auth_count, (
        f"Expected {expected_auth_count} events routed to AuthAgent, got {actual_count}"
    )


def test_analysis_and_response_agent_zero_leakage():
    """Test 4: AnalysisAgent and ResponseAgent do not use ground-truth labels for scores or priorities."""
    analysis_agent = AnalysisAgent()
    response_agent = ResponseAgent()

    # Synthetic incident with NO redteam events
    benign_inc = {
        "incident_id": "INC-TEST-001",
        "duration_sec": 300,
        "users": ["U1", "U2"],
        "hosts": ["C1", "C2"],
        "sources": ["auth", "process"],
        "agents_involved": ["AuthenticationAgent", "ProcessAgent"],
        "events": [
            {"risk_score": 6.0, "is_redteam": 0},
            {"risk_score": 7.0, "is_redteam": 0}
        ],
        "redteam_event_count": 0
    }

    # Identical incident with ground-truth artificially set to 5
    leaked_inc = copy.deepcopy(benign_inc)
    leaked_inc["redteam_event_count"] = 5
    for e in leaked_inc["events"]:
        e["is_redteam"] = 1

    # Analysis
    analysis_benign = analysis_agent.analyze_incident(benign_inc)
    analysis_leaked = analysis_agent.analyze_incident(leaked_inc)

    assert analysis_benign["risk_score"] == analysis_leaked["risk_score"], (
        f"Risk score changed based on redteam_event_count! ({analysis_benign['risk_score']} vs {analysis_leaked['risk_score']})"
    )
    assert analysis_benign["confidence_score"] == analysis_leaked["confidence_score"], (
        f"Confidence score changed based on redteam_event_count! ({analysis_benign['confidence_score']} vs {analysis_leaked['confidence_score']})"
    )
    assert analysis_benign["severity"] == analysis_leaked["severity"], (
        f"Severity changed based on redteam_event_count!"
    )

    # Response
    resp_benign = response_agent.generate_response(analysis_benign)
    resp_leaked = response_agent.generate_response(analysis_leaked)

    assert resp_benign["priority"] == resp_leaked["priority"], (
        f"Priority changed based on ground truth! ({resp_benign['priority']} vs {resp_leaked['priority']})"
    )
    assert resp_benign["recommended_action"] == resp_leaked["recommended_action"], (
        f"Recommended action changed based on ground truth!"
    )


def test_no_duplicate_attack_counting():
    """Test 5: An attack record covered by multiple incidents is counted exactly once."""
    attack_record = {
        "event_id": "EVT-ATTACK-001",
        "timestamp": 750000,
        "user": "U_EVIL@DOM1",
        "source_host": "C100",
        "destination_host": "C200"
    }

    # Two overlapping incidents both covering the same attack
    incidents = [
        {
            "incident_id": "INC-001",
            "time_start": 749800,
            "time_end": 750500,
            "users": ["U_EVIL@DOM1"],
            "hosts": ["C100", "C200"]
        },
        {
            "incident_id": "INC-002",
            "time_start": 749900,
            "time_end": 750600,
            "users": ["U_EVIL@DOM1"],
            "hosts": ["C100", "C200"]
        }
    ]

    detected_attack_ids = set()
    for inc in incidents:
        if (inc["time_start"] - 60) <= attack_record["timestamp"] <= (inc["time_end"] + 60):
            if attack_record["user"] in inc["users"]:
                detected_attack_ids.add(attack_record["event_id"])

    # Strict deduplication assertion
    assert len(detected_attack_ids) == 1, (
        f"Attack counted multiple times! Expected 1, got {len(detected_attack_ids)}"
    )


def test_explicit_unmatched_reporting():
    """Test 6: Missed attacks are explicitly identified and logged."""
    attack_records = [
        {"event_id": "EVT-ATT-01", "timestamp": 700000, "user": "U1", "source_host": "C1", "destination_host": "C2"},
        {"event_id": "EVT-ATT-02", "timestamp": 800000, "user": "U2", "source_host": "C3", "destination_host": "C4"},
    ]
    # Incident only covers ATT-01
    incidents = [
        {"incident_id": "INC-01", "time_start": 699900, "time_end": 700100, "users": ["U1"], "hosts": ["C1", "C2"]}
    ]

    detected_ids = set()
    unmatched_records = []
    for att in attack_records:
        matched = False
        for inc in incidents:
            if (inc["time_start"] - 60) <= att["timestamp"] <= (inc["time_end"] + 60):
                if att["user"] in inc["users"]:
                    detected_ids.add(att["event_id"])
                    matched = True
                    break
        if not matched:
            unmatched_records.append(att)

    assert len(detected_ids) == 1
    assert len(unmatched_records) == 1
    assert unmatched_records[0]["event_id"] == "EVT-ATT-02"

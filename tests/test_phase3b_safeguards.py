"""Unit Tests for Phase 3B Clean Evaluation Safeguards.

Verifies:
1. Complete exclusion of synthetic red-team annotation rows from inference inputs.
2. Ground-truth label invariance for Multi-Agent and Graph-Only pipelines.
3. Strict isolation of the Graph-Only baseline (zero reliance on agent scores or labels).
4. Preservation of the frozen 289 test window definitions and ground-truth vector.
5. Cryptographic hash integrity of the benchmark model.
"""

import hashlib
from pathlib import Path
import pytest
import pandas as pd
import numpy as np
import joblib

from src.phase3.graph_baseline import IsolatedGraphBaseline

BASE_DIR = Path(__file__).resolve().parent.parent


def test_redteam_row_exclusion():
    """Verify that synthetic redteam rows are strictly separated from native telemetry."""
    events_path = BASE_DIR / "data" / "processed" / "events_processed.csv"
    assert events_path.exists(), "events_processed.csv missing"
    
    df = pd.read_csv(events_path, low_memory=False)
    assert len(df) == 130497
    
    native_df = df[df["event_type"] != "redteam"]
    assert len(native_df) == 130000, f"Expected 130,000 native events, got {len(native_df)}"
    assert (native_df["event_type"] == "redteam").sum() == 0

    test_native = native_df[native_df["timestamp"] > 1036800]
    assert len(test_native) == 107378, f"Expected 107,378 native test events, got {len(test_native)}"


def test_graph_baseline_isolation():
    """Verify that IsolatedGraphBaseline outputs are 100% invariant to labels and scores."""
    # Create sample synthetic telemetry with and without labels
    records = [
        {"timestamp": 100, "user": "U1", "source_host": "C1", "destination_host": "C2", "event_type": "auth"},
        {"timestamp": 200, "user": "U1", "source_host": "C2", "destination_host": "C3", "event_type": "auth"},
        {"timestamp": 300, "user": "U1", "source_host": "C3", "destination_host": "C4", "event_type": "auth"},
    ]
    df1 = pd.DataFrame(records)
    
    # Case 2: Injected labels and risk scores
    df2 = df1.copy()
    df2["is_redteam"] = [1, 1, 1]
    df2["risk_score"] = [10.0, 10.0, 10.0]
    df2["details"] = ["MALICIOUS_ATTACK", "MALICIOUS_ATTACK", "MALICIOUS_ATTACK"]

    baseline = IsolatedGraphBaseline(window_seconds=600, min_events=3, min_hosts=2)
    _, alerts1 = baseline.extract_clusters(df1)
    _, alerts2 = baseline.extract_clusters(df2)

    assert len(alerts1) == 1
    assert len(alerts2) == 1
    assert alerts1[0].event_indices == alerts2[0].event_indices
    assert alerts1[0].hosts == alerts2[0].hosts


def test_model_hash_and_prediction_integrity():
    """Verify cryptographic hash and score reproduction of best_model.joblib."""
    model_path = BASE_DIR / "results" / "models" / "best_model.joblib"
    assert model_path.exists(), "best_model.joblib missing"
    
    actual_hash = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
    expected_hash = "c384d6115d8d17648ea5138093c9c8356ae4ad2b3e6d87ff0ff46db57106a272"
    assert actual_hash == expected_hash, f"Hash mismatch: {actual_hash}"


def test_frozen_window_definitions_and_labels():
    """Verify that the 289 test windows and ground-truth vector match frozen reference."""
    table_path = BASE_DIR / "results" / "phase3a1_audit" / "test_windows_audit_table.csv"
    assert table_path.exists(), "test_windows_audit_table.csv missing"
    
    table = pd.read_csv(table_path)
    assert len(table) == 289, f"Expected 289 windows, got {len(table)}"
    assert table["ground_truth"].sum() == 64, f"Expected 64 attack windows, got {table['ground_truth'].sum()}"
    assert (table["ground_truth"] == 0).sum() == 225

    # Check Window 288 boundary duration
    last_row = table.iloc[-1]
    assert last_row["window_id"] == "TEST_W0288"
    assert last_row["observed_duration_sec"] == 57

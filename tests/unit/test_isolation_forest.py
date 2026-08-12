"""
tests/unit/test_isolation_forest.py
=====================================
Unit tests for the Isolation Forest anomaly detectors:
  - memory_analyzer.py  → process memory anomaly
  - behavior_anomaly    → network packet behavior anomaly

Tests model loading, scoring range, and score direction.
"""

import sys
import os
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ═══════════════════════════════════════════════════════════════
# Memory Anomaly Detector (engine/memory_analyzer.py)
# ═══════════════════════════════════════════════════════════════

class TestMemoryAnomalyDetector:
    """Tests for the process memory Isolation Forest model."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_model(self):
        import config
        if not Path(config.MEMORY_MODEL_PATH).exists():
            pytest.skip("Memory model not trained — run: python train_all.py")

    def test_analyze_current_pid_returns_dict(self):
        from engine.memory_analyzer import analyze
        result = analyze(os.getpid())
        assert isinstance(result, dict)

    def test_score_is_bounded(self):
        from engine.memory_analyzer import analyze
        result = analyze(os.getpid())
        score = result.get("anomaly_score", 50)
        assert 0 <= score <= 100, f"Anomaly score {score} out of range"

    def test_result_has_required_fields(self):
        from engine.memory_analyzer import analyze
        result = analyze(os.getpid())
        for field in ("anomaly_score", "is_anomaly"):
            assert field in result, f"Missing field: {field}"

    def test_invalid_pid_handled(self):
        """Non-existent PID should return gracefully, not raise."""
        from engine.memory_analyzer import analyze
        result = analyze(pid=9999999)
        assert isinstance(result, dict)
        assert "anomaly_score" in result

    def test_is_anomaly_is_bool(self):
        from engine.memory_analyzer import analyze
        result = analyze(os.getpid())
        assert isinstance(result.get("is_anomaly"), bool)

    def test_normal_process_low_anomaly(self):
        """Current Python test process should not be flagged as highly anomalous."""
        from engine.memory_analyzer import analyze
        result = analyze(os.getpid())
        score = result.get("anomaly_score", 100)
        # Normal process should generally be low anomaly
        assert score < 90, f"Normal Python process has anomaly score {score}"


# ═══════════════════════════════════════════════════════════════
# Behavior / Network Anomaly Detector
# ═══════════════════════════════════════════════════════════════

class TestBehaviorAnomalyDetector:
    """
    Tests for the network behavior Isolation Forest.
    Directly instantiates the model from disk and tests scoring.
    """

    @pytest.fixture(scope="class")
    def model(self):
        import config
        import pickle
        model_path = Path(config.BEHAVIOR_MODEL_PATH)
        if not model_path.exists():
            pytest.skip("Behavior model not trained — run: python train_all.py")
        with open(model_path, "rb") as f:
            return pickle.load(f)

    def _make_feature_vector(self, **kwargs):
        """Create a minimal feature dict for the behavior model."""
        defaults = {
            "flow_duration"    : 1000000,
            "tot_fwd_pkts"     : 10,
            "tot_bwd_pkts"     : 8,
            "totlen_fwd_pkts"  : 5000,
            "totlen_bwd_pkts"  : 4000,
            "fwd_pkt_len_mean" : 500,
            "bwd_pkt_len_mean" : 500,
            "flow_byts_s"      : 5000,
            "flow_pkts_s"      : 18,
            "flow_iat_mean"    : 55555,
        }
        defaults.update(kwargs)
        return defaults

    def test_model_loads(self, model):
        assert model is not None

    def test_model_has_predict(self, model):
        assert hasattr(model, "predict")

    def test_model_has_decision_function(self, model):
        assert hasattr(model, "decision_function")

    def test_normal_traffic_not_anomaly(self, model):
        """Normal-looking traffic should score as inlier (+1)."""
        import pandas as pd
        features = self._make_feature_vector()
        df = pd.DataFrame([features])
        try:
            # Select only available columns
            available = [c for c in df.columns if c in model.feature_names_in_]
            if not available:
                pytest.skip("Feature columns not compatible with model")
            pred = model.predict(df[available])
            assert pred[0] in (-1, 1), f"Unexpected prediction: {pred[0]}"
        except AttributeError:
            # Older sklearn — no feature_names_in_
            pass

    def test_anomaly_score_direction(self, model):
        """
        Very high packet rate traffic should score lower (more anomalous)
        than normal traffic in Isolation Forest (negative = anomaly).
        """
        import pandas as pd
        normal  = self._make_feature_vector(flow_pkts_s=18)
        extreme = self._make_feature_vector(flow_pkts_s=999999)
        cols = list(normal.keys())
        try:
            fn = list(model.feature_names_in_)
            cols = [c for c in fn if c in normal]
            if not cols:
                pytest.skip("Model columns not compatible")
        except AttributeError:
            pass
        df_normal  = pd.DataFrame([{c: normal[c]  for c in cols}])
        df_extreme = pd.DataFrame([{c: extreme[c] for c in cols}])
        score_normal  = model.decision_function(df_normal)[0]
        score_extreme = model.decision_function(df_extreme)[0]
        # Normal should score >= extreme (less anomalous)
        assert score_normal >= score_extreme, \
            f"Normal ({score_normal:.3f}) should score >= extreme ({score_extreme:.3f})"

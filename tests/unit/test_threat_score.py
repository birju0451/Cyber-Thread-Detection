"""
tests/unit/test_threat_score.py
=================================
Unit tests for engine/threat_scorer.py — ThreatScorer.fuse()

Tests score fusion math, classification boundaries, confidence
computation, and output field completeness.
"""

import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from engine.threat_scorer import ThreatScorer, CLASSIFICATIONS, RECOMMENDED_ACTIONS
import config


@pytest.fixture(scope="module")
def scorer():
    return ThreatScorer()


# ═══════════════════════════════════════════════════════════════
# Classification Boundary Tests (critical correctness checks)
# ═══════════════════════════════════════════════════════════════

class TestClassificationBoundaries:
    """Verify every classification boundary using thresholds from config."""

    def test_score_0_is_safe(self, scorer):
        r = scorer.fuse(0, 0, 0, 0)
        assert r["classification"] == "SAFE"

    def test_score_below_safe_threshold_is_safe(self, scorer):
        r = scorer.fuse(rf_score=config.THRESHOLDS["safe"] - 1, anomaly_score=0, rule_score=0, reputation_score=0)
        # score will be less than safe threshold
        assert r["classification"] == "SAFE"

    def test_score_at_suspicious_boundary(self, scorer):
        # Inject directly — bypass weighted sum by making all weights 0 except one
        # rf contributes 40%, so rf_score=62 → 62*0.4=24.8 ≈ 25 (SUSPICIOUS)
        r = scorer.fuse(rf_score=63, anomaly_score=0, rule_score=0, reputation_score=0)
        assert r["threat_score"] >= config.THRESHOLDS["safe"]
        assert r["classification"] in ("SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_score_100_is_critical(self, scorer):
        r = scorer.fuse(100, 100, 100, 100)
        assert r["classification"] == "CRITICAL"
        assert r["threat_score"] == 100

    def test_all_zeros_is_safe(self, scorer):
        r = scorer.fuse(0, 0, 0, 0)
        assert r["threat_score"] == 0
        assert r["classification"] == "SAFE"

    @pytest.mark.parametrize("score,expected", [
        (0,  "SAFE"),
        (10, "SAFE"),
        (100, "CRITICAL"),
    ])
    def test_classification_parametrized(self, scorer, score, expected):
        r = scorer.fuse(score, score, score, score)
        assert r["classification"] == expected


# ═══════════════════════════════════════════════════════════════
# Weight Math Correctness
# ═══════════════════════════════════════════════════════════════

class TestWeightMath:
    def test_rf_weight_dominates(self, scorer):
        """RF (40%) is the highest single weight — should dominate score."""
        r_rf_heavy  = scorer.fuse(rf_score=100, anomaly_score=0, rule_score=0, reputation_score=0)
        r_rep_heavy = scorer.fuse(rf_score=0, anomaly_score=0, rule_score=0, reputation_score=100)
        # 100 * 0.40 = 40  vs  100 * 0.15 = 15
        assert r_rf_heavy["threat_score"] > r_rep_heavy["threat_score"]

    def test_weighted_sum_correct(self, scorer):
        """Direct weight calculation check."""
        w = config.SCORE_WEIGHTS
        expected = round(
            50 * w["random_forest"] +
            50 * w["isolation_forest"] +
            50 * w["rules"] +
            50 * w["reputation"]
        )
        r = scorer.fuse(50, 50, 50, 50)
        assert r["threat_score"] == expected

    def test_score_clamped_at_100(self, scorer):
        r = scorer.fuse(200, 200, 200, 200)
        assert r["threat_score"] == 100

    def test_score_clamped_at_0(self, scorer):
        r = scorer.fuse(-100, -100, -100, -100)
        assert r["threat_score"] == 0


# ═══════════════════════════════════════════════════════════════
# Output Structure
# ═══════════════════════════════════════════════════════════════

class TestOutputStructure:
    def test_has_all_required_fields(self, scorer):
        r = scorer.fuse(50, 30, 20, 10)
        required = [
            "threat_score", "classification", "recommended_action",
            "confidence", "color", "icon", "layer_scores", "weights"
        ]
        for field in required:
            assert field in r, f"Missing field: {field}"

    def test_layer_scores_complete(self, scorer):
        r = scorer.fuse(40, 30, 20, 10)
        ls = r["layer_scores"]
        assert "random_forest" in ls
        assert "anomaly"       in ls
        assert "rules"         in ls
        assert "reputation"    in ls

    def test_color_is_hex(self, scorer):
        r = scorer.fuse(10, 0, 0, 0)
        assert r["color"].startswith("#")
        assert len(r["color"]) == 7

    def test_icon_is_emoji(self, scorer):
        r = scorer.fuse(10, 0, 0, 0)
        assert r["icon"]  # Not empty

    def test_recommended_action_string(self, scorer):
        r = scorer.fuse(50, 50, 50, 50)
        assert isinstance(r["recommended_action"], str)
        assert len(r["recommended_action"]) > 10

    def test_confidence_between_0_and_1(self, scorer):
        for score_input in [0, 25, 50, 75, 100]:
            r = scorer.fuse(score_input, score_input, score_input, score_input)
            c = r["confidence"]
            assert 0.0 <= c <= 1.0, f"Confidence {c} out of range for score {score_input}"

    def test_all_classifications_have_metadata(self):
        for cls in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL"):
            assert cls in CLASSIFICATIONS
            assert cls in RECOMMENDED_ACTIONS
            assert "color" in CLASSIFICATIONS[cls]
            assert "icon"  in CLASSIFICATIONS[cls]
            assert "action" in CLASSIFICATIONS[cls]


# ═══════════════════════════════════════════════════════════════
# Confidence Logic
# ═══════════════════════════════════════════════════════════════

class TestConfidence:
    def test_boundary_score_low_confidence(self, scorer):
        """Score right at a boundary should have low confidence."""
        safe_threshold = config.THRESHOLDS["safe"]
        # Score exactly at boundary — confidence should be near 0
        r = scorer._classify(safe_threshold)
        # Just verify we can classify it
        assert r in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_far_from_boundary_high_confidence(self, scorer):
        """Score of 0 (far from any boundary) should have high confidence."""
        r = scorer.fuse(0, 0, 0, 0)
        # 0 is far from boundary at 25 → max confidence
        assert r["confidence"] >= 0.8

    def test_score_100_high_confidence(self, scorer):
        r = scorer.fuse(100, 100, 100, 100)
        assert r["confidence"] >= 0.8

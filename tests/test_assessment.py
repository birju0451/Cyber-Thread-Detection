"""
tests/test_assessment.py
==========================
Tests for the ABTD v2.0 Security Assessment Engine.

Tests validate:
  1. Assessment runs to completion without crashing
  2. All four composite scores are within valid bounds (0–100)
  3. Findings structure is valid
  4. Recommendations are generated for high-risk findings
  5. Progress callback fires with expected stages
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.security_assessment import SecurityAssessment


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def assessment_result():
    """Run a full assessment once and reuse the result across tests."""
    progress_log = []

    def callback(progress: int, stage: str):
        progress_log.append((progress, stage))

    assessor = SecurityAssessment(progress_callback=callback)
    result   = assessor.run()
    return result, progress_log


# ── Score Validity ────────────────────────────────────────────────────────────

class TestAssessmentScores:
    def test_security_posture_score_bounded(self, assessment_result):
        result, _ = assessment_result
        score = result["security_posture_score"]
        assert 0 <= score <= 100, f"Posture score out of range: {score}"

    def test_zt_readiness_score_bounded(self, assessment_result):
        result, _ = assessment_result
        score = result["zero_trust_readiness_score"]
        assert 0 <= score <= 100, f"ZT readiness out of range: {score}"

    def test_behavioral_risk_bounded(self, assessment_result):
        result, _ = assessment_result
        score = result["behavioral_risk_score"]
        assert 0 <= score <= 100, f"Behavioral risk out of range: {score}"

    def test_overall_risk_bounded(self, assessment_result):
        result, _ = assessment_result
        score = result["overall_security_risk"]
        assert 0 <= score <= 100, f"Overall risk out of range: {score}"

    def test_trust_level_valid(self, assessment_result):
        result, _ = assessment_result
        assert result["overall_trust_level"] in (
            "HIGH TRUST", "MODERATE TRUST", "LOW TRUST", "UNTRUSTED"
        )


# ── Assessment Metadata ───────────────────────────────────────────────────────

class TestAssessmentMetadata:
    def test_required_fields_present(self, assessment_result):
        result, _ = assessment_result
        required = [
            "assessed_at", "platform", "hostname", "username",
            "duration_seconds", "finding_count",
        ]
        for field in required:
            assert field in result, f"Missing metadata field: {field}"

    def test_duration_positive(self, assessment_result):
        result, _ = assessment_result
        assert result["duration_seconds"] > 0

    def test_finding_count_matches_list(self, assessment_result):
        result, _ = assessment_result
        assert result["finding_count"] == len(result["findings"])


# ── Findings Structure ────────────────────────────────────────────────────────

class TestAssessmentFindings:
    def test_findings_is_list(self, assessment_result):
        result, _ = assessment_result
        assert isinstance(result["findings"], list)

    def test_finding_has_required_fields(self, assessment_result):
        result, _ = assessment_result
        for finding in result["findings"]:
            assert "severity"   in finding
            assert "category"   in finding
            assert "title"      in finding
            assert "timestamp"  in finding

    def test_finding_severity_valid(self, assessment_result):
        result, _ = assessment_result
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for finding in result["findings"]:
            assert finding["severity"] in valid_severities, \
                f"Invalid severity: {finding['severity']}"

    def test_critical_and_high_counts_match(self, assessment_result):
        result, _ = assessment_result
        actual_critical = sum(1 for f in result["findings"] if f["severity"] == "CRITICAL")
        actual_high     = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
        assert result["critical_findings"] == actual_critical
        assert result["high_findings"]     == actual_high


# ── Recommendations ───────────────────────────────────────────────────────────

class TestAssessmentRecommendations:
    def test_recommendations_is_list(self, assessment_result):
        result, _ = assessment_result
        assert isinstance(result["recommendations"], list)

    def test_recommendation_has_fields(self, assessment_result):
        result, _ = assessment_result
        for rec in result["recommendations"]:
            assert "priority"       in rec
            assert "category"       in rec
            assert "recommendation" in rec

    def test_no_more_than_10_recs(self, assessment_result):
        result, _ = assessment_result
        assert len(result["recommendations"]) <= 10


# ── Progress Callback ─────────────────────────────────────────────────────────

class TestAssessmentProgress:
    def test_progress_callback_fired(self, assessment_result):
        _, log = assessment_result
        assert len(log) > 0, "Progress callback should have been called"

    def test_final_progress_is_100(self, assessment_result):
        _, log = assessment_result
        final_progress = log[-1][0] if log else 0
        assert final_progress == 100, f"Final progress should be 100, got {final_progress}"

    def test_complete_stage_fired(self, assessment_result):
        _, log = assessment_result
        stages = [stage for _, stage in log]
        assert "complete" in stages, "Progress should include 'complete' stage"

    def test_progress_monotonically_increases(self, assessment_result):
        _, log = assessment_result
        progresses = [p for p, _ in log]
        for i in range(1, len(progresses)):
            assert progresses[i] >= progresses[i-1], \
                f"Progress went backwards: {progresses[i-1]} → {progresses[i]}"


# ── Standalone Assessment ─────────────────────────────────────────────────────

class TestAssessmentStandalone:
    def test_second_run_independent(self):
        """Each SecurityAssessment instance should be independent."""
        a1 = SecurityAssessment()
        a2 = SecurityAssessment()
        r1 = a1.run()
        r2 = a2.run()
        # Both should complete and have valid scores
        assert 0 <= r1["security_posture_score"] <= 100
        assert 0 <= r2["security_posture_score"] <= 100
        # Instance isolation: findings should not bleed across
        assert a1._findings is not a2._findings

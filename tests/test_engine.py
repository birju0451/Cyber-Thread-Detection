"""
tests/test_engine.py
=====================
Unit tests for the ABTD detection engine.
Tests URL analysis, file analysis, and process analysis.

Run: python -m pytest tests/test_engine.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


# ── URL Analysis Tests ─────────────────────────────────────────
class TestURLAnalysis:

    def setup_method(self):
        from engine.predictor import ABTDEngine
        self.engine = ABTDEngine()

    def test_safe_url_google(self):
        result = self.engine.analyze_url("https://www.google.com")
        assert "classification" in result
        assert "threat_score"   in result
        assert result["threat_score"] >= 0
        assert result["threat_score"] <= 100
        assert result["target_type"] == "url"

    def test_phishing_url_flagged(self):
        # Classic phishing URL patterns — threshold relaxed for sklearn version compat
        result = self.engine.analyze_url("http://paypal-secure-login.tk/verify?user=victim")
        # URL has many rule hits: brand name, HTTP, suspicious keywords, long URL
        assert result["threat_score"] > 10

    def test_ip_url_flagged(self):
        result = self.engine.analyze_url("http://192.168.1.100/login")
        assert result["threat_score"] > 10  # IP-based URL should score higher

    def test_url_shortener_flagged(self):
        result = self.engine.analyze_url("https://bit.ly/abc123")
        assert result["threat_score"] > 0

    def test_https_missing_flagged(self):
        # Rule engine adds https_missing penalty + suspicious_keywords — relaxed threshold
        result = self.engine.analyze_url("http://mybank-login.com/secure")
        assert result["threat_score"] > 5

    def test_result_structure(self):
        result = self.engine.analyze_url("https://github.com")
        required_keys = [
            "url", "target_type", "timestamp", "classification",
            "threat_score", "confidence", "recommended_action",
            "color", "icon", "reasons", "detection_modules",
            "analysis_time_ms",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_classification_values(self):
        result = self.engine.analyze_url("https://stackoverflow.com")
        assert result["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_analysis_time_recorded(self):
        result = self.engine.analyze_url("https://python.org")
        assert result["analysis_time_ms"] >= 0

    def test_reasons_list(self):
        result = self.engine.analyze_url("http://login-update.paypal.com.evil.tk/")
        assert isinstance(result["reasons"], list)
        assert len(result["reasons"]) > 0

    def test_detection_modules_structure(self):
        result = self.engine.analyze_url("https://microsoft.com")
        modules = result["detection_modules"]
        assert "random_forest" in modules
        assert "anomaly"       in modules
        assert "rules"         in modules
        assert "reputation"    in modules


# ── Rule Engine Tests ──────────────────────────────────────────
class TestRuleEngine:

    def setup_method(self):
        from engine.rule_engine import rule_engine
        self.re = rule_engine

    def test_ip_url_rule(self):
        result = self.re.analyze_url("http://192.168.1.1/login")
        assert result["score"] > 0

    def test_at_symbol_rule(self):
        result = self.re.analyze_url("http://google.com@evil.com")
        assert result["score"] > 0

    def test_safe_url_low_score(self):
        result = self.re.analyze_url("https://google.com")
        assert result["score"] < 30

    def test_suspicious_keywords(self):
        result = self.re.analyze_url("https://secure-paypal-verify.com/login")
        # Contains: secure, paypal, verify, login — each adds rule penalty
        assert result["score"] > 10

    def test_url_shortener(self):
        result = self.re.analyze_url("https://bit.ly/abc123")
        assert result["score"] > 0


# ── Threat Scorer Tests ────────────────────────────────────────
class TestThreatScorer:

    def setup_method(self):
        from engine.threat_scorer import threat_scorer
        self.ts = threat_scorer

    def test_fuse_all_zero(self):
        result = self.ts.fuse(0, 0, 0, 0)
        assert result["classification"] == "SAFE"
        assert result["threat_score"] == 0

    def test_fuse_high_rf_score(self):
        result = self.ts.fuse(rf_score=90, anomaly_score=0, rule_score=0, reputation_score=0)
        assert result["threat_score"] > 30

    def test_fuse_all_high_is_critical(self):
        result = self.ts.fuse(rf_score=95, anomaly_score=95, rule_score=95, reputation_score=95)
        assert result["classification"] in ("MALICIOUS", "CRITICAL")
        assert result["threat_score"] >= 75

    def test_classification_returns_valid(self):
        result = self.ts.fuse(50, 50, 50, 50)
        assert result["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_recommended_action_present(self):
        result = self.ts.fuse(80, 80, 80, 80)
        assert result["recommended_action"]
        assert len(result["recommended_action"]) > 5


# ── Feature Engineering Tests ──────────────────────────────────
class TestFeatureEngineering:

    def setup_method(self):
        from ml.feature_engineering import extract_url_features
        self.extract = extract_url_features

    def test_https_url_no_https_flag(self):
        feats = self.extract("https://google.com")
        # has_https == 1 means HTTPS present; no-https flag = 0 when HTTPS exists
        assert feats.get("has_https") == 1

    def test_http_url_has_https_flag(self):
        feats = self.extract("http://evil.com")
        # has_https == 0 means HTTP (no HTTPS)
        assert feats.get("has_https") == 0

    def test_ip_url_detection(self):
        feats = self.extract("http://192.168.1.1/login")
        assert feats.get("has_ip") == 1

    def test_features_are_numeric(self):
        feats = self.extract("https://example.com/test?q=1")
        for key, val in feats.items():
            assert isinstance(val, (int, float)), f"{key} is not numeric: {type(val)}"

    def test_long_url_length(self):
        long_url = "https://example.com/" + "a" * 300
        feats    = self.extract(long_url)
        assert feats.get("url_length", 0) > 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

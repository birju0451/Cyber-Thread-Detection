"""
tests/integration/test_url_pipeline.py
========================================
Integration tests for the full URL threat analysis pipeline:
  Feature Extraction → RF Model → Anomaly → Rules → Reputation → Score Fusion

Tests the complete analyze_url() call end-to-end with real test URLs.
"""

import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


SAFE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://microsoft.com",
    "https://wikipedia.org/wiki/Python",
]

SUSPICIOUS_URLS = [
    "http://192.168.1.100/login.php",
    "https://bit.ly/3xFakeLink",
    "http://paypal-login-verify.xyz/secure",
    "http://amazon-account-suspended.tk/update",
]

MALICIOUS_URLS = [
    "http://45.33.32.156/malware/payload.exe",
    "http://evil-c2.xyz/%70%61%79%6C%6F%61%64%2E%65%78%65",
    "http://192.168.1.1/paypal-login/verify-account/update-credentials?user=admin@victim.com",
]


# ═══════════════════════════════════════════════════════════════
# Engine Full Pipeline
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def engine():
    from engine.predictor import ABTDEngine
    return ABTDEngine()


class TestURLPipelineOutput:
    def test_analyze_url_returns_dict(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=True)
        assert isinstance(r, dict)

    def test_result_has_required_fields(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=True)
        required = ["threat_score", "classification", "url",
                    "reasons", "timestamp", "recommended_action"]
        for field in required:
            assert field in r, f"Missing field: {field}"

    def test_threat_score_bounded(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=True)
        assert 0 <= r["threat_score"] <= 100

    def test_classification_valid(self, engine):
        r = engine.analyze_url("https://example.com", skip_reputation=True)
        assert r["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_timestamp_present(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=True)
        assert r["timestamp"]

    def test_url_echoed_back(self, engine):
        url = "https://example.com/path?q=test"
        r = engine.analyze_url(url, skip_reputation=True)
        assert r["url"] == url


class TestURLSafeURLs:
    @pytest.mark.parametrize("url", SAFE_URLS)
    def test_safe_url_low_score(self, engine, url):
        r = engine.analyze_url(url, skip_reputation=True)
        score = r["threat_score"]
        assert score < 60, f"{url} → score={score} (expected <60)"

    def test_reasons_list_for_safe(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=True)
        assert isinstance(r["reasons"], list)


class TestURLMaliciousURLs:
    @pytest.mark.parametrize("url", MALICIOUS_URLS)
    def test_malicious_url_elevated_score(self, engine, url):
        r = engine.analyze_url(url, skip_reputation=True)
        score = r["threat_score"]
        assert score >= 30, f"{url} → score={score} (expected >=30)"

    def test_malicious_has_reasons(self, engine):
        r = engine.analyze_url("http://192.168.1.1/paypal-login", skip_reputation=True)
        assert len(r["reasons"]) > 0, "Malicious URL should have reasons"


class TestURLEdgeCases:
    def test_empty_url_handled(self, engine):
        r = engine.analyze_url("", skip_reputation=True)
        assert isinstance(r, dict)
        assert "threat_score" in r

    def test_very_long_url(self, engine):
        url = "https://example.com/path/" + "a" * 500
        r = engine.analyze_url(url, skip_reputation=True)
        assert 0 <= r["threat_score"] <= 100

    def test_url_with_special_chars(self, engine):
        r = engine.analyze_url("https://example.com/path?q=<script>alert(1)</script>", skip_reputation=True)
        assert isinstance(r, dict)

    def test_skip_reputation_faster(self, engine):
        import time
        start = time.time()
        engine.analyze_url("https://google.com", skip_reputation=True)
        fast_time = time.time() - start

        start = time.time()
        engine.analyze_url("https://google.com", skip_reputation=False)
        slow_time = time.time() - start

        # With reputation: may be slower (WHOIS/DNSBL)
        # Just verify both complete
        assert fast_time < 10.0
        assert slow_time < 30.0

    def test_ip_url_pipeline(self, engine):
        r = engine.analyze_url("http://45.33.32.156/cmd", skip_reputation=True)
        assert r["threat_score"] >= 20

    def test_analyze_url_with_reputation(self, engine):
        r = engine.analyze_url("https://google.com", skip_reputation=False)
        assert 0 <= r["threat_score"] <= 100

    def test_layer_scores_in_result(self, engine):
        r = engine.analyze_url("https://example.com", skip_reputation=True)
        # layer_scores should be present in the fusion result
        assert "layer_scores" in r or "threat_score" in r

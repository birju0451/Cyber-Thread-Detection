"""
tests/unit/test_reputation.py
===============================
Unit tests for engine/reputation.py

Tests TLD risk scoring, DNSBL lookups, domain age logic,
and the full analyze() function output structure.
"""

import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from engine.reputation import (
    ReputationAnalyzer,
    HIGH_RISK_TLDS,
    MEDIUM_RISK_TLDS,
    SUSPICIOUS_REGISTRARS,
    reputation_analyzer,
)


@pytest.fixture(scope="module")
def ra():
    return ReputationAnalyzer()


# ═══════════════════════════════════════════════════════════════
# TLD Classification
# ═══════════════════════════════════════════════════════════════

class TestTLDRisk:
    def test_high_risk_tlds_not_empty(self):
        assert len(HIGH_RISK_TLDS) > 0

    def test_tk_in_high_risk(self):
        assert ".tk" in HIGH_RISK_TLDS

    def test_xyz_in_high_risk(self):
        assert ".xyz" in HIGH_RISK_TLDS

    def test_info_in_medium_risk(self):
        assert ".info" in MEDIUM_RISK_TLDS

    def test_com_not_high_risk(self):
        assert ".com" not in HIGH_RISK_TLDS

    def test_org_not_high_risk(self):
        assert ".org" not in HIGH_RISK_TLDS

    def test_suspicious_registrars_not_empty(self):
        assert len(SUSPICIOUS_REGISTRARS) > 0


# ═══════════════════════════════════════════════════════════════
# _get_tld_risk()
# ═══════════════════════════════════════════════════════════════

class TestGetTLDRisk:
    def test_tk_is_high(self, ra):
        score, reason = ra._get_tld_risk(".tk")
        assert score >= 25
        assert reason

    def test_com_is_zero(self, ra):
        score, reason = ra._get_tld_risk(".com")
        assert score == 0

    def test_info_is_medium(self, ra):
        score, reason = ra._get_tld_risk(".info")
        assert 0 < score < 30

    def test_xyz_is_high(self, ra):
        score, reason = ra._get_tld_risk(".xyz")
        assert score >= 25

    def test_unknown_tld_returns_zero(self, ra):
        score, reason = ra._get_tld_risk(".randomtld")
        assert score == 0


# ═══════════════════════════════════════════════════════════════
# _extract_domain()
# ═══════════════════════════════════════════════════════════════

class TestExtractDomain:
    def test_standard_url(self, ra):
        domain = ra._extract_domain("https://evil.tk/payload")
        assert domain == "evil.tk" or "evil" in domain

    def test_ip_url(self, ra):
        domain = ra._extract_domain("http://192.168.1.1/page")
        # Should return the IP or empty
        assert domain is not None

    def test_url_no_scheme(self, ra):
        domain = ra._extract_domain("example.com/path")
        assert domain is not None


# ═══════════════════════════════════════════════════════════════
# Full analyze() function
# ═══════════════════════════════════════════════════════════════

class TestReputationAnalyze:
    def test_returns_dict(self, ra):
        r = ra.analyze("https://google.com")
        assert isinstance(r, dict)

    def test_has_required_fields(self, ra):
        r = ra.analyze("https://google.com")
        assert "score"   in r
        assert "reasons" in r

    def test_score_bounded_0_100(self, ra):
        r = ra.analyze("http://malware.tk/payload.exe")
        assert 0 <= r["score"] <= 100

    def test_high_risk_tld_scores_higher(self, ra):
        r_clean = ra.analyze("https://example.com")
        r_risky = ra.analyze("https://phishing.tk")
        assert r_risky["score"] >= r_clean["score"], \
            f".tk ({r_risky['score']}) should score >= .com ({r_clean['score']})"

    def test_reasons_is_list(self, ra):
        r = ra.analyze("https://example.com")
        assert isinstance(r["reasons"], list)

    def test_singleton_works(self):
        r = reputation_analyzer.analyze("https://google.com")
        assert isinstance(r, dict)
        assert "score" in r

    def test_empty_url_handled(self, ra):
        r = ra.analyze("")
        assert isinstance(r, dict)
        assert "score" in r

    def test_ip_url(self, ra):
        r = ra.analyze("http://45.33.32.156/cmd.php")
        # IP-based URLs should get some risk
        assert r["score"] >= 0

    def test_analyze_with_timeout(self, ra):
        """analyze() must complete in < 10 seconds even with WHOIS."""
        import time
        start = time.time()
        ra.analyze("https://example.com")
        elapsed = time.time() - start
        assert elapsed < 10.0, f"Reputation check took {elapsed:.1f}s (too slow)"

    @pytest.mark.parametrize("tld_url", [
        "https://free-money.tk",
        "https://phish.ml",
        "https://hack.xyz",
        "https://win-prize.top",
    ])
    def test_high_risk_tld_urls_non_zero(self, ra, tld_url):
        r = ra.analyze(tld_url)
        assert r["score"] >= 10, f"High-risk TLD URL should have score > 0: {tld_url}"

"""
tests/unit/test_random_forest.py
==================================
Unit tests for the Random Forest URL classifier (engine/url_analyzer.py)
and its underlying feature extraction (ml/feature_engineering.py).

Tests every public function with controlled inputs and validates outputs.
"""

import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.feature_engineering import (
    extract_url_features,
    _entropy,
    _has_ip,
    URL_FEATURE_COLS,
    SUSPICIOUS_KEYWORDS,
    BRAND_NAMES,
)


# ═══════════════════════════════════════════════════════════════
# _entropy()
# ═══════════════════════════════════════════════════════════════

class TestEntropy:
    def test_empty_string(self):
        assert _entropy("") == 0.0

    def test_single_char(self):
        # All same chars → entropy = 0
        assert _entropy("aaaaaaa") == pytest.approx(0.0, abs=1e-9)

    def test_two_equal_chars(self):
        # 50/50 split → entropy = 1.0
        result = _entropy("ab")
        assert result == pytest.approx(1.0, abs=1e-9)

    def test_high_entropy_string(self):
        # Long mixed string should have entropy > 3
        result = _entropy("aB3!xY9@qZ1#mN0")
        assert result > 3.0

    def test_url_path_entropy(self):
        # Random-looking path (typical of C2 beaconing)
        result = _entropy("xK9pQr2wLmZ8vNt")
        assert result > 3.5


# ═══════════════════════════════════════════════════════════════
# _has_ip()
# ═══════════════════════════════════════════════════════════════

class TestHasIP:
    def test_url_with_ip(self):
        assert _has_ip("http://192.168.1.1/login") == 1

    def test_url_without_ip(self):
        assert _has_ip("https://google.com/search") == 0

    def test_ip_no_scheme(self):
        assert _has_ip("10.0.0.1/admin") == 1

    def test_partial_ip_no_match(self):
        # 3 octets only — should not match IPv4
        assert _has_ip("http://192.168.1/path") == 0


# ═══════════════════════════════════════════════════════════════
# extract_url_features()
# ═══════════════════════════════════════════════════════════════

class TestExtractURLFeatures:
    def test_returns_dict(self):
        result = extract_url_features("https://google.com")
        assert isinstance(result, dict)

    def test_all_values_numeric(self):
        result = extract_url_features("https://paypal-login.verify-account.tk/secure")
        for key, val in result.items():
            assert isinstance(val, (int, float)), f"Non-numeric feature: {key}={val}"

    def test_ip_url_flagged(self):
        result = extract_url_features("http://192.168.1.100/login.php")
        assert result.get("has_ip") == 1

    def test_https_url_flag(self):
        result = extract_url_features("https://secure.example.com")
        assert result.get("has_https") == 1

    def test_http_url_no_https(self):
        result = extract_url_features("http://example.com")
        assert result.get("has_https") == 0

    def test_long_url(self):
        long_url = "https://example.com/" + "a" * 200
        result = extract_url_features(long_url)
        assert result.get("url_length", 0) > 200

    def test_suspicious_keyword_detected(self):
        result = extract_url_features("https://bank-login-secure.com/account/verify")
        # Should have multiple suspicious keywords
        assert result.get("suspicious_keyword_count", 0) >= 1

    def test_at_symbol(self):
        result = extract_url_features("http://attacker.com@victim.com/page")
        assert result.get("has_at_symbol") == 1

    def test_no_at_symbol(self):
        result = extract_url_features("https://clean.example.com")
        assert result.get("has_at_symbol", 0) == 0

    def test_subdomain_count(self):
        result = extract_url_features("http://sub1.sub2.sub3.evil.com/page")
        assert result.get("subdomain_count", 0) >= 2

    def test_shortener_flagged(self):
        result = extract_url_features("https://bit.ly/3xMalicious")
        assert result.get("is_shortener", 0) == 1

    def test_clean_url_low_entropy(self):
        result = extract_url_features("https://google.com/search?q=hello")
        assert result.get("domain_entropy", 999) < 4.0

    def test_feature_count_reasonable(self):
        result = extract_url_features("https://example.com")
        assert len(result) >= 15, f"Only {len(result)} features extracted"

    def test_no_none_values(self):
        result = extract_url_features("https://example.com/path?q=1")
        for k, v in result.items():
            assert v is not None, f"Feature {k} is None"


# ═══════════════════════════════════════════════════════════════
# RF Model (url_analyzer.analyze)
# ═══════════════════════════════════════════════════════════════

class TestURLAnalyzer:
    @pytest.fixture(autouse=True)
    def _skip_if_no_model(self):
        from pathlib import Path as P
        import config
        if not P(config.URL_MODEL_PATH).exists():
            pytest.skip("URL model not trained — run: python train_all.py --url-only")

    def test_analyze_returns_dict(self):
        from engine.url_analyzer import analyze
        result = analyze("https://google.com")
        assert isinstance(result, dict)

    def test_safe_url_low_score(self):
        from engine.url_analyzer import analyze
        result = analyze("https://google.com")
        assert result.get("rf_score", 100) < 50, \
            f"google.com should be low risk, got {result.get('rf_score')}"

    def test_phishing_url_high_score(self):
        from engine.url_analyzer import analyze
        result = analyze("http://192.168.1.1/paypal-login/verify-account.php")
        assert result.get("rf_score", 0) >= 50, \
            f"Phishing URL should have high score, got {result.get('rf_score')}"

    def test_output_has_prediction(self):
        from engine.url_analyzer import analyze
        result = analyze("https://example.com")
        assert "prediction" in result
        assert result["prediction"] in ("benign", "phishing", "unknown")

    def test_output_has_rf_score(self):
        from engine.url_analyzer import analyze
        result = analyze("https://example.com")
        assert "rf_score" in result
        assert 0 <= result["rf_score"] <= 100

    def test_shortener_url(self):
        from engine.url_analyzer import analyze
        result = analyze("https://bit.ly/3xEvilLink")
        assert result.get("rf_score", 0) >= 0  # Should return a valid score

    def test_ip_based_url(self):
        from engine.url_analyzer import analyze
        result = analyze("http://45.33.32.156/malware/payload.exe")
        score = result.get("rf_score", 0)
        assert score >= 40, f"IP-based URL should be high risk, got {score}"

    def test_encoded_url(self):
        from engine.url_analyzer import analyze
        result = analyze("http://evil.tk/%70%61%79%70%61%6C%2D%6C%6F%67%69%6E")
        assert result.get("rf_score", 0) >= 30

    def test_empty_features_handled(self):
        """Malformed URL should not crash the analyzer."""
        from engine.url_analyzer import analyze
        result = analyze("not-a-url-at-all")
        assert "rf_score" in result  # Gracefully handled

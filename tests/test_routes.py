"""
tests/test_routes.py
=====================
Integration tests for Flask API routes.
Tests all major API endpoints.

Run: python -m pytest tests/test_routes.py -v
Requires: Flask server NOT running (uses test client)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import json


@pytest.fixture(scope="module")
def client():
    """Create a Flask test client (no live server needed)."""
    from backend.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ── Health / Status ────────────────────────────────────────────
class TestStatus:

    def test_status_returns_200(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200

    def test_status_has_fields(self, client):
        r    = client.get("/api/status")
        data = r.get_json()
        assert "status"  in data
        assert "version" in data
        assert "db"      in data


# ── Predict (Extension endpoint) ──────────────────────────────
class TestPredict:

    def test_predict_safe_url(self, client):
        r = client.post("/predict",
            json={"url": "https://www.google.com"},
            content_type="application/json")
        assert r.status_code == 200
        data = r.get_json()
        assert "classification" in data
        assert "threat_score"   in data

    def test_predict_phishing_url(self, client):
        r = client.post("/predict",
            json={"url": "http://paypal-login-verify.tk/account"},
            content_type="application/json")
        assert r.status_code == 200
        data = r.get_json()
        assert data["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_predict_missing_url_returns_400(self, client):
        r = client.post("/predict", json={}, content_type="application/json")
        assert r.status_code == 400

    def test_predict_empty_url_returns_400(self, client):
        r = client.post("/predict", json={"url": ""}, content_type="application/json")
        assert r.status_code == 400

    def test_predict_result_has_score(self, client):
        r    = client.post("/predict", json={"url": "https://github.com"})
        data = r.get_json()
        assert 0 <= data["threat_score"] <= 100

    def test_predict_has_reasons(self, client):
        r    = client.post("/predict", json={"url": "https://python.org"})
        data = r.get_json()
        assert isinstance(data["reasons"], list)


# ── Scan (Dashboard endpoint) ─────────────────────────────────
class TestScan:

    def test_scan_url(self, client):
        r = client.post("/api/scan",
            json={"target": "https://example.com", "type": "url"})
        assert r.status_code == 200
        data = r.get_json()
        assert "classification" in data

    def test_scan_missing_target_returns_400(self, client):
        r = client.post("/api/scan", json={"type": "url"})
        assert r.status_code == 400

    def test_scan_invalid_type_returns_400(self, client):
        r = client.post("/api/scan",
            json={"target": "https://test.com", "type": "invalid"})
        assert r.status_code == 400

    def test_scan_nonexistent_file_returns_404(self, client):
        r = client.post("/api/scan",
            json={"target": "C:/does/not/exist.exe", "type": "file"})
        assert r.status_code == 404


# ── Stats ──────────────────────────────────────────────────────
class TestStats:

    def test_stats_returns_200(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_stats_has_fields(self, client):
        r    = client.get("/api/stats")
        data = r.get_json()
        assert "total_scans"   in data
        assert "total_threats" in data

    def test_history_returns_200(self, client):
        r = client.get("/api/history")
        assert r.status_code == 200

    def test_history_has_pagination(self, client):
        r    = client.get("/api/history")
        data = r.get_json()
        assert "items" in data
        assert "total" in data
        assert "page"  in data
        assert "pages" in data

    def test_history_page_param(self, client):
        r = client.get("/api/history?page=1&page_size=5")
        assert r.status_code == 200


# ── Alerts ────────────────────────────────────────────────────
class TestAlerts:

    def test_file_alerts_returns_200(self, client):
        r = client.get("/api/file-alerts")
        assert r.status_code == 200

    def test_process_alerts_returns_200(self, client):
        r = client.get("/api/process-alerts")
        assert r.status_code == 200

    def test_network_alerts_returns_200(self, client):
        r = client.get("/api/network-alerts")
        assert r.status_code == 200

    def test_quarantine_returns_200(self, client):
        r = client.get("/api/quarantine")
        assert r.status_code == 200


# ── Settings ──────────────────────────────────────────────────
class TestSettings:

    def test_get_settings_returns_200(self, client):
        r = client.get("/api/settings")
        assert r.status_code == 200

    def test_settings_has_keys(self, client):
        r    = client.get("/api/settings")
        data = r.get_json()
        assert "agent_enabled"    in data
        assert "threat_threshold" in data

    def test_post_settings_updates(self, client):
        r = client.post("/api/settings",
            json={"threat_threshold": 60},
            content_type="application/json")
        assert r.status_code == 200

    def test_post_settings_ignores_unknown_keys(self, client):
        r = client.post("/api/settings",
            json={"unknown_key": "evil_value"},
            content_type="application/json")
        assert r.status_code == 200


# ── Awareness ─────────────────────────────────────────────────
class TestAwareness:

    def test_list_topics_returns_200(self, client):
        r = client.get("/api/awareness")
        assert r.status_code == 200

    def test_list_topics_is_list(self, client):
        r    = client.get("/api/awareness")
        data = r.get_json()
        assert isinstance(data, list)

    def test_phishing_topic_exists(self, client):
        r = client.get("/api/awareness/phishing")
        assert r.status_code == 200

    def test_invalid_topic_returns_404(self, client):
        r = client.get("/api/awareness/nonexistent_topic_xyz")
        assert r.status_code == 404


# ── Page Routes ───────────────────────────────────────────────
class TestPages:

    def test_root_redirects(self, client):
        r = client.get("/")
        assert r.status_code in (301, 302, 308)

    def test_dashboard_page_loads(self, client):
        r = client.get("/dashboard")
        assert r.status_code == 200
        assert b"ABTD" in r.data or b"Dashboard" in r.data

    def test_scanner_page_loads(self, client):
        r = client.get("/scanner")
        assert r.status_code == 200

    def test_history_page_loads(self, client):
        r = client.get("/history")
        assert r.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

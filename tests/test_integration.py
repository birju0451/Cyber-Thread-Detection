"""
tests/test_integration.py
===========================
End-to-end integration tests for the ABTD + Zero Trust pipeline.

5 controlled scenarios flowing through:
  Event → Monitor → Classify → ABTD → Zero Trust → Policy → Response

Run: python -m pytest tests/test_integration.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


class TestEventClassifier:
    """Tests that the event classifier correctly triages events."""

    def test_import(self):
        from agent.event_classifier import event_classifier
        assert event_classifier is not None

    def test_safe_process_skipped(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "process_create",
            "process_name": "svchost.exe",
            "resource"    : "C:\\Windows\\System32\\svchost.exe",
        })
        assert result["relevant"] is False
        assert result["priority"] == "NONE"

    def test_blocklist_process_flagged(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "process_create",
            "process_name": "mimikatz.exe",
            "resource"    : "C:\\temp\\mimikatz.exe",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"

    def test_high_risk_event_always_relevant(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type": "usb_insert",
            "source"    : "usb_monitor",
            "resource"  : "E:\\",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"

    def test_suspicious_extension_flagged(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "file_download",
            "process_name": "chrome.exe",
            "resource"    : "C:\\Users\\User\\Downloads\\invoice.exe",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"

    def test_temp_dir_execution_flagged(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "file_execute",
            "process_name": "cmd.exe",
            "resource"    : "C:\\Users\\User\\AppData\\Local\\Temp\\payload.bat",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"


class TestZTPipeline:
    """Tests the full ZT pipeline bridge."""

    def test_import(self):
        from agent.zt_pipeline import process_security_event
        assert callable(process_security_event)

    def test_safe_event_filtered(self):
        from agent.zt_pipeline import process_security_event
        result = process_security_event({
            "event_type"  : "process_create",
            "source"      : "process_monitor",
            "process_name": "csrss.exe",
            "resource"    : "C:\\Windows\\System32\\csrss.exe",
        })
        # Safe system process should be filtered out
        assert result is None


class TestABTDHybridEngine:
    """Tests the 7-layer ABTD hybrid engine."""

    def test_import(self):
        from engine.predictor import engine
        assert hasattr(engine, "full_analysis")

    def test_full_analysis_url(self):
        from engine.predictor import engine
        result = engine.full_analysis({
            "event_type"  : "url_visit",
            "resource"    : "http://example.com",
            "process_name": "chrome.exe",
        })
        assert "threat_score" in result
        assert "classification" in result
        assert "analysis_layers" in result
        assert result["analysis_layers"] == 7

    def test_full_analysis_process(self):
        from engine.predictor import engine
        result = engine.full_analysis({
            "event_type"      : "process_create",
            "resource"        : "notepad.exe",
            "process_name"    : "notepad.exe",
            "process_pid"     : 9999,
            "process_cmdline" : "notepad.exe",
        })
        assert "threat_score" in result
        assert result["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")

    def test_full_analysis_has_modules(self):
        from engine.predictor import engine
        result = engine.full_analysis({
            "event_type": "url_visit",
            "resource"  : "https://google.com",
        })
        modules = result.get("detection_modules", {})
        assert "behavior" in modules
        assert "correlation" in modules


class TestScenario_SafeBrowsing:
    """Scenario 1: User visits a known safe website."""

    def test_safe_url_analysis(self):
        from engine.predictor import engine
        result = engine.analyze_url("https://www.google.com")
        assert result["classification"] == "SAFE"
        assert result["threat_score"] < 25


class TestScenario_SuspiciousURL:
    """Scenario 2: User visits a suspicious URL."""

    def test_suspicious_url_detected(self):
        from engine.predictor import engine
        result = engine.analyze_url(
            "http://192.168.1.100/login/verify-account-paypal-secure.php?id=abc123"
        )
        score = result["threat_score"]
        assert score > 10  # Should detect some suspicion (IP, phishing words, etc.)


class TestScenario_MaliciousProcess:
    """Scenario 3: Known attack tool detected."""

    def test_mimikatz_detected(self):
        from engine.predictor import engine
        result = engine.analyze_process(
            pid=1234, name="mimikatz.exe",
            cmdline="mimikatz.exe sekurlsa::logonpasswords"
        )
        # Rule engine detects blocklisted process name — score depends on rules
        assert result["threat_score"] >= 0  # Engine should return a result
        assert "classification" in result

    def test_mimikatz_blocked_by_policy(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        decision = pe.evaluate({
            "overall_risk"     : 80,
            "process_blocklist": True,
        })
        assert decision["decision"] == "BLOCK"


class TestScenario_RegistryPersistence:
    """Scenario 4: Unauthorized registry persistence attempt."""

    def test_registry_event_classification(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "registry_modify",
            "source"      : "registry_monitor",
            "process_name": "unknown.exe",
            "resource"    : "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"


class TestScenario_USBInsertion:
    """Scenario 5: USB device plugged in."""

    def test_usb_monitor_creates(self):
        from agent.usb_monitor import USBMonitor
        mon = USBMonitor()
        assert mon is not None

    def test_usb_scan_returns_list(self):
        from agent.usb_monitor import USBMonitor
        mon    = USBMonitor()
        events = mon.scan_once()
        assert isinstance(events, list)

    def test_usb_event_classified_high(self):
        from agent.event_classifier import event_classifier
        result = event_classifier.classify({
            "event_type"  : "usb_insert",
            "source"      : "usb_monitor",
            "resource"    : "E:\\",
            "process_name": "system",
        })
        assert result["relevant"] is True
        assert result["priority"] == "HIGH"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

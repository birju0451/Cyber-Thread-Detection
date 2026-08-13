"""
tests/integration/test_file_pipeline.py
=========================================
Integration tests for the full file threat analysis pipeline:
  Rule Engine → File Analyzer (entropy, PE, hash) → Score Fusion

Tests analyze_file() with real Windows system files and synthetic paths.
"""

import sys
import os
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


SAFE_FILES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\calc.exe",
]

SUSPICIOUS_PATHS = [
    r"C:\Users\test\AppData\Local\Temp\payload.exe",
    r"C:\Users\test\Downloads\invoice.pdf.exe",
    r"C:\Temp\malware.bat",
]


@pytest.fixture(scope="module")
def engine():
    from engine.predictor import ABTDEngine
    return ABTDEngine()


# ═══════════════════════════════════════════════════════════════
# analyze_file() output structure
# ═══════════════════════════════════════════════════════════════

class TestFilePipelineOutput:
    def test_returns_dict(self, engine):
        r = engine.analyze_file(r"C:\Windows\System32\notepad.exe")
        assert isinstance(r, dict)

    def test_required_fields(self, engine):
        r = engine.analyze_file(r"C:\Windows\System32\notepad.exe")
        for field in ("threat_score", "classification", "reasons", "timestamp"):
            assert field in r, f"Missing field: {field}"

    def test_score_bounded(self, engine):
        r = engine.analyze_file(r"C:\Windows\System32\cmd.exe")
        assert 0 <= r["threat_score"] <= 100

    def test_classification_valid(self, engine):
        r = engine.analyze_file(r"C:\Windows\System32\notepad.exe")
        assert r["classification"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL")


# ═══════════════════════════════════════════════════════════════
# Safe Files (system binaries)
# ═══════════════════════════════════════════════════════════════

class TestSafeFiles:
    @pytest.mark.parametrize("path", SAFE_FILES)
    def test_system_binary_exists(self, path):
        """Only test if file actually exists on this system."""
        if not Path(path).exists():
            pytest.skip(f"File not found: {path}")

    @pytest.mark.parametrize("path", SAFE_FILES)
    def test_system_file_not_critical(self, engine, path):
        if not Path(path).exists():
            pytest.skip(f"Not found: {path}")
        r = engine.analyze_file(path)
        assert r["classification"] != "CRITICAL", \
            f"System binary {path} should not be CRITICAL"


# ═══════════════════════════════════════════════════════════════
# Suspicious Paths (path-based heuristics)
# ═══════════════════════════════════════════════════════════════

class TestSuspiciousPaths:
    @pytest.mark.parametrize("path", SUSPICIOUS_PATHS)
    def test_suspicious_path_elevated_score(self, engine, path):
        r = engine.analyze_file(path)
        score = r["threat_score"]
        assert score >= 20, f"{path} should have elevated score, got {score}"

    def test_temp_exe_has_reasons(self, engine):
        r = engine.analyze_file(r"C:\Users\test\AppData\Local\Temp\run.exe")
        assert len(r["reasons"]) > 0

    def test_double_extension_detected(self, engine):
        r = engine.analyze_file(r"C:\Downloads\invoice.pdf.exe")
        reasons_text = " ".join(r["reasons"]).lower()
        assert "extension" in reasons_text or r["threat_score"] >= 30


# ═══════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestFileEdgeCases:
    def test_nonexistent_file(self, engine):
        r = engine.analyze_file(r"C:\NonExistent\fake.exe")
        assert isinstance(r, dict)
        assert "threat_score" in r

    def test_empty_path(self, engine):
        r = engine.analyze_file("")
        assert isinstance(r, dict)

    def test_pdf_extension_not_dangerous(self, engine):
        r = engine.analyze_file(r"C:\Documents\report.pdf")
        assert r["threat_score"] < 40, "PDF should have low base score"

    def test_txt_file_safe(self, engine):
        r = engine.analyze_file(r"C:\Users\user\Documents\notes.txt")
        assert r["threat_score"] == 0 or r["classification"] == "SAFE"

    def test_unicode_path(self, engine):
        r = engine.analyze_file(r"C:\Users\用户\Downloads\文件.exe")
        assert isinstance(r, dict)
        assert "threat_score" in r

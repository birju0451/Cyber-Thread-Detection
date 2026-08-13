"""
tests/test_zero_trust.py
=========================
Unit tests for Zero Trust architecture modules.

Run: python -m pytest tests/test_zero_trust.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


# ── Risk Calculator ──────────────────────────────────────────

class TestRiskCalculator:

    def test_import(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        assert calc is not None

    def test_zero_risk_inputs(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc   = RiskCalculator()
        result = calc.calculate({})
        assert result["overall_risk"] == 0.0
        assert result["trust_score"] == 100.0
        assert result["trust_level"] == "TRUSTED"

    def test_full_risk_inputs(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        signals = {
            "identity_risk": 100,
            "device_risk"  : 100,
            "app_risk"     : 100,
            "process_risk" : 100,
            "url_risk"     : 100,
            "file_risk"    : 100,
            "behavior_risk": 100,
            "network_risk" : 100,
        }
        result = calc.calculate(signals)
        assert result["overall_risk"] == 100.0
        assert result["trust_score"] == 0.0
        assert result["trust_level"] == "UNTRUSTED"

    def test_moderate_risk(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        signals = {"device_risk": 50, "process_risk": 60}
        result = calc.calculate(signals)
        assert 0 < result["overall_risk"] < 100
        assert result["trust_level"] in ("LOW_RISK", "MODERATE_RISK", "HIGH_RISK")

    def test_trust_levels(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        assert RiskCalculator._get_trust_level(95) == "TRUSTED"
        assert RiskCalculator._get_trust_level(75) == "LOW_RISK"
        assert RiskCalculator._get_trust_level(55) == "MODERATE_RISK"
        assert RiskCalculator._get_trust_level(35) == "HIGH_RISK"
        assert RiskCalculator._get_trust_level(15) == "UNTRUSTED"


# ── Policy Engine ────────────────────────────────────────────

class TestPolicyEngine:

    def test_import(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        assert pe is not None

    def test_policies_loaded(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        policies = pe.get_all_policies()
        assert len(policies) >= 8

    def test_low_risk_allows(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        decision = pe.evaluate({"overall_risk": 10, "device_trust": 90, "app_trust": 90})
        assert decision["decision"] in ("ALLOW", "MONITOR")

    def test_critical_risk_blocks(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        decision = pe.evaluate({"overall_risk": 85})
        assert decision["decision"] == "BLOCK"


# ── Access Controller (Full Pipeline) ─────────────────────────

class TestAccessController:

    def test_import(self):
        from zero_trust.access_control.access_controller import access_controller
        assert access_controller is not None

    def test_evaluate_url_access(self):
        from zero_trust.access_control.access_controller import access_controller
        result = access_controller.evaluate_access({
            "event_type"  : "url",
            "resource"    : "http://example.com",
            "action"      : "read",
            "process_name": "chrome.exe",
        })
        assert isinstance(result, dict)
        assert "decision" in result

    def test_evaluate_file_access(self):
        from zero_trust.access_control.access_controller import access_controller
        result = access_controller.evaluate_access({
            "event_type"  : "file",
            "resource"    : "C:\\Windows\\notepad.exe",
            "action"      : "execute",
            "process_name": "explorer.exe",
        })
        assert isinstance(result, dict)
        assert "decision" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

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

    def test_weight_normalisation(self):
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc = RiskCalculator(weights={"identity": 0.5, "device": 0.5, "app": 0.5})
        # Should normalise to sum=1.0
        total = sum(calc.weights.values())
        assert abs(total - 1.0) < 0.01


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
        assert len(policies) >= 8  # We created 10 default policies

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

    def test_moderate_risk_monitors(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        decision = pe.evaluate({"overall_risk": 40})
        assert decision["decision"] in ("MONITOR", "RESTRICT")

    def test_add_custom_policy(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        ok = pe.add_policy({
            "id": "CUSTOM-001", "name": "Test Policy",
            "conditions": {"overall_risk_min": 95},
            "decision": "BLOCK", "priority": 0,
        })
        assert ok is True

    def test_remove_custom_policy(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        pe.add_policy({
            "id": "CUSTOM-002", "name": "Test",
            "conditions": {}, "decision": "MONITOR", "priority": 999,
        })
        removed = pe.remove_policy("CUSTOM-002")
        assert removed is True

    def test_invalid_policy_rejected(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        ok = pe.add_policy({"id": "BAD"})  # missing required fields
        assert ok is False

    def test_blocklist_policy_matches(self):
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        decision = pe.evaluate({
            "overall_risk": 50,
            "process_blocklist": True,
        })
        assert decision["decision"] == "BLOCK"


# ── Identity Manager ─────────────────────────────────────────

class TestIdentityManager:

    def test_import(self):
        from zero_trust.identity.identity_manager import identity_manager
        assert identity_manager is not None

    def test_get_identity_context(self):
        from zero_trust.identity.identity_manager import identity_manager
        ctx = identity_manager.get_identity_context()
        assert isinstance(ctx, dict)
        assert "username" in ctx or "user" in ctx or len(ctx) > 0


# ── Device Assessor ──────────────────────────────────────────

class TestDeviceAssessor:

    def test_import(self):
        from zero_trust.device_trust.device_assessor import device_assessor
        assert device_assessor is not None

    def test_assess_returns_dict(self):
        from zero_trust.device_trust.device_assessor import device_assessor
        result = device_assessor.assess()
        assert isinstance(result, dict)


# ── Application Trust ────────────────────────────────────────

class TestAppAssessor:

    def test_import(self):
        from zero_trust.application_trust.app_assessor import app_assessor
        assert app_assessor is not None


# ── Process Trust ─────────────────────────────────────────────

class TestProcessAssessor:

    def test_import(self):
        from zero_trust.process_trust.process_assessor import process_assessor
        assert process_assessor is not None


# ── Resource Registry ─────────────────────────────────────────

class TestResourceRegistry:

    def test_import(self):
        from zero_trust.resource_protection.resource_registry import resource_registry
        assert resource_registry is not None

    def test_list_resources(self):
        from zero_trust.resource_protection.resource_registry import resource_registry
        resources = resource_registry.list_resources()
        assert isinstance(resources, list)


# ── Trust Manager ─────────────────────────────────────────────

class TestTrustManager:

    def test_import(self):
        from zero_trust.trust_manager.trust_manager import trust_manager
        assert trust_manager is not None


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

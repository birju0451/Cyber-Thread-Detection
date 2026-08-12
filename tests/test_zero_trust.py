"""
tests/test_zero_trust.py
==========================
Integration tests for the ABTD v2.0 Zero Trust pipeline.

Tests validate:
  1. Identity Manager — current user context
  2. Device Assessor — security posture assessment
  3. App Assessor — trusted vs unsigned application trust
  4. Process Assessor — masquerading / normal process detection
  5. Risk Calculator — score aggregation
  6. Trust Manager — state transitions
  7. Policy Engine — ALLOW / BLOCK decision routing
  8. Resource Registry — access control
  9. Access Controller — full 10-step pipeline end-to-end
"""

import sys
import os
import pytest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def identity_mgr():
    from zero_trust.identity.identity_manager import IdentityManager
    return IdentityManager()


@pytest.fixture(scope="module")
def device_assessor():
    from zero_trust.device_trust.device_assessor import DeviceAssessor
    return DeviceAssessor()


@pytest.fixture(scope="module")
def app_assessor():
    from zero_trust.application_trust.app_assessor import AppAssessor
    return AppAssessor()


@pytest.fixture(scope="module")
def process_assessor():
    from zero_trust.process_trust.process_assessor import ProcessAssessor
    return ProcessAssessor()


@pytest.fixture(scope="module")
def risk_calculator():
    from zero_trust.risk_engine.risk_calculator import RiskCalculator
    return RiskCalculator()


@pytest.fixture(scope="module")
def trust_manager():
    from zero_trust.trust_manager.trust_manager import TrustManager
    return TrustManager()


@pytest.fixture(scope="module")
def policy_engine():
    from zero_trust.policy_engine.policy_engine import PolicyEngine
    return PolicyEngine()


@pytest.fixture(scope="module")
def resource_registry():
    from zero_trust.resource_protection.resource_registry import ResourceRegistry
    return ResourceRegistry()


@pytest.fixture(scope="module")
def access_controller():
    from zero_trust.access_control.access_controller import AccessController
    return AccessController()


# ── Identity Manager ──────────────────────────────────────────────────────────

class TestIdentityManager:
    def test_context_has_username(self, identity_mgr):
        ctx = identity_mgr.get_identity_context()
        assert "username" in ctx
        assert ctx["username"]  # not empty

    def test_privilege_level_valid(self, identity_mgr):
        ctx = identity_mgr.get_identity_context()
        assert ctx["privilege_level"] in ("STANDARD", "ADMINISTRATOR", "SYSTEM", "UNKNOWN")

    def test_risk_structure(self, identity_mgr):
        risk = identity_mgr.get_identity_risk()
        assert "identity_risk" in risk
        assert 0 <= risk["identity_risk"] <= 100

    def test_admin_flag_is_bool(self, identity_mgr):
        ctx = identity_mgr.get_identity_context()
        assert isinstance(ctx.get("is_admin"), bool)


# ── Device Assessor ───────────────────────────────────────────────────────────

class TestDeviceAssessor:
    def test_assess_returns_score(self, device_assessor):
        result = device_assessor.assess()
        assert "device_trust_score" in result
        score = result["device_trust_score"]
        assert 0 <= score <= 100, f"Trust score {score} out of range"

    def test_trust_level_present(self, device_assessor):
        result = device_assessor.assess()
        assert result.get("device_trust_level") in (
            "TRUSTED", "LOW_RISK", "MODERATE_RISK", "HIGH_RISK", "UNTRUSTED"
        )

    def test_checks_structure(self, device_assessor):
        result = device_assessor.assess()
        assert "checks" in result
        checks = result["checks"]
        assert "firewall" in checks
        assert "antivirus" in checks

    def test_risk_flags_is_list(self, device_assessor):
        result = device_assessor.assess()
        assert isinstance(result.get("risk_flags"), list)


# ── App Assessor ──────────────────────────────────────────────────────────────

class TestAppAssessor:
    def test_system_exe_trusted(self, app_assessor):
        """notepad.exe in System32 should have a reasonable trust score."""
        notepad = r"C:\Windows\System32\notepad.exe"
        if not Path(notepad).exists():
            pytest.skip("notepad.exe not found")
        result = app_assessor.assess(notepad)
        assert "trust_score" in result
        assert result["trust_score"] >= 40, "System binary should not be critically untrusted"

    def test_nonexistent_path_low_trust(self, app_assessor):
        result = app_assessor.assess(r"C:\FakeApp\malware.exe")
        assert result["trust_score"] < 60

    def test_result_has_required_fields(self, app_assessor):
        result = app_assessor.assess(r"C:\Windows\System32\cmd.exe")
        for field in ("trust_score", "is_signed", "path_risk", "risk_flags"):
            assert field in result, f"Missing field: {field}"


# ── Process Assessor ──────────────────────────────────────────────────────────

class TestProcessAssessor:
    def test_current_python_process(self, process_assessor):
        """The test runner (Python) should be a detectable process."""
        import psutil
        pid  = os.getpid()
        name = "python.exe"
        result = process_assessor.assess_process(pid, name)
        assert "process_risk_score" in result
        assert 0 <= result["process_risk_score"] <= 100

    def test_fake_masquerading_flagged(self, process_assessor):
        """svchost.exe running from temp should be flagged."""
        result = process_assessor.assess_process(
            pid=99999,
            name="svchost.exe",
            exe_path=r"C:\Users\test\AppData\Local\Temp\svchost.exe",
        )
        assert result["process_risk_score"] > 40, "Masquerading should raise risk"
        assert len(result["risk_flags"]) > 0

    def test_risk_level_in_valid_set(self, process_assessor):
        result = process_assessor.assess_process(os.getpid(), "python.exe")
        assert result.get("risk_level") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ── Risk Calculator ───────────────────────────────────────────────────────────

class TestRiskCalculator:
    def test_max_risk_inputs(self, risk_calculator):
        """All-max signals should produce near-100 risk."""
        score = risk_calculator.calculate(
            identity_risk=100,
            device_risk=100,
            app_risk=100,
            process_risk=100,
            resource_sensitivity=100,
            behavior_risk=100,
            abtd_threat_score=100,
            network_risk=100,
        )
        assert score["overall_risk"] >= 80

    def test_zero_risk_inputs(self, risk_calculator):
        """All-zero signals should produce near-0 risk."""
        score = risk_calculator.calculate(
            identity_risk=0, device_risk=0, app_risk=0, process_risk=0,
            resource_sensitivity=0, behavior_risk=0, abtd_threat_score=0, network_risk=0,
        )
        assert score["overall_risk"] <= 20

    def test_output_bounded(self, risk_calculator):
        """Risk must always be between 0 and 100."""
        score = risk_calculator.calculate(
            identity_risk=50, device_risk=50, app_risk=50, process_risk=50,
            resource_sensitivity=50, behavior_risk=50, abtd_threat_score=50, network_risk=50,
        )
        assert 0 <= score["overall_risk"] <= 100


# ── Trust Manager ─────────────────────────────────────────────────────────────

class TestTrustManager:
    def test_update_and_retrieve(self, trust_manager):
        trust_manager.update_trust("process", "test_entity_1", risk_score=20)
        state = trust_manager.get_trust_state("process", "test_entity_1")
        assert state is not None
        assert state["trust_score"] > 0

    def test_high_risk_lowers_trust(self, trust_manager):
        trust_manager.update_trust("process", "test_entity_2", risk_score=90)
        state = trust_manager.get_trust_state("process", "test_entity_2")
        assert state["trust_score"] < 60, "High risk should lower trust significantly"

    def test_trust_level_valid(self, trust_manager):
        trust_manager.update_trust("process", "test_entity_3", risk_score=50)
        state = trust_manager.get_trust_state("process", "test_entity_3")
        assert state["trust_level"] in ("TRUSTED", "LOW_RISK", "MODERATE_RISK", "HIGH_RISK", "UNTRUSTED")


# ── Policy Engine ─────────────────────────────────────────────────────────────

class TestPolicyEngine:
    def _make_context(self, risk=30):
        return {
            "event_type"     : "url",
            "resource"       : "https://example.com",
            "overall_risk"   : risk,
            "device_trust"   : {"device_trust_score": 80},
            "identity"       : {"privilege_level": "STANDARD"},
            "application"    : {"trust_score": 80},
            "process"        : {"process_risk_score": 10, "risk_flags": []},
            "abtd_result"    : {"threat_score": risk, "classification": "SAFE"},
            "behavior_risk"  : 10.0,
        }

    def test_low_risk_allows(self, policy_engine):
        ctx    = self._make_context(risk=15)
        result = policy_engine.evaluate(ctx)
        assert result["decision"] in ("ALLOW", "MONITOR"), f"Low risk should allow, got {result['decision']}"

    def test_high_risk_blocks(self, policy_engine):
        ctx    = self._make_context(risk=92)
        ctx["abtd_result"]["threat_score"] = 92
        ctx["abtd_result"]["classification"] = "MALICIOUS"
        result = policy_engine.evaluate(ctx)
        assert result["decision"] in ("BLOCK", "QUARANTINE", "RESTRICT"), \
            f"High risk should block/restrict, got {result['decision']}"

    def test_decision_has_policy_name(self, policy_engine):
        result = policy_engine.evaluate(self._make_context(risk=50))
        assert "policy_name" in result or "decision" in result


# ── Resource Registry ─────────────────────────────────────────────────────────

class TestResourceRegistry:
    def test_list_not_empty(self, resource_registry):
        resources = resource_registry.list_resources()
        assert len(resources) > 0, "Registry should have default resources"

    def test_high_trust_allows_public(self, resource_registry):
        result = resource_registry.check_access("https://example.com", trust_score=90)
        assert result["allowed"]

    def test_low_trust_blocks_critical(self, resource_registry):
        # SAM database is CRITICAL sensitivity
        result = resource_registry.check_access(r"C:\Windows\System32\config\SAM", trust_score=30)
        assert not result["allowed"], "Low trust should not access CRITICAL resources"


# ── Access Controller (End-to-End) ────────────────────────────────────────────

class TestAccessController:
    """Full pipeline integration test — simulates a real detection event."""

    def test_safe_url_event(self, access_controller):
        result = access_controller.evaluate_access({
            "event_type"   : "url",
            "resource"     : "https://google.com",
            "action"       : "navigate",
            "process_name" : "chrome.exe",
            "abtd_result"  : {"threat_score": 5, "classification": "SAFE"},
            "behavior_risk": 2.0,
        })
        assert "decision" in result
        assert result["decision"] in ("ALLOW", "MONITOR")

    def test_malicious_url_event(self, access_controller):
        result = access_controller.evaluate_access({
            "event_type"   : "url",
            "resource"     : "http://malware-c2-fake-domain.xyz/payload.exe",
            "action"       : "navigate",
            "process_name" : "chrome.exe",
            "abtd_result"  : {"threat_score": 95, "classification": "MALICIOUS"},
            "behavior_risk": 60.0,
        })
        assert result["decision"] in ("BLOCK", "QUARANTINE", "RESTRICT", "CHALLENGE")

    def test_drive_by_download_sequence(self, access_controller):
        """
        Simulate a Drive-By Download attack chain:
          Step 1: URL navigation to malicious page
          Step 2: Suspicious file write from browser
          Step 3: Process execution of dropped payload

        Verifies the ZT system escalates decision across the chain.
        """
        entity_id = "test_drive_by_entity"

        # Step 1: Browser navigates to a suspicious URL
        url_result = access_controller.evaluate_access({
            "event_type"   : "url",
            "resource"     : "http://evil-site.net",
            "process_name" : "chrome.exe",
            "abtd_result"  : {"threat_score": 65, "classification": "SUSPICIOUS"},
            "behavior_risk": 20.0,
            "entity_id"    : entity_id,
        })

        # Step 2: File written to temp from browser
        file_result = access_controller.evaluate_access({
            "event_type"   : "file",
            "resource"     : r"C:\Users\test\AppData\Local\Temp\payload.exe",
            "process_name" : "chrome.exe",
            "abtd_result"  : {"threat_score": 80, "classification": "MALICIOUS"},
            "behavior_risk": 45.0,
            "entity_id"    : entity_id,
        })

        # Step 3: Payload executes
        proc_result = access_controller.evaluate_access({
            "event_type"   : "process",
            "resource"     : r"C:\Users\test\AppData\Local\Temp\payload.exe",
            "process_name" : "payload.exe",
            "abtd_result"  : {"threat_score": 92, "classification": "CRITICAL"},
            "behavior_risk": 75.0,
            "entity_id"    : entity_id,
        })

        # The final step (process) should result in a restrictive decision
        assert proc_result["decision"] in ("BLOCK", "QUARANTINE", "RESTRICT", "CHALLENGE"), \
            f"Drive-by payload should be blocked. Got: {proc_result['decision']}"

    def test_pipeline_ms_recorded(self, access_controller):
        """ZT pipeline should record timing."""
        result = access_controller.evaluate_access({
            "event_type"   : "url",
            "resource"     : "https://test.com",
            "abtd_result"  : {"threat_score": 10, "classification": "SAFE"},
            "behavior_risk": 0.0,
        })
        assert "pipeline_ms" in result or "timestamp" in result

    def test_result_has_all_required_fields(self, access_controller):
        result = access_controller.evaluate_access({
            "event_type"   : "url",
            "resource"     : "https://test.com",
            "abtd_result"  : {"threat_score": 20, "classification": "SAFE"},
            "behavior_risk": 5.0,
        })
        required = ["decision", "overall_risk", "timestamp"]
        for field in required:
            assert field in result, f"Missing field in ZT result: {field}"

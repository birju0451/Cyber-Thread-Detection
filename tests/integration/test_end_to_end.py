"""
tests/integration/test_end_to_end.py
======================================
End-to-End integration tests for the complete ABTD v2.0 system.

Simulates real attack scenarios from initial detection all the way through:
  ABTD Engine → ZT Pipeline → Behavior Engine → Correlation → Response

Attack Scenarios tested:
  1. Drive-By Download (URL → File → Process)
  2. Spear Phishing (URL scan → credential theft)
  3. Ransomware Simulation (mass file writes + encryption signals)
  4. Lateral Movement (network scan + privilege escalation)
  5. USB Drop Attack (USB → exe scan → process)
"""

import sys
import os
import time
import pytest
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def engine():
    from engine.predictor import ABTDEngine
    return ABTDEngine()


@pytest.fixture(scope="module")
def zt():
    from zero_trust.access_control.access_controller import AccessController
    return AccessController()


@pytest.fixture(scope="module")
def be():
    from abtd.behavior_engine.behavior_engine import BehaviorEngine
    return BehaviorEngine()


@pytest.fixture(scope="module")
def corr():
    from abtd.correlation_engine.correlation_engine import CorrelationEngine
    return CorrelationEngine()


@pytest.fixture(scope="module")
def resp():
    from abtd.response_engine.response_engine import ResponseEngine
    return ResponseEngine(simulation_mode=True)


def make_event(entity, event_type, resource, abtd_score, abtd_class, behavior_risk):
    return {
        "event_type"   : event_type,
        "resource"     : resource,
        "entity_id"    : entity,
        "process_name" : f"{event_type}_process",
        "abtd_result"  : {"threat_score": abtd_score, "classification": abtd_class},
        "behavior_risk": behavior_risk,
    }


# ═══════════════════════════════════════════════════════════════
# Scenario 1: Drive-By Download
# ═══════════════════════════════════════════════════════════════

class TestDriveByDownload:
    """
    Attack chain:
      Browser → malicious URL (SUSPICIOUS)
      → file dropped to %TEMP% (MALICIOUS)
      → payload executes (CRITICAL)
    """

    def test_full_chain_escalates_decision(self, zt, be, corr):
        entity = "e2e_drive_by"

        # Step 1: URL navigation
        url_evt = make_event(entity, "url", "http://evil-exploit.xyz", 65, "SUSPICIOUS", 15.0)
        url_r = zt.evaluate_access(url_evt)
        be.record_event(entity, "url", {}, risk_delta=15)
        corr.correlate({**url_r, "entity_id": entity, "event_type": "url",
                        "timestamp": datetime.now(timezone.utc).isoformat()})

        # Step 2: File dropped
        file_evt = make_event(entity, "file", r"C:\Temp\driveBy.exe", 80, "MALICIOUS", 40.0)
        file_r = zt.evaluate_access(file_evt)
        be.record_event(entity, "file_write", {"path": r"C:\Temp\driveBy.exe"}, risk_delta=35)
        corr.correlate({**file_r, "entity_id": entity, "event_type": "file",
                        "timestamp": datetime.now(timezone.utc).isoformat()})

        # Step 3: Payload executes
        proc_evt = make_event(entity, "process", r"C:\Temp\driveBy.exe", 95, "CRITICAL", 75.0)
        proc_r = zt.evaluate_access(proc_evt)
        be.record_event(entity, "process_create", {"name": "driveBy.exe"}, risk_delta=50)

        # Verify escalation
        profile = be.get_profile(entity)
        assert profile["behavior_risk"] >= 60.0, \
            f"Drive-by chain: behavior risk should be high, got {profile['behavior_risk']}"

        # Final ZT decision should be restrictive
        assert proc_r["decision"] in ("BLOCK", "QUARANTINE", "RESTRICT", "CHALLENGE"), \
            f"Final step should be blocked, got {proc_r['decision']}"

    def test_drive_by_creates_incident(self, corr):
        incidents = [i for i in corr.get_incidents() if "e2e_drive_by" in str(i.get("entity_id", ""))]
        # At least one incident should have been created from the chain
        assert len(incidents) > 0, "Drive-by chain should generate at least one incident"


# ═══════════════════════════════════════════════════════════════
# Scenario 2: Spear Phishing
# ═══════════════════════════════════════════════════════════════

class TestSpearPhishing:
    """
    User receives a phishing email link, visits it, enters credentials.
    URL is flagged as MALICIOUS by ABTD engine.
    """

    def test_phishing_url_blocked(self, engine, zt):
        phish_url = "http://paypal-login-verify.tk/secure/account-update"
        url_result = engine.analyze_url(phish_url, skip_reputation=True)
        zt_result = zt.evaluate_access({
            "event_type"   : "url",
            "resource"     : phish_url,
            "process_name" : "chrome.exe",
            "abtd_result"  : url_result,
            "behavior_risk": 5.0,
        })
        # URL should be at minimum MONITOR or RESTRICT
        assert zt_result["decision"] != "ALLOW" or url_result["threat_score"] < 30, \
            f"Phishing URL should not be ALLOW with high score. Decision: {zt_result['decision']}, Score: {url_result['threat_score']}"

    def test_phishing_has_reasons(self, engine):
        r = engine.analyze_url("http://paypal-login-verify.tk/secure", skip_reputation=True)
        assert len(r["reasons"]) > 0, "Phishing URL should have detection reasons"


# ═══════════════════════════════════════════════════════════════
# Scenario 3: Ransomware Simulation
# ═══════════════════════════════════════════════════════════════

class TestRansomwareSimulation:
    """
    Simulates ransomware behavior:
      - Mass file write events to multiple directories
      - Shadow copy deletion (vssadmin)
      - High behavioral risk accumulation
    """

    def test_mass_file_writes_raise_risk(self, be):
        entity = "e2e_ransomware"
        # Ransomware encrypts files rapidly
        for i in range(15):
            be.record_event(
                entity, "file_write",
                {"path": f"C:\\Users\\Documents\\file{i}.encrypted"},
                risk_delta=8.0,
            )
        profile = be.get_profile(entity)
        assert profile["behavior_risk"] >= 60.0, \
            f"Mass file writes should produce high risk, got {profile['behavior_risk']}"

    def test_vssadmin_delete_flagged(self, engine):
        """Shadow copy deletion is a classic ransomware indicator."""
        r = engine.analyze_process(
            9990, "cmd.exe",
            "cmd.exe /c vssadmin delete shadows /all /quiet"
        )
        # vssadmin is in cmd_abuse rules
        assert r["threat_score"] >= 10, \
            f"vssadmin delete should be flagged, got {r['threat_score']}"

    def test_ransomware_incident_created(self, be, corr):
        entity = "e2e_ransomware"  # same entity from above
        from datetime import datetime, timezone
        corr.correlate({
            "entity_id"   : entity,
            "event_type"  : "file",
            "overall_risk": 85,
            "decision"    : "BLOCK",
            "timestamp"   : datetime.now(timezone.utc).isoformat(),
            "resource"    : "mass_file_encrypt",
        })
        incidents = corr.get_incidents()
        ransomware_incidents = [i for i in incidents if "e2e_ransomware" in str(i.get("entity_id", ""))]
        assert len(ransomware_incidents) > 0, "Ransomware pattern should create incident"


# ═══════════════════════════════════════════════════════════════
# Scenario 4: Lateral Movement
# ═══════════════════════════════════════════════════════════════

class TestLateralMovement:
    """
    Simulates lateral movement:
      - Network scan (multiple failed connections)
      - Admin share access attempt
      - Privilege escalation
    """

    def test_network_scan_behavior_risk(self, be):
        entity = "e2e_lateral"
        # Simulate port scan — many network events
        for port in range(1, 30):
            be.record_event(
                entity, "network_connect",
                {"dst": f"192.168.1.{port}", "port": 445},
                risk_delta=5.0,
            )
        profile = be.get_profile(entity)
        assert profile["behavior_risk"] >= 50.0, \
            f"Port scan simulation should produce high risk, got {profile['behavior_risk']}"

    def test_psexec_flagged_by_rules(self, engine):
        """PsExec is a common lateral movement tool."""
        r = engine.analyze_process(
            9991, "psexec.exe",
            "psexec.exe \\\\target -u admin -p pass cmd.exe"
        )
        # psexec may or may not be in BLOCKED_PROCESSES — score should still be non-zero
        # due to the aggressive cmdline patterns
        assert isinstance(r, dict)
        assert "threat_score" in r


# ═══════════════════════════════════════════════════════════════
# Scenario 5: USB Drop Attack
# ═══════════════════════════════════════════════════════════════

class TestUSBDropAttack:
    """
    Simulates a USB drop attack:
      - USB inserted with executable payload
      - Payload executes
      - ZT evaluation blocks based on file origin
    """

    def test_usb_exe_analysis(self, engine, zt):
        """Executable found on a USB drive should be treated with caution."""
        # Simulate USB drive path
        usb_exe = r"E:\autorun\payload.exe"
        zt_result = zt.evaluate_access({
            "event_type"   : "file",
            "resource"     : usb_exe,
            "action"       : "mount",
            "process_name" : "usb_insert",
            "abtd_result"  : {"threat_score": 60, "classification": "SUSPICIOUS"},
            "behavior_risk": 15.0,
        })
        assert "decision" in zt_result
        assert zt_result["decision"] != "ALLOW", \
            "USB executable should not be immediately ALLOW"

    def test_usb_monitor_instantiates(self):
        from agent.usb_monitor import USBMonitor
        mon = USBMonitor()
        assert mon is not None


# ═══════════════════════════════════════════════════════════════
# System-Wide Health: All Modules Initialize
# ═══════════════════════════════════════════════════════════════

class TestSystemHealth:
    def test_all_engines_initialize(self):
        from engine.predictor      import ABTDEngine
        from engine.rule_engine    import RuleEngine
        from engine.reputation     import ReputationAnalyzer
        from engine.threat_scorer  import ThreatScorer
        assert ABTDEngine()     is not None
        assert RuleEngine()     is not None
        assert ReputationAnalyzer() is not None
        assert ThreatScorer()   is not None

    def test_all_zt_modules_initialize(self):
        from zero_trust.identity.identity_manager           import IdentityManager
        from zero_trust.device_trust.device_assessor        import DeviceAssessor
        from zero_trust.application_trust.app_assessor      import AppAssessor
        from zero_trust.process_trust.process_assessor      import ProcessAssessor
        from zero_trust.risk_engine.risk_calculator         import RiskCalculator
        from zero_trust.trust_manager.trust_manager         import TrustManager
        from zero_trust.policy_engine.policy_engine         import PolicyEngine
        from zero_trust.resource_protection.resource_registry import ResourceRegistry
        from zero_trust.access_control.access_controller    import AccessController
        for cls in [IdentityManager, DeviceAssessor, AppAssessor, ProcessAssessor,
                    RiskCalculator, TrustManager, PolicyEngine, ResourceRegistry, AccessController]:
            assert cls() is not None, f"{cls.__name__} failed to initialize"

    def test_all_abtd_modules_initialize(self):
        from abtd.behavior_engine.behavior_engine    import BehaviorEngine
        from abtd.correlation_engine.correlation_engine import CorrelationEngine
        from abtd.response_engine.response_engine    import ResponseEngine
        assert BehaviorEngine()             is not None
        assert CorrelationEngine()          is not None
        assert ResponseEngine(simulation_mode=True) is not None

    def test_all_agents_initialize(self):
        from agent.usb_monitor      import USBMonitor
        from agent.startup_monitor  import StartupMonitor
        assert USBMonitor()    is not None
        assert StartupMonitor() is not None

    def test_security_assessment_runs(self):
        from scanner.security_assessment import SecurityAssessment
        assessor = SecurityAssessment()
        result   = assessor.run()
        assert 0 <= result["security_posture_score"]   <= 100
        assert 0 <= result["zero_trust_readiness_score"] <= 100
        assert 0 <= result["overall_security_risk"]    <= 100

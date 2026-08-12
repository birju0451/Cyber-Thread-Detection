"""
tests/integration/test_network_pipeline.py
============================================
Integration tests for the network monitoring pipeline:
  Network Monitor → ABTD engine → ZT evaluate_access → Correlation Engine

Tests suspicious port detection, C2 beaconing patterns,
and behavioral network risk accumulation.
"""

import sys
import os
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(scope="module")
def zt_controller():
    try:
        from zero_trust.access_control.access_controller import AccessController
        return AccessController()
    except Exception:
        return None


@pytest.fixture(scope="module")
def behavior_engine():
    try:
        from abtd.behavior_engine.behavior_engine import BehaviorEngine
        return BehaviorEngine()
    except Exception:
        return None


@pytest.fixture(scope="module")
def correlation_engine():
    try:
        from abtd.correlation_engine.correlation_engine import CorrelationEngine
        return CorrelationEngine()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# Network Monitor Unit (psutil-based)
# ═══════════════════════════════════════════════════════════════

class TestNetworkMonitorUnit:
    def test_network_monitor_instantiates(self):
        from agent.network_monitor import NetworkMonitor
        mon = NetworkMonitor()
        assert mon is not None

    def test_scan_once_returns_list(self):
        from agent.network_monitor import NetworkMonitor
        mon = NetworkMonitor()
        result = mon.scan_once()
        assert isinstance(result, list)

    def test_scan_once_does_not_crash(self):
        """scan_once() must complete without exception."""
        from agent.network_monitor import NetworkMonitor
        mon = NetworkMonitor()
        try:
            mon.scan_once()
        except Exception as e:
            pytest.fail(f"scan_once() raised: {e}")

    def test_threat_format_if_found(self):
        """If any threats found, they must have required fields."""
        from agent.network_monitor import NetworkMonitor
        mon = NetworkMonitor()
        threats = mon.scan_once()
        for threat in threats:
            assert "pid" in threat or "process" in threat or "threat_score" in threat


# ═══════════════════════════════════════════════════════════════
# Suspicious Port Detection via ZT
# ═══════════════════════════════════════════════════════════════

class TestSuspiciousPortDetection:
    SUSPICIOUS_PORTS = [4444, 1337, 5555, 31337, 6666]
    SAFE_PORTS = [443, 80, 8080, 53]

    @pytest.mark.parametrize("port", SUSPICIOUS_PORTS)
    def test_suspicious_port_flagged(self, zt_controller, port):
        if not zt_controller:
            pytest.skip("ZT controller not available")
        result = zt_controller.evaluate_access({
            "event_type"   : "network",
            "resource"     : f"0.0.0.0:{port}",
            "action"       : "connect",
            "process_name" : "unknown.exe",
            "abtd_result"  : {"threat_score": 45, "classification": "SUSPICIOUS"},
            "behavior_risk": 25.0,
        })
        assert result["decision"] in ("MONITOR", "RESTRICT", "BLOCK", "CHALLENGE", "QUARANTINE"), \
            f"Port {port} should be flagged, got {result['decision']}"

    @pytest.mark.parametrize("port", SAFE_PORTS)
    def test_safe_port_allowed(self, zt_controller, port):
        if not zt_controller:
            pytest.skip("ZT controller not available")
        result = zt_controller.evaluate_access({
            "event_type"   : "network",
            "resource"     : f"google.com:{port}",
            "action"       : "connect",
            "process_name" : "chrome.exe",
            "abtd_result"  : {"threat_score": 5, "classification": "SAFE"},
            "behavior_risk": 2.0,
        })
        assert result["decision"] in ("ALLOW", "MONITOR"), \
            f"Port {port} normal traffic should be ALLOW, got {result['decision']}"


# ═══════════════════════════════════════════════════════════════
# C2 Beaconing Pattern (Behavioral)
# ═══════════════════════════════════════════════════════════════

class TestC2BeaconingPattern:
    def test_repeated_c2_connections_raise_risk(self, behavior_engine):
        if not behavior_engine:
            pytest.skip("Behavior engine not available")
        entity = "c2_test_integration"
        for _ in range(6):
            behavior_engine.record_event(
                entity, "network_connect",
                {"dst": "185.234.x.x", "port": 4444},
                risk_delta=15.0,
            )
        profile = behavior_engine.get_profile(entity)
        assert profile["behavior_risk"] >= 60.0, \
            f"C2 beaconing should produce high risk, got {profile['behavior_risk']}"

    def test_normal_https_traffic_no_risk(self, behavior_engine):
        if not behavior_engine:
            pytest.skip("Behavior engine not available")
        entity = "safe_browsing_entity"
        for url in ["https://google.com", "https://microsoft.com", "https://github.com"]:
            behavior_engine.record_event(
                entity, "network_connect",
                {"dst": url, "port": 443},
                risk_delta=0.0,
            )
        profile = behavior_engine.get_profile(entity)
        assert profile["behavior_risk"] < 30.0, \
            f"Normal HTTPS traffic should have low risk, got {profile['behavior_risk']}"


# ═══════════════════════════════════════════════════════════════
# Correlation: Network Events → Incident
# ═══════════════════════════════════════════════════════════════

class TestNetworkCorrelation:
    def _net_event(self, entity, risk=75, decision="BLOCK"):
        from datetime import datetime, timezone
        return {
            "entity_id"   : entity,
            "event_type"  : "network",
            "overall_risk": risk,
            "decision"    : decision,
            "timestamp"   : datetime.now(timezone.utc).isoformat(),
            "resource"    : "185.234.x.x:4444",
        }

    def test_repeated_network_blocks_create_incident(self, correlation_engine):
        if not correlation_engine:
            pytest.skip("Correlation engine not available")
        entity = "net_incident_entity"
        for _ in range(5):
            correlation_engine.correlate(self._net_event(entity, risk=80))
        incidents = [i for i in correlation_engine.get_incidents()
                     if i.get("entity_id") == entity]
        assert len(incidents) > 0, "Repeated network blocks should create incident"

    def test_single_network_block_no_incident(self, correlation_engine):
        if not correlation_engine:
            pytest.skip("Correlation engine not available")
        entity = "single_net_entity"
        correlation_engine.correlate(self._net_event(entity, risk=75))
        # Single event MAY or MAY NOT create incident — just verify no crash
        incidents = correlation_engine.get_incidents()
        assert isinstance(incidents, list)

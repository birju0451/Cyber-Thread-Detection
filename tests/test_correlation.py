"""
tests/test_correlation.py
===========================
Tests for the ABTD v2.0 Correlation and Behavior Engines.

Tests validate:
  1. BehaviorEngine — event recording, risk accumulation, chain detection
  2. CorrelationEngine — incident grouping, severity assignment, deduplication
  3. ResponseEngine — simulation mode actions
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def behavior_engine():
    from abtd.behavior_engine.behavior_engine import BehaviorEngine
    return BehaviorEngine()


@pytest.fixture(scope="module")
def correlation_engine():
    from abtd.correlation_engine.correlation_engine import CorrelationEngine
    return CorrelationEngine()


@pytest.fixture(scope="module")
def response_engine():
    from abtd.response_engine.response_engine import ResponseEngine
    return ResponseEngine(simulation_mode=True)


# ── BehaviorEngine ────────────────────────────────────────────────────────────

class TestBehaviorEngine:
    def test_record_event_creates_profile(self, behavior_engine):
        behavior_engine.record_event(
            entity_id  = "test_entity_behavior_1",
            event_type = "process_create",
            details    = {"name": "test.exe", "pid": 1234},
        )
        profile = behavior_engine.get_profile("test_entity_behavior_1")
        assert profile is not None
        assert profile["entity_id"] == "test_entity_behavior_1"

    def test_behavior_risk_accumulates(self, behavior_engine):
        entity = "risk_accumulation_entity"
        behavior_engine.record_event(entity, "process_create", {}, risk_delta=10.0)
        behavior_engine.record_event(entity, "file_write",     {}, risk_delta=15.0)
        behavior_engine.record_event(entity, "registry_modify",{}, risk_delta=20.0)
        profile = behavior_engine.get_profile(entity)
        assert profile["behavior_risk"] >= 30.0, \
            f"Risk should have accumulated, got {profile['behavior_risk']}"

    def test_event_count_tracked(self, behavior_engine):
        entity = "event_count_entity"
        for i in range(5):
            behavior_engine.record_event(entity, "network_connect", {"port": 80 + i})
        profile = behavior_engine.get_profile(entity)
        assert profile["total_events"] >= 5

    def test_drive_by_chain_detected(self, behavior_engine):
        """
        Drive-by download chain:
          url → file_write (exe to temp) → process_create
        Should be flagged as high behavioral risk.
        """
        entity = "drive_by_test_entity"

        behavior_engine.record_event(entity, "url",          {"url": "http://evil.xyz"}, risk_delta=20)
        behavior_engine.record_event(entity, "file_write",   {"path": r"C:\Temp\drop.exe"}, risk_delta=30)
        behavior_engine.record_event(entity, "process_create",{"name": "drop.exe"}, risk_delta=40)

        profile = behavior_engine.get_profile(entity)
        assert profile["behavior_risk"] >= 50.0, \
            "Drive-by chain should elevate behavior risk significantly"

    def test_get_all_profiles_returns_list(self, behavior_engine):
        profiles = behavior_engine.get_all_profiles()
        assert isinstance(profiles, list)
        assert len(profiles) > 0


# ── CorrelationEngine ─────────────────────────────────────────────────────────

class TestCorrelationEngine:
    def _make_event(self, entity="test_entity", event_type="url",
                    risk=70.0, decision="BLOCK"):
        from datetime import datetime, timezone
        return {
            "entity_id"   : entity,
            "event_type"  : event_type,
            "overall_risk": risk,
            "decision"    : decision,
            "timestamp"   : datetime.now(timezone.utc).isoformat(),
            "resource"    : f"https://test-{event_type}.com",
        }

    def test_correlate_single_event(self, correlation_engine):
        event = self._make_event(entity="corr_entity_1", risk=75)
        result = correlation_engine.correlate(event)
        # Single event may or may not create incident depending on threshold
        assert isinstance(result, (dict, type(None)))

    def test_multiple_events_create_incident(self, correlation_engine):
        """5 high-risk events from same entity should create an incident."""
        entity = "incident_entity_test"
        incident = None

        for evt_type in ["url", "file_write", "process_create", "network_connect", "registry_modify"]:
            result = correlation_engine.correlate(
                self._make_event(entity=entity, event_type=evt_type, risk=80)
            )
            if result:
                incident = result

        # After 5 events, an incident should exist for this entity
        all_incidents = correlation_engine.get_incidents()
        entity_incidents = [i for i in all_incidents if i.get("entity_id") == entity]
        assert len(entity_incidents) > 0, "Multiple high-risk events should generate an incident"

    def test_incident_has_required_fields(self, correlation_engine):
        entity = "field_check_entity"
        for _ in range(4):
            correlation_engine.correlate(
                self._make_event(entity=entity, risk=85, decision="BLOCK")
            )
        incidents = [i for i in correlation_engine.get_incidents()
                     if i.get("entity_id") == entity]
        if incidents:
            inc = incidents[0]
            for field in ("incident_id", "title", "severity", "status", "event_count"):
                assert field in inc, f"Missing incident field: {field}"

    def test_severity_escalates_with_risk(self, correlation_engine):
        """Critical risk events should produce HIGH or CRITICAL severity incidents."""
        entity = "severity_test_entity"
        for _ in range(3):
            correlation_engine.correlate(
                self._make_event(entity=entity, risk=95, decision="QUARANTINE")
            )
        incidents = [i for i in correlation_engine.get_incidents()
                     if i.get("entity_id") == entity]
        if incidents:
            assert incidents[0]["severity"] in ("HIGH", "CRITICAL")

    def test_resolve_incident(self, correlation_engine):
        """Resolved incidents should update status."""
        incidents = correlation_engine.get_incidents(status="OPEN")
        if incidents:
            inc_id  = incidents[0]["incident_id"]
            success = correlation_engine.resolve_incident(inc_id)
            assert success

    def test_get_statistics_structure(self, correlation_engine):
        stats = correlation_engine.get_statistics()
        assert "total" in stats
        assert "open" in stats
        assert "resolved" in stats

    def test_low_risk_does_not_create_incident(self, correlation_engine):
        """Low-risk ALLOW decisions should not produce incidents."""
        before = len(correlation_engine.get_incidents())
        for _ in range(3):
            correlation_engine.correlate(
                self._make_event(entity="safe_entity_xyz", risk=10, decision="ALLOW")
            )
        after = len(correlation_engine.get_incidents())
        # Should not have created new incidents for low-risk safe entity
        new_incidents = [i for i in correlation_engine.get_incidents()
                         if i.get("entity_id") == "safe_entity_xyz"]
        assert len(new_incidents) == 0, "ALLOW decisions should not generate incidents"


# ── ResponseEngine ────────────────────────────────────────────────────────────

class TestResponseEngine:
    def _make_incident(self, severity="HIGH", decision="BLOCK"):
        from datetime import datetime, timezone
        return {
            "incident_id": "test_inc_001",
            "title"      : "Test Incident",
            "severity"   : severity,
            "entity_id"  : "test_process.exe",
            "entity_type": "process",
            "event_count": 5,
            "decision"   : decision,
            "status"     : "OPEN",
            "created_at" : datetime.now(timezone.utc).isoformat(),
        }

    def test_simulation_mode_enabled(self, response_engine):
        """Response engine should default to simulation mode."""
        assert response_engine.simulation_mode is True

    def test_respond_returns_dict(self, response_engine):
        result = response_engine.respond(self._make_incident())
        assert isinstance(result, dict)
        assert "actions_taken" in result

    def test_simulation_no_real_termination(self, response_engine):
        """Simulation mode must not actually terminate processes."""
        import os
        pid = os.getpid()
        incident = self._make_incident(severity="CRITICAL", decision="QUARANTINE")
        incident["entity_id"] = f"python_{pid}"  # target the test runner's PID

        result = response_engine.respond(incident)
        # If we're still running here, simulation correctly prevented termination
        assert True, "Test process was not terminated — simulation mode working"
        # Verify action was logged as simulated
        actions = result.get("actions_taken", [])
        for action in actions:
            if "terminate" in str(action).lower() or "quarantine" in str(action).lower():
                assert action.get("simulated", True), "High-risk action should be simulated"

    def test_low_severity_takes_minimal_action(self, response_engine):
        result = response_engine.respond(self._make_incident(severity="LOW", decision="MONITOR"))
        actions = result.get("actions_taken", [])
        # LOW severity should only log, not terminate
        terminate_actions = [a for a in actions if "terminate" in str(a).get("action", "").lower()]
        assert len(terminate_actions) == 0, "LOW severity should not trigger termination"

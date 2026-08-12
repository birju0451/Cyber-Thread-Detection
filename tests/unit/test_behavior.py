"""
tests/unit/test_behavior.py
==============================
Unit tests for abtd/behavior_engine/behavior_engine.py

Tests every public method with realistic event sequences.
Includes attack chain detection scenarios.
"""

import sys
import time
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(scope="module")
def be():
    from abtd.behavior_engine.behavior_engine import BehaviorEngine
    return BehaviorEngine()


# ═══════════════════════════════════════════════════════════════
# record_event()
# ═══════════════════════════════════════════════════════════════

class TestRecordEvent:
    def test_creates_profile_on_first_event(self, be):
        be.record_event("unit_entity_1", "process_create", {"name": "calc.exe"})
        p = be.get_profile("unit_entity_1")
        assert p is not None

    def test_profile_has_entity_id(self, be):
        be.record_event("unit_entity_2", "url", {"url": "http://example.com"})
        p = be.get_profile("unit_entity_2")
        assert p["entity_id"] == "unit_entity_2"

    def test_event_count_increments(self, be):
        entity = "count_entity"
        for _ in range(5):
            be.record_event(entity, "file_write", {"path": "/tmp/x"})
        p = be.get_profile(entity)
        assert p["total_events"] >= 5

    def test_risk_delta_accumulates(self, be):
        entity = "risk_delta_entity"
        be.record_event(entity, "process_create", {}, risk_delta=15.0)
        be.record_event(entity, "file_write",     {}, risk_delta=20.0)
        p = be.get_profile(entity)
        assert p["behavior_risk"] >= 25.0

    def test_zero_risk_delta_valid(self, be):
        entity = "zero_risk_entity"
        be.record_event(entity, "url", {}, risk_delta=0.0)
        p = be.get_profile(entity)
        assert p is not None
        assert p["behavior_risk"] >= 0

    def test_event_type_tracked(self, be):
        entity = "event_type_entity"
        be.record_event(entity, "network_connect", {"port": 443})
        be.record_event(entity, "network_connect", {"port": 80})
        p = be.get_profile(entity)
        assert p["event_types"].get("network_connect", 0) >= 2

    def test_risk_capped_at_100(self, be):
        entity = "risk_cap_entity"
        for _ in range(20):
            be.record_event(entity, "process_create", {}, risk_delta=20.0)
        p = be.get_profile(entity)
        assert p["behavior_risk"] <= 100.0

    def test_multiple_event_types(self, be):
        entity = "multi_event_entity"
        types = ["url", "file_write", "process_create", "network_connect", "registry_modify"]
        for t in types:
            be.record_event(entity, t, {})
        p = be.get_profile(entity)
        assert p["total_events"] >= len(types)


# ═══════════════════════════════════════════════════════════════
# get_profile()
# ═══════════════════════════════════════════════════════════════

class TestGetProfile:
    def test_unknown_entity_returns_none(self, be):
        result = be.get_profile("__nonexistent_entity_xyz__")
        assert result is None

    def test_returns_correct_entity(self, be):
        be.record_event("profile_fetch_test", "url", {})
        p = be.get_profile("profile_fetch_test")
        assert p["entity_id"] == "profile_fetch_test"

    def test_profile_has_behavior_risk(self, be):
        be.record_event("has_risk_entity", "url", {}, risk_delta=5)
        p = be.get_profile("has_risk_entity")
        assert "behavior_risk" in p

    def test_profile_has_event_types(self, be):
        be.record_event("has_evt_entity", "file_write", {})
        p = be.get_profile("has_evt_entity")
        assert "event_types" in p

    def test_profile_has_last_seen(self, be):
        be.record_event("last_seen_entity", "url", {})
        p = be.get_profile("last_seen_entity")
        assert "last_seen" in p


# ═══════════════════════════════════════════════════════════════
# get_all_profiles()
# ═══════════════════════════════════════════════════════════════

class TestGetAllProfiles:
    def test_returns_list(self, be):
        assert isinstance(be.get_all_profiles(), list)

    def test_contains_known_entity(self, be):
        entity = "all_profiles_known"
        be.record_event(entity, "url", {})
        profiles = be.get_all_profiles()
        ids = [p["entity_id"] for p in profiles]
        assert entity in ids

    def test_all_profiles_have_entity_id(self, be):
        for p in be.get_all_profiles():
            assert "entity_id" in p


# ═══════════════════════════════════════════════════════════════
# Attack Chain Detection Scenarios
# ═══════════════════════════════════════════════════════════════

class TestAttackChains:
    def test_drive_by_download_chain(self, be):
        """
        Browser visits malicious URL → downloads file to temp → executes payload.
        This is the classic Drive-By Download chain.
        """
        entity = "drive_by_chain_unit"
        be.record_event(entity, "url",            {"url": "http://evil.xyz"},         risk_delta=20)
        be.record_event(entity, "file_write",     {"path": r"C:\Temp\payload.exe"},   risk_delta=35)
        be.record_event(entity, "process_create", {"name": "payload.exe"},             risk_delta=40)
        p = be.get_profile(entity)
        assert p["behavior_risk"] >= 60.0, \
            f"Drive-by chain should accumulate high risk, got {p['behavior_risk']}"

    def test_c2_beaconing_chain(self, be):
        """
        Process makes repeated outbound connections — C2 beaconing pattern.
        """
        entity = "c2_beacon_unit"
        for _ in range(5):
            be.record_event(entity, "network_connect", {"port": 4444, "dst": "malicious.c2.xyz"}, risk_delta=15)
        p = be.get_profile(entity)
        assert p["behavior_risk"] >= 50.0

    def test_persistence_chain(self, be):
        """
        Executable drops a registry key for startup — persistence mechanism.
        """
        entity = "persistence_chain_unit"
        be.record_event(entity, "file_write",      {"path": r"C:\Temp\updater.exe"}, risk_delta=20)
        be.record_event(entity, "registry_modify", {"key": r"HKCU\Run\updater"},     risk_delta=30)
        p = be.get_profile(entity)
        assert p["behavior_risk"] >= 40.0

    def test_credential_theft_chain(self, be):
        """
        PowerShell accesses LSASS or SAM — credential theft.
        """
        entity = "cred_theft_unit"
        be.record_event(entity, "process_create", {"name": "powershell.exe", "cmdline": "-enc abc"}, risk_delta=25)
        be.record_event(entity, "file_read",      {"path": r"C:\Windows\System32\config\SAM"},       risk_delta=40)
        p = be.get_profile(entity)
        assert p["behavior_risk"] >= 50.0

    def test_independent_entities_isolated(self, be):
        """Behavior from one entity must not bleed into another."""
        be.record_event("isolated_a", "url", {}, risk_delta=80)
        be.record_event("isolated_b", "url", {}, risk_delta=5)
        a = be.get_profile("isolated_a")
        b = be.get_profile("isolated_b")
        assert a["behavior_risk"] > b["behavior_risk"]

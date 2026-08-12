"""
abtd/behavior_engine/behavior_engine.py
========================================
Behavioral Analysis Engine.

Builds temporal behavioral profiles for entities (users, processes,
applications) and detects deviations from established baselines.

Key Concepts:
  - Behavioral Baseline: Normal sequence of activities for an entity
  - Behavioral Drift: How far current behavior deviates from baseline
  - Event Sequence: Ordered list of security events for an entity
  - Suspicious Chain: A sequence of events that together indicate threat

Detects patterns like:
  Chrome → EXE download → Execute → PowerShell → Registry modify
  (Each step increases the behavior risk score)

Public API:
    engine = BehaviorEngine()
    engine.record_event(entity_id, event)
    risk   = engine.get_behavior_risk(entity_id)
    chain  = engine.get_event_chain(entity_id)
    profile = engine.get_profile(entity_id)
"""

import sys
import time
import logging
import threading
from collections import deque, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.behavior")

# Maximum events to retain per entity
MAX_EVENTS = 200
# Time window (seconds) for behavioral chain analysis
CHAIN_WINDOW = 300   # 5 minutes

# Suspicious behavioral chains (sequence of event types)
# Each entry is (sequence_pattern, risk_addition, description)
SUSPICIOUS_SEQUENCES = [
    (
        ["url_visit", "file_download", "file_execute"],
        40,
        "Drive-by download pattern: URL → Download → Execute"
    ),
    (
        ["file_download", "file_execute", "process_create"],
        35,
        "Downloaded file executed and spawned child process"
    ),
    (
        ["process_create", "registry_modify"],
        25,
        "Process created and modified registry (potential persistence)"
    ),
    (
        ["file_execute", "network_connect"],
        20,
        "Executed file immediately established network connection"
    ),
    (
        ["url_visit", "file_download", "file_execute", "process_create", "registry_modify"],
        65,
        "Full attack chain: URL → Download → Execute → Child Process → Registry persistence"
    ),
    (
        ["process_create", "network_connect", "file_write"],
        30,
        "Process created network connection and wrote files — possible C2 staging"
    ),
    (
        ["privilege_change", "registry_modify"],
        35,
        "Privilege escalation followed by registry modification"
    ),
    (
        ["file_execute", "file_delete"],
        20,
        "File executed and then deleted — anti-forensics indicator"
    ),
]

# Event type risk weights (standalone risk per event type)
EVENT_BASE_RISK = {
    "file_execute"      : 5,
    "file_download"     : 3,
    "file_write"        : 2,
    "file_delete"       : 3,
    "registry_modify"   : 8,
    "network_connect"   : 2,
    "process_create"    : 3,
    "privilege_change"  : 10,
    "url_visit"         : 1,
    "usb_insert"        : 4,
    "scheduled_task"    : 8,
}


class BehaviorProfile:
    """Behavioral profile for a single entity."""

    def __init__(self, entity_id: str):
        self.entity_id      : str   = entity_id
        self.events         : deque = deque(maxlen=MAX_EVENTS)
        self.behavior_risk  : float = 0.0
        self.baseline_risk  : float = 0.0
        self.created_at     : float = time.time()
        self.last_event     : float = time.time()
        self.event_counts   : dict  = defaultdict(int)
        self.matched_chains : list  = []

    def to_dict(self) -> dict:
        return {
            "entity_id"    : self.entity_id,
            "behavior_risk": round(self.behavior_risk, 1),
            "baseline_risk": round(self.baseline_risk, 1),
            "event_count"  : len(self.events),
            "event_types"  : dict(self.event_counts),
            "matched_chains": self.matched_chains[-5:],
            "last_event"   : datetime.fromtimestamp(self.last_event, tz=timezone.utc).isoformat(),
            "recent_events": list(self.events)[-10:],
        }


class BehaviorEngine:
    """
    Tracks behavioral profiles for entities and detects
    suspicious sequences using temporal analysis.
    """

    def __init__(self):
        self._profiles: dict[str, BehaviorProfile] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def record_event(
        self,
        entity_id  : str,
        event_type : str,
        details    : Optional[dict] = None,
        risk_delta : float = 0.0,
    ) -> None:
        """
        Record a security event for an entity.

        Args:
            entity_id  : Identifier (process name, username, app path)
            event_type : Type from EVENT_BASE_RISK keys
            details    : Optional event metadata
            risk_delta : Manual risk adjustment for this event
        """
        event = {
            "timestamp" : datetime.now(timezone.utc).isoformat(),
            "ts_unix"   : time.time(),
            "type"      : event_type,
            "details"   : details or {},
        }

        with self._lock:
            if entity_id not in self._profiles:
                self._profiles[entity_id] = BehaviorProfile(entity_id)
            profile = self._profiles[entity_id]
            profile.events.append(event)
            profile.last_event = time.time()
            profile.event_counts[event_type] += 1

            # Update behavior risk
            base = EVENT_BASE_RISK.get(event_type, 1)
            profile.behavior_risk = min(100.0, profile.behavior_risk + base + risk_delta)

            # Check for suspicious chains
            self._check_chains(profile)

    def get_behavior_risk(self, entity_id: str) -> float:
        """Return current behavior risk score (0–100)."""
        with self._lock:
            if entity_id not in self._profiles:
                return 0.0
            return self._profiles[entity_id].behavior_risk

    def get_event_chain(self, entity_id: str, window_seconds: int = CHAIN_WINDOW) -> list:
        """Return recent events within the specified time window."""
        cutoff = time.time() - window_seconds
        with self._lock:
            if entity_id not in self._profiles:
                return []
            return [
                e for e in self._profiles[entity_id].events
                if e.get("ts_unix", 0) >= cutoff
            ]

    def get_profile(self, entity_id: str) -> dict:
        """Return full behavioral profile for an entity."""
        with self._lock:
            if entity_id not in self._profiles:
                return {"entity_id": entity_id, "behavior_risk": 0.0, "event_count": 0}
            return self._profiles[entity_id].to_dict()

    def get_all_profiles(self) -> list:
        """Return all behavioral profiles."""
        with self._lock:
            return [p.to_dict() for p in self._profiles.values()]

    def decay_risk(self, entity_id: str, decay_per_hour: float = 5.0) -> None:
        """
        Decay behavior risk score over time.
        Called periodically to allow risk to recover after quiet periods.
        """
        with self._lock:
            if entity_id not in self._profiles:
                return
            profile = self._profiles[entity_id]
            hours_idle = (time.time() - profile.last_event) / 3600.0
            decay = decay_per_hour * hours_idle
            profile.behavior_risk = max(0.0, profile.behavior_risk - decay)

    # ── Chain Detection ───────────────────────────────────────────────────────

    def _check_chains(self, profile: BehaviorProfile) -> None:
        """
        Check recent event sequence against suspicious chain patterns.
        Called after each event is recorded.
        """
        # Get recent event types in order
        cutoff = time.time() - CHAIN_WINDOW
        recent_types = [
            e["type"] for e in profile.events
            if e.get("ts_unix", 0) >= cutoff
        ]

        for pattern, risk_add, description in SUSPICIOUS_SEQUENCES:
            if self._is_subsequence(pattern, recent_types):
                # Check if we already matched this chain recently
                already_matched = any(
                    m["pattern"] == pattern for m in profile.matched_chains[-3:]
                )
                if not already_matched:
                    match_event = {
                        "timestamp"  : datetime.now(timezone.utc).isoformat(),
                        "pattern"    : pattern,
                        "description": description,
                        "risk_added" : risk_add,
                    }
                    profile.matched_chains.append(match_event)
                    profile.behavior_risk = min(100.0, profile.behavior_risk + risk_add)
                    log.warning(
                        f"Suspicious behavioral chain detected for [{profile.entity_id}]: "
                        f"{description} (+{risk_add} risk)"
                    )

    @staticmethod
    def _is_subsequence(pattern: list, sequence: list) -> bool:
        """Check if pattern appears as a subsequence in sequence."""
        pattern_idx = 0
        for item in sequence:
            if pattern_idx < len(pattern) and item == pattern[pattern_idx]:
                pattern_idx += 1
            if pattern_idx == len(pattern):
                return True
        return False


# Singleton
behavior_engine = BehaviorEngine()

"""
zero_trust/trust_manager/trust_manager.py
==========================================
Dynamic Trust State Manager.

Maintains per-entity trust scores that change over time
based on observed behavior and security events.

Zero Trust Principle: Trust is DYNAMIC.
  - A previously trusted process can become suspicious.
  - A previously trusted user can behave abnormally.
  - Trust scores decay toward neutral over time without activity.

Entities tracked:
  - user       (Windows username)
  - device     (hostname)
  - process    (pid or exe name)
  - app        (executable path)
  - connection (remote IP:port)

Public API:
    mgr = TrustManager()
    mgr.update_trust("process", "powershell.exe", -30, "Suspicious cmdline")
    score = mgr.get_trust("process", "powershell.exe")
    history = mgr.get_trust_history("process", "powershell.exe")
    snapshot = mgr.get_all_trust_scores()
"""

import sys
import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.trust_manager")

# Default starting trust for each entity type
DEFAULT_TRUST = {
    "user"      : 75,   # Users start with moderate-high trust
    "device"    : 70,   # Device trust is set by DeviceAssessor
    "process"   : 60,   # Processes start with moderate trust
    "app"       : 65,   # Applications start with moderate trust
    "connection": 50,   # Network connections start neutral
}

# Maximum history entries per entity
MAX_HISTORY = 100

# Trust decay per hour (trust drifts back toward default when no events occur)
TRUST_DECAY_PER_HOUR = 2.0
TRUST_RECOVERY_PER_HOUR = 1.5


class TrustEntry:
    """Trust record for a single entity."""

    def __init__(self, entity_type: str, entity_id: str):
        self.entity_type    : str   = entity_type
        self.entity_id      : str   = entity_id
        self.current_trust  : float = float(DEFAULT_TRUST.get(entity_type, 60))
        self.baseline_trust : float = float(DEFAULT_TRUST.get(entity_type, 60))
        self.created_at     : float = time.time()
        self.last_updated   : float = time.time()
        self.history        : deque = deque(maxlen=MAX_HISTORY)
        self.incident_count : int   = 0

    @property
    def trust_score(self) -> int:
        return max(0, min(100, int(self.current_trust)))

    def to_dict(self) -> dict:
        return {
            "entity_type"   : self.entity_type,
            "entity_id"     : self.entity_id,
            "trust_score"   : self.trust_score,
            "baseline_trust": int(self.baseline_trust),
            "incident_count": self.incident_count,
            "created_at"    : datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat(),
            "last_updated"  : datetime.fromtimestamp(self.last_updated, tz=timezone.utc).isoformat(),
            "trust_level"   : _trust_level(self.trust_score),
            "history"       : list(self.history)[-20:],  # last 20 events
        }


def _trust_level(score: int) -> str:
    if score >= 90: return "TRUSTED"
    if score >= 70: return "LOW_RISK"
    if score >= 50: return "MODERATE_RISK"
    if score >= 30: return "HIGH_RISK"
    return "UNTRUSTED"


class TrustManager:
    """
    Centralized trust state manager for all Zero Trust entities.
    Thread-safe. Supports trust updates, decay, recovery, and history.
    """

    def __init__(self):
        self._entities: dict[str, TrustEntry] = {}   # key: "type:id"
        self._lock     = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_trust(self, entity_type: str, entity_id: str) -> int:
        """Return current trust score for an entity (0–100)."""
        self._apply_decay(entity_type, entity_id)
        entry = self._get_or_create(entity_type, entity_id)
        return entry.trust_score

    def update_trust(
        self,
        entity_type : str,
        entity_id   : str,
        delta       : float = 0.0,
        reason      : str = "Trust update",
        source      : str = "system",
        risk_score  : Optional[float] = None,
        trust_score : Optional[float] = None,
    ) -> dict:
        """
        Adjust trust score for an entity.
        Supports delta adjustments or explicit risk_score / trust_score.
        """
        with self._lock:
            entry = self._get_or_create(entity_type, entity_id)
            old_trust = entry.current_trust

            if risk_score is not None:
                new_val = max(0.0, min(100.0, 100.0 - float(risk_score)))
                delta = new_val - old_trust
                entry.current_trust = new_val
            elif trust_score is not None:
                new_val = max(0.0, min(100.0, float(trust_score)))
                delta = new_val - old_trust
                entry.current_trust = new_val
            else:
                entry.current_trust = max(0.0, min(100.0, entry.current_trust + delta))

            entry.last_updated  = time.time()

            if delta < 0:
                entry.incident_count += 1

            event = {
                "timestamp"  : datetime.now(timezone.utc).isoformat(),
                "old_trust"  : int(old_trust),
                "new_trust"  : entry.trust_score,
                "delta"      : delta,
                "reason"     : reason,
                "source"     : source,
            }
            entry.history.append(event)

            log.info(
                f"Trust update [{entity_type}:{entity_id}] "
                f"{int(old_trust)} → {entry.trust_score} ({delta:+.0f}) — {reason}"
            )
            return entry.to_dict()

    def set_trust(
        self,
        entity_type: str,
        entity_id  : str,
        trust_score: int,
        reason     : str = "explicit set",
    ) -> dict:
        """Set trust score directly (overrides calculation)."""
        with self._lock:
            entry = self._get_or_create(entity_type, entity_id)
            old   = entry.current_trust
            entry.current_trust = max(0.0, min(100.0, float(trust_score)))
            entry.last_updated  = time.time()
            entry.history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "old_trust": int(old),
                "new_trust": entry.trust_score,
                "delta"    : trust_score - old,
                "reason"   : reason,
                "source"   : "explicit",
            })
            return entry.to_dict()

    def get_trust_state(self, entity_type: str, entity_id: str) -> dict:
        """Return full trust state dict for an entity."""
        self._apply_decay(entity_type, entity_id)
        with self._lock:
            return self._get_or_create(entity_type, entity_id).to_dict()

    def get_all_trust_scores(self) -> dict:
        """Return trust scores for all tracked entities, grouped by type."""
        result = defaultdict(list)
        with self._lock:
            for entry in self._entities.values():
                result[entry.entity_type].append(entry.to_dict())
        return dict(result)

    def get_trust_history(self, entity_type: str, entity_id: str) -> list:
        """Return full trust history for an entity."""
        with self._lock:
            entry = self._entities.get(f"{entity_type}:{entity_id}")
            if entry:
                return list(entry.history)
        return []

    def reset_trust(self, entity_type: str, entity_id: str) -> None:
        """Reset entity trust to baseline."""
        with self._lock:
            key = f"{entity_type}:{entity_id}"
            if key in self._entities:
                entry = self._entities[key]
                entry.current_trust  = entry.baseline_trust
                entry.incident_count = 0
                entry.history.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason"   : "Trust reset to baseline",
                    "source"   : "admin",
                })

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_or_create(self, entity_type: str, entity_id: str) -> TrustEntry:
        """Get existing entry or create a new one."""
        key = f"{entity_type}:{entity_id}"
        if key not in self._entities:
            self._entities[key] = TrustEntry(entity_type, entity_id)
        return self._entities[key]

    def _apply_decay(self, entity_type: str, entity_id: str) -> None:
        """
        Apply time-based trust decay/recovery.

        If trust < baseline → slow recovery toward baseline.
        If trust > baseline → no decay (trust gains are sticky).
        """
        key = f"{entity_type}:{entity_id}"
        with self._lock:
            if key not in self._entities:
                return
            entry = self._entities[key]
            hours_elapsed = (time.time() - entry.last_updated) / 3600.0

            if entry.current_trust < entry.baseline_trust:
                # Recover toward baseline
                recovery = TRUST_RECOVERY_PER_HOUR * hours_elapsed
                entry.current_trust = min(
                    entry.baseline_trust,
                    entry.current_trust + recovery
                )
                if recovery > 0.5:
                    entry.last_updated = time.time()


# Singleton
trust_manager = TrustManager()

"""
abtd/correlation_engine/correlation_engine.py
==============================================
Threat Correlation Engine.

Prevents alert fatigue by grouping related security events into
coherent incidents rather than treating each event independently.

Correlation Logic:
  - Events from the same entity within a time window are grouped
  - Related event types are merged into a single incident
  - Incident severity escalates as more related events occur
  - Each incident has a unique ID and audit trail

Example:
  Event 1: Suspicious URL visited (medium risk)
  Event 2: Executable downloaded (medium risk)
  Event 3: Executable executed (high risk)
  Event 4: PowerShell launched with encoded command (critical)
  Event 5: Registry startup key modified (critical)
  ──────────────────────────────────────────────────────────────
  ONE INCIDENT: "Drive-by download → persistence attempt" (CRITICAL)

Public API:
    engine = CorrelationEngine()
    engine.submit_event(event)
    incidents = engine.get_incidents()
    incident  = engine.get_incident(incident_id)
"""

import sys
import uuid
import time
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.correlation")

# Time window for correlating events (seconds)
CORRELATION_WINDOW = 300   # 5 minutes

# Maximum incidents to keep in memory
MAX_INCIDENTS = 200

# Severity escalation rules
# When incident has N+ HIGH events → escalate to CRITICAL
ESCALATION_RULES = {
    3: "CRITICAL",   # 3+ high-severity events in window → CRITICAL
    2: "HIGH",       # 2+ medium events → HIGH
    1: "MEDIUM",     # 1 event → initial severity
}

# Event types that should always start a new incident (high-confidence attacks)
INCIDENT_STARTERS = {
    "registry_persist", "privilege_escalation", "known_malware",
    "blocked_process", "credential_access", "lateral_movement",
}

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH"    : 3,
    "MEDIUM"  : 2,
    "LOW"     : 1,
    "INFO"    : 0,
}


class Incident:
    """A correlated security incident comprised of multiple related events."""

    def __init__(self, incident_id: str, first_event: dict):
        self.incident_id    : str   = incident_id
        self.title          : str   = self._generate_title(first_event)
        self.severity       : str   = first_event.get("severity", "LOW")
        self.entity_id      : str   = first_event.get("entity_id", "unknown")
        self.event_types    : list  = [first_event.get("event_type", "unknown")]
        self.events         : list  = [first_event]
        self.risk_score     : float = float(first_event.get("risk_score", 0))
        self.created_at     : float = time.time()
        self.last_event_at  : float = time.time()
        self.status         : str   = "OPEN"
        self.mitre_tactics  : list  = []
        self.resolved_at    : Optional[float] = None

    def add_event(self, event: dict) -> None:
        """Add a related event to this incident."""
        self.events.append(event)
        self.event_types.append(event.get("event_type", "unknown"))
        self.last_event_at = time.time()

        # Escalate risk score
        new_risk = float(event.get("risk_score", 0))
        # Take max, then add a correlation bonus
        self.risk_score = min(100.0, max(self.risk_score, new_risk) + 5.0)

        # Escalate severity
        event_sev = event.get("severity", "LOW")
        if SEVERITY_WEIGHTS.get(event_sev, 0) > SEVERITY_WEIGHTS.get(self.severity, 0):
            self.severity = event_sev

        # Update title
        self.title = self._generate_title_from_chain()

        # Update MITRE mapping
        tactics = event.get("mitre_tactics", [])
        for tactic in tactics:
            if tactic not in self.mitre_tactics:
                self.mitre_tactics.append(tactic)

    def to_dict(self) -> dict:
        return {
            "incident_id"   : self.incident_id,
            "title"         : self.title,
            "severity"      : self.severity,
            "entity_id"     : self.entity_id,
            "event_count"   : len(self.events),
            "event_types"   : list(set(self.event_types)),
            "risk_score"    : round(self.risk_score, 1),
            "status"        : self.status,
            "mitre_tactics" : self.mitre_tactics,
            "created_at"    : datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat(),
            "last_event_at" : datetime.fromtimestamp(self.last_event_at, tz=timezone.utc).isoformat(),
            "resolved_at"   : (
                datetime.fromtimestamp(self.resolved_at, tz=timezone.utc).isoformat()
                if self.resolved_at else None
            ),
            "events"        : self.events[-20:],   # last 20 events
        }

    def _generate_title(self, event: dict) -> str:
        etype  = event.get("event_type", "unknown")
        entity = event.get("entity_id", "unknown")
        return f"{etype.replace('_',' ').title()} detected for {entity}"

    def _generate_title_from_chain(self) -> str:
        unique_types = list(dict.fromkeys(self.event_types))  # preserve order, dedupe
        if len(unique_types) >= 3:
            return (
                f"Multi-stage attack chain: "
                f"{' → '.join(t.replace('_',' ') for t in unique_types[:4])}"
            )
        return self._generate_title(self.events[0])


class CorrelationEngine:
    """
    Correlates security events into coherent incidents.
    Reduces alert fatigue and surfaces attack chains.
    """

    def __init__(self):
        self._incidents    : dict[str, Incident] = {}   # id → incident
        self._entity_map   : dict[str, list]     = defaultdict(list)  # entity → [incident_ids]
        self._all_incidents: list                 = []   # ordered list
        self._lock         = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def submit_event(self, event: dict) -> dict:
        """
        Submit a security event for correlation.

        Args:
            event: {
                "event_type"    : str,
                "entity_id"     : str  (process name, username, IP, etc.),
                "severity"      : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
                "risk_score"    : float 0–100,
                "description"   : str,
                "source"        : str  (agent module name),
                "details"       : dict,
                "mitre_tactics" : list[str] (optional),
            }

        Returns: {"incident_id": str, "is_new": bool, "incident": dict}
        """
        with self._lock:
            entity_id = event.get("entity_id", "global")
            incident  = self._find_open_incident(entity_id)

            if incident is None or event.get("event_type") in INCIDENT_STARTERS:
                # Create new incident
                incident_id = str(uuid.uuid4())[:12].upper()
                incident    = Incident(incident_id, event)
                self._incidents[incident_id] = incident
                self._entity_map[entity_id].append(incident_id)
                self._all_incidents.append(incident)
                is_new = True
                log.info(f"New incident created: {incident_id} — {incident.title}")
            else:
                # Correlate into existing incident
                incident.add_event(event)
                is_new = False
                log.info(
                    f"Event correlated into incident {incident.incident_id} "
                    f"({len(incident.events)} events)"
                )

            # Trim old incidents
            if len(self._all_incidents) > MAX_INCIDENTS:
                oldest = self._all_incidents[0]
                del self._incidents[oldest.incident_id]
                self._all_incidents.pop(0)

            return {
                "incident_id": incident.incident_id,
                "is_new"     : is_new,
                "incident"   : incident.to_dict(),
            }

    def get_incidents(
        self,
        status   : Optional[str] = None,
        severity : Optional[str] = None,
        limit    : int = 50,
    ) -> list:
        """Return incidents, optionally filtered by status/severity."""
        with self._lock:
            results = list(reversed(self._all_incidents))
            if status:
                results = [i for i in results if i.status == status.upper()]
            if severity:
                results = [i for i in results if i.severity == severity.upper()]
            return [i.to_dict() for i in results[:limit]]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Return a single incident by ID."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            return incident.to_dict() if incident else None

    def resolve_incident(self, incident_id: str) -> bool:
        """Mark an incident as resolved."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident:
                incident.status     = "RESOLVED"
                incident.resolved_at = time.time()
                log.info(f"Incident {incident_id} resolved")
                return True
        return False

    def get_statistics(self) -> dict:
        """Return summary statistics about incidents."""
        with self._lock:
            all_incidents = self._all_incidents
            open_count    = sum(1 for i in all_incidents if i.status == "OPEN")
            sev_counts    = defaultdict(int)
            for i in all_incidents:
                sev_counts[i.severity] += 1
            return {
                "total"    : len(all_incidents),
                "open"     : open_count,
                "resolved" : len(all_incidents) - open_count,
                "by_severity": dict(sev_counts),
            }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _find_open_incident(self, entity_id: str) -> Optional[Incident]:
        """
        Find an open incident for this entity within the correlation window.
        Returns None if no recent incident exists.
        """
        incident_ids = self._entity_map.get(entity_id, [])
        cutoff       = time.time() - CORRELATION_WINDOW

        for incident_id in reversed(incident_ids):
            incident = self._incidents.get(incident_id)
            if incident and incident.status == "OPEN":
                if incident.last_event_at >= cutoff:
                    return incident

        return None


# Singleton
correlation_engine = CorrelationEngine()

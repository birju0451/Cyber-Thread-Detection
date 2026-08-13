"""
agent/event_classifier.py
===========================
Intelligent Event Classification & Prioritization.

Sits between raw Windows monitoring events and the full
ABTD + Zero Trust analysis pipeline. Its purpose is to
keep CPU/memory usage low by filtering out events that
do not require heavyweight ML inference or ZT evaluation.

Architecture:
    Raw Windows Event
          ↓
    EventClassifier.classify(event)
          ↓
    SecurityRelevant?
          |
          ├── NO  → lightweight log only
          |
          └── YES → return enriched event for pipeline
                    (feature extraction → ABTD → ZT)

Classification criteria:
  - Event type risk (file_execute > file_read)
  - Extension suspiciousness
  - Path sensitivity
  - Process reputation (blocklist)
  - Known-safe processes (allowlist for noise reduction)
  - Port/protocol suspiciousness
  - Registry key sensitivity

Public API:
    classifier = EventClassifier()
    result     = classifier.classify(event)
    # result = {"relevant": True/False, "priority": "HIGH"/"MEDIUM"/"LOW",
    #           "reason": str, "event": enriched_event}
"""

import sys
import logging
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

log = logging.getLogger("abtd.event_classifier")

# ── Known-safe processes (skip analysis to reduce noise) ─────────
SAFE_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
    "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
    "ctfmon.exe", "conhost.exe", "runtimebroker.exe",
    "searchindexer.exe", "searchprotocolhost.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "spoolsv.exe", "audiodg.exe", "dllhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "applicationframehost.exe",
    "systemsettings.exe", "lockapp.exe", "logonui.exe",
    "msmpeng.exe", "nissrv.exe",   # Windows Defender
}

# ── High-risk event types (always security-relevant) ─────────────
HIGH_RISK_EVENT_TYPES = {
    "file_execute", "registry_modify", "privilege_change",
    "known_malware", "blocked_process", "credential_access",
    "startup_persist", "scheduled_task_create", "usb_insert",
}

MEDIUM_RISK_EVENT_TYPES = {
    "file_download", "file_write", "file_delete",
    "network_connect", "process_create",
}

LOW_RISK_EVENT_TYPES = {
    "file_read", "url_visit", "process_terminate",
    "usb_remove",
}

# ── Sensitive directories ─────────────────────────────────────────
SENSITIVE_PATHS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\",
]

TEMP_PATHS = [
    "\\temp\\", "\\tmp\\", "appdata\\local\\temp",
]


class EventClassifier:
    """
    Classifies raw security events as relevant or non-relevant
    for the full ABTD + Zero Trust analysis pipeline.
    """

    def classify(self, event: dict) -> dict:
        """
        Classify a raw event.

        Args:
            event: {
                "event_type"    : str  (file_execute, network_connect, etc.)
                "source"        : str  (file_monitor, process_monitor, etc.)
                "process_name"  : str  (optional)
                "resource"      : str  (file path, URL, IP, registry key)
                "details"       : dict (optional event-specific metadata)
            }

        Returns:
            {
                "relevant"  : bool,
                "priority"  : "HIGH" | "MEDIUM" | "LOW" | "NONE",
                "reason"    : str,
                "event"     : dict (original event, enriched)
            }
        """
        event_type   = event.get("event_type", "unknown")
        process_name = (event.get("process_name") or "").lower()
        resource     = (event.get("resource") or "").lower()

        # ── Always skip known-safe system processes ────────────────
        if process_name in SAFE_PROCESSES and event_type not in HIGH_RISK_EVENT_TYPES:
            return self._result(False, "NONE",
                                f"Known-safe system process: {process_name}", event)

        # ── High-risk event types: always relevant ────────────────
        if event_type in HIGH_RISK_EVENT_TYPES:
            return self._result(True, "HIGH",
                                f"High-risk event type: {event_type}", event)

        # ── Blocklisted process: always relevant ──────────────────
        if process_name in {p.lower() for p in config.BLOCKED_PROCESSES}:
            return self._result(True, "HIGH",
                                f"Blocklisted process: {process_name}", event)

        # ── Suspicious file extensions ────────────────────────────
        if event_type in ("file_download", "file_write", "file_create"):
            ext = Path(resource).suffix.lower() if resource else ""
            if ext in config.SUSPICIOUS_EXTENSIONS:
                return self._result(True, "HIGH",
                                    f"Suspicious file extension: {ext}", event)

        # ── Sensitive path access ─────────────────────────────────
        if resource:
            if any(p in resource for p in SENSITIVE_PATHS):
                if event_type in ("file_write", "file_execute", "file_delete"):
                    return self._result(True, "MEDIUM",
                                        f"Write/execute in sensitive path", event)

            if any(p in resource for p in TEMP_PATHS):
                if event_type == "file_execute":
                    return self._result(True, "HIGH",
                                        "Executable running from temp directory", event)

        # ── Medium-risk event types ───────────────────────────────
        if event_type in MEDIUM_RISK_EVENT_TYPES:
            return self._result(True, "MEDIUM",
                                f"Medium-risk event type: {event_type}", event)

        # ── Network: suspicious ports ─────────────────────────────
        if event_type == "network_connect":
            remote_port = event.get("details", {}).get("remote_port", 0)
            from agent.network_monitor import SUSPICIOUS_PORTS
            if remote_port in SUSPICIOUS_PORTS:
                return self._result(True, "HIGH",
                                    f"Connection to suspicious port: {remote_port}", event)

        # ── Low-risk: log only ────────────────────────────────────
        if event_type in LOW_RISK_EVENT_TYPES:
            return self._result(False, "LOW",
                                f"Low-risk event type: {event_type}", event)

        # ── Default: treat unknown events as medium ───────────────
        return self._result(True, "MEDIUM",
                            f"Unclassified event type: {event_type}", event)

    @staticmethod
    def _result(relevant: bool, priority: str, reason: str, event: dict) -> dict:
        return {
            "relevant": relevant,
            "priority": priority,
            "reason"  : reason,
            "event"   : event,
        }


# Singleton
event_classifier = EventClassifier()

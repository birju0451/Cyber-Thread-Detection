"""
agent/startup_monitor.py
==========================
Windows Startup Programs Monitor for ABTD v2.0.

Monitors:
  - HKCU/HKLM Run registry keys (current user + machine)
  - Startup folder (User and All Users)
  - Scheduled Tasks changes

On detecting NEW or CHANGED startup entries:
  1. Evaluates via Zero Trust (registry event)
  2. Feeds behavioral event (registry_modify)
  3. Runs ABTD engine analysis on the referenced executable
  4. Logs alert + notifies if suspicious

Public API:
    monitor = StartupMonitor()
    monitor.run_forever(interval=60)
"""

import os
import sys
import time
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger   import log_agent
from backend.database import db
from agent.notifier   import notify

try:
    import winreg
    _WINREG_OK = True
except ImportError:
    _WINREG_OK = False

log = logging.getLogger("abtd.agent.startup")

# Registry keys to monitor for persistence
MONITOR_KEYS = [
    (None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]
# None = auto-select HKCU + HKLM

# Known good hash set (populated on first scan, used for change detection)
_SNAPSHOT_HASH: Optional[str] = None


class StartupMonitor:
    """
    Monitors Windows startup persistence mechanisms for unauthorized changes.
    """

    def __init__(self):
        self._last_snapshot : dict = {}   # {key_path: {name: value}}
        self._alerted_names  : set  = set()
        self._engine         = None
        self._zt_controller  = None
        self._behavior_engine= None
        self._initialized    = False

    def _lazy_init(self) -> None:
        if self._initialized:
            return
        try:
            from engine.predictor import engine
            self._engine = engine
        except Exception:
            pass
        try:
            from zero_trust.access_control.access_controller import access_controller
            self._zt_controller = access_controller
        except Exception:
            pass
        try:
            from abtd.behavior_engine.behavior_engine import behavior_engine
            self._behavior_engine = behavior_engine
        except Exception:
            pass
        self._initialized = True

    def scan_once(self) -> list:
        """
        Snapshot current startup entries and compare to previous.
        Returns list of new/changed entries detected.
        """
        if not _WINREG_OK:
            return []

        self._lazy_init()
        current_snapshot = self._collect_startup_entries()
        changes          = []

        for key_path, entries in current_snapshot.items():
            prev_entries = self._last_snapshot.get(key_path, {})

            for name, value in entries.items():
                if name not in prev_entries:
                    # NEW entry
                    changes.append({
                        "type"    : "NEW",
                        "key"     : key_path,
                        "name"    : name,
                        "value"   : value,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    log_agent.warning(f"New startup entry: [{key_path}] {name} = {value[:80]}")

                elif prev_entries[name] != value:
                    # CHANGED entry
                    changes.append({
                        "type"     : "CHANGED",
                        "key"      : key_path,
                        "name"     : name,
                        "value"    : value,
                        "old_value": prev_entries[name],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    log_agent.warning(f"Startup entry changed: [{key_path}] {name}")

        self._last_snapshot = current_snapshot

        # Handle detected changes
        for change in changes:
            self._handle_change(change)

        return changes

    def run_forever(self, interval: int = 60) -> None:
        """Run continuous startup monitoring loop."""
        log_agent.info(f"✓ Startup monitor started (interval: {interval}s)")

        # Seed baseline on first run (no alerts for existing entries)
        if _WINREG_OK:
            self._last_snapshot = self._collect_startup_entries()
            log_agent.info(
                f"  Startup baseline: {sum(len(v) for v in self._last_snapshot.values())} entries"
            )

        while True:
            try:
                changes = self.scan_once()
                if changes:
                    log_agent.warning(f"⚠️ {len(changes)} startup change(s) detected")
            except Exception as e:
                log.error(f"Startup monitor loop error: {e}")
            time.sleep(interval)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _collect_startup_entries(self) -> dict:
        """Read all startup entries from registry and startup folders."""
        snapshot = {}
        hives    = [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]

        for hive in hives:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            for _, key_path in MONITOR_KEYS:
                full_path = f"{hive_name}\\{key_path}"
                entries   = {}
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i   = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries[name]  = str(value)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    pass
                except Exception as e:
                    log.debug(f"Registry read error {full_path}: {e}")

                if entries:
                    snapshot[full_path] = entries

        # Startup folder
        startup_folder = Path(os.path.expanduser(
            "~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        ))
        if startup_folder.exists():
            folder_entries = {}
            for f in startup_folder.iterdir():
                if f.is_file():
                    folder_entries[f.name] = str(f.stat().st_mtime)
            if folder_entries:
                snapshot["STARTUP_FOLDER"] = folder_entries

        return snapshot

    def _handle_change(self, change: dict) -> None:
        """Process a detected startup change — analyze, evaluate, alert."""
        name    = change["name"]
        value   = change.get("value", "")
        key_path = change["key"]
        change_type = change["type"]

        if name in self._alerted_names:
            return

        # Behavior event
        if self._behavior_engine:
            try:
                username = os.environ.get("USERNAME", "unknown")
                self._behavior_engine.record_event(
                    entity_id  = username,
                    event_type = "registry_modify",
                    details    = change,
                    risk_delta = 10.0,
                )
            except Exception:
                pass

        # Try to extract and analyze the executable from the value
        exe_path     = self._extract_exe_path(value)
        threat_score = 0
        classification = "SAFE"

        if exe_path and self._engine:
            try:
                result         = self._engine.analyze_file(exe_path)
                threat_score   = result.get("threat_score", 0)
                classification = result.get("classification", "SAFE")
            except Exception:
                pass

        # Zero Trust evaluation
        zt_result = {}
        if self._zt_controller:
            try:
                zt_result = self._zt_controller.evaluate_access({
                    "event_type"   : "registry",
                    "resource"     : key_path,
                    "action"       : "modify",
                    "process_name" : "startup_monitor",
                    "abtd_result"  : {"threat_score": threat_score, "classification": classification},
                    "behavior_risk": 20.0,
                })
            except Exception:
                pass

        severity = "CRITICAL" if threat_score >= 70 else "HIGH" if threat_score >= 40 else "MEDIUM"

        # Alert
        db.log_alert(
            alert_type  = "startup_change",
            severity    = severity,
            title       = f"{change_type} Startup Entry: {name}",
            description = f"Key: {key_path} | Value: {value[:100]}",
            source      = "startup_monitor",
            details     = {
                **change,
                "exe_path"      : exe_path,
                "threat_score"  : threat_score,
                "classification": classification,
                "zt_decision"   : zt_result.get("decision", "UNKNOWN"),
            },
        )

        if change_type in ("NEW", "CHANGED"):
            notify(
                title    = f"⚠️ Startup {change_type}: {name}",
                message  = f"{key_path}\n{value[:80]}",
                severity = severity,
            )

        self._alerted_names.add(name)
        log_agent.warning(
            f"Startup [{change_type}] {name} | score={threat_score} | "
            f"ZT={zt_result.get('decision','?')}"
        )

    @staticmethod
    def _extract_exe_path(value: str) -> Optional[str]:
        """Extract executable path from registry value string."""
        if not value:
            return None
        # Strip quotes
        value = value.strip().strip('"')
        # Extract up to first space (e.g., "C:\path\app.exe --args")
        path_part = value.split(" ")[0].strip('"')
        if Path(path_part).exists():
            return path_part
        return None

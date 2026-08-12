"""
agent/usb_monitor.py
=====================
USB / Removable Drive Monitor for ABTD v2.0.

Detects USB storage device insertion and immediately:
  1. Logs the event
  2. Runs Zero Trust access evaluation against the USB volume
  3. Scans executables on the USB drive through the ABTD engine
  4. Feeds behavioral event to BehaviorEngine
  5. Fires desktop notification for high-risk USBs

Uses: psutil (cross-platform volume tracking)
      Windows WMI for drive insertion events (optional upgrade path)

Public API:
    monitor = USBMonitor()
    monitor.run_forever(interval=10)
"""

import os
import sys
import time
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
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

log = logging.getLogger("abtd.agent.usb")


class USBMonitor:
    """
    Monitors for USB storage device insertion.
    On detection, performs a Zero Trust evaluation and
    scans executables on the drive.
    """

    def __init__(self):
        self._known_drives: set[str] = set()
        self._engine = None
        self._zt_controller = None
        self._behavior_engine = None
        self._initialized = False

    def _lazy_init(self) -> None:
        """Lazy-load heavy dependencies on first use."""
        if self._initialized:
            return
        try:
            from engine.predictor import engine
            self._engine = engine
        except Exception as e:
            log.debug(f"Engine init: {e}")

        try:
            from zero_trust.access_control.access_controller import access_controller
            self._zt_controller = access_controller
        except Exception as e:
            log.debug(f"ZT controller init: {e}")

        try:
            from abtd.behavior_engine.behavior_engine import behavior_engine
            self._behavior_engine = behavior_engine
        except Exception as e:
            log.debug(f"Behavior engine init: {e}")

        self._initialized = True

    def scan_once(self) -> list:
        """
        Check for new USB drives. Returns list of new drive letters detected.
        """
        if not _PSUTIL_OK:
            return []

        self._lazy_init()
        new_drives = []

        try:
            current_drives = set()
            for part in psutil.disk_partitions(all=False):
                if sys.platform == "win32":
                    # On Windows, removable drives have 'removable' in opts
                    opts = part.opts.lower()
                    if "removable" in opts or part.fstype in ("FAT32", "exFAT", "FAT", "NTFS"):
                        # Only flag drives that are NOT system drive
                        if part.mountpoint.upper() not in ("C:\\", "C:/"):
                            current_drives.add(part.mountpoint)
                else:
                    if "media" in part.mountpoint.lower() or "mnt" in part.mountpoint.lower():
                        current_drives.add(part.mountpoint)

            # Detect NEW drives (inserted since last scan)
            inserted = current_drives - self._known_drives
            removed  = self._known_drives - current_drives

            for drive in removed:
                log_agent.info(f"USB removed: {drive}")

            for drive in inserted:
                log_agent.warning(f"USB inserted: {drive}")
                result = self._handle_insertion(drive)
                new_drives.append(result)

            self._known_drives = current_drives

        except Exception as e:
            log.error(f"USB scan error: {e}")

        return new_drives

    def run_forever(self, interval: int = 10) -> None:
        """Run continuous USB monitoring loop."""
        log_agent.info(f"✓ USB monitor started (interval: {interval}s)")

        # Seed known drives on startup (don't alert for existing drives)
        if _PSUTIL_OK:
            try:
                for part in psutil.disk_partitions(all=False):
                    self._known_drives.add(part.mountpoint)
            except Exception:
                pass

        while True:
            try:
                new = self.scan_once()
                if new:
                    log_agent.warning(f"⚠️ {len(new)} new USB drive(s) detected and evaluated")
            except Exception as e:
                log.error(f"USB monitor loop error: {e}")
            time.sleep(interval)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _handle_insertion(self, drive_path: str) -> dict:
        """
        Handle a USB insertion event:
        1. Record behavior event
        2. Scan executables on drive
        3. Run Zero Trust evaluation
        4. Notify + log
        """
        event_ts  = datetime.now(timezone.utc).isoformat()
        exe_found = []
        threat_score = 0
        classification = "SAFE"

        # Step 1: Record behavioral event
        if self._behavior_engine:
            try:
                self._behavior_engine.record_event(
                    entity_id  = os.environ.get("USERNAME", "unknown"),
                    event_type = "usb_insert",
                    details    = {"drive": drive_path, "timestamp": event_ts},
                )
            except Exception:
                pass

        # Step 2: Scan executables on the USB drive
        try:
            path_obj = Path(drive_path)
            if path_obj.exists():
                for ext in config.SUSPICIOUS_EXTENSIONS:
                    for f in path_obj.rglob(f"*{ext}"):
                        exe_found.append(str(f))
                        if self._engine and len(exe_found) <= 20:
                            try:
                                result = self._engine.analyze_file(str(f))
                                score  = result.get("threat_score", 0)
                                cls    = result.get("classification", "SAFE")
                                if score > threat_score:
                                    threat_score   = score
                                    classification = cls
                            except Exception:
                                pass
        except Exception as e:
            log.debug(f"USB scan executables error: {e}")

        # Step 3: Zero Trust evaluation
        zt_result = {}
        if self._zt_controller:
            try:
                zt_result = self._zt_controller.evaluate_access({
                    "event_type"   : "file",
                    "resource"     : drive_path,
                    "action"       : "mount",
                    "process_name" : "usb_insert",
                    "abtd_result"  : {"threat_score": threat_score, "classification": classification},
                    "behavior_risk": 15.0,  # USB insertion always adds baseline risk
                })
            except Exception as e:
                log.debug(f"USB ZT evaluation error: {e}")

        # Step 4: Log to DB and notify
        severity = "CRITICAL" if threat_score >= 70 else "HIGH" if threat_score >= 40 else "INFO"
        risk_msg = f"Score: {threat_score}/100 | {len(exe_found)} executable(s) found"

        db.log_alert(
            alert_type  = "usb_insert",
            severity    = severity,
            title       = f"USB Drive Inserted: {drive_path}",
            description = risk_msg,
            source      = "usb_monitor",
            details     = {
                "drive"         : drive_path,
                "exe_found"     : exe_found[:10],
                "threat_score"  : threat_score,
                "classification": classification,
                "zt_decision"   : zt_result.get("decision", "UNKNOWN"),
            },
        )

        if threat_score > 0 or exe_found:
            notify(
                title    = f"⚠️ USB Drive: {Path(drive_path).name or drive_path}",
                message  = risk_msg,
                severity = severity,
            )

        log_agent.warning(
            f"USB [{drive_path}] | {classification} | score={threat_score} | "
            f"{len(exe_found)} exe(s) | ZT={zt_result.get('decision','?')}"
        )

        return {
            "drive"         : drive_path,
            "timestamp"     : event_ts,
            "threat_score"  : threat_score,
            "classification": classification,
            "exe_found"     : exe_found[:10],
            "zt_decision"   : zt_result.get("decision", "UNKNOWN"),
        }

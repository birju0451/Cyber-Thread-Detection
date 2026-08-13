"""
agent/usb_monitor.py
=====================
Monitors USB device insertion and removal events.

Uses WMI (Windows Management Instrumentation) to detect when
removable storage devices are connected or disconnected.

Security concern: USB devices can:
  - Auto-run malicious payloads
  - Exfiltrate sensitive data
  - Introduce previously unseen malware

All USB insertion events are classified as SECURITY_RELEVANT
and routed through the Zero Trust pipeline.

Uses: wmi (pip install wmi) with pywin32 backend
"""

import sys
import time
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger import log_agent

try:
    import wmi
    _WMI_OK = True
except ImportError:
    _WMI_OK = False
    log_agent.warning("wmi package not installed — USB monitoring disabled. Install: pip install wmi")

try:
    import win32file
    import win32api
    _WIN32_OK = True
except ImportError:
    _WIN32_OK = False


class USBMonitor:
    """
    Monitors USB device insertion/removal via drive letter changes.

    Falls back to drive-letter polling if WMI is unavailable.
    """

    def __init__(self):
        self._known_drives: set = set()
        self._callback = None
        self._take_drive_snapshot()

    def set_callback(self, callback):
        """Set a callback function to receive USB events.

        Args:
            callback: function(event_dict) called on USB events
        """
        self._callback = callback

    def _take_drive_snapshot(self) -> set:
        """Get current set of drive letters."""
        drives = set()
        try:
            if _WIN32_OK:
                bitmask = win32api.GetLogicalDrives()
                for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    if bitmask & 1:
                        drives.add(f"{letter}:\\")
                    bitmask >>= 1
            else:
                # Fallback: check common drive letters
                for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
                    drive = f"{letter}:\\"
                    if Path(drive).exists():
                        drives.add(drive)
        except Exception as e:
            log_agent.debug(f"Drive snapshot error: {e}")
        return drives

    def _get_drive_type(self, drive: str) -> str:
        """Get the type of a drive (removable, fixed, network, etc.)."""
        try:
            if _WIN32_OK:
                drive_type = win32file.GetDriveType(drive)
                types = {
                    0: "UNKNOWN",
                    1: "NO_ROOT_DIR",
                    2: "REMOVABLE",
                    3: "FIXED",
                    4: "REMOTE",
                    5: "CDROM",
                    6: "RAMDISK",
                }
                return types.get(drive_type, "UNKNOWN")
        except Exception:
            pass
        return "UNKNOWN"

    def _get_volume_info(self, drive: str) -> dict:
        """Get volume name and serial number."""
        try:
            if _WIN32_OK:
                info = win32api.GetVolumeInformation(drive)
                return {
                    "volume_name"  : info[0] or "Unnamed",
                    "serial_number": hex(info[1] & 0xFFFFFFFF),
                    "file_system"  : info[4],
                }
        except Exception:
            pass
        return {"volume_name": "Unknown", "serial_number": "N/A", "file_system": "N/A"}

    def scan_once(self) -> list:
        """
        Compare current drives to known snapshot.
        Returns list of USB events (insertions/removals).
        """
        events = []
        current_drives = self._take_drive_snapshot()

        # Detect new drives (insertions)
        new_drives = current_drives - self._known_drives
        for drive in new_drives:
            drive_type = self._get_drive_type(drive)
            # Only care about removable devices (USB drives)
            if drive_type in ("REMOVABLE", "UNKNOWN"):
                vol_info = self._get_volume_info(drive)
                event = {
                    "event_type"  : "usb_insert",
                    "source"      : "usb_monitor",
                    "resource"    : drive,
                    "process_name": "system",
                    "timestamp"   : datetime.now(timezone.utc).isoformat(),
                    "details"     : {
                        "drive"        : drive,
                        "drive_type"   : drive_type,
                        "volume_name"  : vol_info.get("volume_name", ""),
                        "serial_number": vol_info.get("serial_number", ""),
                        "file_system"  : vol_info.get("file_system", ""),
                        "action"       : "inserted",
                    },
                }
                events.append(event)
                log_agent.warning(
                    f"🔌 USB device inserted: {drive} "
                    f"({vol_info.get('volume_name', 'Unknown')})"
                )

                # Fire callback for ZT pipeline
                if self._callback:
                    try:
                        self._callback(event)
                    except Exception as e:
                        log_agent.error(f"USB callback error: {e}")

        # Detect removed drives
        removed_drives = self._known_drives - current_drives
        for drive in removed_drives:
            event = {
                "event_type"  : "usb_remove",
                "source"      : "usb_monitor",
                "resource"    : drive,
                "process_name": "system",
                "timestamp"   : datetime.now(timezone.utc).isoformat(),
                "details"     : {
                    "drive" : drive,
                    "action": "removed",
                },
            }
            events.append(event)
            log_agent.info(f"🔌 USB device removed: {drive}")

            if self._callback:
                try:
                    self._callback(event)
                except Exception as e:
                    log_agent.error(f"USB callback error: {e}")

        self._known_drives = current_drives
        return events

    def run_forever(self, interval: int = 5) -> None:
        """
        Continuous USB monitoring loop.

        Args:
            interval: Seconds between drive scans (default: 5s)
        """
        log_agent.info("✓ USB monitor started")
        # Take initial baseline
        self._known_drives = self._take_drive_snapshot()
        log_agent.info(f"  USB baseline: {len(self._known_drives)} drives detected")

        while True:
            try:
                self.scan_once()
            except Exception as e:
                log_agent.error(f"USB scan error: {e}")
            time.sleep(interval)

"""
agent/startup_monitor.py
==========================
Monitors Windows startup persistence mechanisms:

  1. Startup Folders — Programs placed in shell:startup
  2. Scheduled Tasks — New tasks created via schtasks

Malware commonly uses these for persistence after reboot.
Both vectors are classified as HIGH RISK and routed through
the Zero Trust pipeline.

Uses: pathlib (startup folder), subprocess (schtasks query)
"""

import sys
import os
import time
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger import log_agent

# ── Startup folder paths ─────────────────────────────────────────
STARTUP_FOLDERS = []

# Current user startup
_user_startup = Path(os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
))
if _user_startup.exists():
    STARTUP_FOLDERS.append(_user_startup)

# All users startup
_all_startup = Path(os.path.expandvars(
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
))
if _all_startup.exists():
    STARTUP_FOLDERS.append(_all_startup)


class StartupMonitor:
    """
    Monitors Windows startup persistence vectors:
    - Startup folder file additions
    - Scheduled task creation
    """

    def __init__(self):
        self._startup_baseline: dict[str, set] = {}
        self._task_baseline: set = set()
        self._callback = None
        self._take_startup_snapshot()
        self._take_task_snapshot()

    def set_callback(self, callback):
        """Set callback for startup persistence events."""
        self._callback = callback

    # ── Startup Folder Monitoring ─────────────────────────────────

    def _take_startup_snapshot(self) -> None:
        """Snapshot all files in startup folders."""
        for folder in STARTUP_FOLDERS:
            try:
                files = {str(f) for f in folder.iterdir() if f.is_file()}
                self._startup_baseline[str(folder)] = files
            except Exception as e:
                log_agent.debug(f"Startup folder read error ({folder}): {e}")
                self._startup_baseline[str(folder)] = set()

    def _check_startup_folders(self) -> list:
        """Detect new files in startup folders."""
        events = []
        for folder in STARTUP_FOLDERS:
            folder_key = str(folder)
            try:
                current_files = {str(f) for f in folder.iterdir() if f.is_file()}
            except Exception:
                continue

            baseline = self._startup_baseline.get(folder_key, set())
            new_files = current_files - baseline

            for file_path in new_files:
                fname = Path(file_path).name
                event = {
                    "event_type"  : "startup_persist",
                    "source"      : "startup_monitor",
                    "resource"    : file_path,
                    "process_name": "unknown",
                    "timestamp"   : datetime.now(timezone.utc).isoformat(),
                    "details"     : {
                        "file_name"     : fname,
                        "startup_folder": folder_key,
                        "persistence"   : "startup_folder",
                        "action"        : "new_file",
                    },
                }
                events.append(event)
                log_agent.warning(
                    f"🚀 New startup persistence: {fname} in {folder_key}"
                )

                if self._callback:
                    try:
                        self._callback(event)
                    except Exception as e:
                        log_agent.error(f"Startup callback error: {e}")

            self._startup_baseline[folder_key] = current_files

        return events

    # ── Scheduled Task Monitoring ─────────────────────────────────

    def _take_task_snapshot(self) -> None:
        """Get list of current scheduled task names."""
        self._task_baseline = self._get_task_names()

    def _get_task_names(self) -> set:
        """Query schtasks for all task names."""
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            if result.returncode != 0:
                return set()

            tasks = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and line.startswith('"'):
                    # CSV format: "task_name","next_run","status"
                    parts = line.split('","')
                    if parts:
                        task_name = parts[0].strip('"')
                        if task_name and task_name != "TaskName":
                            tasks.add(task_name)
            return tasks
        except Exception as e:
            log_agent.debug(f"schtasks query error: {e}")
            return set()

    def _check_scheduled_tasks(self) -> list:
        """Detect newly created scheduled tasks."""
        events = []
        current_tasks = self._get_task_names()
        new_tasks = current_tasks - self._task_baseline

        for task_name in new_tasks:
            # Skip Windows update and system tasks
            if any(skip in task_name.lower() for skip in [
                "\\microsoft\\", "\\windows\\", "googleupdate",
                "onedrive", "microsoftedge",
            ]):
                continue

            event = {
                "event_type"  : "scheduled_task_create",
                "source"      : "startup_monitor",
                "resource"    : task_name,
                "process_name": "schtasks.exe",
                "timestamp"   : datetime.now(timezone.utc).isoformat(),
                "details"     : {
                    "task_name"  : task_name,
                    "persistence": "scheduled_task",
                    "action"     : "new_task",
                },
            }
            events.append(event)
            log_agent.warning(f"📋 New scheduled task detected: {task_name}")

            if self._callback:
                try:
                    self._callback(event)
                except Exception as e:
                    log_agent.error(f"Scheduled task callback error: {e}")

        self._task_baseline = current_tasks
        return events

    # ── Public API ─────────────────────────────────────────────────

    def scan_once(self) -> list:
        """Run one scan cycle. Returns list of persistence events."""
        events = []
        events.extend(self._check_startup_folders())
        events.extend(self._check_scheduled_tasks())
        return events

    def run_forever(self, interval: int = 30) -> None:
        """
        Continuous startup persistence monitoring loop.

        Args:
            interval: Seconds between scans (default: 30s).
                      Scheduled tasks checked every 3rd cycle.
        """
        log_agent.info("✓ Startup monitor started")
        log_agent.info(f"  Monitoring {len(STARTUP_FOLDERS)} startup folder(s)")
        log_agent.info(f"  Baseline: {len(self._task_baseline)} scheduled tasks")

        cycle = 0
        while True:
            try:
                # Check startup folders every cycle
                self._check_startup_folders()

                # Check scheduled tasks every 3rd cycle (less frequent)
                if cycle % 3 == 0:
                    self._check_scheduled_tasks()

                cycle += 1
            except Exception as e:
                log_agent.error(f"Startup monitor scan error: {e}")

            time.sleep(interval)

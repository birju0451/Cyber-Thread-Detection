"""
agent/process_monitor.py
=========================
Scans running Windows processes at regular intervals.
Detects:
  - Process creation (new PIDs since last scan)
  - Process termination (disappeared PIDs)
  - Suspicious processes (blocklist, rule engine, memory anomaly)

All security-relevant events are routed through the Zero Trust pipeline.

Uses: psutil
"""

import sys
import time
from pathlib import Path
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


class ProcessMonitor:
    """Periodically scans all running processes for threats."""

    def __init__(self):
        from engine.predictor import engine
        self._engine    = engine
        self._alerted   = set()   # PIDs already alerted (avoid spam)
        self._last_pids = set()   # PIDs from previous scan (for creation detection)

    def scan_once(self) -> list:
        """Scan all running processes. Returns list of threats found."""
        if not _PSUTIL_OK:
            return []

        threats = []
        current_pids = set()

        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "status", "exe", "ppid"]):
                try:
                    info    = proc.info
                    pid     = info["pid"]
                    name    = info["name"] or ""
                    cmdline = " ".join(info["cmdline"] or [])
                    exe     = info.get("exe") or ""
                    ppid    = info.get("ppid", 0)

                    current_pids.add(pid)

                    if pid in self._alerted:
                        continue

                    # ── Detect new processes (creation) ───────────
                    if self._last_pids and pid not in self._last_pids:
                        self._handle_new_process(pid, name, exe, cmdline, ppid)

                    # ── ABTD Analysis ─────────────────────────────
                    result = self._engine.analyze_process(pid, name, cmdline)
                    classification = result.get("classification", "SAFE")
                    score          = result.get("threat_score", 0)

                    if classification in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
                        threats.append(result)
                        self._alerted.add(pid)

                        # Log alert to MongoDB
                        db.log_alert(
                            alert_type  = "process",
                            severity    = classification,
                            title       = f"Suspicious process: {name} (PID {pid})",
                            description = " | ".join(result.get("reasons", [])[:3]),
                            source      = "process_monitor",
                            details     = {"pid": pid, "name": name, "score": score,
                                           "cmdline": cmdline[:200]},
                        )

                        # Route through ZT pipeline for high threats
                        if classification in ("MALICIOUS", "CRITICAL"):
                            self._route_to_zt(pid, name, exe, cmdline, ppid, result)

                            notify(
                                title    = f"Suspicious Process: {name}",
                                message  = f"PID {pid} — Score {score}/100\n{result.get('recommended_action','')}",
                                severity = "CRITICAL" if classification == "CRITICAL" else "WARNING",
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log_agent.error(f"Process scan error: {e}")

        # Detect terminated processes
        if self._last_pids:
            terminated = self._last_pids - current_pids
            # Clean up stale PIDs from alerted set
            self._alerted -= terminated

        self._last_pids = current_pids
        return threats

    def _handle_new_process(self, pid: int, name: str, exe: str,
                             cmdline: str, ppid: int) -> None:
        """Handle a newly detected process creation."""
        # Skip common safe processes to reduce noise
        from agent.event_classifier import SAFE_PROCESSES
        if name.lower() in SAFE_PROCESSES:
            return

        # Get parent process name
        parent_name = ""
        try:
            parent = psutil.Process(ppid)
            parent_name = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Route through ZT pipeline
        try:
            from agent.zt_pipeline import process_security_event
            event = {
                "event_type"      : "process_create",
                "source"          : "process_monitor",
                "resource"        : exe or name,
                "process_name"    : name,
                "process_pid"     : pid,
                "process_exe"     : exe,
                "process_cmdline" : cmdline,
                "parent_process"  : parent_name,
                "details"         : {
                    "pid"         : pid,
                    "ppid"        : ppid,
                    "parent_name" : parent_name,
                    "exe"         : exe,
                    "cmdline"     : cmdline[:200],
                },
            }
            process_security_event(event)
        except Exception as e:
            log_agent.debug(f"ZT pipeline for new process failed: {e}")

    def _route_to_zt(self, pid: int, name: str, exe: str,
                      cmdline: str, ppid: int, abtd_result: dict) -> None:
        """Route high-threat process through ZT pipeline."""
        try:
            from agent.zt_pipeline import process_security_event
            event = {
                "event_type"      : "blocked_process" if name.lower() in
                                    {p.lower() for p in config.BLOCKED_PROCESSES}
                                    else "process_create",
                "source"          : "process_monitor",
                "resource"        : exe or name,
                "process_name"    : name,
                "process_pid"     : pid,
                "process_exe"     : exe,
                "process_cmdline" : cmdline,
                "details"         : {
                    "pid"     : pid,
                    "ppid"    : ppid,
                    "cmdline" : cmdline[:200],
                    "abtd_score": abtd_result.get("threat_score", 0),
                },
            }
            process_security_event(event)
        except Exception as e:
            log_agent.debug(f"ZT pipeline routing failed: {e}")

    def run_forever(self, interval: int = None) -> None:
        """Run continuous process monitoring loop."""
        interval = interval or config.AGENT_SCAN_INTERVAL_S
        log_agent.info(f"✓ Process monitor started (interval: {interval}s)")

        # Take initial PID snapshot
        if _PSUTIL_OK:
            self._last_pids = {p.pid for p in psutil.process_iter(["pid"])}
            log_agent.info(f"  Process baseline: {len(self._last_pids)} processes")

        while True:
            threats = self.scan_once()
            if threats:
                log_agent.warning(f"⚠️ {len(threats)} suspicious process(es) detected")
            time.sleep(interval)

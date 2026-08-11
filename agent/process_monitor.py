"""
agent/process_monitor.py
=========================
Scans running Windows processes at regular intervals.
Flags suspicious processes using the ABTD rule engine and memory anomaly detector.

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
        self._alerted   = set()  # PIDs already alerted (avoid spam)
        self._last_pids = set()

    def scan_once(self) -> list:
        """Scan all running processes. Returns list of threats found."""
        if not _PSUTIL_OK:
            return []

        threats = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "status"]):
                try:
                    info    = proc.info
                    pid     = info["pid"]
                    name    = info["name"] or ""
                    cmdline = " ".join(info["cmdline"] or [])

                    if pid in self._alerted:
                        continue

                    result = self._engine.analyze_process(pid, name, cmdline)
                    classification = result.get("classification", "SAFE")
                    score          = result.get("threat_score", 0)

                    if classification in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
                        threats.append(result)
                        self._alerted.add(pid)

                        db.log_alert(
                            alert_type  = "process",
                            severity    = classification,
                            title       = f"Suspicious process: {name} (PID {pid})",
                            description = " | ".join(result.get("reasons", [])[:3]),
                            source      = "process_monitor",
                            details     = {"pid": pid, "name": name, "score": score,
                                           "cmdline": cmdline[:200]},
                        )

                        if classification in ("MALICIOUS", "CRITICAL"):
                            notify(
                                title    = f"Suspicious Process: {name}",
                                message  = f"PID {pid} — Score {score}/100\n{result.get('recommended_action','')}",
                                severity = "CRITICAL" if classification == "CRITICAL" else "WARNING",
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log_agent.error(f"Process scan error: {e}")

        # Clean up stale PIDs from alerted set
        current_pids = {p.pid for p in psutil.process_iter(["pid"]) if p.info}
        self._alerted &= current_pids

        return threats

    def run_forever(self, interval: int = None) -> None:
        """Run continuous process monitoring loop."""
        interval = interval or config.AGENT_SCAN_INTERVAL_S
        log_agent.info(f"✓ Process monitor started (interval: {interval}s)")
        while True:
            threats = self.scan_once()
            if threats:
                log_agent.warning(f"⚠️ {len(threats)} suspicious process(es) detected")
            time.sleep(interval)

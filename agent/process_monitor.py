"""
agent/process_monitor.py
=========================
ABTD Process Monitor v2.0.

Scans running Windows processes at regular intervals.
Detects:
  - Process creation (new PIDs since last scan)
  - Process termination (disappeared PIDs)
  - Suspicious processes (blocklist, rule engine, memory anomaly)

Suspicious process handling uses ABTD scoring with Zero Trust enrichment
before alerting/response.

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
    """
    Periodically scans all running processes for threats.
    v2.0: Routes every suspicious process through the ZT pipeline.
    """

    def __init__(self):
        from engine.predictor import engine
        self._engine          = engine
        self._alerted         : set = set()   # PIDs already alerted
        self._last_pids       : set = set()   # PIDs from previous scan
        self._zt_controller   = None
        self._behavior_engine = None
        self._zt_initialized  = False

    def _lazy_init_zt(self) -> None:
        """Lazy-load ZT components to avoid circular imports at startup."""
        if self._zt_initialized:
            return
        try:
            from zero_trust.access_control.access_controller import access_controller
            self._zt_controller = access_controller
        except Exception as e:
            log_agent.debug(f"ZT controller not loaded: {e}")
        try:
            from abtd.behavior_engine.behavior_engine import behavior_engine
            self._behavior_engine = behavior_engine
        except Exception as e:
            log_agent.debug(f"Behavior engine not loaded: {e}")
        self._zt_initialized = True

    def scan_once(self) -> list:
        """
        Scan all running processes. Returns list of threats found.
        Each threat is now evaluated through the ZT pipeline.
        """
        if not _PSUTIL_OK:
            return []

        self._lazy_init_zt()
        threats = []
        current_pids = set()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status', 'exe', 'ppid']):
                try:
                    info    = proc.info
                    pid     = info["pid"]
                    name    = info["name"] or ""
                    exe     = info.get("exe") or ""
                    cmdline = " ".join(info["cmdline"] or [])
                    exe     = info.get("exe") or ""
                    ppid    = info.get("ppid", 0)

                    current_pids.add(pid)

                    if pid in self._alerted:
                        continue

                    # ── Detect new processes (creation) ───────────
                    if self._last_pids and pid not in self._last_pids:
                        self._handle_new_process(pid, name, exe, cmdline, ppid)

                    # ── Step 1: ABTD engine analysis ──────────────────
                    result = self._engine.analyze_process(pid, name, cmdline)
                    classification = result.get("classification", "SAFE")
                    score          = result.get("threat_score", 0)

                    if classification not in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
                        continue

                    # ── Step 2: Behavior event record ─────────────────
                    if self._behavior_engine:
                        try:
                            self._behavior_engine.record_event(
                                entity_id  = str(pid),
                                event_type = 'process_create',
                                details    = {
                                    'pid'    : pid,
                                    'name'   : name,
                                    'exe'    : exe[:200],
                                    'cmdline': cmdline[:200],
                                    'score'  : score,
                                },
                                risk_delta = score * 0.4,
                            )
                        except Exception:
                            pass

                    # ── Step 3: Zero Trust evaluation ─────────────────
                    zt_decision = 'UNKNOWN'
                    zt_risk     = score
                    if self._zt_controller:
                        try:
                            zt_result = self._zt_controller.evaluate_access({
                                'event_type'   : 'process',
                                'resource'     : exe or name,
                                'action'       : 'execute',
                                'process_name' : name,
                                'process_pid'  : pid,
                                'abtd_result'  : result,
                                'behavior_risk': float(score) * 0.5,
                            })
                            zt_decision = zt_result.get('decision', 'UNKNOWN')
                            zt_risk     = zt_result.get('overall_risk', score)
                            db.log_access_decision(zt_result)
                        except Exception as e:
                            log_agent.debug(f"Process ZT eval error: {e}")

                    threats.append({**result, 'zt_decision': zt_decision, 'zt_risk': zt_risk})
                    self._alerted.add(pid)

                    # ── Step 4: Log alert ─────────────────────────────
                    db.log_alert(
                        alert_type  = 'process',
                        severity    = classification,
                        title       = f'Suspicious process: {name} (PID {pid})',
                        description = ' | '.join(result.get('reasons', [])[:3]),
                        source      = 'process_monitor',
                        details     = {
                            'pid'        : pid,
                            'name'       : name,
                            'exe'        : exe[:200],
                            'score'      : score,
                            'cmdline'    : cmdline[:200],
                            'zt_decision': zt_decision,
                        },
                    )

                    # Keep existing high-severity route integration
                    if classification in ('MALICIOUS', 'CRITICAL'):
                        self._route_to_zt(pid, name, exe, cmdline, ppid, result)

                    # ── Step 5: Desktop notification ──────────────────
                    if classification in ('MALICIOUS', 'CRITICAL') or zt_decision in ('BLOCK', 'QUARANTINE'):
                        notify(
                            title    = f'🚨 Suspicious Process: {name}',
                            message  = (
                                f'PID {pid} | Score {score}/100 | ZT: {zt_decision}\n'
                                f"{result.get('recommended_action','')}"
                            ),
                            severity = 'CRITICAL' if classification == 'CRITICAL' else 'WARNING',
                        )

                    log_agent.warning(
                        f'Process [{name}] PID={pid} | {classification} | '
                        f'score={score} | ZT={zt_decision}'
                    )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    log_agent.debug(f"Process scan item error: {e}")

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
        log_agent.info(f"✓ Process monitor v2.0 started (interval: {interval}s)")

        # Take initial PID snapshot
        if _PSUTIL_OK:
            self._last_pids = {p.pid for p in psutil.process_iter(["pid"])}
            log_agent.info(f"  Process baseline: {len(self._last_pids)} processes")

        while True:
            threats = self.scan_once()
            if threats:
                log_agent.warning(f"⚠️ {len(threats)} suspicious process(es) → ZT evaluated")
            time.sleep(interval)

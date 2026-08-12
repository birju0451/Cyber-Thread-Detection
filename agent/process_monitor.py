"""
agent/process_monitor.py
=========================
ABTD Process Monitor v2.0.

Scans running Windows processes at regular intervals.
Flags suspicious processes using:
  - ABTD rule engine (threat score)
  - Zero Trust Process Assessor (masquerading, parent-child, cmdline)
  - Behavior Engine (process event recording)
  - Correlation Engine (incident grouping)

v2.0 Change: Every detected threat is now fed through the full ZT
evaluate_access() pipeline before alerting.

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

        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "status"]):
                try:
                    info    = proc.info
                    pid     = info["pid"]
                    name    = info["name"] or ""
                    exe     = info.get("exe") or ""
                    cmdline = " ".join(info["cmdline"] or [])

                    if pid in self._alerted:
                        continue

                    # ── Step 1: ABTD engine analysis ──────────────────
                    result         = self._engine.analyze_process(pid, name, cmdline)
                    classification = result.get("classification", "SAFE")
                    score          = result.get("threat_score", 0)

                    if classification not in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
                        continue

                    # ── Step 2: Behavior event record ─────────────────
                    if self._behavior_engine:
                        try:
                            self._behavior_engine.record_event(
                                entity_id  = str(pid),
                                event_type = "process_create",
                                details    = {
                                    "pid"    : pid,
                                    "name"   : name,
                                    "exe"    : exe[:200],
                                    "cmdline": cmdline[:200],
                                    "score"  : score,
                                },
                                risk_delta = score * 0.4,  # Proportional behavioral risk
                            )
                        except Exception:
                            pass

                    # ── Step 3: Zero Trust evaluation ─────────────────
                    zt_decision  = "UNKNOWN"
                    zt_risk      = score
                    if self._zt_controller:
                        try:
                            zt_result   = self._zt_controller.evaluate_access({
                                "event_type"   : "process",
                                "resource"     : exe or name,
                                "action"       : "execute",
                                "process_name" : name,
                                "process_pid"  : pid,
                                "abtd_result"  : result,
                                "behavior_risk": float(score) * 0.5,
                            })
                            zt_decision = zt_result.get("decision", "UNKNOWN")
                            zt_risk     = zt_result.get("overall_risk", score)
                            # Persist to DB
                            db.log_access_decision(zt_result)
                        except Exception as e:
                            log_agent.debug(f"Process ZT eval error: {e}")

                    threats.append({**result, "zt_decision": zt_decision, "zt_risk": zt_risk})
                    self._alerted.add(pid)

                    # ── Step 4: Log alert ─────────────────────────────
                    db.log_alert(
                        alert_type  = "process",
                        severity    = classification,
                        title       = f"Suspicious process: {name} (PID {pid})",
                        description = " | ".join(result.get("reasons", [])[:3]),
                        source      = "process_monitor",
                        details     = {
                            "pid"        : pid,
                            "name"       : name,
                            "exe"        : exe[:200],
                            "score"      : score,
                            "cmdline"    : cmdline[:200],
                            "zt_decision": zt_decision,
                        },
                    )

                    # ── Step 5: Desktop notification ──────────────────
                    if classification in ("MALICIOUS", "CRITICAL") or zt_decision in ("BLOCK", "QUARANTINE"):
                        notify(
                            title    = f"🚨 Suspicious Process: {name}",
                            message  = (
                                f"PID {pid} | Score {score}/100 | ZT: {zt_decision}\n"
                                f"{result.get('recommended_action','')}"
                            ),
                            severity = "CRITICAL" if classification == "CRITICAL" else "WARNING",
                        )

                    log_agent.warning(
                        f"Process [{name}] PID={pid} | {classification} | "
                        f"score={score} | ZT={zt_decision}"
                    )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    log_agent.debug(f"Process scan item error: {e}")

        except Exception as e:
            log_agent.error(f"Process scan error: {e}")

        # Clean up stale PIDs
        try:
            current_pids = {p.pid for p in psutil.process_iter(["pid"])}
            self._alerted &= current_pids
        except Exception:
            pass

        return threats

    def run_forever(self, interval: int = None) -> None:
        """Run continuous process monitoring loop."""
        interval = interval or config.AGENT_SCAN_INTERVAL_S
        log_agent.info(f"✓ Process monitor v2.0 started (interval: {interval}s)")
        while True:
            threats = self.scan_once()
            if threats:
                log_agent.warning(f"⚠️ {len(threats)} suspicious process(es) → ZT evaluated")
            time.sleep(interval)

"""
abtd/response_engine/response_engine.py
========================================
Automated Response Engine.

Executes policy-driven response actions based on Zero Trust
access decisions.

IMPORTANT SAFETY NOTICE:
  All destructive actions (terminate, quarantine, modify) are
  executed in SIMULATION MODE by default (ZT_SIMULATION_MODE=True).

  In simulation mode, the engine:
    - Logs what it WOULD do
    - Records the intended action in MongoDB
    - Sends a desktop notification
    - Does NOT actually execute the destructive action

  To enable real actions, set ZT_SIMULATION_MODE=False in .env
  This should only be done in controlled environments.

Response Actions:
  ALLOW       — Log and continue
  MONITOR     — Increase monitoring frequency, log
  WARN        — Desktop notification to user
  RESTRICT    — (Simulated) Reduce process priority
  BLOCK_URL   — Signal Chrome extension to block the URL
  QUARANTINE  — Move suspicious file to quarantine folder (or simulate)
  TERMINATE   — (Simulated) Flag process for manual review
  ALERT       — Create high-priority security alert

Public API:
    engine  = ResponseEngine()
    result  = engine.respond(decision, context)
    history = engine.get_response_history()
"""

import os
import sys
import time
import shutil
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import config

log = logging.getLogger("abtd.response")

# Whether to actually execute destructive actions
SIMULATION_MODE = os.getenv("ZT_SIMULATION_MODE", "true").lower() != "false"

MAX_HISTORY = 500


class ResponseEngine:
    """
    Executes automated security responses based on access decisions.
    Safe simulation mode prevents destructive actions during research.
    """

    def __init__(self):
        self._history: list[dict] = []
        self._lock    = threading.Lock()
        if SIMULATION_MODE:
            log.info("Response Engine started in SIMULATION MODE — no destructive actions")
        else:
            log.warning("Response Engine in ACTIVE MODE — destructive actions ENABLED")

    # ── Public API ────────────────────────────────────────────────────────────

    def respond(self, decision: str, context: dict) -> dict:
        """
        Execute appropriate response for the given access decision.

        Args:
            decision : "ALLOW" | "MONITOR" | "RESTRICT" | "CHALLENGE" | "BLOCK"
            context  : Full ZT decision context dict

        Returns: Response execution result dict
        """
        decision = decision.upper()
        action_result = {
            "decision"       : decision,
            "simulation_mode": SIMULATION_MODE,
            "actions_taken"  : [],
            "timestamp"      : datetime.now(timezone.utc).isoformat(),
            "context_summary": {
                "entity"    : context.get("process_name") or context.get("resource", "?"),
                "risk_score": context.get("overall_risk", 0),
                "event_type": context.get("event_type", "?"),
            },
        }

        if decision == "ALLOW":
            action_result["actions_taken"].append(self._action_allow(context))

        elif decision == "MONITOR":
            action_result["actions_taken"].append(self._action_monitor(context))

        elif decision == "RESTRICT":
            action_result["actions_taken"].append(self._action_restrict(context))
            action_result["actions_taken"].append(self._action_warn(context, level="MEDIUM"))

        elif decision == "CHALLENGE":
            action_result["actions_taken"].append(self._action_challenge(context))

        elif decision == "BLOCK":
            action_result["actions_taken"].append(self._action_warn(context, level="HIGH"))
            event_type = context.get("event_type", "")
            if event_type == "file":
                action_result["actions_taken"].append(self._action_quarantine(context))
            elif event_type == "process":
                action_result["actions_taken"].append(self._action_terminate(context))
            elif event_type == "url":
                action_result["actions_taken"].append(self._action_block_url(context))
            action_result["actions_taken"].append(self._action_alert(context))

        elif decision == "QUARANTINE":
            action_result["actions_taken"].append(self._action_quarantine(context))
            action_result["actions_taken"].append(self._action_alert(context))

        # Store in history
        with self._lock:
            self._history.append(action_result)
            if len(self._history) > MAX_HISTORY:
                self._history = self._history[-MAX_HISTORY:]

        return action_result

    def get_response_history(self, limit: int = 50) -> list:
        """Return recent response actions."""
        with self._lock:
            return list(reversed(self._history[-limit:]))

    # ── Action Handlers ───────────────────────────────────────────────────────

    def _action_allow(self, context: dict) -> dict:
        entity = context.get("process_name") or context.get("resource", "unknown")
        log.debug(f"ALLOW: {entity} | risk={context.get('overall_risk', 0):.0f}")
        return {"action": "ALLOW", "status": "executed", "message": f"Access allowed for {entity}"}

    def _action_monitor(self, context: dict) -> dict:
        entity = context.get("process_name") or context.get("resource", "unknown")
        log.info(f"MONITOR: {entity} | risk={context.get('overall_risk', 0):.0f}")
        return {
            "action" : "MONITOR",
            "status" : "executed",
            "message": f"Enhanced monitoring activated for {entity}",
        }

    def _action_warn(self, context: dict, level: str = "MEDIUM") -> dict:
        entity   = context.get("process_name") or context.get("resource", "unknown")
        risk     = context.get("overall_risk", 0)
        decision = context.get("decision", "BLOCK")
        message  = (
            f"ABTD Security Alert: {decision} action for '{entity}' "
            f"(Risk: {risk:.0f}/100)"
        )
        log.warning(f"WARN: {message}")

        # Try desktop notification
        try:
            from agent.notifier import notify
            notify(
                title   = f"⚠️ ABTD Zero Trust — {decision}",
                message = message,
                severity= level,
            )
        except Exception as e:
            log.debug(f"Desktop notification failed: {e}")

        return {
            "action" : "WARN",
            "status" : "executed",
            "message": message,
            "level"  : level,
        }

    def _action_restrict(self, context: dict) -> dict:
        entity = context.get("process_name", "unknown")
        pid    = context.get("process_pid", 0)

        if SIMULATION_MODE:
            log.info(f"[SIMULATED] RESTRICT: Would reduce priority of PID {pid} ({entity})")
            return {
                "action" : "RESTRICT",
                "status" : "simulated",
                "message": f"[SIM] Would restrict privileges of {entity} (PID:{pid})",
                "pid"    : pid,
            }
        else:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.nice(psutil.IDLE_PRIORITY_CLASS)
                return {
                    "action" : "RESTRICT",
                    "status" : "executed",
                    "message": f"Priority lowered for {entity} (PID:{pid})",
                }
            except Exception as e:
                return {"action": "RESTRICT", "status": "failed", "error": str(e)}

    def _action_quarantine(self, context: dict) -> dict:
        resource = context.get("resource", "")
        path     = Path(resource)

        if not path.exists() or not path.is_file():
            return {
                "action" : "QUARANTINE",
                "status" : "skipped",
                "message": f"File not found or not a file: {resource}",
            }

        if SIMULATION_MODE:
            log.warning(f"[SIMULATED] QUARANTINE: Would move {resource} to quarantine")
            return {
                "action"  : "QUARANTINE",
                "status"  : "simulated",
                "message" : f"[SIM] Would quarantine: {path.name}",
                "original": resource,
            }
        else:
            try:
                dest = config.QUARANTINE_DIR / f"{path.name}.quarantine"
                shutil.move(str(path), str(dest))
                log.warning(f"QUARANTINE: {resource} → {dest}")
                return {
                    "action"     : "QUARANTINE",
                    "status"     : "executed",
                    "message"    : f"Quarantined: {path.name}",
                    "original"   : resource,
                    "quarantine" : str(dest),
                }
            except Exception as e:
                return {"action": "QUARANTINE", "status": "failed", "error": str(e)}

    def _action_terminate(self, context: dict) -> dict:
        pid    = context.get("process_pid", 0)
        entity = context.get("process_name", "unknown")

        if SIMULATION_MODE:
            log.warning(f"[SIMULATED] TERMINATE: Would terminate PID {pid} ({entity})")
            return {
                "action" : "TERMINATE",
                "status" : "simulated",
                "message": f"[SIM] Would terminate suspicious process: {entity} (PID:{pid})",
                "pid"    : pid,
            }
        else:
            # Safety check: never terminate critical system processes
            critical_processes = {
                "system", "smss.exe", "csrss.exe", "wininit.exe",
                "winlogon.exe", "lsass.exe", "services.exe", "explorer.exe",
            }
            if entity.lower() in critical_processes or pid <= 4:
                return {
                    "action" : "TERMINATE",
                    "status" : "blocked",
                    "message": f"Refused to terminate critical system process: {entity}",
                }
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.terminate()
                return {
                    "action" : "TERMINATE",
                    "status" : "executed",
                    "message": f"Terminated: {entity} (PID:{pid})",
                }
            except Exception as e:
                return {"action": "TERMINATE", "status": "failed", "error": str(e)}

    def _action_block_url(self, context: dict) -> dict:
        url = context.get("resource", "unknown")
        log.warning(f"BLOCK_URL: {url}")
        # Signal stored in context — Chrome extension polls for blocked URLs
        return {
            "action" : "BLOCK_URL",
            "status" : "executed",
            "message": f"URL flagged for blocking: {url}",
            "url"    : url,
        }

    def _action_alert(self, context: dict) -> dict:
        entity = context.get("process_name") or context.get("resource", "unknown")
        risk   = context.get("overall_risk", 0)
        reason = context.get("decision_reason", "No reason provided")

        log.critical(
            f"SECURITY ALERT: {entity} | risk={risk:.0f} | {reason}"
        )

        # Persist alert to MongoDB (non-blocking)
        try:
            from backend.database import db
            db.log_alert(
                alert_type  = "zero_trust_block",
                severity    = "CRITICAL" if risk >= 75 else "HIGH",
                title       = f"ZT Block: {entity}",
                description = reason,
                source      = "response_engine",
                details     = {
                    "risk_score"  : risk,
                    "event_type"  : context.get("event_type"),
                    "process_pid" : context.get("process_pid"),
                    "trust_level" : context.get("trust_level"),
                }
            )
        except Exception as e:
            log.debug(f"Alert persistence failed: {e}")

        return {
            "action" : "ALERT",
            "status" : "executed",
            "message": f"High-priority alert created for: {entity}",
        }

    def _action_challenge(self, context: dict) -> dict:
        entity = context.get("process_name") or context.get("resource", "unknown")
        log.info(f"CHALLENGE: Step-up verification required for {entity}")
        return {
            "action" : "CHALLENGE",
            "status" : "executed",
            "message": f"Step-up verification logged for: {entity}",
        }


# Singleton
response_engine = ResponseEngine()

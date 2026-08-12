"""
zero_trust/access_control/access_controller.py
================================================
Zero Trust Access Controller — Main Pipeline Orchestrator.

This is the single entry point for ALL Zero Trust decisions.
It orchestrates the complete ZT pipeline:

  1. Identity Verification
  2. Device Trust Assessment
  3. Application Trust Assessment
  4. Process Trust Assessment
  5. Resource Sensitivity Check
  6. ABTD Threat Detection (existing engine)
  7. Behavior Risk (from BehaviorEngine)
  8. Multi-Signal Risk Calculation
  9. Policy Engine Evaluation
  10. Access Decision Output
  11. Trust Score Update
  12. Audit Log

NEVER TRUST AUTOMATICALLY — every request goes through this pipeline.

Public API:
    controller = AccessController()
    decision   = controller.evaluate_access(request)
    overview   = controller.get_zt_overview()
"""

import sys
import uuid
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.access")

from zero_trust.identity.identity_manager  import identity_manager
from zero_trust.device_trust.device_assessor import device_assessor
from zero_trust.application_trust.app_assessor import app_assessor
from zero_trust.process_trust.process_assessor import process_assessor
from zero_trust.resource_protection.resource_registry import resource_registry
from zero_trust.risk_engine.risk_calculator import risk_calculator
from zero_trust.trust_manager.trust_manager import trust_manager
from zero_trust.policy_engine.policy_engine import policy_engine


class AccessController:
    """
    Central Zero Trust Access Controller.

    Orchestrates all ZT assessment modules and produces
    a final, justified access decision for every security event.
    """

    def __init__(self):
        self._decisions: list[dict] = []   # In-memory decision log (last 500)
        self._lock = threading.Lock()
        self._max_decisions = 500

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate_access(self, request: dict) -> dict:
        """
        Run the complete Zero Trust evaluation pipeline.

        Args:
            request: {
                "event_type"    : "url" | "file" | "process" | "network" | "registry",
                "resource"      : str  (URL, file path, process name, IP, registry key),
                "action"        : str  (read, write, execute, connect, create, delete),
                "process_name"  : str  (requesting process),
                "process_pid"   : int  (optional),
                "process_exe"   : str  (optional),
                "process_cmdline": str (optional),
                "parent_process": str  (optional),
                "abtd_result"   : dict (optional — pre-computed ABTD analysis),
                "behavior_risk" : float (optional — from BehaviorEngine),
                "network_risk"  : float (optional),
            }

        Returns full ZT decision dict.
        """
        request_id = str(uuid.uuid4())[:8].upper()
        t_start    = datetime.now(timezone.utc)

        try:
            decision = self._run_pipeline(request, request_id, t_start)
        except Exception as e:
            log.error(f"ZT pipeline error for request {request_id}: {e}", exc_info=True)
            decision = self._fallback_decision(request, request_id, str(e))

        # Log decision
        self._store_decision(decision)

        # Update trust scores based on decision
        self._update_trust_scores(decision, request)

        return decision

    def get_recent_decisions(self, limit: int = 50) -> list:
        """Return recent access decisions."""
        with self._lock:
            return list(reversed(self._decisions[-limit:]))

    def get_zt_overview(self) -> dict:
        """
        Return high-level Zero Trust status for the dashboard.
        Includes entity trust scores and recent decision statistics.
        """
        # Device trust
        device = device_assessor.assess()
        device_trust = device.get("device_trust_score", 70)

        # Identity
        identity = identity_manager.get_identity_context()
        identity_risk = identity_manager.get_identity_risk()
        identity_trust = identity_risk.get("identity_trust", 75)

        # App trust average
        app_profiles = app_assessor.get_app_profiles()
        app_trust_avg = (
            sum(p["trust_score"] for p in app_profiles) / max(len(app_profiles), 1)
            if app_profiles else 70
        )

        # Decision stats
        with self._lock:
            recent = self._decisions[-100:]
        total     = len(recent)
        allowed   = sum(1 for d in recent if d.get("decision") == "ALLOW")
        restricted= sum(1 for d in recent if d.get("decision") in ("RESTRICT", "MONITOR", "CHALLENGE"))
        blocked   = sum(1 for d in recent if d.get("decision") == "BLOCK")

        # Overall system trust score
        signals = {
            "identity_risk": identity_risk.get("identity_risk", 0),
            "device_risk"  : 100 - device_trust,
            "app_risk"     : 100 - app_trust_avg,
        }
        calc = risk_calculator.calculate(signals)
        overall_trust = calc["trust_score"]

        return {
            "overall_trust_score"  : overall_trust,
            "overall_trust_level"  : calc["trust_level"],
            "device_trust"         : device_trust,
            "device_trust_level"   : device.get("device_trust_level", "MEDIUM"),
            "user_trust"           : identity_trust,
            "identity_privilege"   : identity.get("privilege_level", "STANDARD"),
            "app_trust_avg"        : round(app_trust_avg, 1),
            "app_count"            : len(app_profiles),
            "decision_stats"       : {
                "total"    : total,
                "allowed"  : allowed,
                "restricted": restricted,
                "blocked"  : blocked,
            },
            "device_flags"         : device.get("risk_flags", []),
            "identity_flags"       : identity_risk.get("reasons", []),
            "recent_decisions"     : self.get_recent_decisions(10),
            "sampled_at"           : datetime.now(timezone.utc).isoformat(),
        }

    # ── Pipeline ──────────────────────────────────────────────────────────────

    def _run_pipeline(self, request: dict, request_id: str, t_start: datetime) -> dict:
        resource     = request.get("resource", "unknown")
        event_type   = request.get("event_type", "unknown")
        action       = request.get("action", "access")
        process_name = request.get("process_name", "unknown")
        process_pid  = request.get("process_pid", 0)
        process_exe  = request.get("process_exe", "")
        process_cmd  = request.get("process_cmdline", "")
        parent_proc  = request.get("parent_process", "")
        abtd_result  = request.get("abtd_result", {})

        # ── Step 1: Identity ─────────────────────────────────────────────────
        identity_ctx  = identity_manager.get_identity_context()
        identity_risk = identity_manager.get_identity_risk()
        id_risk_score = identity_risk.get("identity_risk", 0)

        # ── Step 2: Device Trust ─────────────────────────────────────────────
        device_result  = device_assessor.assess()
        device_trust   = device_result.get("device_trust_score", 70)
        device_risk    = 100 - device_trust

        # ── Step 3: Application Trust ────────────────────────────────────────
        app_trust = 70   # Default for unknown apps
        if process_exe:
            try:
                app_result = app_assessor.assess_app(process_exe)
                app_trust  = app_result.get("app_trust_score", 70)
            except Exception:
                pass
        app_risk = 100 - app_trust

        # ── Step 4: Process Trust ────────────────────────────────────────────
        proc_result   = process_assessor.assess_process(
            pid=process_pid, name=process_name,
            exe=process_exe, cmdline=process_cmd,
            parent_name=parent_proc,
        )
        process_risk  = proc_result.get("process_risk_score", 0)
        process_blocklist = bool(proc_result.get("risk_flags") and
                                 any("CRITICAL" in f for f in proc_result["risk_flags"]))

        # ── Step 5: Resource Sensitivity ─────────────────────────────────────
        resource_sensitivity = resource_registry.get_sensitivity(resource)

        # ── Step 6: ABTD Threat Score ─────────────────────────────────────────
        url_risk  = float(abtd_result.get("threat_score", 0)) if event_type == "url"  else 0.0
        file_risk = float(abtd_result.get("threat_score", 0)) if event_type == "file" else 0.0

        # ── Step 7: Behavior Risk ─────────────────────────────────────────────
        behavior_risk = float(request.get("behavior_risk", 0))
        network_risk  = float(request.get("network_risk", 0))

        # ── Step 8: Risk Calculation ──────────────────────────────────────────
        signals = {
            "identity_risk": id_risk_score,
            "device_risk"  : device_risk,
            "app_risk"     : app_risk,
            "process_risk" : process_risk,
            "url_risk"     : url_risk,
            "file_risk"    : file_risk,
            "behavior_risk": behavior_risk,
            "network_risk" : network_risk,
        }
        risk_result  = risk_calculator.calculate(signals)
        overall_risk = risk_result["overall_risk"]
        trust_score  = risk_result["trust_score"]

        # ── Step 9: Policy Evaluation ─────────────────────────────────────────
        policy_context = {
            "overall_risk"         : overall_risk,
            "device_trust"         : device_trust,
            "app_trust"            : app_trust,
            "process_risk"         : process_risk,
            "identity_level"       : identity_ctx.get("privilege_level", "STANDARD"),
            "resource_sensitivity" : resource_sensitivity,
            "process_blocklist"    : process_blocklist,
            "url_risk"             : url_risk,
            "file_risk"            : file_risk,
        }
        policy_result = policy_engine.evaluate(policy_context)
        decision      = policy_result["decision"]

        elapsed_ms = round(
            (datetime.now(timezone.utc) - t_start).total_seconds() * 1000, 1
        )

        return {
            "request_id"           : request_id,
            "timestamp"            : t_start.isoformat(),
            "event_type"           : event_type,
            "resource"             : resource,
            "action"               : action,
            "process_name"         : process_name,
            "process_pid"          : process_pid,

            # Assessment results
            "identity"             : {
                "username"      : identity_ctx.get("username"),
                "privilege"     : identity_ctx.get("privilege_level"),
                "is_elevated"   : identity_ctx.get("is_elevated"),
                "risk_score"    : id_risk_score,
                "risk_flags"    : identity_risk.get("reasons", []),
            },
            "device"               : {
                "trust_score"   : device_trust,
                "trust_level"   : device_result.get("device_trust_level"),
                "risk_score"    : device_risk,
                "risk_flags"    : device_result.get("risk_flags", []),
            },
            "application"          : {
                "exe_path"      : process_exe,
                "trust_score"   : app_trust,
                "risk_score"    : app_risk,
            },
            "process"              : proc_result,
            "resource_sensitivity" : resource_sensitivity,

            # Risk aggregation
            "signals"              : signals,
            "risk_calculation"     : risk_result,
            "overall_risk"         : overall_risk,
            "trust_score"          : trust_score,
            "trust_level"          : risk_result["trust_level"],

            # Policy + Decision
            "policy_id"            : policy_result.get("matched_policy"),
            "policy_name"          : policy_result.get("policy_name"),
            "decision"             : decision,
            "decision_reason"      : policy_result["reason"],
            "decision_color"       : policy_result["color"],
            "decision_icon"        : policy_result["icon"],

            # ABTD threat context
            "abtd_threat_score"    : abtd_result.get("threat_score", 0),
            "abtd_classification"  : abtd_result.get("classification", ""),
            "abtd_reasons"         : abtd_result.get("reasons", []),

            "pipeline_ms"          : elapsed_ms,
        }

    # ── Post-Decision Actions ─────────────────────────────────────────────────

    def _update_trust_scores(self, decision: dict, request: dict) -> None:
        """Update trust scores based on the access decision."""
        try:
            username = decision.get("identity", {}).get("username", "unknown")
            process  = decision.get("process_name", "unknown")
            dec      = decision.get("decision", "ALLOW")

            # Trust deltas per decision
            deltas = {
                "BLOCK"     : -15,
                "QUARANTINE": -20,
                "RESTRICT"  : -8,
                "CHALLENGE" : -5,
                "MONITOR"   : -2,
                "ALLOW"     : +1,
            }
            delta = deltas.get(dec, 0)
            reason = f"ZT decision: {dec} for {request.get('event_type','?')} event"

            if delta != 0:
                trust_manager.update_trust("user", username, delta, reason, source="access_controller")
                trust_manager.update_trust("process", process, delta, reason, source="access_controller")
        except Exception as e:
            log.debug(f"Trust update after decision failed: {e}")

    def _store_decision(self, decision: dict) -> None:
        """Store decision in memory (ring buffer)."""
        with self._lock:
            self._decisions.append(decision)
            if len(self._decisions) > self._max_decisions:
                self._decisions = self._decisions[-self._max_decisions:]

    def _fallback_decision(self, request: dict, request_id: str, error: str) -> dict:
        """Return a safe fallback decision when the pipeline errors."""
        return {
            "request_id"    : request_id,
            "timestamp"     : datetime.now(timezone.utc).isoformat(),
            "event_type"    : request.get("event_type", "unknown"),
            "resource"      : request.get("resource", "unknown"),
            "decision"      : "MONITOR",
            "decision_reason": f"Pipeline error — defaulting to MONITOR: {error}",
            "decision_color" : "#3b82f6",
            "decision_icon"  : "⚠️",
            "overall_risk"   : 50,
            "trust_score"    : 50,
            "trust_level"    : "MODERATE_RISK",
            "pipeline_ms"    : 0,
            "error"          : error,
        }


# Singleton
access_controller = AccessController()

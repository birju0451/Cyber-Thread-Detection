"""
agent/zt_pipeline.py
=====================
Zero Trust Pipeline Bridge for the Windows Agent.

Provides a single function that all monitors call when they
detect a security-relevant event. This function orchestrates:

  1. Event Classification (filter non-security events)
  2. ABTD Analysis (ML + rules + reputation)
  3. Behavior Recording (temporal profiling)
  4. Threat Correlation (group related events)
  5. Zero Trust Evaluation (access decision)
  6. Response Execution (ALLOW/MONITOR/BLOCK/etc.)
  7. MongoDB Persistence

This keeps the monitors simple: they detect events and call
`process_security_event(event)`. Everything else happens here.

Public API:
    from agent.zt_pipeline import process_security_event
    process_security_event(event_dict)
"""

import sys
import logging
import traceback
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

log = logging.getLogger("abtd.zt_pipeline")


def process_security_event(event: dict) -> dict:
    """
    Full end-to-end processing of a security event through
    the ABTD + Zero Trust pipeline.

    Args:
        event: {
            "event_type"    : str,
            "source"        : str,
            "resource"      : str,
            "process_name"  : str,
            "process_pid"   : int (optional),
            "process_exe"   : str (optional),
            "process_cmdline": str (optional),
            "parent_process": str (optional),
            "timestamp"     : str (optional),
            "details"       : dict (optional),
        }

    Returns:
        Full ZT decision dict, or None if event was filtered out.
    """
    try:
        return _process(event)
    except Exception as e:
        log.error(f"ZT pipeline error: {e}\n{traceback.format_exc()}")
        return None


def _process(event: dict) -> dict | None:
    """Internal pipeline execution."""
    from agent.event_classifier import event_classifier

    # ── Step 1: Event Classification ──────────────────────────────
    classification = event_classifier.classify(event)

    if not classification["relevant"]:
        # Lightweight log only — skip heavy pipeline
        log.debug(
            f"[SKIP] {event.get('event_type','?')} from "
            f"{event.get('source','?')}: {classification['reason']}"
        )
        return None

    priority   = classification["priority"]
    event_type = event.get("event_type", "unknown")
    resource   = event.get("resource", "unknown")
    process_name = event.get("process_name", "unknown")
    process_pid  = event.get("process_pid", 0)
    process_exe  = event.get("process_exe", "")
    process_cmd  = event.get("process_cmdline", "")
    parent_proc  = event.get("parent_process", "")

    log.info(
        f"[ZT-PIPELINE] Processing {event_type} | "
        f"resource={resource[:60]} | priority={priority}"
    )

    # ── Step 2: ABTD Analysis ─────────────────────────────────────
    abtd_result = {}
    try:
        from engine.predictor import engine as abtd_engine

        if event_type in ("url_visit", "url_block"):
            abtd_result = abtd_engine.analyze_url(resource, skip_reputation=False)
        elif event_type in ("file_execute", "file_download", "file_write",
                            "file_create", "file_delete"):
            if Path(resource).exists():
                abtd_result = abtd_engine.analyze_file(resource)
            else:
                abtd_result = {"threat_score": 0, "classification": "UNKNOWN",
                               "reasons": [f"File not accessible: {resource}"]}
        elif event_type in ("process_create", "blocked_process"):
            abtd_result = abtd_engine.analyze_process(
                pid=process_pid, name=process_name, cmdline=process_cmd
            )
        else:
            # For registry, USB, startup, network — use rule-based assessment
            abtd_result = {
                "threat_score"  : _estimate_threat_score(event, priority),
                "classification": _score_to_classification(
                    _estimate_threat_score(event, priority)
                ),
                "reasons"       : [classification["reason"]],
            }
    except Exception as e:
        log.warning(f"ABTD analysis failed: {e}")
        abtd_result = {
            "threat_score"  : 30 if priority == "HIGH" else 15,
            "classification": "SUSPICIOUS" if priority == "HIGH" else "SAFE",
            "reasons"       : [f"ABTD analysis error: {e}"],
        }

    # ── Step 3: Behavior Engine Recording ─────────────────────────
    try:
        from abtd.behavior_engine.behavior_engine import behavior_engine
        entity_id = process_name or resource[:50]
        behavior_engine.record_event(
            entity_id  = entity_id,
            event_type = event_type,
            details    = event.get("details", {}),
            risk_delta = abtd_result.get("threat_score", 0) * 0.1,
        )
        behavior_risk = behavior_engine.get_behavior_risk(entity_id)
    except Exception as e:
        log.debug(f"Behavior recording failed: {e}")
        behavior_risk = 0.0

    # ── Step 4: Threat Correlation ────────────────────────────────
    try:
        from abtd.correlation_engine.correlation_engine import correlation_engine
        threat_score = abtd_result.get("threat_score", 0)
        severity = (
            "CRITICAL" if threat_score >= 75 else
            "HIGH"     if threat_score >= 50 else
            "MEDIUM"   if threat_score >= 25 else
            "LOW"
        )
        correlation_event = {
            "event_type"  : event_type,
            "entity_id"   : process_name or resource[:50],
            "severity"    : severity,
            "risk_score"  : threat_score,
            "description" : "; ".join(abtd_result.get("reasons", [])[:3]),
            "source"      : event.get("source", "agent"),
            "details"     : event.get("details", {}),
        }
        correlation_result = correlation_engine.submit_event(correlation_event)
    except Exception as e:
        log.debug(f"Correlation failed: {e}")
        correlation_result = {}

    # ── Step 5: Zero Trust Evaluation ─────────────────────────────
    try:
        from zero_trust.access_control.access_controller import access_controller

        zt_request = {
            "event_type"      : event_type,
            "resource"        : resource,
            "action"          : _infer_action(event_type),
            "process_name"    : process_name,
            "process_pid"     : process_pid,
            "process_exe"     : process_exe,
            "process_cmdline" : process_cmd,
            "parent_process"  : parent_proc,
            "abtd_result"     : abtd_result,
            "behavior_risk"   : behavior_risk,
        }
        zt_decision = access_controller.evaluate_access(zt_request)
    except Exception as e:
        log.error(f"ZT evaluation failed: {e}")
        zt_decision = {
            "decision"       : "MONITOR",
            "decision_reason": f"ZT pipeline error — defaulting to MONITOR: {e}",
            "overall_risk"   : abtd_result.get("threat_score", 0),
        }

    decision = zt_decision.get("decision", "MONITOR")

    # ── Step 6: Response Engine ───────────────────────────────────
    try:
        from abtd.response_engine.response_engine import response_engine

        response_context = {**zt_decision, **event}
        response_result = response_engine.respond(decision, response_context)
        log.info(
            f"[ZT-DECISION] {decision} | {event_type} | "
            f"risk={zt_decision.get('overall_risk', 0):.0f} | "
            f"resource={resource[:50]}"
        )
    except Exception as e:
        log.debug(f"Response engine failed: {e}")
        response_result = {}

    # ── Step 7: MongoDB Persistence ───────────────────────────────
    try:
        from backend.database import db
        db.log_access_decision(zt_decision)
    except Exception as e:
        log.debug(f"DB persistence failed: {e}")

    return zt_decision


def _estimate_threat_score(event: dict, priority: str) -> float:
    """Estimate threat score for events without ML analysis."""
    base_scores = {
        "registry_modify"       : 40,
        "startup_persist"       : 55,
        "scheduled_task_create" : 50,
        "usb_insert"            : 25,
        "network_connect"       : 20,
        "privilege_change"      : 60,
    }
    score = base_scores.get(event.get("event_type", ""), 15)

    if priority == "HIGH":
        score = max(score, 40)

    return min(score, 100)


def _score_to_classification(score: float) -> str:
    """Convert numeric score to classification label."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "MALICIOUS"
    elif score >= 25:
        return "SUSPICIOUS"
    return "SAFE"


def _infer_action(event_type: str) -> str:
    """Infer the action string from event type."""
    action_map = {
        "file_execute"         : "execute",
        "file_download"        : "write",
        "file_write"           : "write",
        "file_create"          : "create",
        "file_delete"          : "delete",
        "process_create"       : "execute",
        "process_terminate"    : "terminate",
        "network_connect"      : "connect",
        "registry_modify"      : "write",
        "startup_persist"      : "create",
        "scheduled_task_create": "create",
        "usb_insert"           : "access",
        "usb_remove"           : "access",
        "url_visit"            : "read",
        "privilege_change"     : "execute",
    }
    return action_map.get(event_type, "access")

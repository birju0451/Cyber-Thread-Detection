"""
backend/routes/assessment_routes.py
=====================================
Flask API routes for Full Security Assessment.

Endpoints:
  POST /api/assessment/run     — Trigger full security assessment (async)
  GET  /api/assessment/status  — Current assessment progress
  GET  /api/assessment/result  — Latest assessment result
  GET  /api/assessment/history — Assessment run history
"""

import sys
import threading
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, jsonify, request
from backend.database import db
from backend.logger   import log_system

assessment_bp = Blueprint("assessment", __name__)

# Assessment state (in-memory, not a full task queue)
_assessment_state = {
    "running"   : False,
    "progress"  : 0,
    "stage"     : "idle",
    "result"    : None,
    "started_at": None,
    "error"     : None,
}
_state_lock = threading.Lock()


@assessment_bp.post("/api/assessment/run")
def run_assessment():
    """
    Trigger a full security assessment.
    Assessment runs in a background thread.
    Poll /api/assessment/status for progress.
    """
    with _state_lock:
        if _assessment_state["running"]:
            return jsonify({
                "status" : "error",
                "message": "Assessment already running — poll /api/assessment/status"
            }), 409

        _assessment_state["running"]    = True
        _assessment_state["progress"]   = 0
        _assessment_state["stage"]      = "starting"
        _assessment_state["error"]      = None
        _assessment_state["result"]     = None

    thread = threading.Thread(
        target=_run_assessment_thread,
        name="SecurityAssessment",
        daemon=True,
    )
    thread.start()

    return jsonify({
        "status" : "ok",
        "message": "Security assessment started",
        "poll"   : "/api/assessment/status",
    })


@assessment_bp.get("/api/assessment/status")
def assessment_status():
    """Return current assessment progress."""
    with _state_lock:
        state = dict(_assessment_state)
        # Don't return the full result in status poll
        if state.get("result"):
            state["result"] = {"available": True, "fetch": "/api/assessment/result"}
    return jsonify({"status": "ok", "data": state})


@assessment_bp.get("/api/assessment/result")
def assessment_result():
    """Return the latest assessment result."""
    with _state_lock:
        result = _assessment_state.get("result")

    if not result:
        # Try DB
        result = db.get_latest_assessment()

    if not result:
        return jsonify({
            "status" : "error",
            "message": "No assessment available — run POST /api/assessment/run first"
        }), 404

    return jsonify({"status": "ok", "data": result})


@assessment_bp.get("/api/assessment/history")
def assessment_history():
    """Return assessment run history."""
    history = db.get_assessment_history(limit=10)
    return jsonify({"status": "ok", "data": history})


# ── Background Assessment Thread ──────────────────────────────────────────────

def _run_assessment_thread():
    """Run the full security assessment in background and update state."""
    from datetime import datetime, timezone
    try:
        from scanner.security_assessment import SecurityAssessment
        assessor = SecurityAssessment(progress_callback=_update_progress)
        result   = assessor.run()

        with _state_lock:
            _assessment_state["result"]   = result
            _assessment_state["running"]  = False
            _assessment_state["progress"] = 100
            _assessment_state["stage"]    = "complete"

        # Persist to MongoDB
        db.save_assessment(result)
        log_system.info(
            f"Security assessment complete — "
            f"posture={result.get('security_posture_score')}, "
            f"zt={result.get('zero_trust_readiness_score')}"
        )

    except Exception as e:
        log_system.error(f"Assessment thread error: {e}", exc_info=True)
        with _state_lock:
            _assessment_state["running"]  = False
            _assessment_state["error"]    = str(e)
            _assessment_state["stage"]    = "error"
            _assessment_state["progress"] = 0


def _update_progress(progress: int, stage: str) -> None:
    """Callback used by SecurityAssessment to report progress."""
    with _state_lock:
        _assessment_state["progress"] = progress
        _assessment_state["stage"]    = stage

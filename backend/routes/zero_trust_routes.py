"""
backend/routes/zero_trust_routes.py
=====================================
Flask API routes for Zero Trust architecture data.

Endpoints:
  GET  /api/zero-trust/overview          — Dashboard overview (trust scores, decisions)
  GET  /api/zero-trust/trust-scores      — All entity trust scores
  GET  /api/zero-trust/access-decisions  — Paginated access decision log
  GET  /api/zero-trust/access-decisions/<id> — Single decision detail
  POST /api/zero-trust/evaluate          — Manual ZT evaluation
  GET  /api/zero-trust/incidents         — Correlated incidents
  GET  /api/zero-trust/incidents/<id>    — Single incident detail
  POST /api/zero-trust/incidents/<id>/resolve — Resolve an incident
  GET  /api/zero-trust/policies          — Policy list
  POST /api/zero-trust/policies          — Add custom policy
  GET  /api/zero-trust/trust-history/<type>/<id> — Entity trust history
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from backend.database  import db
from backend.logger    import log_system

zero_trust_bp = Blueprint("zero_trust", __name__)


# ── Overview ──────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/overview")
def zt_overview():
    """Zero Trust dashboard overview — all trust scores and recent decisions."""
    try:
        from zero_trust.access_control.access_controller import access_controller
        overview = access_controller.get_zt_overview()

        # Enrich with DB decision stats
        db_stats = db.get_decision_stats()
        overview["db_decision_stats"] = db_stats

        return jsonify({"status": "ok", "data": overview})
    except Exception as e:
        log_system.error(f"zt_overview error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Trust Scores ──────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/trust-scores")
def zt_trust_scores():
    """Return all entity trust scores from TrustManager."""
    try:
        from zero_trust.trust_manager.trust_manager import trust_manager
        scores = trust_manager.get_all_trust_scores()
        return jsonify({"status": "ok", "data": scores})
    except Exception as e:
        log_system.error(f"zt_trust_scores error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.get("/api/zero-trust/trust-history/<entity_type>/<path:entity_id>")
def zt_trust_history(entity_type: str, entity_id: str):
    """Return trust score history for a specific entity."""
    try:
        from zero_trust.trust_manager.trust_manager import trust_manager
        history = trust_manager.get_trust_history(entity_type, entity_id)
        state   = trust_manager.get_trust_state(entity_type, entity_id)
        return jsonify({"status": "ok", "data": {"state": state, "history": history}})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Access Decisions ──────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/access-decisions")
def zt_access_decisions():
    """Return paginated access decision log."""
    try:
        page       = int(request.args.get("page", 1))
        decision   = request.args.get("decision")
        event_type = request.args.get("event_type")

        # Try in-memory (live) first, then DB
        from zero_trust.access_control.access_controller import access_controller
        live = access_controller.get_recent_decisions(50)

        if live:
            # Filter in-memory data
            filtered = live
            if decision:
                filtered = [d for d in filtered if d.get("decision") == decision.upper()]
            if event_type:
                filtered = [d for d in filtered if d.get("event_type") == event_type]
            return jsonify({
                "status": "ok",
                "data"  : {
                    "items" : filtered[:25],
                    "total" : len(filtered),
                    "source": "live",
                }
            })
        else:
            # Fall back to DB
            result = db.get_access_decisions(page=page, decision=decision, event_type=event_type)
            result["source"] = "database"
            return jsonify({"status": "ok", "data": result})
    except Exception as e:
        log_system.error(f"zt_access_decisions error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.post("/api/zero-trust/evaluate")
def zt_evaluate():
    """
    Manual Zero Trust evaluation endpoint.
    Accepts a request context and runs the full ZT pipeline.
    """
    try:
        body = request.get_json(force=True) or {}
        if not body.get("resource") and not body.get("process_name"):
            return jsonify({
                "status" : "error",
                "message": "Request must include 'resource' or 'process_name'"
            }), 400

        from zero_trust.access_control.access_controller import access_controller
        result = access_controller.evaluate_access(body)

        # Persist to DB
        db.log_access_decision(result)

        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        log_system.error(f"zt_evaluate error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Incidents ─────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/incidents")
def zt_incidents():
    """Return correlated security incidents."""
    try:
        status   = request.args.get("status")
        severity = request.args.get("severity")
        limit    = int(request.args.get("limit", 50))

        from abtd.correlation_engine.correlation_engine import correlation_engine

        # Live (in-memory) incidents
        live = correlation_engine.get_incidents(status=status, severity=severity, limit=limit)
        stats = correlation_engine.get_statistics()

        return jsonify({
            "status": "ok",
            "data"  : {
                "incidents": live,
                "stats"    : stats,
                "source"   : "live",
            }
        })
    except Exception as e:
        log_system.error(f"zt_incidents error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.get("/api/zero-trust/incidents/<incident_id>")
def zt_incident_detail(incident_id: str):
    """Return detail for a single incident."""
    try:
        from abtd.correlation_engine.correlation_engine import correlation_engine
        incident = correlation_engine.get_incident(incident_id)
        if not incident:
            return jsonify({"status": "error", "message": "Incident not found"}), 404
        return jsonify({"status": "ok", "data": incident})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.post("/api/zero-trust/incidents/<incident_id>/resolve")
def zt_resolve_incident(incident_id: str):
    """Mark an incident as resolved."""
    try:
        from abtd.correlation_engine.correlation_engine import correlation_engine
        success = correlation_engine.resolve_incident(incident_id)
        if success:
            return jsonify({"status": "ok", "message": f"Incident {incident_id} resolved"})
        return jsonify({"status": "error", "message": "Incident not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Policies ──────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/policies")
def zt_policies():
    """Return all active Zero Trust policies."""
    try:
        from zero_trust.policy_engine.policy_engine import policy_engine
        policies = policy_engine.get_all_policies()
        return jsonify({"status": "ok", "data": policies, "count": len(policies)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.post("/api/zero-trust/policies")
def zt_add_policy():
    """Add a custom Zero Trust policy at runtime."""
    try:
        body = request.get_json(force=True) or {}
        from zero_trust.policy_engine.policy_engine import policy_engine
        success = policy_engine.add_policy(body)
        if success:
            return jsonify({"status": "ok", "message": "Policy added", "policy_id": body.get("id")})
        return jsonify({"status": "error", "message": "Invalid policy definition"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Device Trust ──────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/device-trust")
def zt_device_trust():
    """Return current device trust assessment."""
    try:
        from zero_trust.device_trust.device_assessor import device_assessor
        assessment = device_assessor.assess()
        return jsonify({"status": "ok", "data": assessment})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.get("/api/zero-trust/device-trust/history")
def zt_device_trust_history():
    """Return device trust history from DB."""
    try:
        history = db.get_device_posture_history(limit=20)
        return jsonify({"status": "ok", "data": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Identity ──────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/identity")
def zt_identity():
    """Return current user identity context."""
    try:
        from zero_trust.identity.identity_manager import identity_manager
        ctx  = identity_manager.get_identity_context()
        risk = identity_manager.get_identity_risk()
        return jsonify({"status": "ok", "data": {"context": ctx, "risk": risk}})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Application Trust ─────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/app-trust")
def zt_app_trust():
    """Return all tracked application trust profiles."""
    try:
        from zero_trust.application_trust.app_assessor import app_assessor
        profiles = app_assessor.get_app_profiles()
        return jsonify({"status": "ok", "data": profiles, "count": len(profiles)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Process Trust ─────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/process-trust")
def zt_process_trust():
    """Return trust assessment for all running processes (top 50 by risk)."""
    try:
        from zero_trust.process_trust.process_assessor import process_assessor
        processes = process_assessor.assess_all_running(max_processes=50)
        # Filter to non-trivial processes (risk > 0)
        flagged   = [p for p in processes if p.get("process_risk_score", 0) > 0]
        return jsonify({
            "status": "ok",
            "data"  : {
                "processes": processes[:25],   # Top 25 by risk
                "flagged"  : flagged[:10],     # Top 10 flagged
                "total"    : len(processes),
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Behavior ──────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/behavior")
def zt_behavior():
    """Return all behavioral profiles."""
    try:
        from abtd.behavior_engine.behavior_engine import behavior_engine
        profiles = behavior_engine.get_all_profiles()
        return jsonify({"status": "ok", "data": profiles, "count": len(profiles)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Resources ─────────────────────────────────────────────────────────────────

@zero_trust_bp.get("/api/zero-trust/resources")
def zt_resources():
    """Return all registered sensitive resources."""
    try:
        from zero_trust.resource_protection.resource_registry import resource_registry
        resources = resource_registry.list_resources()
        return jsonify({"status": "ok", "data": resources, "count": len(resources)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@zero_trust_bp.post("/api/zero-trust/resources/check")
def zt_check_resource():
    """Check if an entity's trust score allows access to a resource."""
    try:
        body         = request.get_json(force=True) or {}
        resource     = body.get("resource", "")
        trust_score  = int(body.get("trust_score", 50))
        from zero_trust.resource_protection.resource_registry import resource_registry
        result = resource_registry.check_access(resource, trust_score)
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

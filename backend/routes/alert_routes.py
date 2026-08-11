"""
backend/routes/alert_routes.py
================================
Blueprint: /api/*-alerts, /api/threats/hourly
Agent-generated alert feeds for the dashboard.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from backend.database import db

alert_bp = Blueprint("alert", __name__)


@alert_bp.route("/api/file-alerts", methods=["GET"])
def file_alerts():
    limit = min(100, int(request.args.get("limit", 20)))
    return jsonify(db.get_alerts(alert_type="file", limit=limit)), 200


@alert_bp.route("/api/process-alerts", methods=["GET"])
def process_alerts():
    limit = min(100, int(request.args.get("limit", 20)))
    return jsonify(db.get_alerts(alert_type="process", limit=limit)), 200


@alert_bp.route("/api/network-alerts", methods=["GET"])
def network_alerts():
    limit = min(100, int(request.args.get("limit", 20)))
    return jsonify(db.get_alerts(alert_type="network", limit=limit)), 200


@alert_bp.route("/api/registry-alerts", methods=["GET"])
def registry_alerts():
    limit = min(100, int(request.args.get("limit", 20)))
    return jsonify(db.get_alerts(alert_type="registry", limit=limit)), 200


@alert_bp.route("/api/usb-alerts", methods=["GET"])
def usb_alerts():
    limit = min(100, int(request.args.get("limit", 20)))
    return jsonify(db.get_alerts(alert_type="usb", limit=limit)), 200


@alert_bp.route("/api/threats/hourly", methods=["GET"])
def hourly_threats():
    """Return hourly threat count for the past 24 hours."""
    if not db.is_connected:
        return jsonify([]), 200
    try:
        from datetime import datetime, timezone, timedelta
        from pymongo import DESCENDING
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        pipeline = [
            {"$match": {
                "timestamp": {"$gte": since.isoformat()},
                "classification": {"$in": ["MALICIOUS", "CRITICAL", "SUSPICIOUS"]},
            }},
            {"$group": {
                "_id": {"$substr": ["$timestamp", 0, 13]},
                "count": {"$sum": 1},
            }},
            {"$sort": {"_id": 1}},
        ]
        import config
        result = list(db._db[config.COLLECTIONS["scans"]].aggregate(pipeline))
        return jsonify(result), 200
    except Exception as e:
        return jsonify([]), 200


@alert_bp.route("/api/quarantine", methods=["GET"])
def quarantine_list():
    return jsonify(db.get_quarantine_list()), 200

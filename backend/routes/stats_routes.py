"""
backend/routes/stats_routes.py
================================
Blueprint: /api/stats, /api/history, /api/recent-threats
Dashboard statistics and paginated history endpoints.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from backend.database import db
import config

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/api/stats", methods=["GET"])
def get_stats():
    """Return dashboard KPI statistics."""
    return jsonify(db.get_stats()), 200


@stats_bp.route("/api/history", methods=["GET"])
def get_history():
    """
    Return paginated scan history.

    Query params:
        page        : int (default 1)
        page_size   : int (default 25)
        type        : url | file | process (optional filter)
        classification: SAFE | SUSPICIOUS | MALICIOUS | CRITICAL (optional)
    """
    page           = max(1, int(request.args.get("page", 1)))
    page_size      = min(100, int(request.args.get("page_size", config.PAGE_SIZE)))
    target_type    = request.args.get("type")
    classification = request.args.get("classification")

    result = db.get_scan_history(
        page=page,
        page_size=page_size,
        target_type=target_type,
        classification=classification,
    )
    return jsonify(result), 200


@stats_bp.route("/api/recent-threats", methods=["GET"])
def recent_threats():
    """Return the 10 most recent threats (SUSPICIOUS/MALICIOUS/CRITICAL)."""
    result = db.get_scan_history(
        page=1, page_size=10, classification=None
    )
    threats = [
        r for r in result["items"]
        if r.get("classification") in ("SUSPICIOUS", "MALICIOUS", "CRITICAL")
    ][:10]
    return jsonify(threats), 200


@stats_bp.route("/api/threats/timeline", methods=["GET"])
def threat_timeline():
    """Return daily threat counts for chart rendering."""
    days = min(30, int(request.args.get("days", 7)))
    data = db.get_threat_timeline(days=days)
    return jsonify(data), 200


@stats_bp.route("/api/threats/combined", methods=["GET"])
def combined_feed():
    """All threat records — URLs + files + processes combined."""
    page      = max(1, int(request.args.get("page", 1)))
    page_size = min(100, int(request.args.get("page_size", 20)))
    result    = db.get_scan_history(page=page, page_size=page_size)
    return jsonify(result), 200

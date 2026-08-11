"""
backend/routes/settings_routes.py
====================================
Blueprint: GET/POST /api/settings
Read and update system configuration at runtime.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from backend.database import db

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(db.get_settings()), 200


@settings_bp.route("/api/settings", methods=["POST"])
def update_settings():
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No settings provided"}), 400

    # Whitelist of allowed keys
    allowed = {
        "agent_enabled", "scan_interval", "gemini_enabled",
        "notifications", "auto_quarantine", "threat_threshold",
        "watched_dirs",
    }
    filtered = {k: v for k, v in data.items() if k in allowed}

    current = db.get_settings()
    current.update(filtered)
    db.save_settings(current)

    return jsonify({"message": "Settings updated", "settings": current}), 200

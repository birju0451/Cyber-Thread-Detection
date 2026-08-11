"""
backend/routes/scan_routes.py
==============================
Blueprint: /api/scan
Manual URL and file scans from the web dashboard.
"""

import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from engine.predictor import engine
from backend.database import db
from backend.utils    import gemini_explain
from backend.logger   import log_api

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/api/scan", methods=["POST"])
def manual_scan():
    """
    Dashboard manual scan endpoint.

    Request JSON:
        { "target": "https://example.com", "type": "url" }
        { "target": "C:/Users/User/Downloads/file.exe", "type": "file" }

    Response JSON: Full ABTD analysis result
    """
    data        = request.get_json(silent=True) or {}
    target      = str(data.get("target", "")).strip()
    target_type = str(data.get("type", "url")).lower()

    if not target:
        return jsonify({"error": "Missing 'target' field"}), 400

    if target_type not in ("url", "file"):
        return jsonify({"error": "type must be 'url' or 'file'"}), 400

    log_api.info(f"Manual scan [{target_type}] → {target[:80]}")

    if target_type == "url":
        result = engine.analyze_url(target)
    else:
        if not os.path.exists(target):
            return jsonify({"error": f"File not found: {target}"}), 404
        result = engine.analyze_file(target)

    db.log_scan(result)

    # Gemini AI explanation for threats
    if result["classification"] in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
        result["ai_explanation"] = gemini_explain(result)
    else:
        result["ai_explanation"] = ""

    return jsonify(result), 200

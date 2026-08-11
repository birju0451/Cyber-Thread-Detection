"""
backend/routes/predict_routes.py
==================================
Blueprint: /predict
Used by the Chrome Extension to analyze URLs in real time.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, request, jsonify
from engine.predictor import engine
from backend.database import db
from backend.utils    import gemini_explain
from backend.logger   import log_api

predict_bp = Blueprint("predict", __name__)


@predict_bp.route("/predict", methods=["POST"])
def predict():
    """
    Analyze a URL from the Chrome Extension.

    Request JSON:  { "url": "https://example.com" }
    Response JSON: Full ABTD analysis result + optional Gemini explanation
    """
    data = request.get_json(silent=True) or {}
    url  = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400

    log_api.info(f"Extension scan → {url[:80]}")

    result = engine.analyze_url(url, skip_reputation=False)

    # Persist to MongoDB
    db.log_scan(result)

    # Gemini explanation (if enabled)
    if result["classification"] in ("SUSPICIOUS", "MALICIOUS", "CRITICAL"):
        result["ai_explanation"] = gemini_explain(result)
    else:
        result["ai_explanation"] = ""

    return jsonify(result), 200

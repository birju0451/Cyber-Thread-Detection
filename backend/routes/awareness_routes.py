"""
backend/routes/awareness_routes.py
=====================================
Blueprint: /api/awareness, /api/awareness/<topic>
Serve cybersecurity education content from awareness/ JSON files.
"""

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, jsonify
import config

awareness_bp = Blueprint("awareness", __name__)

_TOPIC_META = {
    "phishing"           : {"title": "Phishing Attacks",        "icon": "🎣", "color": "#ef4444"},
    "malware"            : {"title": "Malware & Viruses",       "icon": "🦠", "color": "#f59e0b"},
    "ransomware"         : {"title": "Ransomware",              "icon": "🔒", "color": "#7c3aed"},
    "password_security"  : {"title": "Password Security",       "icon": "🔑", "color": "#3b82f6"},
    "social_engineering" : {"title": "Social Engineering",      "icon": "🎭", "color": "#ec4899"},
    "safe_browsing"      : {"title": "Safe Browsing",           "icon": "🛡️", "color": "#22c55e"},
}


def _load_topic(slug: str) -> dict | None:
    path = config.AWARENESS_DIR / f"{slug}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@awareness_bp.route("/api/awareness", methods=["GET"])
def list_topics():
    """List all available awareness topics."""
    topics = []
    for slug, meta in _TOPIC_META.items():
        data = _load_topic(slug)
        topics.append({
            "slug"    : slug,
            "title"   : meta["title"],
            "icon"    : meta["icon"],
            "color"   : meta["color"],
            "summary" : data.get("summary", "") if data else "",
        })
    return jsonify(topics), 200


@awareness_bp.route("/api/awareness/<slug>", methods=["GET"])
def get_topic(slug: str):
    """Return full content for a single awareness topic."""
    if slug not in _TOPIC_META:
        return jsonify({"error": f"Topic '{slug}' not found"}), 404

    data = _load_topic(slug)
    if data is None:
        return jsonify({"error": "Content not available"}), 404

    return jsonify({**_TOPIC_META[slug], "slug": slug, **data}), 200

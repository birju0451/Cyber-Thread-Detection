"""
backend/utils.py
=================
Shared utility functions for the ABTD Flask backend.
"""

import sys
import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config


def hash_file(file_path: str, algorithm: str = "sha256") -> str | None:
    """Compute file hash. Returns hex string or None on error."""
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def safe_str(value, max_len: int = 500) -> str:
    """Safely convert any value to a truncated string."""
    return str(value)[:max_len] if value is not None else ""


def utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def paginate(items: list, page: int, page_size: int) -> dict:
    """Paginate a list in memory."""
    total = len(items)
    start = (page - 1) * page_size
    end   = start + page_size
    return {
        "items" : items[start:end],
        "total" : total,
        "page"  : page,
        "pages" : (total + page_size - 1) // page_size,
    }


def gemini_explain(threat_result: dict) -> str:
    """
    Use Google Gemini to generate a natural-language threat explanation.
    Returns explanation string or empty string if Gemini is disabled/unavailable.
    """
    if not config.GEMINI_ENABLED or not config.GEMINI_API_KEY:
        return ""

    try:
        import google.generativeai as genai
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel(config.GEMINI_MODEL)

        target = (
            threat_result.get("url") or
            threat_result.get("file_name") or
            threat_result.get("process_name") or
            "Unknown target"
        )
        classification = threat_result.get("classification", "UNKNOWN")
        threat_score   = threat_result.get("threat_score", 0)
        reasons        = threat_result.get("reasons", [])

        prompt = f"""You are a cybersecurity expert. A user's ABTD (Adaptive Behavioral Threat Detection) system
has analyzed the following target and produced these results:

Target: {target}
Classification: {classification}
Threat Score: {threat_score}/100
Detection Reasons:
{chr(10).join(f"- {r}" for r in reasons[:5])}

In 2-3 clear, non-technical sentences explain to the user:
1. What this threat means
2. Why it was flagged
3. What they should do

Keep it simple, friendly, and actionable. Do NOT use markdown or bullet points."""

        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"AI explanation unavailable: {e}"

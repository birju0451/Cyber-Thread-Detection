"""
engine/url_analyzer.py
=======================
Layer 1+2 of ABTD for URLs:
  - Extracts 30 URL features
  - Runs the trained Random Forest URL classifier
  - Returns RF score (0–100) and a label

Falls back gracefully if the model is not yet trained.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

import numpy as np

_model = None   # Lazy-loaded on first use


def _load_model():
    global _model
    if _model is not None:
        return _model
    if not config.URL_MODEL_PATH.exists():
        return None
    try:
        import joblib
        _model = joblib.load(config.URL_MODEL_PATH)
        return _model
    except Exception as e:
        print(f"[URLAnalyzer] Model load error: {e}")
        return None


def analyze(url: str) -> dict:
    """
    Analyze a URL using the trained RF classifier.

    Returns:
        {
          "rf_score"   : float (0–100),
          "prediction" : str ("benign" | "malicious"),
          "confidence" : float (0–1),
          "model_used" : bool,
        }
    """
    from ml.feature_engineering import extract_url_features, URL_FEATURE_COLS

    features = extract_url_features(url)
    feature_vector = [features.get(col, 0.0) for col in URL_FEATURE_COLS]

    model = _load_model()

    if model is None:
        # Fallback: heuristic score from features
        heuristic = (
            features.get("has_ip", 0) * 30 +
            features.get("has_at_symbol", 0) * 20 +
            features.get("is_url_shortener", 0) * 15 +
            features.get("has_hex_chars", 0) * 10 +
            features.get("has_suspicious_word", 0) * 10 +
            (1 - features.get("has_https", 1)) * 10
        )
        heuristic = min(heuristic, 100)
        return {
            "rf_score"   : float(heuristic),
            "prediction" : "malicious" if heuristic >= 50 else "benign",
            "confidence" : 0.5,
            "model_used" : False,
        }

    X = np.array(feature_vector).reshape(1, -1)
    proba = model.predict_proba(X)[0]
    # proba[1] = probability of class 1 (malicious/phishing)
    malicious_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
    rf_score       = round(malicious_prob * 100, 2)
    prediction     = "malicious" if malicious_prob >= 0.5 else "benign"
    confidence     = max(proba)

    return {
        "rf_score"   : rf_score,
        "prediction" : prediction,
        "confidence" : float(confidence),
        "model_used" : True,
    }

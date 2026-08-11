"""
engine/predictor.py
====================
ABTD Main Orchestrator — ties all 5 detection layers together.

This is THE entry point for all threat analysis in the system.
The Flask routes and Windows agent both call this module.

Public API:
    engine = ABTDEngine()
    result = engine.analyze_url("https://suspicious.tk/login?verify=account")
    result = engine.analyze_file("C:/Users/User/Downloads/invoice.exe")
    result = engine.analyze_process(pid=1234, name="powershell.exe", cmdline="...")
"""

import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

from engine.url_analyzer    import analyze as analyze_url_ml
from engine.memory_analyzer import analyze as analyze_memory_ml
from engine.rule_engine     import rule_engine
from engine.reputation      import reputation_analyzer
from engine.threat_scorer   import threat_scorer


# ---------------------------------------------------------------------------
# ABTD Engine
# ---------------------------------------------------------------------------

class ABTDEngine:
    """
    Adaptive Behavioral Threat Detection Engine.

    Orchestrates all 5 detection layers:
      1. Feature Extraction
      2. Random Forest Classifier
      3. Isolation Forest Anomaly Detector
      4. Rule-Based Heuristics
      5. Reputation Analysis
      → Adaptive Threat Score Fusion
    """

    def analyze_url(self, url: str, skip_reputation: bool = False) -> dict:
        """
        Full ABTD analysis of a URL.

        Args:
            url              : The URL to analyze
            skip_reputation  : Skip WHOIS/DNSBL (faster, useful for batch)

        Returns a comprehensive threat analysis dict.
        """
        t_start = time.time()
        url     = str(url).strip()
        reasons = []

        # ── Layer 2: Random Forest ────────────────────────────────────
        try:
            url_result = analyze_url_ml(url)
            rf_score   = url_result["rf_score"]
            prediction = url_result["prediction"]
        except Exception as e:
            rf_score   = 0.0
            prediction = "unknown"
            reasons.append(f"ML model unavailable: {e}")

        # ── Layer 3: Anomaly Score ────────────────────────────────────
        # For URLs we proxy anomaly from URL structural features
        # (True memory anomaly is used for processes)
        anomaly_score = 0.0
        if rf_score > 70:
            anomaly_score = min(rf_score * 0.6, 100)

        # ── Layer 4: Rule Engine ──────────────────────────────────────
        try:
            rule_result  = rule_engine.analyze_url(url)
            rule_score   = rule_result["score"]
            reasons.extend(rule_result["reasons"])
        except Exception as e:
            rule_score = 0.0
            reasons.append(f"Rule engine error: {e}")

        # ── Layer 5: Reputation ───────────────────────────────────────
        reputation_score = 0.0
        rep_details      = {}
        if not skip_reputation:
            try:
                rep_result       = reputation_analyzer.analyze_url(url)
                reputation_score = rep_result["score"]
                rep_details      = rep_result.get("details", {})
                reasons.extend(rep_result["reasons"])
            except Exception as e:
                reasons.append(f"Reputation check unavailable: {e}")

        # ── Score Fusion ──────────────────────────────────────────────
        fusion = threat_scorer.fuse(
            rf_score         = rf_score,
            anomaly_score    = anomaly_score,
            rule_score       = rule_score,
            reputation_score = reputation_score,
        )

        elapsed_ms = round((time.time() - t_start) * 1000, 1)

        return {
            "url"                : url,
            "target_type"        : "url",
            "timestamp"          : datetime.now(timezone.utc).isoformat(),
            "prediction"         : fusion["classification"].lower(),
            "classification"     : fusion["classification"],
            "threat_score"       : fusion["threat_score"],
            "confidence"         : fusion["confidence"],
            "recommended_action" : fusion["recommended_action"],
            "color"              : fusion["color"],
            "icon"               : fusion["icon"],
            "reasons"            : reasons if reasons else ["No specific threat indicators found"],
            "detection_modules"  : {
                "random_forest"  : {"score": rf_score,         "label": prediction},
                "anomaly"        : {"score": anomaly_score,    "label": "anomaly" if anomaly_score > 50 else "normal"},
                "rules"          : {"score": rule_score,       "flags": rule_result.get("flags", {}) if 'rule_result' in dir() else {}},
                "reputation"     : {"score": reputation_score, "details": rep_details},
            },
            "layer_scores"       : fusion["layer_scores"],
            "analysis_time_ms"   : elapsed_ms,
        }

    def analyze_file(self, file_path: str) -> dict:
        """
        Analyze a file for malware using rules and ML.

        Returns full threat analysis dict.
        """
        t_start    = time.time()
        reasons    = []
        path       = Path(file_path)

        # ── Layer 4: Rule Engine (File) ───────────────────────────────
        try:
            rule_result = rule_engine.analyze_file(file_path)
            rule_score  = rule_result["score"]
            reasons.extend(rule_result["reasons"])
        except Exception as e:
            rule_score = 0.0

        # ── ML: Malware Classifier ────────────────────────────────────
        rf_score = 0.0
        try:
            if config.MALWARE_MODEL_PATH.exists():
                import joblib
                import numpy as np
                from ml.feature_engineering import extract_file_features, MALWARE_FEATURE_COLS

                bundle   = joblib.load(config.MALWARE_MODEL_PATH)
                pipeline = bundle["pipeline"]
                feat_cols= bundle["feature_cols"]
                features = extract_file_features(file_path)
                X        = np.array([features.get(c, 0.0) for c in feat_cols]).reshape(1, -1)
                proba    = pipeline.predict_proba(X)[0]
                rf_score = float(proba[1] if len(proba) > 1 else proba[0]) * 100
                if rf_score > 50:
                    reasons.append(f"Malware classifier flagged this file (confidence: {rf_score:.1f}%)")
        except Exception as e:
            reasons.append(f"Malware model unavailable: {e}")

        # ── Score Fusion ──────────────────────────────────────────────
        fusion = threat_scorer.fuse(
            rf_score         = rf_score,
            anomaly_score    = 0.0,
            rule_score       = rule_score,
            reputation_score = 0.0,
        )

        elapsed_ms = round((time.time() - t_start) * 1000, 1)

        return {
            "file_path"          : str(file_path),
            "file_name"          : path.name,
            "target_type"        : "file",
            "timestamp"          : datetime.now(timezone.utc).isoformat(),
            "prediction"         : fusion["classification"].lower(),
            "classification"     : fusion["classification"],
            "threat_score"       : fusion["threat_score"],
            "confidence"         : fusion["confidence"],
            "recommended_action" : fusion["recommended_action"],
            "color"              : fusion["color"],
            "icon"               : fusion["icon"],
            "reasons"            : reasons if reasons else ["No specific threat indicators found"],
            "detection_modules"  : {
                "random_forest"  : {"score": rf_score,  "label": "malware" if rf_score >= 50 else "benign"},
                "anomaly"        : {"score": 0.0,       "label": "normal"},
                "rules"          : {"score": rule_score, "flags": rule_result.get("flags", {}) if 'rule_result' in dir() else {}},
                "reputation"     : {"score": 0.0,       "details": {}},
            },
            "layer_scores"       : fusion["layer_scores"],
            "analysis_time_ms"   : elapsed_ms,
        }

    def analyze_process(self, pid: int, name: str, cmdline: str = "") -> dict:
        """
        Analyze a running process for malicious behavior.
        """
        t_start = time.time()
        reasons = []

        # ── Layer 4: Rule Engine (Process) ────────────────────────────
        try:
            rule_result = rule_engine.analyze_process(name, cmdline)
            rule_score  = rule_result["score"]
            reasons.extend(rule_result["reasons"])
        except Exception:
            rule_score = 0.0

        # ── Layer 3: Memory Anomaly ───────────────────────────────────
        from engine.memory_analyzer import analyze_process_memory
        try:
            mem_result    = analyze_process_memory(pid)
            anomaly_score = mem_result["anomaly_score"]
            if mem_result["is_anomaly"]:
                reasons.append(f"Process memory pattern is anomalous (score: {anomaly_score:.1f})")
        except Exception:
            anomaly_score = 0.0

        fusion = threat_scorer.fuse(
            rf_score         = 0.0,
            anomaly_score    = anomaly_score,
            rule_score       = rule_score,
            reputation_score = 0.0,
        )

        elapsed_ms = round((time.time() - t_start) * 1000, 1)

        return {
            "pid"                : pid,
            "process_name"       : name,
            "cmdline"            : cmdline[:200],
            "target_type"        : "process",
            "timestamp"          : datetime.now(timezone.utc).isoformat(),
            "prediction"         : fusion["classification"].lower(),
            "classification"     : fusion["classification"],
            "threat_score"       : fusion["threat_score"],
            "confidence"         : fusion["confidence"],
            "recommended_action" : fusion["recommended_action"],
            "color"              : fusion["color"],
            "icon"               : fusion["icon"],
            "reasons"            : reasons if reasons else ["Process appears normal"],
            "detection_modules"  : {
                "random_forest"  : {"score": 0.0,          "label": "n/a"},
                "anomaly"        : {"score": anomaly_score, "label": "anomaly" if anomaly_score > 50 else "normal"},
                "rules"          : {"score": rule_score,    "flags": {}},
                "reputation"     : {"score": 0.0,           "details": {}},
            },
            "layer_scores"       : fusion["layer_scores"],
            "analysis_time_ms"   : elapsed_ms,
        }


# Singleton used by all routes and agent
engine = ABTDEngine()

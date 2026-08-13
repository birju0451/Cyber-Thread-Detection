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

        except Exception:
            rule_result = {"score": 0, "reasons": [], "flags": {}}
            rule_score  = 0.0

        # ── File Analyzer (entropy + PE + malware ML) ─────────────────
        rf_score      = 0.0
        anomaly_score = 0.0
        fa_result     = {}
        try:
            from engine.file_analyzer import analyze_file as fa_analyze
            fa_result = fa_analyze(file_path)
            rf_score  = float(fa_result.get("ml_score", 0))
            for r in fa_result.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)

            # Entropy anomaly → anomaly detection layer
            entropy = fa_result.get("entropy", 0.0)
            if entropy > 7.5:
                anomaly_score = min((entropy - 7.0) * 50, 85)
            elif entropy > 7.0:
                anomaly_score = min((entropy - 7.0) * 30, 60)
        except Exception as e:
            reasons.append(f"File analyzer error: {e}")

        # ── Score Fusion ──────────────────────────────────────────────
        fusion = threat_scorer.fuse(
            rf_score         = rf_score,
            anomaly_score    = anomaly_score,
            rule_score       = rule_score,
            reputation_score = 0.0,
        )

        elapsed_ms = round((time.time() - t_start) * 1000, 1)

        return {
            "file_path"          : str(file_path),
            "file_name"          : path.name,
            "file_size_bytes"    : fa_result.get("file_size_bytes", 0),
            "extension"          : fa_result.get("extension", path.suffix.lower()),
            "sha256"             : fa_result.get("sha256", ""),
            "entropy"            : fa_result.get("entropy", 0.0),
            "is_pe"              : fa_result.get("is_pe", False),
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
                "random_forest"  : {"score": rf_score,      "label": "malware" if rf_score >= 50 else "benign"},
                "anomaly"        : {"score": anomaly_score,  "label": "anomaly" if anomaly_score > 50 else "normal"},
                "rules"          : {"score": rule_score,     "flags": rule_result.get("flags", {})},
                "reputation"     : {"score": 0.0,            "details": {}},
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

    # ── Full Hybrid Analysis (7 Layers) ──────────────────────────

    def full_analysis(self, event: dict) -> dict:
        """
        Full 7-layer ABTD hybrid analysis orchestrating ALL detection modules.

        Layers:
          1. Feature Extraction (extract_url_features / extract_file_features)
          2. Random Forest Classifier (supervised ML)
          3. Isolation Forest Anomaly Detector (unsupervised ML)
          4. Rule-Based Heuristics
          5. Reputation Analysis
          6. Behavior Engine (temporal pattern profiling)
          7. Correlation Engine (multi-event incident grouping)
          → Adaptive Weighted Fusion → final score & classification

        Args:
            event: {
                "event_type": str, "resource": str,
                "process_name": str, "details": dict, ...
            }

        Returns:
            Full ABTD analysis result with all 7 layer scores.
        """
        t_start = time.time()
        event_type   = event.get("event_type", "unknown")
        resource     = event.get("resource", "")
        process_name = event.get("process_name", "")
        pid          = event.get("process_pid", 0)
        cmdline      = event.get("process_cmdline", "")

        # ── Base ABTD Analysis (Layers 1-5) ───────────────────────
        if event_type in ("url_visit", "url_block"):
            base_result = self.analyze_url(resource, skip_reputation=False)
        elif event_type in ("file_execute", "file_download", "file_write",
                            "file_create", "file_delete"):
            if Path(resource).exists():
                base_result = self.analyze_file(resource)
            else:
                base_result = {
                    "threat_score": 0, "classification": "UNKNOWN",
                    "confidence": 0.3, "reasons": [f"File inaccessible: {resource}"],
                    "detection_modules": {},
                }
        elif event_type in ("process_create", "blocked_process"):
            base_result = self.analyze_process(pid, process_name, cmdline)
        else:
            # For other event types, use rule engine only
            rule_flags = rule_engine.evaluate_event(event)
            rule_score = sum(rule_flags.values()) * 20 if rule_flags else 0
            base_result = {
                "threat_score": min(rule_score, 100),
                "classification": (
                    "CRITICAL" if rule_score >= 75 else
                    "MALICIOUS" if rule_score >= 50 else
                    "SUSPICIOUS" if rule_score >= 25 else "SAFE"
                ),
                "confidence": 0.5,
                "reasons": [f"Rule: {k}" for k, v in (rule_flags or {}).items() if v],
                "detection_modules": {"rules": {"score": rule_score, "flags": rule_flags}},
            }

        # ── Layer 6: Behavior Engine ──────────────────────────────
        behavior_score = 0.0
        behavior_data  = {}
        try:
            from abtd.behavior_engine.behavior_engine import behavior_engine
            entity_id = process_name or resource[:50]
            behavior_engine.record_event(
                entity_id  = entity_id,
                event_type = event_type,
                details    = event.get("details", {}),
                risk_delta = base_result.get("threat_score", 0) * 0.1,
            )
            behavior_score = behavior_engine.get_behavior_risk(entity_id)
            behavior_data  = {
                "entity_id": entity_id,
                "risk": behavior_score,
                "profile": behavior_engine.get_profile(entity_id),
            }
        except Exception:
            pass

        # ── Layer 7: Correlation Engine ───────────────────────────
        correlation_data = {}
        try:
            from abtd.correlation_engine.correlation_engine import correlation_engine
            threat_score = base_result.get("threat_score", 0)
            severity = (
                "CRITICAL" if threat_score >= 75 else
                "HIGH"     if threat_score >= 50 else
                "MEDIUM"   if threat_score >= 25 else "LOW"
            )
            corr_event = {
                "event_type" : event_type,
                "entity_id"  : process_name or resource[:50],
                "severity"   : severity,
                "risk_score" : threat_score,
                "description": "; ".join(base_result.get("reasons", [])[:3]),
                "source"     : event.get("source", "engine"),
            }
            correlation_data = correlation_engine.submit_event(corr_event)
        except Exception:
            pass

        # ── Fusion: Blend Layer 6 & 7 into base score ─────────────
        base_score = base_result.get("threat_score", 0)
        # Behavior contributes up to +15 points
        behavior_boost = min(behavior_score * 0.15, 15)
        # Correlation contributes up to +10 points if incident was created
        corr_boost = 10 if correlation_data.get("incident_created") else 0

        final_score = min(100, base_score + behavior_boost + corr_boost)
        final_score = round(final_score, 1)

        # Re-classify based on final score
        if final_score >= 75:
            final_cls = "CRITICAL"
        elif final_score >= 50:
            final_cls = "MALICIOUS"
        elif final_score >= 25:
            final_cls = "SUSPICIOUS"
        else:
            final_cls = "SAFE"

        elapsed_ms = round((time.time() - t_start) * 1000, 1)

        # Build 7-layer detection module report
        modules = base_result.get("detection_modules", {})
        modules["behavior"]    = {"score": behavior_score, "data": behavior_data}
        modules["correlation"] = {"score": corr_boost,     "data": correlation_data}

        reasons = list(base_result.get("reasons", []))
        if behavior_score > 30:
            reasons.append(f"Behavioral anomaly detected (risk={behavior_score:.0f})")
        if corr_boost > 0:
            reasons.append("Correlated with active security incident")

        return {
            "event_type"         : event_type,
            "resource"           : resource,
            "target_type"        : base_result.get("target_type", event_type),
            "timestamp"          : datetime.now(timezone.utc).isoformat(),
            "classification"     : final_cls,
            "threat_score"       : final_score,
            "confidence"         : base_result.get("confidence", 0.5),
            "recommended_action" : base_result.get("recommended_action", ""),
            "color"              : base_result.get("color", "#6b7280"),
            "icon"               : base_result.get("icon", "❓"),
            "reasons"            : reasons,
            "detection_modules"  : modules,
            "behavior_score"     : behavior_score,
            "correlation_active" : corr_boost > 0,
            "analysis_layers"    : 7,
            "analysis_time_ms"   : elapsed_ms,
        }


# Singleton used by all routes and agent
engine = ABTDEngine()


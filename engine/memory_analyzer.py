"""
engine/memory_analyzer.py
==========================
Isolation Forest anomaly detector for memory forensics data.
Used to detect obfuscated malware hiding in process memory.

Returns an anomaly score 0–100 (higher = more anomalous = more suspicious).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config
import numpy as np

_bundle = None


def _load_model():
    global _bundle
    if _bundle is not None:
        return _bundle
    if not config.MEMORY_MODEL_PATH.exists():
        return None
    try:
        import joblib
        _bundle = joblib.load(config.MEMORY_MODEL_PATH)
        return _bundle
    except Exception as e:
        print(f"[MemoryAnalyzer] Model load error: {e}")
        return None


def analyze(features: dict) -> dict:
    """
    Score a set of memory/process features for anomalies.

    Args:
        features: dict mapping feature names → numeric values
                  (as returned by psutil process inspection)

    Returns:
        {
          "anomaly_score": float (0–100, higher = more anomalous),
          "is_anomaly"   : bool,
          "model_used"   : bool,
        }
    """
    bundle = _load_model()

    if bundle is None:
        return {"anomaly_score": 0.0, "is_anomaly": False, "model_used": False}

    pipeline     = bundle["pipeline"]
    feature_cols = bundle["feature_cols"]

    # Build feature vector in the same order as training
    X = np.array([features.get(col, 0.0) for col in feature_cols]).reshape(1, -1)

    try:
        # decision_function: negative = anomaly (lower = more anomalous)
        score_raw  = pipeline.decision_function(X)[0]
        prediction = pipeline.predict(X)[0]   # -1=anomaly, +1=normal

        # Convert to 0–100 (higher = more anomalous)
        # Typical range of decision_function: [-0.5, 0.5]
        anomaly_score = max(0.0, min((-score_raw + 0.5) * 100, 100.0))
        is_anomaly    = (prediction == -1)

        return {
            "anomaly_score": round(anomaly_score, 2),
            "is_anomaly"   : is_anomaly,
            "model_used"   : True,
        }
    except Exception as e:
        return {"anomaly_score": 0.0, "is_anomaly": False, "model_used": False}


def analyze_process_memory(pid: int) -> dict:
    """
    Extract memory features from a live process and score it.

    Args:
        pid: Process ID

    Returns anomaly analysis result.
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        mem_info = proc.memory_info()

        features = {
            "rss"              : mem_info.rss,
            "vms"              : mem_info.vms,
            "num_threads"      : proc.num_threads(),
            "num_handles"      : proc.num_handles() if hasattr(proc, "num_handles") else 0,
            "cpu_percent"      : proc.cpu_percent(interval=0.1),
            "open_files_count" : len(proc.open_files()),
            "connections_count": len(proc.connections()),
        }
        return analyze(features)
    except Exception:
        return {"anomaly_score": 0.0, "is_anomaly": False, "model_used": False}

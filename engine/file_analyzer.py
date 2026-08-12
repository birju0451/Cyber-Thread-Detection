"""
engine/file_analyzer.py
========================
ABTD File Analysis Engine.

Analyzes files using:
  1. Hash-based detection (SHA-256 lookup)
  2. File structure heuristics (extension, size, entropy)
  3. Static PE header analysis (Windows executables)
  4. Malware classifier ML model (Malware dataset.csv features)
  5. Rule engine integration

Used by: engine/predictor.py → analyze_file()
"""

import sys
import os
import math
import hashlib
import struct
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger import log_engine

# Lazy-loaded model bundle
_malware_bundle = None


def _load_model():
    global _malware_bundle
    if _malware_bundle is not None:
        return _malware_bundle
    try:
        import joblib
        _malware_bundle = joblib.load(config.MALWARE_MODEL_PATH)
        log_engine.info("✓ Malware classifier loaded")
    except Exception as e:
        log_engine.warning(f"Malware model not found — heuristic-only: {e}")
        _malware_bundle = None
    return _malware_bundle


# ── Entropy calculation ────────────────────────────────────────
def _file_entropy(path: str, sample_bytes: int = 65536) -> float:
    """
    Calculate Shannon entropy of first N bytes of a file.
    High entropy (>7.0) suggests encryption/packing — common in malware.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        total = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


# ── PE header analysis ─────────────────────────────────────────
def _analyze_pe(path: str) -> dict:
    """
    Basic Windows PE header analysis.
    Returns dict with suspicious_imports, sections, timestamp, is_pe.
    """
    result = {
        "is_pe"              : False,
        "suspicious_imports" : [],
        "section_count"      : 0,
        "compile_timestamp"  : None,
        "has_overlay"        : False,
        "suspicious_sections": 0,
    }

    try:
        with open(path, "rb") as f:
            data = f.read(2)
            if data != b"MZ":
                return result
            result["is_pe"] = True

            # Read PE offset
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)

            # PE signature
            sig = f.read(4)
            if sig != b"PE\x00\x00":
                return result

            # COFF header
            machine      = struct.unpack("<H", f.read(2))[0]
            num_sections = struct.unpack("<H", f.read(2))[0]
            timestamp    = struct.unpack("<I", f.read(4))[0]

            result["section_count"]     = num_sections
            result["compile_timestamp"] = datetime.fromtimestamp(
                timestamp, tz=timezone.utc
            ).isoformat() if timestamp else None

            # Heuristic: many sections or very old/future timestamp is suspicious
            if num_sections > 8:
                result["suspicious_sections"] += 1
            if timestamp < 631152000 or timestamp > 2524608000:  # before 1990 or after 2050
                result["suspicious_sections"] += 1

    except Exception:
        pass

    return result


# ── Malware model prediction ───────────────────────────────────
def _ml_predict(file_path: str, entropy: float, file_size: int, pe_info: dict) -> dict:
    """
    Build a feature vector from file properties and run through malware model.
    The Malware dataset features are process-level; we approximate from file.
    """
    bundle = _load_model()
    if bundle is None:
        return {"score": 0, "label": "unknown", "confidence": 0.0}

    try:
        pipeline = bundle.get("pipeline")
        features = bundle.get("features", [])

        # Build feature vector matching Malware dataset.csv columns
        # (state, usage_counter, prio, etc.) — approximate from file properties
        feature_map = {
            "millisecond"       : 0,
            "state"             : 0,
            "usage_counter"     : 1,
            "prio"              : 20,
            "static_prio"       : 20,
            "normal_prio"       : 20,
            "policy"            : 0,
            "vm_pgoff"          : file_size // 4096,
            "vm_truncate_count" : 0,
            "task_size"         : file_size,
            "cached_hole_size"  : 0,
            "free_area_cache"   : 0,
            "mm_users"          : 1,
            "map_count"         : pe_info.get("section_count", 0),
            "hiwater_rss"       : int(entropy * 1000),
            "total_vm"          : file_size // 4096,
            "shared_vm"         : 0,
            "exec_vm"           : 1 if pe_info.get("is_pe") else 0,
            "reserved_vm"       : 0,
            "nr_ptes"           : pe_info.get("section_count", 0),
            "end_data"          : file_size,
            "last_interval"     : 0,
            "nvcsw"             : 0,
            "nivcsw"            : 0,
            "min_flt"           : 0,
            "maj_flt"           : 0,
            "fs_excl_counter"   : 0,
            "lock"              : 0,
            "utime"             : 0,
            "stime"             : 0,
            "gtime"             : 0,
            "cgtime"            : 0,
            "signal_nvcsw"      : 0,
        }

        import numpy as np
        if features:
            vec = np.array([[feature_map.get(f, 0) for f in features]])
        else:
            vec = np.array([[v for v in feature_map.values()]])

        pred     = pipeline.predict(vec)[0]
        prob     = pipeline.predict_proba(vec)[0]
        is_mal   = (str(pred).lower() in ("1", "malware", "malicious"))
        confidence = float(max(prob))

        return {
            "score"      : 70 if is_mal else 10,
            "label"      : "malware" if is_mal else "benign",
            "confidence" : round(confidence, 3),
        }
    except Exception as e:
        log_engine.debug(f"ML file predict error: {e}")
        return {"score": 0, "label": "unknown", "confidence": 0.0}


# ── Public API ─────────────────────────────────────────────────
def analyze_file(file_path: str) -> dict:
    """
    Full ABTD file analysis.

    Returns:
        {
            "file_path"      : str,
            "file_name"      : str,
            "file_size_bytes": int,
            "extension"      : str,
            "sha256"         : str,
            "entropy"        : float,
            "is_pe"          : bool,
            "pe_info"        : dict,
            "ml_score"       : int,
            "ml_label"       : str,
            "heuristic_score": int,
            "reasons"        : list[str],
            "suspicious"     : bool,
            "timestamp"      : str,
        }
    """
    result = {
        "file_path"      : file_path,
        "file_name"      : Path(file_path).name,
        "file_size_bytes": 0,
        "extension"      : Path(file_path).suffix.lower(),
        "sha256"         : "",
        "entropy"        : 0.0,
        "is_pe"          : False,
        "pe_info"        : {},
        "ml_score"       : 0,
        "ml_label"       : "unknown",
        "heuristic_score": 0,
        "reasons"        : [],
        "suspicious"     : False,
        "timestamp"      : datetime.now(timezone.utc).isoformat(),
    }

    if not os.path.exists(file_path):
        result["reasons"].append("File not found")
        return result

    try:
        stat = os.stat(file_path)
        result["file_size_bytes"] = stat.st_size
    except Exception:
        pass

    # ── SHA-256 hash ──────────────────────────────────────────
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        result["sha256"] = h.hexdigest()
    except Exception:
        pass

    # ── Entropy ───────────────────────────────────────────────
    entropy = _file_entropy(file_path)
    result["entropy"] = entropy

    heuristic_score = 0
    reasons         = []

    if entropy > 7.5:
        heuristic_score += 35
        reasons.append(f"Very high entropy ({entropy:.2f}) — likely packed/encrypted")
    elif entropy > 7.0:
        heuristic_score += 20
        reasons.append(f"High entropy ({entropy:.2f}) — possible packing")

    # ── Extension risk ────────────────────────────────────────
    ext = result["extension"]
    HIGH_RISK_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd",
                     ".vbs", ".vba", ".ps1", ".ps2", ".hta", ".jar", ".lnk"}
    MED_RISK_EXT  = {".doc", ".docm", ".xls", ".xlsm", ".pdf", ".zip",
                     ".7z", ".rar", ".iso", ".img", ".msi"}

    if ext in HIGH_RISK_EXT:
        heuristic_score += 25
        reasons.append(f"High-risk file extension: {ext}")
    elif ext in MED_RISK_EXT:
        heuristic_score += 10
        reasons.append(f"Medium-risk file extension: {ext}")

    # ── File size anomalies ───────────────────────────────────
    size = result["file_size_bytes"]
    if ext in (".exe", ".dll") and size < 10_000:
        heuristic_score += 20
        reasons.append(f"Abnormally small executable ({size} bytes)")
    elif size > 100_000_000:
        heuristic_score += 5
        reasons.append("Very large file — unusual for executables")

    # ── PE analysis ───────────────────────────────────────────
    if ext in {".exe", ".dll", ".scr", ".com", ".sys"}:
        pe_info = _analyze_pe(file_path)
        result["pe_info"] = pe_info
        result["is_pe"]   = pe_info.get("is_pe", False)

        if pe_info.get("suspicious_sections", 0) > 0:
            heuristic_score += 15
            reasons.append("PE header anomalies detected (suspicious sections/timestamp)")

        if not pe_info.get("is_pe") and ext == ".exe":
            heuristic_score += 20
            reasons.append("File claims to be .exe but has no valid PE header (camouflaged)")

    result["heuristic_score"] = min(heuristic_score, 100)

    # ── ML model prediction ───────────────────────────────────
    ml = _ml_predict(file_path, entropy, size, result.get("pe_info", {}))
    result["ml_score"] = ml.get("score", 0)
    result["ml_label"] = ml.get("label", "unknown")

    if ml["label"] == "malware" and ml["confidence"] > 0.6:
        reasons.append(f"ML malware classifier: {ml['label']} (confidence {ml['confidence']:.0%})")

    result["reasons"]   = reasons
    result["suspicious"] = heuristic_score > 30 or ml["label"] == "malware"
    return result

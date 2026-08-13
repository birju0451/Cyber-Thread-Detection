"""
tests/evaluation/evaluate_models.py
=====================================
Model Performance Evaluation — All 4 ML Models

Evaluates each trained model against held-out test samples and prints:
  - Accuracy, Precision, Recall, F1 Score
  - Confusion Matrix
  - ROC-AUC (where applicable)
  - Per-class statistics

Usage:
    python tests/evaluation/evaluate_models.py
    python tests/evaluation/evaluate_models.py --model url
    python tests/evaluation/evaluate_models.py --model malware
    python tests/evaluation/evaluate_models.py --model memory
    python tests/evaluation/evaluate_models.py --model behavior
"""

import sys
import argparse
import pickle
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import config

try:
    import pandas as pd
    import numpy as np
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, roc_auc_score,
        classification_report,
    )
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False
    print("❌ sklearn/pandas/numpy not installed. Run: pip install scikit-learn pandas numpy")
    sys.exit(1)

from ml.feature_engineering import extract_url_features, URL_FEATURE_COLS, MALWARE_FEATURE_COLS


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str):
    print("\n" + "═" * 60)
    print(f"  {title}")
    print("═" * 60)


def load_model(path: str):
    p = Path(path)
    if not p.exists():
        print(f"  ⚠️  Model not found: {path}")
        print(f"  → Run: python train_all.py")
        return None
    with open(p, "rb") as f:
        return pickle.load(f)


def print_metrics(y_true, y_pred, labels=None, y_prob=None):
    print(f"\n  Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
    print(f"  Precision : {precision_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"  Recall    : {recall_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"  F1 Score  : {f1_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")

    if y_prob is not None:
        try:
            auc = roc_auc_score(y_true, y_prob)
            print(f"  ROC-AUC   : {auc:.4f}")
        except Exception:
            pass

    print("\n  Classification Report:")
    print(classification_report(y_true, y_pred, target_names=labels, zero_division=0))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_true, y_pred)
    print(f"  {cm}")


# ─────────────────────────────────────────────────────────────────────────────
# URL Classifier Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_url_model():
    banner("URL / Phishing Classifier (Random Forest)")
    model = load_model(config.URL_MODEL_PATH)
    if not model:
        return

    # Built-in test samples (ground truth)
    test_data = [
        # (url, true_label)  0=benign, 1=phishing
        ("https://google.com",                                                     0),
        ("https://github.com",                                                     0),
        ("https://stackoverflow.com",                                              0),
        ("https://microsoft.com",                                                  0),
        ("https://wikipedia.org",                                                  0),
        ("https://youtube.com",                                                    0),
        ("https://amazon.com",                                                     0),
        ("http://192.168.1.100/paypal-login/verify",                               1),
        ("http://paypal-login-secure.xyz/account/update",                          1),
        ("http://amazon-account-suspended.tk/verify",                              1),
        ("http://bit.ly/3xSuspiciousLink",                                         1),
        ("http://45.33.32.156/malware",                                            1),
        ("http://secure-login.paypal.com.evil-phish.tk/verify/account",            1),
        ("http://free-iphone%20win%6Eer.click/claim%20prize",                      1),
    ]

    print(f"\n  Evaluating on {len(test_data)} test URLs...")
    features_list = []
    y_true = []

    for url, label in test_data:
        feats = extract_url_features(url)
        row = [feats.get(col, 0) for col in URL_FEATURE_COLS if col in feats]
        if len(row) == len(URL_FEATURE_COLS):
            features_list.append(row)
            y_true.append(label)
        elif hasattr(model, 'n_features_in_'):
            # Pad or truncate to match model input shape
            row = row[:model.n_features_in_] + [0] * max(0, model.n_features_in_ - len(row))
            features_list.append(row)
            y_true.append(label)

    if not features_list:
        print("  ❌ Could not extract features matching model input shape")
        return

    X = np.array(features_list)
    y_pred = model.predict(X)
    y_prob = None
    try:
        y_prob = model.predict_proba(X)[:, 1]
    except Exception:
        pass

    print_metrics(y_true, y_pred, labels=["Benign", "Phishing"], y_prob=y_prob)

    # Per-URL results
    print("\n  Per-URL Results:")
    print(f"  {'URL':<55} {'TRUE':>6} {'PRED':>6} {'MATCH':>6}")
    print("  " + "-" * 75)
    label_map = {0: "BENIGN", 1: "PHISH "}
    for i, (url, label) in enumerate(test_data[:len(y_pred)]):
        pred = y_pred[i]
        match = "✅" if pred == label else "❌"
        print(f"  {url[:53]:<55} {label_map[label]:>6} {label_map[pred]:>6}   {match}")


# ─────────────────────────────────────────────────────────────────────────────
# Malware Classifier Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_malware_model():
    banner("Malware Process Classifier (Random Forest)")
    model = load_model(config.MALWARE_MODEL_PATH)
    if not model:
        return

    # Minimal sanity check with synthetic feature vectors
    n_features = getattr(model, 'n_features_in_', len(MALWARE_FEATURE_COLS))
    print(f"\n  Model expects {n_features} features")

    # Create synthetic benign and malicious samples
    rng = np.random.RandomState(42)

    # Benign: low memory, normal CPU, known process names
    benign_samples  = rng.uniform(0.0, 0.3, size=(10, n_features))
    # Malicious: high memory spikes, anomalous patterns
    malicious_samples = rng.uniform(0.6, 1.0, size=(10, n_features))

    X = np.vstack([benign_samples, malicious_samples])
    y_true = [0] * 10 + [1] * 10  # 0=benign, 1=malware

    try:
        y_pred = model.predict(X)
        y_prob = None
        try:
            y_prob = model.predict_proba(X)[:, 1]
        except Exception:
            pass

        print_metrics(y_true, y_pred, labels=["Benign", "Malware"], y_prob=y_prob)
        print("\n  ℹ️  Synthetic samples used — train on real dataset for meaningful metrics.")
    except Exception as e:
        print(f"  ❌ Evaluation failed: {e}")
        print(f"  → Ensure model was trained with matching feature set")


# ─────────────────────────────────────────────────────────────────────────────
# Memory Anomaly Detector Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_memory_model():
    banner("Memory Anomaly Detector (Isolation Forest)")
    model = load_model(config.MEMORY_MODEL_PATH)
    if not model:
        return

    import os
    from engine.memory_analyzer import analyze

    print(f"\n  Testing on live processes (first 20 PIDs)...")
    import psutil
    results = []
    try:
        for proc in list(psutil.process_iter(["pid", "name"]))[:20]:
            try:
                pid  = proc.info["pid"]
                name = proc.info["name"]
                r    = analyze(pid)
                score = r.get("anomaly_score", 0)
                is_anomaly = r.get("is_anomaly", False)
                results.append((pid, name, score, is_anomaly))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        print(f"  ⚠️  Process iteration: {e}")

    if results:
        anomalies = [r for r in results if r[3]]
        print(f"\n  Processes analyzed : {len(results)}")
        print(f"  Anomalies flagged  : {len(anomalies)}")
        print(f"  Anomaly rate       : {len(anomalies)/len(results)*100:.1f}%")
        print(f"\n  {'PID':>7}  {'NAME':<25}  {'SCORE':>6}  {'ANOMALY':>8}")
        print("  " + "-" * 52)
        for pid, name, score, is_an in sorted(results, key=lambda x: -x[2]):
            flag = "🚨" if is_an else "✅"
            print(f"  {pid:>7}  {name:<25}  {score:>6}  {flag:>8}")
    else:
        print("  No results obtained")


# ─────────────────────────────────────────────────────────────────────────────
# Behavior / Network Anomaly Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_behavior_model():
    banner("Network Behavior Anomaly Detector (Isolation Forest)")
    model = load_model(config.BEHAVIOR_MODEL_PATH)
    if not model:
        return

    n_features = getattr(model, 'n_features_in_', 10)
    print(f"\n  Model expects {n_features} features")

    rng = np.random.RandomState(42)
    # Normal traffic
    normal   = rng.normal(loc=0.3, scale=0.1, size=(20, n_features)).clip(0, 1)
    # Anomalous traffic (C2 beaconing, DDoS)
    anomalous = rng.normal(loc=0.9, scale=0.05, size=(20, n_features)).clip(0, 1)

    X      = np.vstack([normal, anomalous])
    y_true = [1] * 20 + [-1] * 20  # 1=normal, -1=anomaly (IF convention)

    try:
        y_pred = model.predict(X)
        scores = model.decision_function(X)

        print(f"\n  Normal traffic   — avg IF score: {scores[:20].mean():.4f}")
        print(f"  Anomalous traffic — avg IF score: {scores[20:].mean():.4f}")

        correct_normal   = (y_pred[:20] == 1).sum()
        correct_anomaly  = (y_pred[20:] == -1).sum()
        print(f"\n  Normal correctly identified   : {correct_normal}/20")
        print(f"  Anomalies correctly identified : {correct_anomaly}/20")
        print(f"  Overall accuracy              : {(correct_normal+correct_anomaly)/40*100:.1f}%")
        print("\n  ℹ️  Synthetic samples — real dataset needed for production accuracy.")
    except Exception as e:
        print(f"  ❌ Evaluation error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ABTD ML Model Evaluator")
    parser.add_argument("--model", choices=["url", "malware", "memory", "behavior", "all"],
                        default="all", help="Model to evaluate")
    args = parser.parse_args()

    start = time.time()
    print("\n🔬 ABTD ML Model Evaluation Suite")
    print("=" * 60)

    if args.model in ("url",     "all"): evaluate_url_model()
    if args.model in ("malware", "all"): evaluate_malware_model()
    if args.model in ("memory",  "all"): evaluate_memory_model()
    if args.model in ("behavior","all"): evaluate_behavior_model()

    elapsed = time.time() - start
    print(f"\n✅ Evaluation complete in {elapsed:.1f}s")


if __name__ == "__main__":
    main()

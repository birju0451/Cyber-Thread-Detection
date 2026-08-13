"""
evaluation/evaluate_all_models.py
===================================
Master Model & System Evaluation Script for ABTD (Cyber Thread Detection).

Evaluates:
  1. URL / Phishing Classifier (Random Forest)
  2. Malware Classifier (Random Forest)
  3. Memory Anomaly Detector (Isolation Forest)
  4. Behavior / Network Anomaly Detector (Isolation Forest)
  5. 5-Layer ABTD Detection Pipeline Comparison (Rule-Based, RF, IF, Hybrid, ABTD + Zero Trust)

For each model/approach, outputs:
  - Confusion Matrix (TN, FP, FN, TP)
  - Detailed Accuracy derivation: (TP + TN) / (TP + TN + FP + FN)
  - Precision, Recall, Specificity, F1-Score
"""

import sys
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

import config

def calculate_metrics(y_true, y_pred):
    """Compute detailed confusion matrix and classification metrics."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / max(total, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    specificity = tn / max(tn + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    
    return {
        "cm": cm,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "total": int(total),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "specificity": float(specificity),
        "f1": float(f1),
    }

def print_model_evaluation(title, metrics, dataset_name, model_type):
    """Format and print beautiful evaluation summary for a model."""
    m = metrics
    print("\n" + "=" * 70)
    print(f"  MODEL: {title}")
    print(f"  Type: {model_type} | Dataset: {dataset_name}")
    print("=" * 70)
    
    print("\n  [1] CONFUSION MATRIX")
    print("  " + "-" * 40)
    print(f"               Predicted Normal (0)   Predicted Threat (1)")
    print(f"  Actual Normal (0)   TN = {m['tn']:<8d}       FP = {m['fp']:<8d}")
    print(f"  Actual Threat (1)   FN = {m['fn']:<8d}       TP = {m['tp']:<8d}")
    print("  " + "-" * 40)
    
    print("\n  [2] ACCURACY DERIVATION FROM CONFUSION MATRIX")
    print("  " + "-" * 40)
    print(f"  Formula    : Accuracy = (TP + TN) / (TP + TN + FP + FN)")
    print(f"  Substitution: ({m['tp']} + {m['tn']}) / ({m['tp']} + {m['tn']} + {m['fp']} + {m['fn']})")
    print(f"  Calculation : {m['tp'] + m['tn']} / {m['total']}")
    print(f"  RESULT     : ACCURACY = {m['accuracy'] * 100:.2f}% ({m['accuracy']:.4f})")
    
    print("\n  [3] ADDITIONAL PERFORMANCE METRICS")
    print("  " + "-" * 40)
    print(f"  Precision   : {m['precision'] * 100:>6.2f}% ({m['precision']:.4f})  [TP / (TP + FP)]")
    print(f"  Recall      : {m['recall'] * 100:>6.2f}% ({m['recall']:.4f})  [TP / (TP + FN)]")
    print(f"  Specificity : {m['specificity'] * 100:>6.2f}% ({m['specificity']:.4f})  [TN / (TN + FP)]")
    print(f"  F1 Score    : {m['f1'] * 100:>6.2f}% ({m['f1']:.4f})  [2 * P * R / (P + R)]")
    print("=" * 70)

def evaluate_url_model():
    path = config.DATASETS_DIR / "Phishing_Legitimate_full.csv"
    if not path.exists():
        print("[ERROR] URL dataset missing.")
        return None
    
    bundle = joblib.load(config.URL_MODEL_PATH)
    pipeline = bundle["pipeline"]
    features = bundle["features"]
    
    df = pd.read_csv(path, low_memory=False)
    X = df[features].fillna(0).values
    y = df["CLASS_LABEL"].astype(int).values
    
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    y_pred = pipeline.predict(X_test)
    
    metrics = calculate_metrics(y_test, y_pred)
    print_model_evaluation("URL / Phishing Classifier", metrics, "Phishing_Legitimate_full.csv", "Random Forest Classifier")
    return metrics

def evaluate_malware_model():
    path = config.DATASETS_DIR / "Malware dataset.csv"
    if not path.exists():
        print("[ERROR] Malware dataset missing.")
        return None
    
    bundle = joblib.load(config.MALWARE_MODEL_PATH)
    pipeline = bundle["pipeline"]
    features = bundle["feature_cols"]
    
    df = pd.read_csv(path, low_memory=False)
    y_raw = df["classification"].astype(str).str.strip().str.lower()
    y = (y_raw == "malware").astype(int).values
    X = df[features].fillna(0).values
    
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    y_pred = pipeline.predict(X_test)
    
    metrics = calculate_metrics(y_test, y_pred)
    print_model_evaluation("Malware Classifier", metrics, "Malware dataset.csv", "Random Forest Classifier")
    return metrics

def evaluate_memory_model():
    path = config.DATASETS_DIR / "Obfuscated-MalMem2022.csv"
    if not path.exists():
        print("[ERROR] Memory dataset missing.")
        return None
    
    bundle = joblib.load(config.MEMORY_MODEL_PATH)
    pipeline = bundle["pipeline"]
    features = bundle["feature_cols"]
    
    df = pd.read_csv(path, low_memory=False)
    y_raw = df["Class"].astype(str).str.strip().str.lower()
    y = y_raw.apply(lambda v: 0 if v in {"benign", "0", "normal"} else 1).values
    X = df[features].fillna(0).values
    
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    raw_pred = pipeline.predict(X_test)
    y_pred = np.where(raw_pred == -1, 1, 0)
    
    metrics = calculate_metrics(y_test, y_pred)
    print_model_evaluation("Memory Anomaly Detector", metrics, "Obfuscated-MalMem2022.csv", "Isolation Forest (Unsupervised)")
    return metrics

def evaluate_behavior_model():
    from ml.train_behavior_anomaly import load_network_pcap, load_synthetic_normal, NET_FEATURES
    
    bundle = joblib.load(config.BEHAVIOR_MODEL_PATH)
    pipeline = bundle["pipeline"]
    
    net_df = load_network_pcap(max_rows=100000)
    syn_df = load_synthetic_normal(n=1000)
    
    if net_df is None:
        print("[ERROR] PCAP dataset missing.")
        return None
    
    X_net = net_df[NET_FEATURES].values
    X_syn = syn_df[NET_FEATURES].values
    
    y_syn = np.zeros(len(syn_df), dtype=int)
    y_net = np.ones(len(net_df), dtype=int)
    
    X_all = np.vstack([X_syn, X_net])
    y_all = np.concatenate([y_syn, y_net])
    
    raw_pred = pipeline.predict(X_all)
    y_pred = np.where(raw_pred == -1, 1, 0)
    
    metrics = calculate_metrics(y_all, y_pred)
    print_model_evaluation("Behavior / Network Anomaly Detector", metrics, "Midterm_53_group.csv + Synthetic Normal", "Isolation Forest (Unsupervised)")
    return metrics

def main():
    print("""
======================================================================
  CYBER THREAD DETECTION SYSTEM (ABTD v2.0)
  MODEL ACCURACY & CONFUSION MATRIX EVALUATION
======================================================================
    """)
    
    summary = {}
    
    m_url = evaluate_url_model()
    if m_url: summary["URL Classifier (RF)"] = m_url
    
    m_mal = evaluate_malware_model()
    if m_mal: summary["Malware Classifier (RF)"] = m_mal
    
    m_mem = evaluate_memory_model()
    if m_mem: summary["Memory Anomaly Detector (IF)"] = m_mem
    
    m_beh = evaluate_behavior_model()
    if m_beh: summary["Behavior Anomaly Detector (IF)"] = m_beh
    
    # ── Grand Summary Table ──────────────────────────────────────
    print("\n\n" + "=" * 80)
    print("  ALL MODELS CONFUSION MATRIX & ACCURACY SUMMARY")
    print("=" * 80)
    header = f"{'Model Name':<32} {'TN':>6} {'FP':>6} {'FN':>6} {'TP':>6} {'Accuracy':>10} {'F1-Score':>10}"
    print(header)
    print("-" * 80)
    for name, m in summary.items():
        acc_str = f"{m['accuracy']*100:.2f}%"
        f1_str = f"{m['f1']*100:.2f}%"
        print(f"{name:<32} {m['tn']:>6d} {m['fp']:>6d} {m['fn']:>6d} {m['tp']:>6d} {acc_str:>10} {f1_str:>10}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()

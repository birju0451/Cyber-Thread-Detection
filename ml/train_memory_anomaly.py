"""
ml/train_memory_anomaly.py
===========================
Train an Isolation Forest anomaly detector using:
  - datasets/Obfuscated-MalMem2022.csv

This dataset contains Windows memory forensic features.
We train in ONE-CLASS mode: fit only on benign samples so the model
learns what "normal" memory looks like. Obfuscated malware
will appear as anomalies (outliers).

Outputs: models/memory_anomaly.pkl
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, roc_auc_score

import config


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATASET_PATH  = config.DATASETS_DIR / "Obfuscated-MalMem2022.csv"
MODEL_PATH    = config.MEMORY_MODEL_PATH
RANDOM_STATE  = 42
CONTAMINATION = 0.15   # Expected fraction of anomalies (tunable)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def _find_label_column(df: pd.DataFrame) -> str | None:
    for col in df.columns:
        if col.lower() in ("label", "class", "type", "category",
                           "classification", "malware_class"):
            return col
    return None


def train() -> None:
    print("\n" + "=" * 60)
    print("  ABTD — Memory Anomaly Detector Training (Isolation Forest)")
    print("=" * 60)

    if not DATASET_PATH.exists():
        print(f"[ERROR] Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    print(f"  Loading {DATASET_PATH.name} ...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"  Shape: {df.shape}")

    label_col = _find_label_column(df)
    if label_col:
        print(f"  Label column: '{label_col}'")
        print(f"  Label distribution:\n{df[label_col].value_counts().head(10).to_string()}")

        # Encode binary: benign=0, malware=1
        raw = df[label_col].astype(str).str.strip().str.lower()
        benign_terms = {"benign", "0", "normal", "legitimate", "clean"}
        y = raw.apply(lambda v: 0 if v in benign_terms else 1).values
    else:
        print("  [WARN] No label column found — using full dataset for training")
        y = None

    # Keep only numeric columns
    feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if label_col and label_col in feature_cols:
        feature_cols.remove(label_col)
    print(f"  Numeric features: {len(feature_cols)}")

    X = df[feature_cols].values

    # Train Isolation Forest on benign-only samples (one-class learning)
    if y is not None:
        benign_mask = y == 0
        X_train = X[benign_mask]
        X_eval  = X
        y_eval  = y
        print(f"  Training on {benign_mask.sum():,} benign samples only (one-class)")
    else:
        X_train = X
        X_eval  = None
        y_eval  = None
        print(f"  Training on {len(X_train):,} samples (no label info)")

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler",  RobustScaler()),
        ("iforest", IsolationForest(
            n_estimators=200,
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])

    print("  Training Isolation Forest ...")
    pipeline.fit(X_train)

    # Evaluation (if labels available)
    if X_eval is not None and y_eval is not None:
        # IsolationForest: -1=anomaly (malware), +1=normal (benign)
        raw_pred = pipeline.predict(X_eval)
        y_pred   = np.where(raw_pred == -1, 1, 0)  # convert to 0/1

        # Anomaly scores (lower = more anomalous)
        scores = pipeline.decision_function(X_eval)
        # Invert: higher score → more malicious
        inv_scores = -scores
        # Normalize to 0–1 for AUC
        inv_norm = (inv_scores - inv_scores.min()) / (inv_scores.max() - inv_scores.min() + 1e-9)

        print("\n" + "=" * 60)
        print("  Evaluation Results")
        print("=" * 60)
        print(classification_report(y_eval, y_pred,
              target_names=["Benign", "Malware"]))
        try:
            auc = roc_auc_score(y_eval, inv_norm)
            print(f"  AUC-ROC: {auc:.4f}")
        except Exception:
            pass

    # Save bundle (pipeline + feature columns)
    model_bundle = {
        "pipeline"    : pipeline,
        "feature_cols": feature_cols,
    }

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, MODEL_PATH)
    print(f"\n  ✓ Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()

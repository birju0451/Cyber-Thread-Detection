"""
ml/train_behavior_anomaly.py
=============================
Train a behavioral anomaly detector using:
  - datasets/Midterm_53_group.csv
  - datasets/social_media_behavior_dataset.csv

Uses Isolation Forest on network/system behavior features to detect
unusual activity patterns indicative of malware, data exfiltration,
or social engineering.

Outputs: models/behavior_anomaly.pkl
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

DATASETS = [
    config.DATASETS_DIR / "Midterm_53_group.csv",
    config.DATASETS_DIR / "social_media_behavior_dataset.csv",
]

MODEL_PATH   = config.BEHAVIOR_MODEL_PATH
RANDOM_STATE = 42
CONTAMINATION = 0.10
MAX_ROWS_PER_FILE = 150_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_label_column(df: pd.DataFrame) -> str | None:
    for col in df.columns:
        if col.lower() in ("label", "class", "target", "type", "attack",
                           "anomaly", "category", "classification", "threat"):
            return col
    return None


def load_dataset(path: Path) -> tuple[pd.DataFrame | None, str | None]:
    if not path.exists():
        print(f"  [SKIP] Not found: {path.name}")
        return None, None

    print(f"  Loading {path.name} ...")
    try:
        df = pd.read_csv(path, nrows=MAX_ROWS_PER_FILE, low_memory=False)
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None, None

    print(f"  Shape: {df.shape}")
    label_col = _find_label_column(df)
    return df, label_col


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train() -> None:
    print("\n" + "=" * 60)
    print("  ABTD — Behavioral Anomaly Detector Training")
    print("=" * 60)

    all_X     = []
    all_y     = []
    all_cols  = None
    has_labels = False

    for ds_path in DATASETS:
        df, label_col = load_dataset(ds_path)
        if df is None:
            continue

        if label_col:
            print(f"  Label column: '{label_col}'")
            raw = df[label_col].astype(str).str.strip().str.lower()
            normal_terms = {"normal", "0", "benign", "legitimate", "safe", "regular"}
            y = raw.apply(lambda v: 0 if v in normal_terms else 1).values
            has_labels = True
        else:
            y = np.zeros(len(df), dtype=int)

        # Numeric features only
        feat_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if label_col and label_col in feat_cols:
            feat_cols.remove(label_col)

        if all_cols is None:
            all_cols = feat_cols
        else:
            # Intersection of feature columns across datasets
            all_cols = [c for c in all_cols if c in feat_cols]

        all_X.append(df)
        all_y.append(y)

    if not all_X or all_cols is None or len(all_cols) == 0:
        print("[ERROR] No usable datasets or features found. Aborting.")
        sys.exit(1)

    # Merge
    frames = []
    ys     = []
    for df, y in zip(all_X, all_y):
        available_cols = [c for c in all_cols if c in df.columns]
        frames.append(df[available_cols])
        ys.append(y[:len(df)])

    # Align columns across frames
    common_cols = list(set.intersection(*[set(f.columns) for f in frames]))
    combined_X  = pd.concat([f[common_cols] for f in frames], ignore_index=True).values
    combined_y  = np.concatenate(ys)

    print(f"\n  Combined: {len(combined_X):,} samples | {len(common_cols)} features")
    if has_labels:
        print(f"  Normal: {(combined_y==0).sum():,}  |  Anomaly: {(combined_y==1).sum():,}")

    # Train on normal samples only
    if has_labels:
        normal_mask = combined_y == 0
        X_train = combined_X[normal_mask]
        print(f"  Training on {X_train.sum():,} normal samples (one-class)")
    else:
        X_train = combined_X

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler",  RobustScaler()),
        ("iforest", IsolationForest(
            n_estimators=150,
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])

    print("  Training Isolation Forest ...")
    pipeline.fit(X_train)

    # Evaluate
    if has_labels:
        raw_pred = pipeline.predict(combined_X)
        y_pred   = np.where(raw_pred == -1, 1, 0)
        scores   = -pipeline.decision_function(combined_X)
        norm_scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

        print("\n" + "=" * 60)
        print("  Evaluation Results")
        print("=" * 60)
        print(classification_report(combined_y, y_pred,
              target_names=["Normal", "Anomaly"]))
        try:
            auc = roc_auc_score(combined_y, norm_scores)
            print(f"  AUC-ROC: {auc:.4f}")
        except Exception:
            pass

    model_bundle = {
        "pipeline"    : pipeline,
        "feature_cols": common_cols,
    }

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, MODEL_PATH)
    print(f"\n  ✓ Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()

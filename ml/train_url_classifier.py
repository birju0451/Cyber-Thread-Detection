"""
ml/train_url_classifier.py
===========================
Train a Random Forest URL classifier using:
  - datasets/balanced_urls.csv
  - datasets/Phishing_Legitimate_full.csv

Outputs: models/url_classifier.pkl

Label conventions detected automatically:
  balanced_urls.csv        → label column: 'label'  (0=benign, 1=phishing)
  Phishing_Legitimate_full → label column: 'label'  (1=phishing, 0=legitimate)
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

import config
from ml.feature_engineering import extract_url_features, URL_FEATURE_COLS


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATASETS = [
    config.DATASETS_DIR / "balanced_urls.csv",
    config.DATASETS_DIR / "Phishing_Legitimate_full.csv",
]

MODEL_PATH = config.URL_MODEL_PATH

RANDOM_STATE = 42
N_ESTIMATORS = 200
MAX_DEPTH    = 20
N_JOBS       = -1


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def _detect_url_column(df: pd.DataFrame) -> str | None:
    """Heuristically find the URL column."""
    for col in df.columns:
        if col.lower() in ("url", "urls", "domain", "link", "website"):
            return col
    return None


def _detect_label_column(df: pd.DataFrame) -> str | None:
    """Heuristically find the label/target column."""
    for col in df.columns:
        if col.lower() in ("label", "target", "class", "phishing", "result", "type", "status"):
            return col
    return None


def load_and_featurize(csv_path: Path, max_rows: int = 200_000) -> pd.DataFrame | None:
    """
    Load a CSV, detect URL + label columns, extract features, return DataFrame.
    Returns None if file not found or cannot be parsed.
    """
    if not csv_path.exists():
        print(f"  [SKIP] Not found: {csv_path.name}")
        return None

    print(f"  Loading {csv_path.name} ...")
    try:
        df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    except Exception as e:
        print(f"  [ERROR] Could not read {csv_path.name}: {e}")
        return None

    print(f"  Columns: {list(df.columns[:10])} ... ({len(df.columns)} total)")
    print(f"  Rows: {len(df):,}")

    url_col   = _detect_url_column(df)
    label_col = _detect_label_column(df)

    if url_col is None:
        print(f"  [SKIP] No URL column found in {csv_path.name}")
        return None
    if label_col is None:
        print(f"  [SKIP] No label column found in {csv_path.name}")
        return None

    print(f"  URL column: '{url_col}' | Label column: '{label_col}'")

    # Drop rows with null URL or label
    df = df[[url_col, label_col]].dropna()

    # Encode labels to binary 0/1
    unique_labels = df[label_col].unique()
    if set(unique_labels) == {"phishing", "legitimate"} or \
       set(unique_labels) == {"benign", "malicious"} or \
       set(unique_labels) == {"good", "bad"}:
        le = LabelEncoder()
        df["label_enc"] = le.fit_transform(df[label_col].astype(str).str.lower())
    else:
        # Assume numeric
        df["label_enc"] = pd.to_numeric(df[label_col], errors="coerce")
        df = df.dropna(subset=["label_enc"])
        df["label_enc"] = df["label_enc"].astype(int)

    print(f"  Label distribution:\n{df['label_enc'].value_counts().to_string()}")

    # Extract URL features row by row
    print(f"  Extracting features from {len(df):,} URLs ...")
    features_list = []
    for i, url in enumerate(df[url_col].astype(str)):
        features_list.append(extract_url_features(url))
        if i % 20_000 == 0 and i > 0:
            print(f"    {i:,} / {len(df):,} processed...")

    feat_df = pd.DataFrame(features_list)
    feat_df["label"] = df["label_enc"].values
    return feat_df


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train() -> None:
    print("\n" + "=" * 60)
    print("  ABTD — URL Classifier Training")
    print("=" * 60)

    all_frames = []
    for ds in DATASETS:
        frame = load_and_featurize(ds)
        if frame is not None:
            all_frames.append(frame)

    if not all_frames:
        print("\n[ERROR] No datasets could be loaded. Aborting.")
        sys.exit(1)

    combined = pd.concat(all_frames, ignore_index=True)
    combined = combined.dropna(subset=["label"])
    combined["label"] = combined["label"].astype(int)

    print(f"\n  Combined dataset: {len(combined):,} samples")
    print(f"  Class balance:\n{combined['label'].value_counts().to_string()}")

    X = combined[URL_FEATURE_COLS].values
    y = combined["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n  Train: {len(X_train):,} | Test: {len(X_test):,}")

    # Pipeline: impute NaN → Random Forest
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=N_ESTIMATORS,
            max_depth=MAX_DEPTH,
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            min_samples_leaf=2,
        )),
    ])

    print("\n  Training Random Forest ...")
    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred     = pipeline.predict(X_test)
    y_prob     = pipeline.predict_proba(X_test)[:, 1]
    accuracy   = accuracy_score(y_test, y_pred)
    auc        = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 60)
    print("  Evaluation Results")
    print("=" * 60)
    print(f"  Accuracy : {accuracy:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print("\n" + classification_report(y_test, y_pred,
          target_names=["Benign", "Phishing/Malicious"]))

    # Feature importance (top 10)
    rf = pipeline.named_steps["clf"]
    importances = rf.feature_importances_
    top_idx = np.argsort(importances)[::-1][:10]
    print("  Top 10 Feature Importances:")
    for idx in top_idx:
        print(f"    {URL_FEATURE_COLS[idx]:<30} {importances[idx]:.4f}")

    # Save
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\n  ✓ Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()

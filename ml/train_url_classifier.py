"""
ml/train_url_classifier.py  — Dataset-Aware v2
================================================
Trains URL phishing detector using ACTUAL datasets:

  1. Phishing_Legitimate_full.csv — 10,000 rows, 48 pre-extracted features
     Label: CLASS_LABEL (1=phishing, 0=legitimate)

  2. balanced_urls.csv — 632,509 raw URLs
     Label: result (0=benign, 1=phishing)
     → Features extracted via feature_engineering.py

Output: models/url_classifier.pkl
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

import config
from ml.feature_engineering import extract_url_features

RANDOM_STATE = 42

# Structural features common to both datasets
SHARED_FEATURES = [
    "NumDots", "NumDash", "AtSymbol", "NumUnderscore", "NumPercent",
    "NumAmpersand", "NumHash", "NumNumericChars", "NoHttps", "IpAddress",
    "HostnameLength", "PathLength", "QueryLength", "NumSensitiveWords",
    "SubdomainLevel", "UrlLength", "DoubleSlashInPath",
]


def load_phishing_full() -> pd.DataFrame | None:
    """Phishing_Legitimate_full.csv — uses pre-extracted 48 features directly."""
    path = config.DATASETS_DIR / "Phishing_Legitimate_full.csv"
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return None

    print(f"  Loading {path.name} ...")
    df = pd.read_csv(path, low_memory=False)
    print(f"  Rows: {len(df):,} | Columns: {len(df.columns)}")

    if "CLASS_LABEL" not in df.columns:
        print(f"  [SKIP] CLASS_LABEL column missing")
        return None

    rows = []
    for _, row in df.iterrows():
        r = {}
        r["NumDots"]           = row.get("NumDots", 0)
        r["NumDash"]           = row.get("NumDash", 0)
        r["AtSymbol"]          = row.get("AtSymbol", 0)
        r["NumUnderscore"]     = row.get("NumUnderscore", 0)
        r["NumPercent"]        = row.get("NumPercent", 0)
        r["NumAmpersand"]      = row.get("NumAmpersand", 0)
        r["NumHash"]           = row.get("NumHash", 0)
        r["NumNumericChars"]   = row.get("NumNumericChars", 0)
        r["NoHttps"]           = row.get("NoHttps", 0)
        r["IpAddress"]         = row.get("IpAddress", 0)
        r["HostnameLength"]    = row.get("HostnameLength", 0)
        r["PathLength"]        = row.get("PathLength", 0)
        r["QueryLength"]       = row.get("QueryLength", 0)
        r["NumSensitiveWords"] = row.get("NumSensitiveWords", 0)
        r["SubdomainLevel"]    = row.get("SubdomainLevel", 0)
        r["UrlLength"]         = row.get("UrlLength", 0)
        r["DoubleSlashInPath"] = row.get("DoubleSlashInPath", 0)
        r["label"]             = int(pd.to_numeric(row["CLASS_LABEL"], errors="coerce") or 0)
        rows.append(r)

    result = pd.DataFrame(rows)
    print(f"  Classes: {result['label'].value_counts().to_dict()}")
    return result


def load_balanced_urls(max_rows: int = 100_000) -> pd.DataFrame | None:
    """balanced_urls.csv — extracts structural features from raw URLs."""
    path = config.DATASETS_DIR / "balanced_urls.csv"
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return None

    print(f"  Loading {path.name} (max {max_rows:,} rows) ...")
    df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    print(f"  Rows: {len(df):,}")

    if "url" not in df.columns:
        print(f"  [SKIP] No url column")
        return None

    # label from 'result' (int) or 'label' (string)
    if "result" in df.columns:
        df["_lbl"] = pd.to_numeric(df["result"], errors="coerce").fillna(0).astype(int).clip(0, 1)
    elif "label" in df.columns:
        df["_lbl"] = df["label"].map({"benign": 0, "phishing": 1, "malicious": 1}).fillna(0).astype(int)
    else:
        print(f"  [SKIP] No label column")
        return None

    df = df[["url", "_lbl"]].dropna()

    print(f"  Extracting features from {len(df):,} URLs ...")
    rows = []
    for i, (_, row) in enumerate(df.iterrows()):
        feats = extract_url_features(str(row["url"]))
        r = {k: feats.get(k, 0) for k in SHARED_FEATURES}
        r["label"] = int(row["_lbl"])
        rows.append(r)
        if (i + 1) % 25_000 == 0:
            print(f"    {i+1:,}/{len(df):,} processed ...")

    result = pd.DataFrame(rows)
    print(f"  Classes: {result['label'].value_counts().to_dict()}")
    return result


def train() -> None:
    print("\n" + "=" * 60)
    print("  ABTD — URL/Phishing Classifier Training")
    print("=" * 60)

    frames = []
    for loader in [load_phishing_full, load_balanced_urls]:
        try:
            df = loader()
            if df is not None:
                frames.append(df[SHARED_FEATURES + ["label"]])
        except Exception as e:
            print(f"  [ERROR] {e}")

    if not frames:
        print("\n[ERROR] No datasets could be loaded.")
        sys.exit(1)

    data = pd.concat(frames, ignore_index=True).dropna()
    data["label"] = data["label"].astype(int)

    print(f"\n  Combined: {len(data):,} samples")
    print(f"  Distribution: {data['label'].value_counts().to_dict()}")

    X = data[SHARED_FEATURES].fillna(0).values
    y = data["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=300, max_depth=20,
            n_jobs=-1, random_state=RANDOM_STATE,
            class_weight="balanced", min_samples_leaf=2,
        )),
    ])

    print("\n  Training Random Forest (300 trees) ...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    print(f"\n  Accuracy : {acc:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline" : pipeline,
        "features" : SHARED_FEATURES,
        "accuracy" : round(acc, 4),
        "auc"      : round(auc, 4),
        "version"  : "2.0",
    }
    joblib.dump(bundle, config.URL_MODEL_PATH)
    print(f"\n  ✓ URL model saved → {config.URL_MODEL_PATH}")


if __name__ == "__main__":
    train()

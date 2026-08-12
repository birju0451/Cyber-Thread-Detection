"""
ml/train_behavior_anomaly.py  — Dataset-Aware v2
=================================================
Trains a behavior/network anomaly detector using:

  Midterm_53_group.csv  — Wireshark PCAP export
    Columns: Time, Source, No., Destination, Protocol, Length, Info
    → Extract statistical network features per IP (packet rate, proto diversity, etc.)
    → Isolation Forest for unsupervised anomaly detection

  social_media_behavior_dataset.csv — supplementary (not security-critical)
    → Not used for anomaly, used only to enrich feature diversity

Output: models/behavior_anomaly.pkl
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

import config

RANDOM_STATE = 42

# Network features we derive from Midterm_53_group.csv
NET_FEATURES = [
    "pkt_count", "avg_pkt_len", "std_pkt_len", "total_bytes",
    "unique_dst_ips", "unique_protocols", "unique_src_ips",
    "tcp_ratio", "udp_ratio", "icmp_ratio", "dns_ratio",
    "http_ratio", "nbns_ratio", "other_ratio",
    "max_pkt_len", "min_pkt_len",
]


def _proto_ratios(sub: pd.DataFrame) -> dict:
    """Compute protocol ratios for a group of packets."""
    total = max(len(sub), 1)
    protos = sub["Protocol"].str.upper().value_counts()

    def ratio(proto):
        return protos.get(proto, 0) / total

    return {
        "tcp_ratio"  : ratio("TCP"),
        "udp_ratio"  : ratio("UDP"),
        "icmp_ratio" : ratio("ICMP"),
        "dns_ratio"  : ratio("DNS"),
        "http_ratio" : ratio("HTTP"),
        "nbns_ratio" : ratio("NBNS"),
        "other_ratio": 1.0 - sum([
            ratio("TCP"), ratio("UDP"), ratio("ICMP"),
            ratio("DNS"), ratio("HTTP"), ratio("NBNS"),
        ]),
    }


def load_network_pcap(max_rows: int = 200_000) -> pd.DataFrame | None:
    """
    Load Midterm_53_group.csv (Wireshark export) and extract
    per-source-IP statistical features as training samples.
    """
    path = config.DATASETS_DIR / "Midterm_53_group.csv"
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return None

    print(f"  Loading {path.name} (max {max_rows:,} rows) ...")
    try:
        df = pd.read_csv(path, nrows=max_rows, low_memory=False,
                         quotechar='"', on_bad_lines="skip")
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None

    # Normalize column names
    df.columns = [c.strip().strip('"') for c in df.columns]
    print(f"  Rows: {len(df):,} | Columns: {list(df.columns)}")

    required = {"Source", "Protocol", "Length"}
    if not required.issubset(set(df.columns)):
        print(f"  [SKIP] Missing columns. Found: {list(df.columns)}")
        return None

    # Clean
    df["Length"] = pd.to_numeric(df["Length"].astype(str).str.strip('"'), errors="coerce").fillna(0)
    df["Source"] = df["Source"].astype(str).str.strip('"')
    df["Protocol"] = df["Protocol"].astype(str).str.strip('"').str.upper()

    if "Destination" in df.columns:
        df["Destination"] = df["Destination"].astype(str).str.strip('"')

    print(f"  Aggregating per-source-IP features ...")
    rows = []
    for src_ip, sub in df.groupby("Source"):
        if len(sub) < 3:
            continue
        lengths = sub["Length"].values
        r = {
            "pkt_count"      : len(sub),
            "avg_pkt_len"    : float(np.mean(lengths)),
            "std_pkt_len"    : float(np.std(lengths)),
            "total_bytes"    : float(np.sum(lengths)),
            "max_pkt_len"    : float(np.max(lengths)),
            "min_pkt_len"    : float(np.min(lengths)),
            "unique_protocols": sub["Protocol"].nunique(),
        }
        if "Destination" in sub.columns:
            r["unique_dst_ips"] = sub["Destination"].nunique()
        else:
            r["unique_dst_ips"] = 1
        r["unique_src_ips"] = 1  # per-source grouping

        r.update(_proto_ratios(sub))
        rows.append(r)

    if not rows:
        print("  [SKIP] No valid source groups extracted")
        return None

    result = pd.DataFrame(rows)
    print(f"  Extracted {len(result):,} IP-level behavior samples")
    return result[NET_FEATURES]


def load_synthetic_normal(n: int = 2000) -> pd.DataFrame:
    """
    Generate synthetic 'normal' network behavior to anchor the Isolation Forest.
    Normal traffic: moderate packet counts, small-medium lengths, common protocols.
    """
    rng = np.random.default_rng(42)
    rows = []
    for _ in range(n):
        pkt_count   = int(rng.integers(10, 200))
        avg_pkt_len = float(rng.normal(512, 150))
        std_pkt_len = float(rng.uniform(20, 200))
        total_bytes = pkt_count * avg_pkt_len
        tcp_r  = float(rng.uniform(0.3, 0.7))
        udp_r  = float(rng.uniform(0.1, 0.3))
        dns_r  = float(rng.uniform(0.05, 0.15))
        http_r = float(rng.uniform(0.05, 0.2))
        rem    = max(0.0, 1.0 - tcp_r - udp_r - dns_r - http_r)
        rows.append({
            "pkt_count"      : pkt_count,
            "avg_pkt_len"    : max(64, avg_pkt_len),
            "std_pkt_len"    : std_pkt_len,
            "total_bytes"    : total_bytes,
            "max_pkt_len"    : avg_pkt_len + std_pkt_len * 2,
            "min_pkt_len"    : max(20, avg_pkt_len - std_pkt_len),
            "unique_protocols": int(rng.integers(1, 5)),
            "unique_dst_ips" : int(rng.integers(1, 20)),
            "unique_src_ips" : 1,
            "tcp_ratio"      : tcp_r,
            "udp_ratio"      : udp_r,
            "icmp_ratio"     : 0.0,
            "dns_ratio"      : dns_r,
            "http_ratio"     : http_r,
            "nbns_ratio"     : float(rng.uniform(0, 0.05)),
            "other_ratio"    : rem,
        })
    return pd.DataFrame(rows)[NET_FEATURES]


def train() -> None:
    print("\n" + "=" * 60)
    print("  ABTD — Behavior/Network Anomaly Detector Training")
    print("=" * 60)

    frames = []

    # Real network data from Wireshark PCAP
    net_df = load_network_pcap()
    if net_df is not None:
        frames.append(net_df)

    # Synthetic normal anchor
    syn_df = load_synthetic_normal(n=2000)
    frames.append(syn_df)
    print(f"  Added {len(syn_df):,} synthetic normal samples")

    if not frames:
        print("\n[ERROR] No training data available.")
        sys.exit(1)

    data = pd.concat(frames, ignore_index=True).fillna(0)
    print(f"\n  Total training samples: {len(data):,}")

    X = data[NET_FEATURES].values

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iso",    IsolationForest(
            n_estimators=200,
            contamination=0.08,   # ~8% anomaly expected in mixed traffic
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])

    print("\n  Training Isolation Forest (200 trees) ...")
    pipeline.fit(X)

    # Self-evaluation: flag what fraction is anomalous
    preds   = pipeline.predict(X)
    n_anom  = (preds == -1).sum()
    scores  = pipeline.decision_function(X)

    print(f"\n  Anomaly rate on training data : {n_anom}/{len(X)} ({100*n_anom/len(X):.1f}%)")
    print(f"  Decision score range          : [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"  Mean decision score           : {scores.mean():.3f}")

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline"      : pipeline,
        "features"      : NET_FEATURES,
        "anomaly_rate"  : round(n_anom / len(X), 4),
        "version"       : "2.0",
        "dataset_source": "Midterm_53_group.csv + synthetic",
    }
    joblib.dump(bundle, config.BEHAVIOR_MODEL_PATH)
    print(f"\n  ✓ Behavior model saved → {config.BEHAVIOR_MODEL_PATH}")


if __name__ == "__main__":
    train()

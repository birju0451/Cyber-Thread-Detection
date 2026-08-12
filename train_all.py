"""
train_all.py  — ABTD Master Training Orchestrator
===================================================
Trains ALL 4 ABTD machine learning models in sequence:

  1. URL/Phishing Classifier       → models/url_classifier.pkl
     Dataset: Phishing_Legitimate_full.csv + balanced_urls.csv

  2. Malware Classifier            → models/malware_classifier.pkl
     Dataset: Malware dataset.csv

  3. Memory Anomaly Detector       → models/memory_anomaly.pkl
     Dataset: Obfuscated-MalMem2022.csv (Volatility features)

  4. Behavior/Network Anomaly      → models/behavior_anomaly.pkl
     Dataset: Midterm_53_group.csv (Wireshark PCAP)

Usage:
    python train_all.py                  # Train all models
    python train_all.py --url-only       # Train URL model only
    python train_all.py --skip-url       # Skip URL model (slow)
    python train_all.py --skip-behavior  # Skip behavior model

Expected time: 10–30 minutes depending on hardware.
"""

import sys
import time
import argparse
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import config


def _check_datasets():
    """Verify which datasets are present and warn about missing ones."""
    EXPECTED = {
        "Phishing_Legitimate_full.csv" : "URL classifier (Strategy A)",
        "balanced_urls.csv"            : "URL classifier (Strategy B)",
        "Malware dataset.csv"          : "Malware classifier",
        "Obfuscated-MalMem2022.csv"    : "Memory anomaly detector",
        "Midterm_53_group.csv"         : "Behavior/Network anomaly",
    }
    print("\n" + "=" * 60)
    print("  Dataset Status")
    print("=" * 60)
    any_missing = False
    for fname, purpose in EXPECTED.items():
        path   = config.DATASETS_DIR / fname
        exists = path.exists()
        size   = f"({path.stat().st_size // 1_000_000} MB)" if exists else ""
        status = "✓" if exists else "✗ MISSING"
        print(f"  {status}  {fname} {size}")
        print(f"       → {purpose}")
        if not exists:
            any_missing = True
    if any_missing:
        print("\n  ⚠ Some datasets missing. Place them in datasets/ and re-run.")
    else:
        print("\n  ✓ All datasets present")
    print()


def train_url():
    print("\n" + "█" * 60)
    print("  PHASE 1/4  —  URL Phishing Classifier")
    print("█" * 60)
    t0 = time.time()
    from ml.train_url_classifier import train
    train()
    print(f"\n  Done in {time.time() - t0:.1f}s")


def train_malware():
    print("\n" + "█" * 60)
    print("  PHASE 2/4  —  Malware Classifier")
    print("█" * 60)
    t0 = time.time()
    from ml.train_malware_classifier import train
    train()
    print(f"\n  Done in {time.time() - t0:.1f}s")


def train_memory():
    print("\n" + "█" * 60)
    print("  PHASE 3/4  —  Memory Anomaly Detector")
    print("█" * 60)
    t0 = time.time()
    from ml.train_memory_anomaly import train
    train()
    print(f"\n  Done in {time.time() - t0:.1f}s")


def train_behavior():
    print("\n" + "█" * 60)
    print("  PHASE 4/4  —  Behavior / Network Anomaly Detector")
    print("█" * 60)
    t0 = time.time()
    from ml.train_behavior_anomaly import train
    train()
    print(f"\n  Done in {time.time() - t0:.1f}s")


def check_results():
    """Print a summary of trained model files."""
    MODELS = {
        "url_classifier.pkl"   : config.URL_MODEL_PATH,
        "malware_classifier.pkl": config.MALWARE_MODEL_PATH,
        "memory_anomaly.pkl"   : config.MEMORY_MODEL_PATH,
        "behavior_anomaly.pkl" : config.BEHAVIOR_MODEL_PATH,
    }
    print("\n" + "=" * 60)
    print("  Trained Models Summary")
    print("=" * 60)
    all_ok = True
    for name, path in MODELS.items():
        if path.exists():
            size = path.stat().st_size // 1024
            print(f"  ✓  {name:<30} ({size} KB)")
        else:
            print(f"  ✗  {name:<30} NOT FOUND")
            all_ok = False
    if all_ok:
        print("\n  ✅ All models trained successfully!")
        print("  🚀 Now run: python run.py")
    else:
        print("\n  ⚠ Some models failed to train. Check errors above.")
    print()


def main():
    parser = argparse.ArgumentParser(description="ABTD — Train all ML models")
    parser.add_argument("--url-only",       action="store_true", help="Train URL model only")
    parser.add_argument("--malware-only",   action="store_true", help="Train malware model only")
    parser.add_argument("--memory-only",    action="store_true", help="Train memory model only")
    parser.add_argument("--behavior-only",  action="store_true", help="Train behavior model only")
    parser.add_argument("--skip-url",       action="store_true", help="Skip URL model (slowest)")
    parser.add_argument("--skip-behavior",  action="store_true", help="Skip behavior model")
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════╗
║   ABTD — AI Model Training Pipeline                      ║
║   Trains all 4 ML models from real datasets              ║
╚══════════════════════════════════════════════════════════╝""")

    _check_datasets()

    t_global = time.time()
    errors   = []

    # Determine which phases to run
    any_specific = args.url_only or args.malware_only or args.memory_only or args.behavior_only

    def should_run(name):
        if any_specific:
            return getattr(args, f"{name}_only", False)
        skip_attr = f"skip_{name}"
        return not getattr(args, skip_attr, False)

    phases = [
        ("url",      train_url,      should_run("url")),
        ("malware",  train_malware,  should_run("malware")),
        ("memory",   train_memory,   should_run("memory")),
        ("behavior", train_behavior, should_run("behavior")),
    ]

    for name, fn, run in phases:
        if not run:
            print(f"\n  [SKIP] {name} model")
            continue
        try:
            fn()
        except SystemExit:
            pass
        except Exception as e:
            errors.append((name, str(e)))
            print(f"\n  [ERROR] {name} training failed: {e}")
            traceback.print_exc()

    total_time = time.time() - t_global

    if errors:
        print(f"\n\n  ⚠ {len(errors)} phase(s) failed:")
        for name, err in errors:
            print(f"    - {name}: {err}")

    check_results()
    print(f"  Total training time: {total_time/60:.1f} minutes")


if __name__ == "__main__":
    main()

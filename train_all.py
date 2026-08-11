"""
train_all.py
=============
Master training orchestrator.
Runs all ML training pipelines in sequence.

Usage:
    python train_all.py
    python train_all.py --skip-url
    python train_all.py --only memory
"""

import sys
import time
import argparse
from pathlib import Path


def banner(title: str) -> None:
    print(f"\n{'#'*62}")
    print(f"#  {title}")
    print(f"{'#'*62}\n")


def run_trainer(name: str, module_path: str) -> bool:
    """Import and run a trainer module. Returns True on success."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod  = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        mod.train()
        return True
    except SystemExit as e:
        if e.code != 0:
            print(f"  [FAILED] {name} exited with code {e.code}")
            return False
        return True
    except Exception as e:
        print(f"  [FAILED] {name}: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="ABTD — Train all ML models")
    parser.add_argument("--only", choices=["url", "malware", "memory", "behavior"],
                        help="Train only this model")
    parser.add_argument("--skip-url",      action="store_true")
    parser.add_argument("--skip-malware",  action="store_true")
    parser.add_argument("--skip-memory",   action="store_true")
    parser.add_argument("--skip-behavior", action="store_true")
    args = parser.parse_args()

    base = Path(__file__).resolve().parent / "ml"

    trainers = {
        "url"     : base / "train_url_classifier.py",
        "malware" : base / "train_malware_classifier.py",
        "memory"  : base / "train_memory_anomaly.py",
        "behavior": base / "train_behavior_anomaly.py",
    }

    if args.only:
        trainers = {args.only: trainers[args.only]}

    if args.skip_url:      trainers.pop("url", None)
    if args.skip_malware:  trainers.pop("malware", None)
    if args.skip_memory:   trainers.pop("memory", None)
    if args.skip_behavior: trainers.pop("behavior", None)

    banner("ABTD — Master Training Pipeline")
    print(f"  Models to train: {list(trainers.keys())}")
    print(f"  Datasets dir   : d:/cyber_threat/datasets/")
    print(f"  Models dir     : d:/cyber_threat/models/\n")

    results = {}
    total_start = time.time()

    for name, path in trainers.items():
        banner(f"Training: {name.upper()} Model")
        t0 = time.time()
        success = run_trainer(name, str(path))
        elapsed = time.time() - t0
        results[name] = ("✓" if success else "✗", elapsed)
        print(f"\n  Time: {elapsed:.1f}s")

    # Summary
    banner("Training Summary")
    for name, (status, elapsed) in results.items():
        print(f"  {status}  {name:<12}  {elapsed:.1f}s")

    total = time.time() - total_start
    print(f"\n  Total time: {total:.1f}s")

    failures = [n for n, (s, _) in results.items() if s == "✗"]
    if failures:
        print(f"\n  [WARN] Some models failed: {failures}")
        print("  The system will still run — failed models fall back to rule engine.")
    else:
        print("\n  All models trained successfully!")
        print("  Start the system: python run.py")


if __name__ == "__main__":
    main()

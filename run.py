"""
run.py — ABTD Main Entry Point
================================
Starts the Flask server + Windows background agent together.

Usage:
    python run.py                  # Start everything
    python run.py --no-agent       # Flask only (no background agent)
    python run.py --agent-only     # Agent only (no Flask server)
    python run.py --host 0.0.0.0   # Expose on local network

Prerequisites:
    python setup.py    # Install deps + create .env
    python train_all.py  # Train ML models
"""

import sys
import os
import threading
import argparse
import time
from pathlib import Path

# ── Ensure project root is on sys.path ───────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import config
from backend.logger import log_system


def print_banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════╗
║   ABTD — Adaptive Behavioral Threat Detection v1.0       ║
║   AI-Powered Windows Endpoint Protection Platform        ║
╠══════════════════════════════════════════════════════════╣
║   Flask API   : http://127.0.0.1:5000                   ║
║   Dashboard   : http://127.0.0.1:5000/dashboard         ║
║   Scanner     : http://127.0.0.1:5000/scanner           ║
║   MongoDB     : Atlas Cloud                              ║
║   Gemini AI   : Enabled                                  ║
╚══════════════════════════════════════════════════════════╝
""")


def check_models() -> None:
    """Warn if ML models are missing."""
    missing = []
    for name, path in [
        ("URL Classifier",    config.URL_MODEL_PATH),
        ("Malware Classifier",config.MALWARE_MODEL_PATH),
        ("Memory Anomaly",    config.MEMORY_MODEL_PATH),
        ("Behavior Anomaly",  config.BEHAVIOR_MODEL_PATH),
    ]:
        if not path.exists():
            missing.append(name)

    if missing:
        log_system.warning("=" * 55)
        log_system.warning("  ML Models not found — rule-based fallback active")
        log_system.warning(f"  Missing: {', '.join(missing)}")
        log_system.warning("  Run: python train_all.py")
        log_system.warning("=" * 55)
    else:
        log_system.info(f"✓ All {4 - len(missing)} ML models loaded")


def start_agent_thread() -> None:
    """Start the Windows background agent in a daemon thread."""
    def _run():
        try:
            from backend.database import db
            from agent.agent      import agent
            agent.start()
            while True:
                time.sleep(10)
        except Exception as e:
            log_system.error(f"Agent thread error: {e}")

    t = threading.Thread(target=_run, name="ABTDAgent", daemon=True)
    t.start()
    log_system.info("✓ Windows background agent started (daemon thread)")


def start_flask(host: str, port: int, debug: bool) -> None:
    """Create and run the Flask application."""
    from backend.app import create_app
    app = create_app()

    log_system.info(f"✓ Flask server starting on http://{host}:{port}")
    log_system.info(f"  Dashboard: http://{host}:{port}/dashboard")

    # Use Werkzeug server (development) — for production use gunicorn
    app.run(
        host    = host,
        port    = port,
        debug   = debug,
        use_reloader = False,   # Reloader conflicts with threading
        threaded = True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="ABTD — Cyber Threat Detection System")
    parser.add_argument("--no-agent",   action="store_true", help="Start Flask only, no agent")
    parser.add_argument("--agent-only", action="store_true", help="Start agent only, no Flask")
    parser.add_argument("--host",       default=config.FLASK_HOST, help="Flask bind host")
    parser.add_argument("--port",       default=config.FLASK_PORT, type=int, help="Flask port")
    parser.add_argument("--debug",      action="store_true", default=config.FLASK_DEBUG)
    args = parser.parse_args()

    print_banner()
    check_models()

    if args.agent_only:
        log_system.info("Starting agent-only mode…")
        from backend.database import db
        db.connect()
        from agent.agent import agent
        agent.run_blocking()
        return

    if not args.no_agent:
        start_agent_thread()

    start_flask(args.host, args.port, args.debug)


if __name__ == "__main__":
    main()

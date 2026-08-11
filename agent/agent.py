"""
agent/agent.py
===============
ABTD Windows Background Agent — Main Orchestrator.

Starts and manages all monitoring sub-threads:
  - File Monitor      (watchdog)
  - Process Monitor   (psutil)
  - Registry Monitor  (winreg)
  - Network Monitor   (psutil)

Runs as a daemon. Can be started from run.py or independently.
"""

import sys
import time
import signal
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger   import log_agent
from backend.database import db


class ABTDAgent:
    """
    Main Windows Background Monitoring Agent.

    Coordinates all monitoring modules in separate daemon threads.
    """

    def __init__(self):
        self._running   = False
        self._threads   = []
        self._file_mon  = None

    def start(self) -> None:
        if not config.AGENT_ENABLED:
            log_agent.info("Agent disabled in config — skipping")
            return

        log_agent.info("=" * 50)
        log_agent.info("  ABTD Windows Agent — Starting")
        log_agent.info("=" * 50)

        self._running = True

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        # ── File Monitor ──────────────────────────────────────────────
        try:
            from agent.file_monitor import FileMonitor
            self._file_mon = FileMonitor()
            self._file_mon.start()
        except Exception as e:
            log_agent.warning(f"File monitor failed to start: {e}")

        # ── Process Monitor ───────────────────────────────────────────
        self._spawn_thread(self._run_process_monitor, "ProcessMonitor")

        # ── Registry Monitor ──────────────────────────────────────────
        self._spawn_thread(self._run_registry_monitor, "RegistryMonitor")

        # ── Network Monitor ───────────────────────────────────────────
        self._spawn_thread(self._run_network_monitor, "NetworkMonitor")

        log_agent.info(f"✓ ABTD Agent running | {len(self._threads)} monitoring threads")
        log_agent.info(f"  Scan interval: {config.AGENT_SCAN_INTERVAL_S}s")

    def _spawn_thread(self, target, name: str) -> None:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        log_agent.info(f"  ▸ {name} thread started")

    def _run_process_monitor(self) -> None:
        try:
            from agent.process_monitor import ProcessMonitor
            ProcessMonitor().run_forever(config.AGENT_SCAN_INTERVAL_S)
        except Exception as e:
            log_agent.error(f"ProcessMonitor crashed: {e}")

    def _run_registry_monitor(self) -> None:
        try:
            from agent.registry_monitor import RegistryMonitor
            RegistryMonitor().run_forever(interval=60)
        except Exception as e:
            log_agent.error(f"RegistryMonitor crashed: {e}")

    def _run_network_monitor(self) -> None:
        try:
            from agent.network_monitor import NetworkMonitor
            NetworkMonitor().run_forever(interval=20)
        except Exception as e:
            log_agent.error(f"NetworkMonitor crashed: {e}")

    def _shutdown(self, *args) -> None:
        log_agent.info("Shutting down ABTD Agent…")
        self._running = False
        if self._file_mon:
            self._file_mon.stop()
        sys.exit(0)

    def run_blocking(self) -> None:
        """Start agent and keep main thread alive."""
        self.start()
        try:
            while self._running:
                time.sleep(5)
        except KeyboardInterrupt:
            self._shutdown()


# Singleton
agent = ABTDAgent()


if __name__ == "__main__":
    db.connect()
    agent.run_blocking()

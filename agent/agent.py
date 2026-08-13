"""
agent/agent.py
===============
ABTD Windows Background Agent — Main Orchestrator v2.0.

Starts and manages all monitoring sub-threads:
  - File Monitor       (watchdog)   — file creation/modification
  - Process Monitor    (psutil)     — suspicious process detection
  - Registry Monitor   (winreg)     — registry persistence changes
  - Network Monitor    (psutil)     — suspicious connections
  - USB Monitor        (drive letter polling)
  - Startup Monitor    (startup folders + scheduled tasks)

All security-relevant events are routed through:
  Event → Classifier → ABTD → Zero Trust → Policy → Response → MongoDB

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
    Main Windows Background Monitoring Agent v2.0.

    Coordinates all monitoring modules in separate daemon threads.
    Routes events through the Zero Trust pipeline.
    """

    def __init__(self):
        self._running   = False
        self._threads   = []
        self._file_mon  = None

    def start(self) -> None:
        if not config.AGENT_ENABLED:
            log_agent.info("Agent disabled in config — skipping")
            return

        log_agent.info("=" * 55)
        log_agent.info("  ABTD Windows Agent v2.0 — Starting")
        log_agent.info("  Zero Trust Pipeline: ACTIVE")
        log_agent.info("=" * 55)

        self._running = True

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        # ── File Monitor ──────────────────────────────────────────────
        try:
            from agent.file_monitor import FileMonitor
            self._file_mon = FileMonitor()
            self._file_mon.start()
            log_agent.info("  ▸ FileMonitor started (watchdog)")
        except Exception as e:
            log_agent.warning(f"File monitor failed to start: {e}")

        # ── Process Monitor ───────────────────────────────────────────
        self._spawn_thread(self._run_process_monitor, "ProcessMonitor")

        # ── Registry Monitor ──────────────────────────────────────────
        self._spawn_thread(self._run_registry_monitor, "RegistryMonitor")

        # ── Network Monitor ───────────────────────────────────────────
        self._spawn_thread(self._run_network_monitor, "NetworkMonitor")

        # ── USB Monitor (v2.0) ────────────────────────────────────────
        self._spawn_thread(self._run_usb_monitor, "USBMonitor")

        # ── Startup Monitor (v2.0) ────────────────────────────────────
        self._spawn_thread(self._run_startup_monitor, "StartupMonitor")

        log_agent.info(
            f"✓ ABTD Agent v2.0 active | {len(self._threads)} monitoring threads"
        )
        log_agent.info(f"  Scan interval: {config.AGENT_SCAN_INTERVAL_S}s")
        log_agent.info(f"  ZT Pipeline: Active")

    def _spawn_thread(self, target, name: str) -> None:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        log_agent.info(f"  ▸ {name} thread started")

    # ── Monitor Thread Runners ────────────────────────────────────────────────

    def _run_process_monitor(self) -> None:
        try:
            from agent.process_monitor import ProcessMonitor
            ProcessMonitor().run_forever(config.AGENT_SCAN_INTERVAL_S)
        except Exception as e:
            log_agent.error(f"ProcessMonitor crashed: {e}", exc_info=True)

    def _run_registry_monitor(self) -> None:
        try:
            from agent.registry_monitor import RegistryMonitor
            RegistryMonitor().run_forever(interval=60)
        except Exception as e:
            log_agent.error(f"RegistryMonitor crashed: {e}", exc_info=True)

    def _run_network_monitor(self) -> None:
        try:
            from agent.network_monitor import NetworkMonitor
            NetworkMonitor().run_forever(interval=20)
        except Exception as e:
            log_agent.error(f"NetworkMonitor crashed: {e}", exc_info=True)

    def _run_usb_monitor(self) -> None:
        try:
            from agent.usb_monitor import USBMonitor
            USBMonitor().run_forever(interval=10)
        except Exception as e:
            log_agent.error(f"USBMonitor crashed: {e}", exc_info=True)

    def _run_startup_monitor(self) -> None:
        try:
            from agent.startup_monitor import StartupMonitor
            StartupMonitor().run_forever(interval=60)
        except Exception as e:
            log_agent.error(f"StartupMonitor crashed: {e}", exc_info=True)

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def _run_usb_monitor(self) -> None:
        try:
            from agent.usb_monitor import USBMonitor
            from agent.zt_pipeline import process_security_event
            mon = USBMonitor()
            mon.set_callback(process_security_event)
            mon.run_forever(interval=5)
        except Exception as e:
            log_agent.error(f"USBMonitor crashed: {e}")

    def _run_startup_monitor(self) -> None:
        try:
            from agent.startup_monitor import StartupMonitor
            from agent.zt_pipeline import process_security_event
            mon = StartupMonitor()
            mon.set_callback(process_security_event)
            mon.run_forever(interval=30)
        except Exception as e:
            log_agent.error(f"StartupMonitor crashed: {e}")

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

"""
agent/file_monitor.py
======================
Watches configured directories for newly created/modified files.
Suspicious files are analyzed by the ABTD engine and routed
through the Zero Trust pipeline.

Uses: watchdog (cross-platform file system events)
"""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from backend.logger   import log_agent
from backend.database import db
from agent.notifier   import notify

try:
    from watchdog.observers import Observer
    from watchdog.events    import FileSystemEventHandler
    _WATCHDOG_OK = True
except ImportError:
    _WATCHDOG_OK = False
    log_agent.warning("watchdog not installed — file monitoring disabled")


class ThreatFileHandler(FileSystemEventHandler):
    """Handle file system events and run ABTD + ZT analysis on suspicious files."""

    def __init__(self):
        from engine.predictor import engine
        self._engine = engine

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path, "created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path, "modified")

    def _check_file(self, path: str, action: str) -> None:
        suffix = Path(path).suffix.lower()

        # Only analyze suspicious extensions
        if suffix not in config.SUSPICIOUS_EXTENSIONS:
            return

        log_agent.info(f"📁 Suspicious file {action}: {path}")

        try:
            result = self._engine.analyze_file(path)
            classification = result.get("classification", "UNKNOWN")
            score          = result.get("threat_score", 0)

            # Log to MongoDB
            db.log_alert(
                alert_type  = "file",
                severity    = classification,
                title       = f"Suspicious file {action}: {Path(path).name}",
                description = " | ".join(result.get("reasons", [])[:3]),
                source      = "file_monitor",
                details     = {"path": path, "score": score, "action": action},
            )

            # Route through Zero Trust pipeline
            try:
                from agent.zt_pipeline import process_security_event
                event_type = "file_download" if action == "created" else "file_write"
                event = {
                    "event_type"    : event_type,
                    "source"        : "file_monitor",
                    "resource"      : path,
                    "process_name"  : "unknown",
                    "details"       : {
                        "path"          : path,
                        "action"        : action,
                        "extension"     : suffix,
                        "file_name"     : Path(path).name,
                        "abtd_score"    : score,
                        "classification": classification,
                    },
                }
                process_security_event(event)
            except Exception as e:
                log_agent.debug(f"ZT pipeline for file event failed: {e}")

            if classification in ("MALICIOUS", "CRITICAL"):
                notify(
                    title    = f"Malicious File {action.title()}",
                    message  = f"{Path(path).name} — Score: {score}/100\n{result.get('recommended_action', '')}",
                    severity = "CRITICAL" if classification == "CRITICAL" else "WARNING",
                )

        except Exception as e:
            log_agent.error(f"File analysis error ({path}): {e}")


class FileMonitor:
    """Manages watchdog observer for all configured watch directories."""

    def __init__(self):
        self._observer = None

    def start(self) -> None:
        if not _WATCHDOG_OK:
            log_agent.warning("File monitoring skipped — watchdog unavailable")
            return

        self._observer = Observer()
        handler = ThreatFileHandler()

        for watch_dir in config.WATCHED_DIRS:
            if Path(watch_dir).exists():
                self._observer.schedule(handler, watch_dir, recursive=False)
                log_agent.info(f"👁 Watching: {watch_dir}")
            else:
                log_agent.debug(f"Watch dir not found (skipping): {watch_dir}")

        self._observer.start()
        log_agent.info("✓ File monitor started")

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join()
            log_agent.info("File monitor stopped")

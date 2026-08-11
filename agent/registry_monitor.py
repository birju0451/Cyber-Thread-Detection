"""
agent/registry_monitor.py
==========================
Monitors Windows Registry startup persistence keys.
Detects unauthorized programs added to Run/RunOnce entries.

Uses: winreg (built-in Windows module)
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
    import winreg
    _WINREG_OK = True
except ImportError:
    _WINREG_OK = False
    log_agent.warning("winreg not available — registry monitoring disabled (Linux/Mac)")


class RegistryMonitor:
    """Monitors startup registry keys for unauthorized persistence entries."""

    def __init__(self):
        self._baseline: dict[str, dict] = {}

    def _read_key(self, hive, key_path: str) -> dict:
        """Read all values from a registry key. Returns {name: value} dict."""
        values = {}
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name]  = str(data)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            log_agent.debug(f"Registry read error ({key_path}): {e}")
        return values

    def _snapshot(self) -> dict:
        """Read all monitored registry keys and return combined snapshot."""
        snapshot = {}
        if not _WINREG_OK:
            return snapshot

        for key_path in config.PERSISTENCE_REGISTRY_KEYS:
            for hive, label in [(winreg.HKEY_CURRENT_USER, "HKCU"),
                                 (winreg.HKEY_LOCAL_MACHINE, "HKLM")]:
                full_key = f"{label}\\{key_path}"
                snapshot[full_key] = self._read_key(hive, key_path)
        return snapshot

    def scan_once(self) -> list:
        """Compare current registry state to baseline. Return new/changed entries."""
        if not _WINREG_OK:
            return []

        current = self._snapshot()
        alerts  = []

        for key, values in current.items():
            baseline_values = self._baseline.get(key, {})
            for name, data in values.items():
                if name not in baseline_values:
                    # NEW entry — potential persistence
                    log_agent.warning(f"🔑 New registry entry: [{key}] {name} = {data[:80]}")
                    alerts.append({"key": key, "name": name, "data": data, "type": "new"})

                    db.log_alert(
                        alert_type  = "registry",
                        severity    = "HIGH",
                        title       = f"New registry persistence entry: {name}",
                        description = f"Key: {key}\nValue: {data[:200]}",
                        source      = "registry_monitor",
                        details     = {"key": key, "name": name, "data": data[:500]},
                    )

                    notify(
                        title    = "Registry Persistence Detected",
                        message  = f"New startup entry: {name}\n{data[:100]}",
                        severity = "WARNING",
                    )

        self._baseline = current
        return alerts

    def run_forever(self, interval: int = 60) -> None:
        """Run continuous registry monitoring loop."""
        log_agent.info("✓ Registry monitor started")
        # Take initial baseline
        self._baseline = self._snapshot()
        log_agent.info(f"  Baseline captured ({sum(len(v) for v in self._baseline.values())} entries)")

        while True:
            time.sleep(interval)
            self.scan_once()

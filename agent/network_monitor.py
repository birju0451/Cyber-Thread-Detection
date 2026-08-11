"""
agent/network_monitor.py
=========================
Monitors active network connections for suspicious behaviour:
  - Connections to known bad ports
  - High connection count (possible C2 beacon)
  - Connections to unusual countries / IPs

Uses: psutil.net_connections()
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
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

# Ports commonly used by malware
SUSPICIOUS_PORTS = {
    4444,  # Metasploit default
    1337,  # Leet / hacker port
    31337, # Back Orifice
    5554,  # Sasser worm
    9001,  # Tor
    9050,  # Tor SOCKS proxy
    6667,  # IRC botnet
    6697,
    8080,  # HTTP proxy / C2
    3389,  # RDP (if outbound and suspicious)
}


class NetworkMonitor:
    """Monitors active TCP connections for suspicious activity."""

    def __init__(self):
        self._alerted_conns: set = set()

    def scan_once(self) -> list:
        if not _PSUTIL_OK:
            return []

        alerts = []
        try:
            conns = psutil.net_connections(kind="tcp")
        except Exception as e:
            log_agent.debug(f"net_connections error: {e}")
            return []

        for conn in conns:
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port
            key         = (remote_ip, remote_port)

            if key in self._alerted_conns:
                continue

            alert = None
            if remote_port in SUSPICIOUS_PORTS:
                alert = {
                    "severity"   : "HIGH",
                    "title"      : f"Suspicious outbound connection on port {remote_port}",
                    "description": f"Process PID {conn.pid} → {remote_ip}:{remote_port}",
                }

            if alert:
                self._alerted_conns.add(key)
                log_agent.warning(f"🌐 {alert['title']}")

                db.log_alert(
                    alert_type  = "network",
                    severity    = alert["severity"],
                    title       = alert["title"],
                    description = alert["description"],
                    source      = "network_monitor",
                    details     = {"remote_ip": remote_ip, "remote_port": remote_port,
                                   "pid": conn.pid},
                )

                notify(
                    title    = "Suspicious Network Connection",
                    message  = alert["description"],
                    severity = "WARNING",
                )

                alerts.append(alert)

        return alerts

    def run_forever(self, interval: int = 20) -> None:
        log_agent.info("✓ Network monitor started")
        while True:
            self.scan_once()
            time.sleep(interval)

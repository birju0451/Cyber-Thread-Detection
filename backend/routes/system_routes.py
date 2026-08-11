"""
backend/routes/system_routes.py
=================================
Blueprint: /api/status, /api/system-info
Health check and live system telemetry.
"""

import sys
import time
import platform
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, jsonify
from backend.database import db
import config

system_bp = Blueprint("system", __name__)
_START_TIME = time.time()


@system_bp.route("/api/status", methods=["GET"])
def health_check():
    """Health check — always returns 200."""
    return jsonify({
        "status"   : "online",
        "version"  : "1.0.0",
        "uptime_s" : round(time.time() - _START_TIME),
        "db"       : "connected" if db.is_connected else "disconnected",
        "gemini"   : "enabled" if config.GEMINI_ENABLED else "disabled",
    }), 200


@system_bp.route("/api/system-info", methods=["GET"])
def system_info():
    """Return live CPU, RAM, and uptime stats."""
    try:
        import psutil
        cpu_pct  = psutil.cpu_percent(interval=0.5)
        ram      = psutil.virtual_memory()
        disk     = psutil.disk_usage("/")
        boot_t   = psutil.boot_time()
        uptime_s = int(time.time() - boot_t)

        return jsonify({
            "cpu_percent"    : cpu_pct,
            "ram_percent"    : ram.percent,
            "ram_used_gb"    : round(ram.used / 1e9, 2),
            "ram_total_gb"   : round(ram.total / 1e9, 2),
            "disk_percent"   : disk.percent,
            "disk_free_gb"   : round(disk.free / 1e9, 2),
            "uptime_seconds" : uptime_s,
            "uptime_human"   : _format_uptime(uptime_s),
            "platform"       : platform.system(),
            "platform_ver"   : platform.version()[:60],
            "hostname"       : platform.node(),
            "python_version" : platform.python_version(),
            "app_uptime_s"   : round(time.time() - _START_TIME),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _format_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s   = divmod(rem, 60)
    parts  = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

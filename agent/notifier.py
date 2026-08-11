"""
agent/notifier.py
==================
Windows desktop toast notifications for ABTD alerts.
Uses plyer (cross-platform) with Windows-specific fallback to win10toast.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.logger import log_agent

_NOTIFIER = None


def _get_notifier():
    global _NOTIFIER
    if _NOTIFIER:
        return _NOTIFIER
    try:
        from plyer import notification
        _NOTIFIER = "plyer"
    except Exception:
        try:
            from win10toast import ToastNotifier
            _NOTIFIER = ToastNotifier()
        except Exception:
            _NOTIFIER = "none"
    return _NOTIFIER


def notify(title: str, message: str, severity: str = "INFO", duration: int = 8) -> None:
    """
    Send a Windows desktop notification.

    Args:
        title    : Notification title
        message  : Body text (keep under 200 chars)
        severity : INFO | WARNING | CRITICAL
        duration : Display duration in seconds
    """
    icons = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🔴"}
    full_title = f"{icons.get(severity, '')} ABTD — {title}"
    message    = message[:250]

    notifier = _get_notifier()

    try:
        if notifier == "plyer":
            from plyer import notification as pn
            pn.notify(
                title      = full_title,
                message    = message,
                app_name   = "ABTD Security",
                timeout    = duration,
            )
        elif hasattr(notifier, "show_toast"):
            notifier.show_toast(
                title    = full_title,
                msg      = message,
                duration = duration,
                threaded = True,
            )
        else:
            log_agent.info(f"[NOTIFY] {full_title}: {message}")
    except Exception as e:
        log_agent.warning(f"Notification failed: {e}")

    log_agent.info(f"🔔 {full_title} — {message[:80]}")

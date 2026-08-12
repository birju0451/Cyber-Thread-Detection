"""
zero_trust/identity/identity_manager.py
========================================
Windows Identity Verification Module.

Responsibilities:
  - Retrieve current Windows user identity (username, SID, groups)
  - Detect administrator / elevated privilege status
  - Track session start time and duration
  - Detect unexpected privilege changes (elevation events)
  - Produce an Identity Risk contribution for the ZT Risk Calculator

Public API:
    mgr = IdentityManager()
    ctx = mgr.get_identity_context()   # Returns IdentityContext dict
    score = mgr.get_identity_risk()    # 0-100 risk score
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.identity")

# ── Optional Windows-specific imports ────────────────────────────────────────
try:
    import ctypes
    import ctypes.wintypes
    _CTYPES_OK = True
except ImportError:
    _CTYPES_OK = False

try:
    import win32api
    import win32con
    import win32security
    _WIN32_OK = True
except ImportError:
    _WIN32_OK = False
    log.debug("pywin32 not available — using os module fallback for identity")


class IdentityContext:
    """Snapshot of the current Windows user identity and trust state."""

    def __init__(self):
        self.username: str             = ""
        self.domain: str               = ""
        self.sid: str                  = ""
        self.is_admin: bool            = False
        self.is_elevated: bool         = False
        self.groups: list[str]         = []
        self.session_start: datetime   = datetime.now(timezone.utc)
        self.privilege_level: str      = "STANDARD"   # STANDARD | ADMIN | SYSTEM
        self.logon_type: str           = "INTERACTIVE"
        self.risk_flags: list[str]     = []
        self.sampled_at: datetime      = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "username"       : self.username,
            "domain"         : self.domain,
            "sid"            : self.sid,
            "is_admin"       : self.is_admin,
            "is_elevated"    : self.is_elevated,
            "groups"         : self.groups,
            "session_start"  : self.session_start.isoformat(),
            "privilege_level": self.privilege_level,
            "logon_type"     : self.logon_type,
            "risk_flags"     : self.risk_flags,
            "sampled_at"     : self.sampled_at.isoformat(),
        }


class IdentityManager:
    """
    Windows Identity Verification for Zero Trust.

    Uses win32security where available, falls back to os module
    for cross-environment compatibility (CI, non-Windows).
    """

    # How often to re-sample identity (seconds)
    _RESAMPLE_INTERVAL = 60

    def __init__(self):
        self._last_context: Optional[IdentityContext] = None
        self._last_sampled: float = 0.0
        self._lock = threading.Lock()
        self._privilege_history: list[dict] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def get_identity_context(self, force_refresh: bool = False) -> dict:
        """
        Return the current Windows user identity context.

        Results are cached for _RESAMPLE_INTERVAL seconds.
        Pass force_refresh=True to bypass cache.
        """
        now = time.time()
        with self._lock:
            if (force_refresh
                    or self._last_context is None
                    or now - self._last_sampled > self._RESAMPLE_INTERVAL):
                self._last_context = self._collect_identity()
                self._last_sampled = now
                self._detect_privilege_changes(self._last_context)

            return self._last_context.to_dict()

    def get_identity_risk(self) -> dict:
        """
        Calculate identity risk contribution (0–100).

        Higher risk when:
          - Running as SYSTEM
          - Elevated with no legitimate context
          - Recent unexpected privilege change
          - Unusual session characteristics
        """
        ctx = self.get_identity_context()
        score = 0
        reasons = []

        if ctx["privilege_level"] == "SYSTEM":
            score += 35
            reasons.append("Running as SYSTEM account — elevated risk")

        if ctx["is_elevated"] and ctx["privilege_level"] == "ADMIN":
            score += 20
            reasons.append("Process running with administrator elevation")

        if ctx["is_admin"] and not ctx["is_elevated"]:
            score += 5
            reasons.append("User is in Administrators group")

        # Recent privilege changes
        recent_changes = [
            p for p in self._privilege_history
            if (datetime.now(timezone.utc) - datetime.fromisoformat(p["timestamp"])).total_seconds() < 300
        ]
        if recent_changes:
            score += min(len(recent_changes) * 15, 30)
            reasons.append(f"{len(recent_changes)} privilege change(s) in last 5 minutes")

        score = min(score, 100)
        trust_score = max(0, 100 - score)

        return {
            "identity_risk"    : score,
            "identity_trust"   : trust_score,
            "username"         : ctx["username"],
            "privilege_level"  : ctx["privilege_level"],
            "is_elevated"      : ctx["is_elevated"],
            "reasons"          : reasons,
            "privilege_history": self._privilege_history[-10:],
        }

    # ── Internal Methods ──────────────────────────────────────────────────────

    def _collect_identity(self) -> IdentityContext:
        """Collect current Windows identity information."""
        ctx = IdentityContext()

        if _WIN32_OK:
            ctx = self._collect_win32(ctx)
        else:
            ctx = self._collect_os_fallback(ctx)

        return ctx

    def _collect_win32(self, ctx: IdentityContext) -> IdentityContext:
        """Collect identity using win32security (most accurate)."""
        try:
            ctx.username = win32api.GetUserName()
            ctx.domain   = os.environ.get("USERDOMAIN", os.environ.get("COMPUTERNAME", ""))

            # Get token SID
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            sid_obj = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            ctx.sid = win32security.ConvertSidToStringSid(sid_obj)

            # Check elevation
            elevation = win32security.GetTokenInformation(
                token, win32security.TokenElevation
            )
            ctx.is_elevated = bool(elevation)

            # Get groups
            groups_info = win32security.GetTokenInformation(
                token, win32security.TokenGroups
            )
            group_names = []
            for sid, _ in groups_info:
                try:
                    name, domain, _ = win32security.LookupAccountSid(None, sid)
                    group_names.append(f"{domain}\\{name}" if domain else name)
                except Exception:
                    pass
            ctx.groups = group_names

            # Determine privilege level
            admin_sid = win32security.CreateWellKnownSid(
                win32security.WinBuiltinAdministratorsSid, None
            )
            ctx.is_admin = win32security.CheckTokenMembership(None, admin_sid)

            system_sid = win32security.CreateWellKnownSid(
                win32security.WinLocalSystemSid, None
            )
            is_system = win32security.CheckTokenMembership(None, system_sid)

            if is_system:
                ctx.privilege_level = "SYSTEM"
            elif ctx.is_admin:
                ctx.privilege_level = "ADMIN"
            else:
                ctx.privilege_level = "STANDARD"

        except Exception as e:
            log.debug(f"win32security identity collection partial: {e}")
            ctx = self._collect_os_fallback(ctx)

        return ctx

    def _collect_os_fallback(self, ctx: IdentityContext) -> IdentityContext:
        """Collect identity using standard os module (cross-platform fallback)."""
        ctx.username = os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
        ctx.domain   = os.environ.get("USERDOMAIN", os.environ.get("COMPUTERNAME", ""))
        ctx.sid      = os.environ.get("USERPROFILE", "").replace("\\", "/")

        # Check admin via ctypes (Windows)
        if _CTYPES_OK and sys.platform == "win32":
            try:
                ctx.is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
                ctx.is_admin    = ctx.is_elevated
            except Exception:
                ctx.is_elevated = False
                ctx.is_admin    = False
        else:
            # Unix: check UID 0
            ctx.is_admin    = (os.getuid() == 0) if hasattr(os, "getuid") else False
            ctx.is_elevated = ctx.is_admin

        if ctx.is_admin:
            ctx.privilege_level = "ADMIN"
        else:
            ctx.privilege_level = "STANDARD"

        return ctx

    def _detect_privilege_changes(self, ctx: IdentityContext) -> None:
        """Detect unexpected privilege escalations vs previous snapshot."""
        if self._last_context is None:
            return

        prev = self._last_context
        if prev.privilege_level != ctx.privilege_level:
            change = {
                "timestamp"  : datetime.now(timezone.utc).isoformat(),
                "from_level" : prev.privilege_level,
                "to_level"   : ctx.privilege_level,
                "username"   : ctx.username,
            }
            self._privilege_history.append(change)
            log.warning(
                f"Privilege change detected: {prev.privilege_level} → {ctx.privilege_level} "
                f"for user '{ctx.username}'"
            )
            # Keep last 100 changes
            self._privilege_history = self._privilege_history[-100:]


# Singleton
identity_manager = IdentityManager()

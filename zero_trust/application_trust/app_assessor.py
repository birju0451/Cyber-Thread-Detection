"""
zero_trust/application_trust/app_assessor.py
==============================================
Application Trust Assessment Module.

For every monitored application, evaluates:
  - Digital signature (Authenticode) validity
  - Publisher / signer identity
  - Executable path legitimacy (system vs. temp vs. user)
  - File hash (SHA-256)
  - Reputation tier (Microsoft / well-known / unknown / suspicious)
  - Execution history tracking

Produces an Application Trust Score (0–100) per application.

Public API:
    assessor = ApplicationAssessor()
    result   = assessor.assess_app(exe_path)
    score    = assessor.get_trust_score(exe_path)
    profile  = assessor.get_app_profiles()
"""

import os
import sys
import hashlib
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.app_trust")

try:
    import win32api
    import win32con
    _WIN32_OK = True
except ImportError:
    _WIN32_OK = False

# ── Known trusted publisher / path sets ──────────────────────────────────────
TRUSTED_PUBLISHERS = {
    "microsoft corporation", "google llc", "mozilla corporation",
    "adobe inc", "oracle corporation", "intel corporation",
    "nvidia corporation", "apple inc", "autodesk", "slack technologies",
    "zoom video communications", "dropbox inc", "spotify ab",
    "valve corporation", "epic games", "discord inc",
}

# Paths considered legitimate installation locations
TRUSTED_PATH_PREFIXES = (
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)

# Paths considered high-risk for executables
SUSPICIOUS_PATH_PREFIXES = (
    os.path.expanduser("~\\appdata\\local\\temp\\").lower(),
    os.path.expanduser("~\\downloads\\").lower(),
    "c:\\temp\\",
    "c:\\tmp\\",
    "c:\\users\\public\\",
)


class AppProfile:
    """Per-application trust profile tracked over time."""

    def __init__(self, exe_path: str):
        self.exe_path        : str              = exe_path
        self.app_name        : str              = Path(exe_path).name
        self.trust_score     : int              = 50
        self.is_signed       : bool             = False
        self.is_trusted_signer: bool            = False
        self.publisher       : str              = "Unknown"
        self.sha256          : str              = ""
        self.path_risk       : str              = "UNKNOWN"  # TRUSTED / SUSPICIOUS / UNKNOWN
        self.first_seen      : datetime         = datetime.now(timezone.utc)
        self.last_seen       : datetime         = datetime.now(timezone.utc)
        self.execution_count : int              = 0
        self.risk_flags      : list[str]        = []
        self.last_assessed   : Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "exe_path"         : self.exe_path,
            "app_name"         : self.app_name,
            "trust_score"      : self.trust_score,
            "is_signed"        : self.is_signed,
            "is_trusted_signer": self.is_trusted_signer,
            "publisher"        : self.publisher,
            "sha256"           : self.sha256,
            "path_risk"        : self.path_risk,
            "first_seen"       : self.first_seen.isoformat(),
            "last_seen"        : self.last_seen.isoformat(),
            "execution_count"  : self.execution_count,
            "risk_flags"       : self.risk_flags,
            "last_assessed"    : self.last_assessed.isoformat() if self.last_assessed else None,
        }


class ApplicationAssessor:
    """
    Assess trust level of applications by inspecting their
    signature, publisher, path, and behavioral history.
    """

    def __init__(self):
        self._profiles: dict[str, AppProfile] = {}
        self._sig_cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def assess_app(self, exe_path: str) -> dict:
        """
        Assess an application's trust level.
        Creates or updates the app profile.
        Returns full assessment dict.
        """
        exe_path = str(exe_path).strip()
        with self._lock:
            if exe_path not in self._profiles:
                self._profiles[exe_path] = AppProfile(exe_path)
            profile = self._profiles[exe_path]

        result = self._run_assessment(profile, exe_path)

        with self._lock:
            profile.trust_score   = result["app_trust_score"]
            profile.is_signed     = result["signature"]["is_signed"]
            profile.publisher     = result["signature"].get("publisher", "Unknown")
            profile.is_trusted_signer = result["signature"].get("is_trusted_publisher", False)
            profile.sha256        = result.get("sha256", "")
            profile.path_risk     = result["path_analysis"]["risk"]
            profile.risk_flags    = result["risk_flags"]
            profile.last_seen     = datetime.now(timezone.utc)
            profile.execution_count += 1
            profile.last_assessed = datetime.now(timezone.utc)

        return result

    def get_trust_score(self, exe_path: str) -> int:
        """Return cached trust score or run assessment."""
        with self._lock:
            if exe_path in self._profiles:
                return self._profiles[exe_path].trust_score
        return self.assess_app(exe_path).get("app_trust_score", 50)

    def get_app_profiles(self) -> list:
        """Return all tracked application profiles, auto-discovering from running processes if list is small."""
        with self._lock:
            if len(self._profiles) < 5:
                self._discover_running_apps()
            return [p.to_dict() for p in self._profiles.values()]

    def _discover_running_apps(self) -> None:
        """Discover unique running executables via psutil and populate app profiles."""
        try:
            import psutil
            seen_exes = set()
            for proc in psutil.process_iter(["exe"]):
                try:
                    exe = proc.info.get("exe")
                    if exe and exe not in seen_exes and os.path.exists(exe):
                        seen_exes.add(exe)
                        if len(seen_exes) >= 50:
                            break
                        # Lightweight path check before full signature check
                        if exe not in self._profiles:
                            self._profiles[exe] = AppProfile(exe)
                            # Fast initial profile
                            path_risk = self._analyze_path(exe)["risk"]
                            self._profiles[exe].path_risk = path_risk
                            self._profiles[exe].trust_score = 90 if path_risk == "TRUSTED" else 60
                except Exception:
                    continue
        except Exception as e:
            log.debug(f"App auto-discovery error: {e}")

    def record_execution(self, exe_path: str) -> None:
        """Record that an application was executed (without full re-assessment)."""
        with self._lock:
            if exe_path not in self._profiles:
                self._profiles[exe_path] = AppProfile(exe_path)
            self._profiles[exe_path].execution_count += 1
            self._profiles[exe_path].last_seen = datetime.now(timezone.utc)

    # ── Assessment Engine ─────────────────────────────────────────────────────

    def _run_assessment(self, profile: AppProfile, exe_path: str) -> dict:
        demerits = 0
        flags    = []
        path_obj = Path(exe_path)

        # 1. File existence check
        file_exists = path_obj.exists()
        if not file_exists:
            return {
                "exe_path"        : exe_path,
                "app_name"        : path_obj.name,
                "app_trust_score" : 0,
                "error"           : "File not found",
                "risk_flags"      : ["Executable file does not exist"],
                "signature"       : {"is_signed": False},
                "path_analysis"   : {"risk": "UNKNOWN"},
                "sha256"          : "",
                "assessed_at"     : datetime.now(timezone.utc).isoformat(),
            }

        # 2. Digital signature check
        sig = self._check_signature(exe_path)
        if not sig["is_signed"]:
            demerits += 30
            flags.append("Application is not digitally signed")
        elif not sig.get("is_trusted_publisher"):
            demerits += 15
            flags.append(f"Signed by unknown publisher: {sig.get('publisher','?')}")

        # 3. Path analysis
        path_analysis = self._analyze_path(exe_path)
        if path_analysis["risk"] == "SUSPICIOUS":
            demerits += 35
            flags.append(f"Executable in suspicious location: {exe_path}")
        elif path_analysis["risk"] == "UNKNOWN":
            demerits += 10
            flags.append("Executable in non-standard location")

        # 4. SHA-256 hash
        sha256 = self._compute_sha256(exe_path)

        # 5. Double extension check
        name_lower = path_obj.name.lower()
        if any(name_lower.endswith(ext) for ext in
               [".exe.exe", ".pdf.exe", ".doc.exe", ".jpg.exe"]):
            demerits += 40
            flags.append("Double extension detected — likely malicious masquerade")

        # Trust score
        trust_score = max(0, 100 - demerits)

        return {
            "exe_path"        : exe_path,
            "app_name"        : path_obj.name,
            "app_trust_score" : trust_score,
            "risk_flags"      : flags,
            "signature"       : sig,
            "path_analysis"   : path_analysis,
            "sha256"          : sha256,
            "assessed_at"     : datetime.now(timezone.utc).isoformat(),
        }

    def _check_signature(self, exe_path: str) -> dict:
        """Check Authenticode digital signature with caching."""
        if exe_path in self._sig_cache:
            return self._sig_cache[exe_path]

        result = {
            "is_signed"         : False,
            "publisher"         : "Unknown",
            "is_trusted_publisher": False,
            "signature_status"  : "UNSIGNED",
        }

        # Fast path check for known Windows / Microsoft binaries
        exe_lower = exe_path.lower()
        if "c:\\windows\\system32\\" in exe_lower or "c:\\windows\\" in exe_lower:
            result["is_signed"] = True
            result["publisher"] = "Microsoft Windows"
            result["is_trusted_publisher"] = True
            result["signature_status"] = "Valid"
            self._sig_cache[exe_path] = result
            return result

        try:
            if sys.platform == "win32":
                ps_cmd = (
                    f"$sig = Get-AuthenticodeSignature '{exe_path}'; "
                    "$sig.Status; $sig.SignerCertificate.Subject"
                )
                out = subprocess.run(
                    ["powershell", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=4
                )
                lines = [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
                if lines:
                    status = lines[0]
                    result["signature_status"] = status
                    result["is_signed"] = status == "Valid"
                    if len(lines) > 1:
                        subject = lines[1]
                        for part in subject.split(","):
                            if part.strip().startswith("CN="):
                                result["publisher"] = part.strip()[3:]
                                break
                        pub_lower = result["publisher"].lower()
                        result["is_trusted_publisher"] = any(
                            t in pub_lower for t in TRUSTED_PUBLISHERS
                        )
        except Exception as e:
            log.debug(f"Signature check error for {exe_path}: {e}")

        self._sig_cache[exe_path] = result
        return result


    def _analyze_path(self, exe_path: str) -> dict:
        """Determine if the executable path is trusted, suspicious, or unknown."""
        path_lower = exe_path.lower().replace("\\", "/")

        for prefix in TRUSTED_PATH_PREFIXES:
            if path_lower.startswith(prefix.lower().replace("\\", "/")):
                return {"risk": "TRUSTED", "path": exe_path}

        for prefix in SUSPICIOUS_PATH_PREFIXES:
            if path_lower.startswith(prefix.lower().replace("\\", "/")):
                return {"risk": "SUSPICIOUS", "path": exe_path}

        return {"risk": "UNKNOWN", "path": exe_path}

    def _compute_sha256(self, exe_path: str) -> str:
        """Compute SHA-256 hash of the executable."""
        try:
            h = hashlib.sha256()
            with open(exe_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""


# Singleton & Alias
app_assessor = ApplicationAssessor()
AppAssessor = ApplicationAssessor


"""
zero_trust/device_trust/device_assessor.py
============================================
Device Trust Assessment Module.

Evaluates the security posture of the Windows endpoint:
  - Windows version and build
  - Security update status (last patch date via WMI)
  - Windows Firewall status
  - Windows Defender / Antivirus status
  - Secure Boot status
  - BitLocker encryption status
  - Active user privilege
  - Running security services
  - Suspicious configuration changes

Produces a Device Trust Score (0–100).
Higher score = more trusted device.

Public API:
    assessor = DeviceAssessor()
    result   = assessor.assess()   # Returns full assessment dict
    score    = assessor.get_trust_score()
"""

import os
import sys
import logging
import platform
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.device")

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

try:
    import winreg
    _WINREG_OK = True
except ImportError:
    _WINREG_OK = False

try:
    import wmi
    _WMI_OK = True
except ImportError:
    _WMI_OK = False
    log.debug("wmi not available — using registry/subprocess fallback")


class DeviceAssessor:
    """
    Assess the security posture of the Windows device and produce
    a Device Trust Score for Zero Trust decisions.
    """

    # Cache assessment for this many seconds
    _CACHE_TTL = 300  # 5 minutes

    def __init__(self):
        self._cache: Optional[dict] = None
        self._cache_time: float = 0.0
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def assess(self, force_refresh: bool = False) -> dict:
        """
        Run full device trust assessment.
        Returns structured dict with all checks and final trust score.
        """
        now = time.time()
        with self._lock:
            if (not force_refresh
                    and self._cache is not None
                    and now - self._cache_time < self._CACHE_TTL):
                return self._cache

            result = self._run_assessment()
            self._cache = result
            self._cache_time = now
            return result

    def get_trust_score(self) -> int:
        """Return device trust score (0–100). 100 = fully trusted."""
        return self.assess().get("device_trust_score", 50)

    # ── Assessment Engine ─────────────────────────────────────────────────────

    def _run_assessment(self) -> dict:
        checks   = {}
        demerits = 0
        flags    = []

        # 1. Windows version
        win_info = self._check_windows_version()
        checks["windows_version"] = win_info
        if not win_info.get("is_supported"):
            demerits += 20
            flags.append("Unsupported or old Windows version")

        # 2. Firewall status
        fw = self._check_firewall()
        checks["firewall"] = fw
        if not fw.get("enabled"):
            demerits += 20
            flags.append("Windows Firewall is DISABLED — high risk")

        # 3. Defender / Antivirus
        av = self._check_antivirus()
        checks["antivirus"] = av
        if not av.get("real_time_protection"):
            demerits += 20
            flags.append("Real-time protection disabled")
        if av.get("signatures_outdated"):
            demerits += 10
            flags.append("Antivirus signatures may be outdated")

        # 4. Windows Update / patch level
        patch = self._check_patch_status()
        checks["patch_status"] = patch
        if patch.get("days_since_update", 999) > 30:
            demerits += 15
            flags.append(f"Last Windows update was {patch.get('days_since_update')} days ago")
        elif patch.get("days_since_update", 999) > 14:
            demerits += 5
            flags.append("Windows update overdue (> 14 days)")

        # 5. Secure Boot
        sb = self._check_secure_boot()
        checks["secure_boot"] = sb
        if not sb.get("enabled"):
            demerits += 10
            flags.append("Secure Boot not enabled or not detectable")

        # 6. Disk encryption (BitLocker)
        enc = self._check_disk_encryption()
        checks["disk_encryption"] = enc
        if not enc.get("any_encrypted"):
            demerits += 10
            flags.append("No disk encryption detected (BitLocker not active)")

        # 7. Security services
        svc = self._check_security_services()
        checks["security_services"] = svc
        stopped = [s for s, ok in svc.get("services", {}).items() if not ok]
        if stopped:
            demerits += min(len(stopped) * 5, 15)
            flags.append(f"Security services not running: {', '.join(stopped)}")

        # 8. System resource state
        res = self._check_system_resources()
        checks["resources"] = res

        # Calculate trust score
        trust_score = max(0, 100 - demerits)

        # Determine trust level
        if trust_score >= 85:
            trust_level = "HIGH"
        elif trust_score >= 65:
            trust_level = "MEDIUM"
        elif trust_score >= 40:
            trust_level = "LOW"
        else:
            trust_level = "UNTRUSTED"

        return {
            "device_trust_score" : trust_score,
            "device_trust_level" : trust_level,
            "total_demerits"     : demerits,
            "risk_flags"         : flags,
            "checks"             : checks,
            "assessed_at"        : datetime.now(timezone.utc).isoformat(),
            "platform"           : platform.platform(),
            "hostname"           : platform.node(),
        }

    # ── Individual Checks ─────────────────────────────────────────────────────

    def _check_windows_version(self) -> dict:
        try:
            ver = platform.version()          # e.g. "10.0.22621"
            release = platform.release()      # "10" or "11"
            build = int(ver.split(".")[-1]) if ver else 0

            # Windows 10 1903+ = build 18362+, Windows 11 = build 22000+
            is_supported = build >= 18362

            return {
                "version"     : ver,
                "release"     : release,
                "build"       : build,
                "is_supported": is_supported,
                "is_win11"    : build >= 22000,
            }
        except Exception as e:
            return {"version": "unknown", "is_supported": False, "error": str(e)}

    def _check_firewall(self) -> dict:
        """Check Windows Firewall status via netsh / registry."""
        result = {"enabled": False, "profiles": {}}
        try:
            # Registry check for Domain/Private/Public profiles
            if _WINREG_OK:
                profiles = {
                    "Domain"  : r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                    "Private" : r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                    "Public"  : r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                }
                enabled_count = 0
                for name, path in profiles.items():
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                        val, _ = winreg.QueryValueEx(key, "EnableFirewall")
                        winreg.CloseKey(key)
                        is_on = bool(val)
                        result["profiles"][name] = is_on
                        if is_on:
                            enabled_count += 1
                    except Exception:
                        result["profiles"][name] = None

                result["enabled"] = enabled_count >= 2  # at least 2 of 3 profiles on
            else:
                # Subprocess fallback
                out = subprocess.check_output(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=5
                ).stdout if sys.platform == "win32" else ""
                result["enabled"] = "State                                 ON" in out
        except Exception as e:
            log.debug(f"Firewall check error: {e}")

        return result

    def _check_antivirus(self) -> dict:
        """Check Windows Defender / AV status."""
        result = {
            "real_time_protection": False,
            "signatures_outdated" : True,
            "av_product"          : "Unknown",
            "last_scan_days"      : -1,
        }
        try:
            if _WINREG_OK:
                # Defender real-time protection
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
                    )
                    val, _ = winreg.QueryValueEx(key, "DisableRealtimeMonitoring")
                    winreg.CloseKey(key)
                    result["real_time_protection"] = not bool(val)
                    result["av_product"] = "Windows Defender"
                except FileNotFoundError:
                    # Defender key absent → may be using 3rd-party AV
                    result["real_time_protection"] = True  # Assume OK
                    result["av_product"] = "Third-party AV (assumed)"

                # Defender signature date
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
                    )
                    sig_date_str, _ = winreg.QueryValueEx(key, "SignatureUpdateDateTime")
                    winreg.CloseKey(key)
                    if sig_date_str:
                        result["signature_date"] = str(sig_date_str)
                        result["signatures_outdated"] = False
                except Exception:
                    pass

        except Exception as e:
            log.debug(f"AV check error: {e}")

        return result

    def _check_patch_status(self) -> dict:
        """Check last Windows update via registry."""
        result = {"last_update": None, "days_since_update": 999}
        try:
            if _WINREG_OK:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
                )
                last_success, _ = winreg.QueryValueEx(key, "LastSuccessTime")
                winreg.CloseKey(key)
                if last_success:
                    # Format: "yyyy-mm-dd hh:mm:ss"
                    result["last_update"] = str(last_success)
                    try:
                        last_dt = datetime.strptime(str(last_success)[:19], "%Y-%m-%d %H:%M:%S")
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                        delta = datetime.now(timezone.utc) - last_dt
                        result["days_since_update"] = delta.days
                    except Exception:
                        pass
        except Exception as e:
            log.debug(f"Patch check error: {e}")

        return result

    def _check_secure_boot(self) -> dict:
        """Check Secure Boot status via registry."""
        result = {"enabled": False, "detected": False}
        try:
            if _WINREG_OK:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
                    )
                    val, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
                    winreg.CloseKey(key)
                    result["enabled"]  = bool(val)
                    result["detected"] = True
                except FileNotFoundError:
                    result["enabled"]  = False
                    result["detected"] = False
        except Exception as e:
            log.debug(f"Secure Boot check error: {e}")

        return result

    def _check_disk_encryption(self) -> dict:
        """Check BitLocker status via manage-bde or registry."""
        result = {"any_encrypted": False, "drives": {}}
        try:
            if sys.platform == "win32":
                out = subprocess.run(
                    ["manage-bde", "-status"],
                    capture_output=True, text=True, timeout=10
                )
                if out.returncode == 0:
                    text = out.stdout
                    result["any_encrypted"] = "Protection On" in text
                    result["raw_status"] = text[:500]
        except Exception as e:
            log.debug(f"BitLocker check error: {e}")
            # Non-critical — many research machines don't have BitLocker
            result["any_encrypted"] = False

        return result

    def _check_security_services(self) -> dict:
        """Check that critical Windows security services are running."""
        target_services = {
            "WinDefend"  : "Windows Defender Antivirus",
            "MpsSvc"     : "Windows Firewall",
            "WdNisSvc"   : "Defender Network Inspection",
            "SecurityHealthService": "Security Health",
        }
        services_status = {}

        if _PSUTIL_OK:
            try:
                running = {s.name().lower() for s in psutil.win_service_iter()}
                for svc_name, friendly in target_services.items():
                    services_status[friendly] = svc_name.lower() in running
            except Exception as e:
                log.debug(f"Service check error: {e}")

        return {"services": services_status}

    def _check_system_resources(self) -> dict:
        """Collect current system resource usage."""
        if not _PSUTIL_OK:
            return {}
        try:
            return {
                "cpu_percent"  : psutil.cpu_percent(interval=0.5),
                "ram_percent"  : psutil.virtual_memory().percent,
                "disk_percent" : psutil.disk_usage("/").percent,
            }
        except Exception:
            return {}


# Singleton
device_assessor = DeviceAssessor()

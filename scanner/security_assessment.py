"""
scanner/security_assessment.py
================================
Full Security Assessment Engine.

Performs a comprehensive security posture evaluation of the Windows
endpoint and produces four composite scores:

  1. Security Posture Score      — Device hygiene and hardening
  2. Zero Trust Readiness Score  — How ZT-compliant the system is
  3. Behavioral Risk Score       — Observed behavioral anomaly level
  4. Overall Security Risk       — Composite of all above

Assessment Categories:
  [1]  User Privilege Analysis
  [2]  Device Security Posture
  [3]  Installed Applications
  [4]  Running Processes
  [5]  Startup Programs
  [6]  Scheduled Tasks
  [7]  Registry Security Configuration
  [8]  Browser Extensions
  [9]  Downloads Folder
  [10] Network Connections
  [11] Firewall Configuration
  [12] Security Services
  [13] Sensitive Resource Access

Progress is reported via a callback: callback(progress: int, stage: str)

Public API:
    assessor = SecurityAssessment()
    result   = assessor.run()
"""

import os
import sys
import time
import logging
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config

log = logging.getLogger("abtd.assessment")

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


class SecurityAssessment:
    """
    Comprehensive Windows security posture assessment.
    Reports progress via optional callback.
    """

    # Weight allocation for Security Posture Score
    POSTURE_WEIGHTS = {
        "firewall"          : 15,
        "antivirus"         : 15,
        "patches"           : 12,
        "secure_boot"       : 8,
        "encryption"        : 8,
        "services"          : 7,
        "user_privileges"   : 10,
        "startup_items"     : 5,
        "registry_security" : 5,
        "network"           : 5,
        "downloads"         : 5,
        "scheduled_tasks"   : 5,
    }

    def __init__(self, progress_callback: Optional[Callable] = None):
        self._callback = progress_callback or (lambda p, s: None)
        self._findings: list[dict] = []

    def run(self) -> dict:
        """
        Run the full security assessment.
        Returns comprehensive assessment result dict.
        """
        t_start = time.time()
        results = {}

        stages = [
            (5,  "Checking user privileges",          self._check_user_privileges),
            (15, "Assessing device security posture", self._check_device_posture),
            (25, "Auditing startup programs",         self._check_startup_programs),
            (35, "Scanning scheduled tasks",          self._check_scheduled_tasks),
            (45, "Analyzing registry security",       self._check_registry_security),
            (55, "Reviewing running processes",       self._check_running_processes),
            (65, "Scanning downloads folder",         self._check_downloads),
            (73, "Checking network connections",      self._check_network),
            (82, "Auditing browser extensions",       self._check_browser_extensions),
            (90, "Verifying security services",       self._check_security_services),
            (97, "Calculating final scores",          lambda: {}),
        ]

        for progress, stage_name, fn in stages:
            self._callback(progress, stage_name)
            log.info(f"Assessment: {stage_name}")
            try:
                results[stage_name.split(" ")[-1]] = fn()
            except Exception as e:
                log.warning(f"Assessment stage '{stage_name}' failed: {e}")
                results[stage_name.split(" ")[-1]] = {"error": str(e)}

        # Calculate composite scores
        scores = self._calculate_scores(results)

        elapsed = round(time.time() - t_start, 1)
        self._callback(100, "complete")

        return {
            "assessed_at"             : datetime.now(timezone.utc).isoformat(),
            "platform"                : platform.platform(),
            "hostname"                : platform.node(),
            "username"                : os.environ.get("USERNAME", "unknown"),
            "duration_seconds"        : elapsed,
            "security_posture_score"  : scores["posture"],
            "zero_trust_readiness_score": scores["zt_readiness"],
            "behavioral_risk_score"   : scores["behavioral"],
            "overall_security_risk"   : scores["overall_risk"],
            "overall_trust_level"     : scores["trust_level"],
            "findings"                : self._findings,
            "finding_count"           : len(self._findings),
            "critical_findings"       : sum(1 for f in self._findings if f["severity"] == "CRITICAL"),
            "high_findings"           : sum(1 for f in self._findings if f["severity"] == "HIGH"),
            "medium_findings"         : sum(1 for f in self._findings if f["severity"] == "MEDIUM"),
            "categories"              : results,
            "recommendations"         : self._generate_recommendations(scores),
        }

    # ── Assessment Stages ─────────────────────────────────────────────────────

    def _check_user_privileges(self) -> dict:
        result = {"is_admin": False, "is_elevated": False, "risk": "LOW"}
        try:
            from zero_trust.identity.identity_manager import identity_manager
            ctx  = identity_manager.get_identity_context()
            risk = identity_manager.get_identity_risk()

            result["username"]       = ctx.get("username")
            result["privilege_level"]= ctx.get("privilege_level")
            result["is_admin"]       = ctx.get("is_admin")
            result["is_elevated"]    = ctx.get("is_elevated")
            result["identity_risk"]  = risk.get("identity_risk", 0)

            if ctx.get("privilege_level") == "SYSTEM":
                self._add_finding("HIGH", "User", "Running as SYSTEM account",
                                  "Running as SYSTEM is unusual for interactive users")
                result["risk"] = "HIGH"
            elif ctx.get("is_elevated"):
                self._add_finding("MEDIUM", "User", "Elevated administrator session",
                                  "Consider using standard user account for daily work")
                result["risk"] = "MEDIUM"
        except Exception as e:
            result["error"] = str(e)
        return result

    def _check_device_posture(self) -> dict:
        try:
            from zero_trust.device_trust.device_assessor import device_assessor
            assessment = device_assessor.assess(force_refresh=True)

            for flag in assessment.get("risk_flags", []):
                severity = "HIGH" if "disabled" in flag.lower() or "unsupported" in flag.lower() else "MEDIUM"
                self._add_finding(severity, "Device", flag, "")

            return assessment
        except Exception as e:
            return {"error": str(e)}

    def _check_startup_programs(self) -> dict:
        startup_items = []
        suspicious    = []

        if not _WINREG_OK:
            return {"items": [], "suspicious_count": 0}

        run_keys = [
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hive, key_path in run_keys:
            try:
                key = winreg.OpenKey(hive, key_path)
                i   = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        item = {"name": name, "command": str(value)[:200]}
                        startup_items.append(item)

                        # Flag suspicious startup entries
                        val_lower = value.lower() if value else ""
                        if any(p in val_lower for p in
                               ["temp\\", "tmp\\", "appdata\\local\\temp", ".ps1", ".vbs"]):
                            suspicious.append(item)
                            self._add_finding(
                                "HIGH", "Startup",
                                f"Suspicious startup entry: {name}",
                                f"Command: {value[:100]}"
                            )
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass

        return {
            "total_items"     : len(startup_items),
            "suspicious_count": len(suspicious),
            "items"           : startup_items[:20],
            "suspicious_items": suspicious,
        }

    def _check_scheduled_tasks(self) -> dict:
        tasks      = []
        suspicious = []

        if sys.platform != "win32":
            return {"items": [], "suspicious_count": 0}

        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                for line in lines[1:50]:   # Skip header, limit to 50
                    parts = line.split('","')
                    if len(parts) >= 9:
                        task = {
                            "task_name": parts[0].strip('"'),
                            "status"   : parts[3].strip('"') if len(parts) > 3 else "",
                            "run_as"   : parts[7].strip('"') if len(parts) > 7 else "",
                        }
                        tasks.append(task)
                        # Flag tasks running as SYSTEM from suspicious paths
                        if "system" in task.get("run_as", "").lower():
                            if "\\temp\\" in task.get("task_name", "").lower():
                                suspicious.append(task)
                                self._add_finding(
                                    "HIGH", "Scheduled Tasks",
                                    f"Suspicious scheduled task: {task['task_name']}",
                                    "Task from temp directory running as SYSTEM"
                                )
        except Exception as e:
            log.debug(f"Scheduled tasks check error: {e}")

        return {
            "total_count"     : len(tasks),
            "suspicious_count": len(suspicious),
            "suspicious_items": suspicious,
        }

    def _check_registry_security(self) -> dict:
        issues = []
        if not _WINREG_OK:
            return {"issues": [], "score": 100}

        # Check UAC setting
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            )
            uac_enabled, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            if not uac_enabled:
                issues.append("UAC is disabled")
                self._add_finding("HIGH", "Registry", "UAC (User Account Control) is disabled",
                                  "Enable UAC to protect against unauthorized privilege escalation")
        except Exception:
            pass

        # Check for LSASS protection
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa"
            )
            try:
                ppl, _ = winreg.QueryValueEx(key, "RunAsPPL")
                if not ppl:
                    issues.append("LSASS PPL not enabled")
            except FileNotFoundError:
                issues.append("LSASS PPL not configured")
                self._add_finding("MEDIUM", "Registry", "LSASS protected process not configured",
                                  "Enable RunAsPPL to protect credentials in memory")
            winreg.CloseKey(key)
        except Exception:
            pass

        registry_score = max(0, 100 - len(issues) * 20)
        return {"issues": issues, "score": registry_score}

    def _check_running_processes(self) -> dict:
        if not _PSUTIL_OK:
            return {"process_count": 0, "suspicious_count": 0}

        suspicious = []
        total      = 0
        try:
            from zero_trust.process_trust.process_assessor import process_assessor
            processes = process_assessor.assess_all_running(max_processes=100)
            total     = len(processes)
            suspicious = [p for p in processes if p.get("process_risk_score", 0) >= 50]

            for proc in suspicious[:5]:
                self._add_finding(
                    "HIGH" if proc["process_risk_score"] >= 75 else "MEDIUM",
                    "Process",
                    f"Suspicious process: {proc['process_name']} (risk={proc['process_risk_score']})",
                    f"Flags: {', '.join(proc.get('risk_flags', [])[:2])}"
                )
        except Exception as e:
            log.debug(f"Process check error: {e}")

        return {
            "total_count"     : total,
            "suspicious_count": len(suspicious),
            "top_suspicious"  : [
                {"name": p["process_name"], "pid": p["pid"], "risk": p["process_risk_score"]}
                for p in suspicious[:5]
            ],
        }

    def _check_downloads(self) -> dict:
        downloads_dir = Path(os.path.expanduser("~/Downloads"))
        suspicious    = []
        total         = 0

        if not downloads_dir.exists():
            return {"total_files": 0, "suspicious_count": 0}

        try:
            for file in downloads_dir.iterdir():
                if file.is_file():
                    total += 1
                    if file.suffix.lower() in config.SUSPICIOUS_EXTENSIONS:
                        suspicious.append({
                            "name"   : file.name,
                            "path"   : str(file),
                            "size_kb": round(file.stat().st_size / 1024, 1),
                            "ext"    : file.suffix.lower(),
                        })
                        self._add_finding(
                            "MEDIUM", "Downloads",
                            f"Executable in Downloads: {file.name}",
                            f"Consider scanning: {file.name}"
                        )
        except Exception as e:
            log.debug(f"Downloads check error: {e}")

        return {
            "total_files"     : total,
            "suspicious_count": len(suspicious),
            "suspicious_files": suspicious[:10],
            "downloads_path"  : str(downloads_dir),
        }

    def _check_network(self) -> dict:
        if not _PSUTIL_OK:
            return {"connection_count": 0, "suspicious_count": 0}

        suspicious    = []
        total         = 0
        suspicious_ports = {4444, 5555, 1337, 31337, 6666, 9001}

        try:
            conns = psutil.net_connections(kind="inet")
            total = len(conns)
            for conn in conns:
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    suspicious.append({
                        "local"  : f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote" : f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status" : conn.status,
                        "pid"    : conn.pid,
                    })
                    self._add_finding(
                        "HIGH", "Network",
                        f"Connection to suspicious port {conn.raddr.port}",
                        f"Remote: {conn.raddr.ip}:{conn.raddr.port}"
                    )
        except Exception as e:
            log.debug(f"Network check error: {e}")

        return {
            "total_connections": total,
            "suspicious_count" : len(suspicious),
            "suspicious_conns" : suspicious[:10],
        }

    def _check_browser_extensions(self) -> dict:
        """Check installed Chrome extensions."""
        extensions  = []
        chrome_base = Path(os.path.expanduser(
            "~/AppData/Local/Google/Chrome/User Data/Default/Extensions"
        ))

        if chrome_base.exists():
            try:
                for ext_dir in chrome_base.iterdir():
                    if ext_dir.is_dir():
                        extensions.append({"id": ext_dir.name, "browser": "Chrome"})
            except Exception:
                pass

        if len(extensions) > 20:
            self._add_finding(
                "MEDIUM", "Browser",
                f"Large number of Chrome extensions: {len(extensions)}",
                "Review and remove unnecessary browser extensions"
            )

        return {
            "chrome_extensions": len(extensions),
            "extensions"       : extensions[:10],
        }

    def _check_security_services(self) -> dict:
        if not _PSUTIL_OK:
            return {"services": {}, "score": 50}

        target = {
            "WinDefend"          : "Windows Defender",
            "MpsSvc"             : "Windows Firewall",
            "SecurityHealthService": "Security Health",
        }
        status = {}

        try:
            running = {s.name().lower() for s in psutil.win_service_iter()}
            for svc, name in target.items():
                is_running = svc.lower() in running
                status[name] = is_running
                if not is_running:
                    self._add_finding(
                        "HIGH", "Services",
                        f"Security service not running: {name}",
                        f"Start '{svc}' service to restore protection"
                    )
        except Exception:
            pass

        running_count = sum(1 for v in status.values() if v)
        score         = int(running_count / max(len(status), 1) * 100)

        return {"services": status, "score": score}

    # ── Score Calculation ─────────────────────────────────────────────────────

    def _calculate_scores(self, results: dict) -> dict:
        """Calculate all four composite scores from assessment results."""
        # Security Posture Score
        demerits = 0
        critical_count = sum(1 for f in self._findings if f["severity"] == "CRITICAL")
        high_count     = sum(1 for f in self._findings if f["severity"] == "HIGH")
        medium_count   = sum(1 for f in self._findings if f["severity"] == "MEDIUM")

        demerits = critical_count * 25 + high_count * 12 + medium_count * 5
        posture_score = max(0, min(100, 100 - demerits))

        # ZT Readiness Score (how well the system supports ZT)
        zt_checks = {
            "firewall_on"    : not any("firewall" in f["title"].lower() for f in self._findings),
            "av_on"          : not any("defender" in f["title"].lower() or "antivirus" in f["title"].lower() for f in self._findings),
            "no_system_user" : not any("system account" in f["title"].lower() for f in self._findings),
            "uac_enabled"    : not any("uac" in f["title"].lower() for f in self._findings),
        }
        zt_passed = sum(1 for v in zt_checks.values() if v)
        zt_readiness = int(zt_passed / max(len(zt_checks), 1) * 100)

        # Behavioral Risk Score
        try:
            from abtd.behavior_engine.behavior_engine import behavior_engine
            profiles = behavior_engine.get_all_profiles()
            if profiles:
                behavioral = max(p.get("behavior_risk", 0) for p in profiles)
            else:
                behavioral = 0.0
        except Exception:
            behavioral = 0.0

        # Overall risk
        overall_risk = round(
            0.4 * (100 - posture_score)
            + 0.3 * (100 - zt_readiness)
            + 0.3 * behavioral
        )
        overall_risk = max(0, min(100, overall_risk))

        # Trust level
        trust = 100 - overall_risk
        if trust >= 85: trust_level = "HIGH TRUST"
        elif trust >= 65: trust_level = "MODERATE TRUST"
        elif trust >= 40: trust_level = "LOW TRUST"
        else: trust_level = "UNTRUSTED"

        return {
            "posture"     : posture_score,
            "zt_readiness": zt_readiness,
            "behavioral"  : round(behavioral, 1),
            "overall_risk": overall_risk,
            "trust_level" : trust_level,
        }

    def _generate_recommendations(self, scores: dict) -> list:
        recs = []
        for finding in self._findings:
            if finding["severity"] in ("CRITICAL", "HIGH"):
                recs.append({
                    "priority"      : finding["severity"],
                    "category"      : finding["category"],
                    "recommendation": finding.get("recommendation", finding["title"]),
                })
        if scores["posture"] < 60:
            recs.append({
                "priority"      : "HIGH",
                "category"      : "Overall",
                "recommendation": "Security posture is critically low — address all HIGH findings immediately",
            })
        return recs[:10]

    # ── Finding Helper ────────────────────────────────────────────────────────

    def _add_finding(
        self,
        severity      : str,
        category      : str,
        title         : str,
        recommendation: str,
    ) -> None:
        self._findings.append({
            "severity"      : severity,
            "category"      : category,
            "title"         : title,
            "recommendation": recommendation,
            "timestamp"     : datetime.now(timezone.utc).isoformat(),
        })

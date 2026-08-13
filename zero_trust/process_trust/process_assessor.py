"""
zero_trust/process_trust/process_assessor.py
==============================================
Process Trust Assessment Module.

Evaluates running processes for Zero Trust compliance:
  - Process name and location legitimacy
  - Parent-child process chain analysis
  - Command-line argument risk scanning
  - CPU / memory anomaly detection
  - Network connections opened by the process
  - Masquerading detection (legitimate name, wrong path)
  - Hollow process indicators

Produces a Process Risk Score (0–100) where higher = more suspicious.

Public API:
    assessor = ProcessAssessor()
    result   = assessor.assess_process(pid, name, exe, cmdline, parent_name)
    score    = assessor.get_process_risk(pid)
    all_procs = assessor.assess_all_running()
"""

import os
import sys
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.process_trust")

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

# ── Process risk indicators ───────────────────────────────────────────────────

# System processes that should only run from System32
SYSTEM_PROCESS_PATHS = {
    "svchost.exe"     : ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    "lsass.exe"       : ["c:\\windows\\system32\\"],
    "csrss.exe"       : ["c:\\windows\\system32\\"],
    "winlogon.exe"    : ["c:\\windows\\system32\\"],
    "explorer.exe"    : ["c:\\windows\\"],
    "taskhost.exe"    : ["c:\\windows\\system32\\"],
    "taskhostw.exe"   : ["c:\\windows\\system32\\"],
    "services.exe"    : ["c:\\windows\\system32\\"],
    "smss.exe"        : ["c:\\windows\\system32\\"],
    "wininit.exe"     : ["c:\\windows\\system32\\"],
    "spoolsv.exe"     : ["c:\\windows\\system32\\"],
}

# Processes that are HIGH risk if found running
HIGH_RISK_PROCESS_NAMES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe", "wce.exe", "fgdump.exe",
    "meterpreter.exe", "cobalt_strike.exe", "empire.exe", "metasploit.exe",
    "keylogger.exe", "psexec.exe", "wmiexec.exe", "crackmapexec.exe",
    "lazagne.exe", "sharphound.exe", "bloodhound.exe",
}

# Suspicious command-line keywords
SUSPICIOUS_CMDLINE_PATTERNS = [
    "-encodedcommand", "-enc ", "iex(", "invoke-expression",
    "downloadstring", "bypass", "-nop", "-windowstyle hidden",
    "-executionpolicy bypass", "webclient", "net.webclient",
    "frombase64string", "invoke-webrequest", "bitsadmin",
    "/transfer", "certutil -decode", "mshta http",
    "regsvr32 /s /n /u /i:http", "rundll32.exe javascript",
    "wscript.exe http", "cscript.exe http",
]

# Suspicious parent→child relationships
SUSPICIOUS_CHAINS = {
    ("winword.exe"    , "cmd.exe")         : "Office spawning cmd — possible macro execution",
    ("winword.exe"    , "powershell.exe")  : "Office spawning PowerShell — malware macro indicator",
    ("excel.exe"      , "powershell.exe")  : "Excel spawning PowerShell — malware macro indicator",
    ("outlook.exe"    , "cmd.exe")         : "Outlook spawning cmd — phishing execution",
    ("chrome.exe"     , "cmd.exe")         : "Browser spawning cmd — drive-by download indicator",
    ("firefox.exe"    , "powershell.exe")  : "Browser spawning PowerShell",
    ("explorer.exe"   , "powershell.exe")  : "Explorer spawning PowerShell",
    ("powershell.exe" , "regsvr32.exe")    : "PowerShell spawning regsvr32 — LOLBin abuse",
    ("cmd.exe"        , "mshta.exe")       : "cmd spawning mshta — HTA abuse",
    ("svchost.exe"    , "cmd.exe")         : "svchost spawning cmd — possible exploitation",
}


class ProcessAssessor:
    """
    Assess trust/risk level of running Windows processes.
    """

    def __init__(self):
        self._scores: dict[int, dict] = {}   # pid → last assessment
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def assess_process(
        self,
        pid         : int,
        name        : str,
        exe         : str  = "",
        cmdline     : str  = "",
        parent_name : str  = "",
    ) -> dict:
        """
        Assess a single process.
        Returns full risk assessment dict.
        """
        result = self._run_assessment(pid, name, exe, cmdline, parent_name)
        with self._lock:
            self._scores[pid] = result
        return result

    def get_process_risk(self, pid: int) -> int:
        """Return cached risk score for a PID, or 50 (neutral) if unknown."""
        with self._lock:
            return self._scores.get(pid, {}).get("process_risk_score", 50)

    def assess_all_running(self, max_processes: int = 150) -> list:
        """
        Assess all currently running processes (capped at max_processes).
        Returns list of assessment dicts sorted by risk (highest first).
        """
        if not _PSUTIL_OK:
            return []

        results = []
        count   = 0
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
            if count >= max_processes:
                break
            try:
                info = proc.info or {}
                pid  = info.get("pid")
                if pid is None:
                    continue

                parent_name = ""
                if info.get("ppid"):
                    try:
                        parent_name = psutil.Process(info["ppid"]).name()
                    except Exception:
                        pass

                cmdline_list = info.get("cmdline") or []
                cmdline_str  = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)

                result = self.assess_process(
                    pid         = pid,
                    name        = info.get("name") or f"PID-{pid}",
                    exe         = info.get("exe")  or "",
                    cmdline     = cmdline_str,
                    parent_name = parent_name,
                )
                results.append(result)
                count += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as e:
                log.debug(f"Process assessment error for entry: {e}")

        results.sort(key=lambda r: r.get("process_risk_score", 0), reverse=True)
        return results

    # ── Assessment Engine ─────────────────────────────────────────────────────

    def _run_assessment(
        self,
        pid         : int,
        name        : str,
        exe         : str,
        cmdline     : str,
        parent_name : str,
    ) -> dict:
        risk_score = 0
        flags      = []
        name_lower = (name or "").lower()
        exe_lower  = (exe or "").lower()

        # 1. Blocklist check
        if name_lower in HIGH_RISK_PROCESS_NAMES:
            risk_score += 95
            flags.append(f"CRITICAL: Known malicious tool detected: {name}")

        # 2. Process masquerading
        if name_lower in SYSTEM_PROCESS_PATHS:
            expected_paths = SYSTEM_PROCESS_PATHS[name_lower]
            if exe_lower and not any(exe_lower.startswith(p) for p in expected_paths):
                risk_score += 50
                flags.append(
                    f"Process masquerading: '{name}' running from unusual path: {exe}"
                )

        # 3. Suspicious parent-child chain
        if parent_name:
            chain_key = (parent_name.lower(), name_lower)
            if chain_key in SUSPICIOUS_CHAINS:
                risk_score += 40
                flags.append(SUSPICIOUS_CHAINS[chain_key])

        # 4. Command-line analysis
        cmdline_lower = cmdline.lower()
        cmdline_flags = []
        for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern in cmdline_lower:
                cmdline_flags.append(pattern)
        if cmdline_flags:
            risk_score += min(len(cmdline_flags) * 15, 45)
            flags.append(f"Suspicious cmdline patterns: {', '.join(cmdline_flags[:3])}")

        # 5. Execution from suspicious path
        suspicious_path_prefixes = (
            os.path.expanduser("~\\appdata\\local\\temp\\").lower(),
            os.path.expanduser("~\\downloads\\").lower(),
            "c:\\temp\\", "c:\\tmp\\", "c:\\users\\public\\",
        )
        if exe_lower and any(exe_lower.startswith(p) for p in suspicious_path_prefixes):
            risk_score += 25
            flags.append(f"Executable running from suspicious path: {exe}")

        # 6. Psutil non-blocking extended checks (if available)
        if _PSUTIL_OK and pid > 0:
            try:
                proc = psutil.Process(pid)

                # Non-blocking CPU check (interval=None avoid 0.5s sleep)
                try:
                    cpu = proc.cpu_percent(interval=None)
                    if cpu > 90:
                        risk_score += 10
                        flags.append(f"Very high CPU usage: {cpu:.1f}%")
                except Exception:
                    pass

                # Memory anomaly (> 1 GB for a normal user process)
                try:
                    mem_mb = proc.memory_info().rss / 1024 / 1024
                    if mem_mb > 1024:
                        risk_score += 5
                        flags.append(f"Unusually high memory usage: {mem_mb:.0f} MB")
                except Exception:
                    pass

                # Network connections opened by this process
                try:
                    conns = proc.net_connections(kind="inet")
                    suspicious_ports = {4444, 5555, 1337, 31337, 6666, 9001, 9090}
                    for conn in conns:
                        if conn.raddr and conn.raddr.port in suspicious_ports:
                            risk_score += 20
                            flags.append(
                                f"Connection to suspicious port {conn.raddr.port}"
                            )
                except Exception:
                    pass

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            except Exception as e:
                log.debug(f"psutil extended check error for PID {pid}: {e}")


        risk_score = min(risk_score, 100)
        trust_score = max(0, 100 - risk_score)

        # Risk level label
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "pid"               : pid,
            "process_name"      : name,
            "exe_path"          : exe,
            "cmdline_snippet"   : cmdline[:200],
            "parent_name"       : parent_name,
            "process_risk_score": risk_score,
            "process_trust"     : trust_score,
            "risk_level"        : risk_level,
            "risk_flags"        : flags,
            "assessed_at"       : datetime.now(timezone.utc).isoformat(),
        }


# Singleton
process_assessor = ProcessAssessor()

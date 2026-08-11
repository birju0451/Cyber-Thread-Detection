"""
engine/rule_engine.py
======================
Layer 3 of ABTD: Rule-Based Heuristic Detection.

Applies a set of deterministic security rules to URLs, file paths,
process names, and command lines. Each rule contributes a weighted
penalty score (0–100).

This layer provides explainability — it generates human-readable
reasons for every detection.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Applies heuristic security rules and returns a score + list of reasons.

    Usage:
        engine = RuleEngine()
        result = engine.analyze_url("http://192.168.1.1/login")
        # → {"score": 40, "reasons": ["IP address used as hostname", ...]}
    """

    def analyze_url(self, url: str) -> dict:
        """
        Run all URL heuristic rules.

        Returns:
            {
              "score"  : int (0–100, higher = more suspicious),
              "reasons": list[str],
              "flags"  : dict[str, bool],
            }
        """
        url    = str(url).strip()
        score  = 0
        reasons = []
        flags   = {}

        # ── Rule 1: IP address as hostname ──────────────────────────
        if re.search(r"(https?://)?\d{1,3}(\.\d{1,3}){3}", url):
            score  += config.RULE_PENALTIES["ip_in_url"]
            reasons.append("IP address used as hostname (bypasses domain reputation)")
            flags["ip_in_url"] = True

        # ── Rule 2: Excessive URL length ─────────────────────────────
        if len(url) > 75:
            score  += config.RULE_PENALTIES["url_length_excessive"]
            reasons.append(f"Abnormally long URL ({len(url)} chars) — common in phishing")
            flags["url_length_excessive"] = True

        # ── Rule 3: Hex/percent encoded characters ───────────────────
        hex_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
        if len(hex_matches) >= 3:
            score  += config.RULE_PENALTIES["hex_encoded_chars"]
            reasons.append(f"URL contains {len(hex_matches)} percent-encoded chars (obfuscation)")
            flags["hex_encoded_chars"] = True

        # ── Rule 4: Suspicious keywords ──────────────────────────────
        matched_kw = [kw for kw in config.SUSPICIOUS_KEYWORDS if kw in url.lower()]
        if matched_kw:
            score  += config.RULE_PENALTIES["suspicious_keywords"]
            reasons.append(f"Contains suspicious keywords: {', '.join(matched_kw[:4])}")
            flags["suspicious_keywords"] = True

        # ── Rule 5: Multiple subdomains ───────────────────────────────
        try:
            from urllib.parse import urlparse
            host = urlparse(url if "://" in url else "http://" + url).netloc
            subdomain_depth = host.count(".")
            if subdomain_depth >= 3:
                score  += config.RULE_PENALTIES["multiple_subdomains"]
                reasons.append(f"Excessive subdomain depth ({subdomain_depth} dots) — hiding real domain")
                flags["multiple_subdomains"] = True
        except Exception:
            pass

        # ── Rule 6: HTTPS missing ─────────────────────────────────────
        if url.lower().startswith("http://"):
            score  += config.RULE_PENALTIES["https_missing"]
            reasons.append("Connection is not encrypted (HTTP, not HTTPS)")
            flags["https_missing"] = True

        # ── Rule 7: URL shortener ─────────────────────────────────────
        if any(s in url.lower() for s in config.URL_SHORTENER_DOMAINS):
            score  += config.RULE_PENALTIES["url_shortener"]
            reasons.append("URL uses a shortener service (destination hidden)")
            flags["url_shortener"] = True

        # ── Rule 8: Brand name impersonation ─────────────────────────
        BRANDS = ["paypal", "amazon", "google", "microsoft", "apple",
                  "netflix", "facebook", "instagram", "ebay", "bankofamerica"]
        try:
            from urllib.parse import urlparse
            import tldextract
            ext  = tldextract.extract(url)
            real = ext.domain.lower()
            host = urlparse(url if "://" in url else "http://" + url).netloc.lower()
            for brand in BRANDS:
                if brand in host and brand != real:
                    score  += config.RULE_PENALTIES["brand_impersonation"]
                    reasons.append(f"Brand impersonation detected: '{brand}' in URL but domain is '{real}'")
                    flags["brand_impersonation"] = True
                    break
        except Exception:
            pass

        # ── Rule 9: Double file extension ────────────────────────────
        DANGEROUS_EXTS = r"\.(exe|bat|cmd|ps1|vbs|js|msi|hta|scr|jar)"
        if re.search(DANGEROUS_EXTS + r"\.", url.lower()):
            score  += config.RULE_PENALTIES["double_extension"]
            reasons.append("Double file extension in URL path (common malware delivery)")
            flags["double_extension"] = True

        # ── Rule 10: @ symbol in URL ──────────────────────────────────
        if "@" in url:
            score  += config.RULE_PENALTIES["at_symbol_in_url"]
            reasons.append("@ symbol in URL (browser ignores everything before @)")
            flags["at_symbol_in_url"] = True

        # Clamp
        score = min(score, 100)

        return {
            "score"  : score,
            "reasons": reasons,
            "flags"  : flags,
        }

    def analyze_process(self, process_name: str, cmdline: str = "") -> dict:
        """
        Check a running process against security rules.

        Returns {"score": int, "reasons": list[str]}
        """
        score   = 0
        reasons = []
        pname   = process_name.lower()
        cmd     = (cmdline or "").lower()

        # Blocked process names
        if pname in {p.lower() for p in config.BLOCKED_PROCESSES}:
            score  += 90
            reasons.append(f"Known malicious tool detected: {process_name}")

        # PowerShell abuse signals
        ps_abuse_flags = [
            ("-encodedcommand", "PowerShell encoded command (obfuscation)"),
            ("-enc",            "PowerShell short encoded flag"),
            ("-nop",            "PowerShell -NoProfile (evasion)"),
            ("-windowstyle hidden", "PowerShell hidden window (stealth)"),
            ("downloadstring",  "PowerShell DownloadString (remote payload)"),
            ("invoke-expression", "PowerShell Invoke-Expression (code injection)"),
            ("iex ",            "PowerShell IEX shorthand"),
            ("bypass",          "PowerShell execution policy bypass"),
        ]
        if "powershell" in pname or "pwsh" in pname:
            for flag, reason in ps_abuse_flags:
                if flag in cmd:
                    score  += 25
                    reasons.append(f"PowerShell abuse: {reason}")
                    if score >= 100:
                        break

        # CMD abuse
        cmd_abuse = [
            ("certutil",   "certutil misuse (file download/decode)"),
            ("regsvr32",   "regsvr32 LOLBin abuse"),
            ("mshta",      "mshta (HTA execution, often malicious)"),
            ("wscript",    "wscript (script host abuse)"),
            ("cscript",    "cscript (script host abuse)"),
            ("rundll32",   "rundll32 (LOLBin abuse)"),
        ]
        for term, reason in cmd_abuse:
            if term in cmd:
                score  += 20
                reasons.append(f"Suspicious command: {reason}")

        score = min(score, 100)
        return {"score": score, "reasons": reasons}

    def analyze_file(self, file_path: str) -> dict:
        """
        Apply file-based heuristic rules.

        Returns {"score": int, "reasons": list[str]}
        """
        score   = 0
        reasons = []
        path    = file_path.lower()

        # Dangerous extension
        DANGEROUS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                     ".jar", ".msi", ".hta", ".scr", ".pif", ".com"}
        from pathlib import Path as P
        suffix = P(path).suffix
        if suffix in DANGEROUS:
            score  += 20
            reasons.append(f"Dangerous file extension: {suffix}")

        # In temp/startup directory
        if any(t in path for t in ["\\temp\\", "\\tmp\\", "appdata\\local\\temp"]):
            score  += 15
            reasons.append("File located in temporary directory (suspicious drop location)")

        if any(s in path for s in ["\\startup\\", "\\start menu\\programs\\startup"]):
            score  += 25
            reasons.append("File in startup folder (persistence attempt)")

        # Double extension
        name = P(path).name
        if name.count(".") >= 2:
            score  += 15
            reasons.append(f"Double extension in filename: {name}")

        score = min(score, 100)
        return {"score": score, "reasons": reasons}


# Singleton instance
rule_engine = RuleEngine()

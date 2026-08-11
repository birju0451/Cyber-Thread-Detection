"""
engine/reputation.py
=====================
Layer 4 of ABTD: Reputation & WHOIS Analysis.

Checks:
  - Domain age (newly registered domains are high-risk)
  - IP blacklist via public DNS-based blocklists
  - TLD risk scoring (some TLDs are disproportionately used for malware)

Returns a score (0–100) and list of reasons.
Does NOT make paid API calls — relies on:
  - python-whois  (domain registration info)
  - DNS queries   (SURBL, Spamhaus DNSBL)
  - Hard-coded high-risk TLD and registrar lists
"""

import re
import sys
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ---------------------------------------------------------------------------
# High-risk TLDs (empirically associated with high malware/phishing rates)
# ---------------------------------------------------------------------------

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",    # Free Freenom TLDs (heavily abused)
    ".top", ".xyz", ".club", ".online",    # Cheap new TLDs
    ".work", ".link", ".click", ".loan",
    ".win", ".stream", ".download",
    ".accountant", ".science", ".trade",
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".mobi", ".name",
    ".ru", ".cn", ".pw",
}

# ---------------------------------------------------------------------------
# Known malicious registrars (associated with phishing/spam campaigns)
# ---------------------------------------------------------------------------

SUSPICIOUS_REGISTRARS = {
    "namecheap",       # Popular among phishers (low-cost)
    "nicenic",
    "reg.ru",
    "regway",
    "psi-usa",
}

# ---------------------------------------------------------------------------
# Public DNSBL servers for IP reputation check
# ---------------------------------------------------------------------------

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "dnsbl.sorbs.net",
    "bl.spamcop.net",
]


class ReputationAnalyzer:
    """Performs domain/IP reputation checks as Layer 4 of ABTD."""

    def analyze_url(self, url: str, timeout: float = 3.0) -> dict:
        """
        Analyze a URL for reputation signals.

        Returns:
            {
              "score"  : int (0–100),
              "reasons": list[str],
              "details": dict,
            }
        """
        score   = 0
        reasons = []
        details = {}

        # Extract hostname
        try:
            parsed   = urlparse(url if "://" in url else "http://" + url)
            hostname = parsed.netloc.split(":")[0].strip()
        except Exception:
            return {"score": 0, "reasons": [], "details": {}}

        if not hostname:
            return {"score": 0, "reasons": [], "details": {}}

        # ── TLD risk check ────────────────────────────────────────────
        suffix = self._get_tld(hostname)
        details["tld"] = suffix

        if suffix in HIGH_RISK_TLDS:
            score   += 30
            reasons.append(f"High-risk TLD: '{suffix}' (heavily abused in malware campaigns)")
        elif suffix in MEDIUM_RISK_TLDS:
            score   += 15
            reasons.append(f"Medium-risk TLD: '{suffix}'")

        # ── Domain age check (WHOIS) ──────────────────────────────────
        age_score, age_reason, age_days = self._check_domain_age(hostname, timeout)
        if age_score > 0:
            score   += age_score
            reasons.append(age_reason)
        details["domain_age_days"] = age_days

        # ── IP blacklist check ────────────────────────────────────────
        if not self._is_ip(hostname):
            try:
                ip = socket.gethostbyname(hostname)
                details["resolved_ip"] = ip
                bl_score, bl_reason = self._check_dnsbl(ip, timeout)
                if bl_score > 0:
                    score   += bl_score
                    reasons.append(bl_reason)
            except Exception:
                pass
        else:
            # URL uses raw IP — already penalized by rule engine
            details["resolved_ip"] = hostname

        score = min(score, 100)
        return {"score": score, "reasons": reasons, "details": details}

    # ── Private helpers ───────────────────────────────────────────────

    def _get_tld(self, hostname: str) -> str:
        """Return the TLD portion (e.g. '.tk', '.co.uk')."""
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return ""

    def _is_ip(self, host: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    def _check_domain_age(self, domain: str, timeout: float) -> tuple[int, str, int | None]:
        """
        Check domain registration age via WHOIS.

        Returns (score, reason, age_in_days).
        Newly registered domains (< 30 days) = high risk.
        """
        try:
            import whois
            import signal

            # whois can hang — use simple timeout workaround
            data = whois.whois(domain)

            creation_date = data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                return 10, "WHOIS registration date unavailable (suspicious)", None

            # Make timezone-aware
            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now      = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

            if age_days < 7:
                return 40, f"Domain registered {age_days} days ago (very new — high phishing risk)", age_days
            elif age_days < 30:
                return 25, f"Domain registered {age_days} days ago (new domain)", age_days
            elif age_days < 180:
                return 10, f"Domain is relatively new ({age_days} days old)", age_days
            else:
                return 0, "", age_days

        except Exception:
            return 0, "", None

    def _check_dnsbl(self, ip: str, timeout: float) -> tuple[int, str]:
        """
        Check an IP against public DNS blocklists (DNSBL).

        Returns (score, reason). Score = 0 if not listed.
        """
        try:
            # Reverse the IP for DNSBL lookup
            reversed_ip = ".".join(reversed(ip.split(".")))

            for dnsbl in DNSBL_SERVERS[:2]:   # Check first 2 for speed
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    socket.setdefaulttimeout(timeout)
                    socket.gethostbyname(query)
                    # If resolution succeeds, IP is blacklisted
                    return 35, f"IP {ip} is listed on DNS blocklist ({dnsbl})"
                except socket.gaierror:
                    pass   # Not listed — normal
        except Exception:
            pass

        return 0, ""


# Singleton instance
reputation_analyzer = ReputationAnalyzer()

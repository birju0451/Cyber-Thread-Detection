"""
zero_trust/resource_protection/resource_registry.py
=====================================================
Resource Protection Registry.

Maintains a registry of sensitive resources and their protection levels.
Resources include files, folders, registry keys, and network resources.

Sensitivity Levels:
  PUBLIC    — No special protection needed
  INTERNAL  — Normal user access, monitored
  SENSITIVE — Requires trusted application + authenticated user
  CRITICAL  — Requires highest trust, any access triggers review

Public API:
    registry = ResourceRegistry()
    level    = registry.get_sensitivity("C:\\Users\\...\\passwords.txt")
    registry.register_resource(path, level, description)
    registry.check_access(path, requester_trust_score)
"""

import os
import sys
import re
import logging
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.resource")

# Sensitivity tiers
SENSITIVITY_LEVELS = ["PUBLIC", "INTERNAL", "SENSITIVE", "CRITICAL"]

# Minimum trust scores required per sensitivity level
MIN_TRUST_FOR_ACCESS = {
    "PUBLIC"   : 0,    # Anyone
    "INTERNAL" : 40,   # Low-risk entities
    "SENSITIVE": 65,   # Medium-trust entities
    "CRITICAL" : 85,   # High-trust entities only
}


class ResourceRegistry:
    """
    Registry of protected resources and their sensitivity levels.
    Determines whether an entity's trust score allows access.
    """

    def __init__(self):
        self._resources: dict[str, dict] = {}
        self._patterns : list[tuple]     = []  # (compiled_regex, level, description)
        self._load_defaults()

    # ── Public API ────────────────────────────────────────────────────────────

    def register_resource(
        self,
        path_or_pattern : str,
        sensitivity     : str,
        description     : str = "",
        is_pattern      : bool = False,
    ) -> None:
        """Register a resource with its sensitivity level."""
        sensitivity = sensitivity.upper()
        if sensitivity not in SENSITIVITY_LEVELS:
            raise ValueError(f"Invalid sensitivity: {sensitivity}")

        if is_pattern:
            try:
                compiled = re.compile(path_or_pattern, re.IGNORECASE)
                self._patterns.append((compiled, sensitivity, description))
            except re.error as e:
                log.warning(f"Invalid resource pattern '{path_or_pattern}': {e}")
        else:
            normalized = path_or_pattern.lower().replace("\\", "/")
            self._resources[normalized] = {
                "sensitivity" : sensitivity,
                "description" : description,
                "path"        : path_or_pattern,
            }

    def get_sensitivity(self, resource_path: str) -> str:
        """
        Return sensitivity level for a resource.
        Returns 'PUBLIC' for unregistered resources.
        """
        normalized = resource_path.lower().replace("\\", "/")

        # Exact match
        if normalized in self._resources:
            return self._resources[normalized]["sensitivity"]

        # Prefix match (folder containing the resource)
        for reg_path, info in self._resources.items():
            if normalized.startswith(reg_path):
                return info["sensitivity"]

        # Pattern match
        for pattern, level, _ in self._patterns:
            if pattern.search(resource_path):
                return level

        return "PUBLIC"

    def check_access(
        self,
        resource_path  : str,
        requester_trust: int = 50,
        trust_score    : int = 50,
    ) -> dict:
        """
        Determine whether an entity with the given trust score
        may access the specified resource.
        """
        actual_trust = requester_trust if requester_trust != 50 else trust_score
        sensitivity    = self.get_sensitivity(resource_path)
        required_trust = MIN_TRUST_FOR_ACCESS[sensitivity]

        if requester_trust >= required_trust:
            decision = "ALLOW"
            allowed  = True
            reason   = (
                f"{sensitivity} resource accessible — trust {requester_trust} "
                f"≥ required {required_trust}"
            )
        elif requester_trust >= required_trust - 20:
            decision = "RESTRICT"
            allowed  = False
            reason   = (
                f"{sensitivity} resource restricted — trust {requester_trust} "
                f"below required {required_trust} but within review range"
            )
        else:
            decision = "BLOCK"
            allowed  = False
            reason   = (
                f"{sensitivity} resource blocked — trust {requester_trust} "
                f"far below required {required_trust}"
            )

        return {
            "resource_path"  : resource_path,
            "allowed"        : allowed,
            "sensitivity"    : sensitivity,
            "required_trust" : required_trust,
            "actual_trust"   : requester_trust,
            "decision"       : decision,
            "reason"         : reason,
        }

    def list_resources(self) -> list:
        """Return all registered resources."""
        return [
            {**v, "type": "exact"} for v in self._resources.values()
        ] + [
            {"path": p.pattern, "sensitivity": lv, "description": d, "type": "pattern"}
            for p, lv, d in self._patterns
        ]

    # ── Default Resource Definitions ──────────────────────────────────────────

    def _load_defaults(self) -> None:
        """Load well-known sensitive Windows paths."""
        user_home = os.path.expanduser("~")

        # CRITICAL resources
        critical = [
            (os.path.join(user_home, "AppData", "Roaming", "Microsoft", "Credentials"),
             "Windows Credential Manager store"),
            (os.path.join(user_home, "AppData", "Local", "Microsoft", "Credentials"),
             "Windows Credential Manager store (local)"),
            (r"C:\Windows\System32\config\SAM",
             "Windows Security Account Manager — password hashes"),
            (r"C:\Windows\System32\config\SECURITY",
             "Windows Security hive — LSA secrets"),
            (os.path.join(user_home, ".ssh"),
             "SSH private keys"),
        ]
        for path, desc in critical:
            self.register_resource(path, "CRITICAL", desc)

        # SENSITIVE resources
        sensitive = [
            (os.path.join(user_home, "Documents"),
             "User Documents folder"),
            (os.path.join(user_home, "Desktop"),
             "User Desktop"),
            (os.path.join(user_home, "AppData", "Roaming"),
             "Application Roaming Data (may contain tokens/cookies)"),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "Registry startup key"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
             "Windows Logon configuration"),
            (os.path.join(user_home, "AppData", "Local", "Google", "Chrome", "User Data"),
             "Chrome browser profile (cookies, passwords)"),
            (os.path.join(user_home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
             "Firefox browser profile"),
        ]
        for path, desc in sensitive:
            self.register_resource(path, "SENSITIVE", desc)

        # Pattern-based sensitive resource detection
        sensitive_patterns = [
            (r"\.(key|pem|pfx|p12|cer|crt|der)$", "Cryptographic certificate/key file"),
            (r"(password|passwd|credential|secret|token|apikey|api_key).*\.(txt|csv|json|xml|cfg|ini|env)$",
             "Potential credential file"),
            (r"(wallet|seed|mnemonic)\.(dat|json|txt)$", "Cryptocurrency wallet file"),
            (r"\.kdbx?$", "KeePass password database"),
        ]
        for pattern, desc in sensitive_patterns:
            self.register_resource(pattern, "SENSITIVE", desc, is_pattern=True)

        # INTERNAL resources
        internal_patterns = [
            (r"\.(doc|docx|xls|xlsx|pdf|ppt|pptx)$", "Office document"),
            (r"\.(sql|db|sqlite|mdb)$", "Database file"),
        ]
        for pattern, desc in internal_patterns:
            self.register_resource(pattern, "INTERNAL", desc, is_pattern=True)


# Singleton
resource_registry = ResourceRegistry()

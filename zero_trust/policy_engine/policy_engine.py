"""
zero_trust/policy_engine/policy_engine.py
==========================================
Zero Trust Policy Engine.

The Policy Engine is the heart of Zero Trust enforcement.
It evaluates security context against defined policies and
returns a final access decision.

Policies are defined in policies.json and can be overridden
via MongoDB at runtime.

Policy Evaluation Order:
  1. Load policies sorted by priority (lowest number = highest priority)
  2. Evaluate each policy's conditions against the security context
  3. Return decision from first matching policy
  4. Default decision: MONITOR (if no policy matches)

Access Decisions:
  ALLOW     — Permit the action
  RESTRICT  — Allow with reduced scope / monitoring
  CHALLENGE — Require additional verification
  MONITOR   — Allow but flag for enhanced monitoring
  BLOCK     — Deny the action
  QUARANTINE— Isolate the resource

Public API:
    engine   = PolicyEngine()
    decision = engine.evaluate(context)
"""

import json
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.policy")

POLICIES_FILE = Path(__file__).parent / "policies.json"

VALID_DECISIONS = {"ALLOW", "RESTRICT", "CHALLENGE", "MONITOR", "BLOCK", "QUARANTINE"}

# Decision severity ordering (for conflict resolution)
DECISION_SEVERITY = {
    "ALLOW"     : 0,
    "MONITOR"   : 1,
    "RESTRICT"  : 2,
    "CHALLENGE" : 3,
    "QUARANTINE": 4,
    "BLOCK"     : 5,
}

# Decision color codes for UI
DECISION_COLORS = {
    "ALLOW"     : "#22c55e",
    "MONITOR"   : "#3b82f6",
    "RESTRICT"  : "#f59e0b",
    "CHALLENGE" : "#f97316",
    "QUARANTINE": "#a855f7",
    "BLOCK"     : "#ef4444",
}

DECISION_ICONS = {
    "ALLOW"     : "✅",
    "MONITOR"   : "👁️",
    "RESTRICT"  : "⚠️",
    "CHALLENGE" : "🔐",
    "QUARANTINE": "🔒",
    "BLOCK"     : "🚫",
}


class PolicyEngine:
    """
    Evaluates Zero Trust policies against security context
    to produce access decisions.
    """

    def __init__(self, policies_file: Optional[Path] = None):
        self._policies: list[dict]      = []
        self._custom_policies: list[dict] = []
        self._file = policies_file or POLICIES_FILE
        self._load_policies()

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, context: dict) -> dict:
        """
        Evaluate security context against all policies.

        Args:
            context: Security context dict containing:
                overall_risk       : 0–100 (from RiskCalculator)
                device_trust       : 0–100
                app_trust          : 0–100
                process_risk       : 0–100
                identity_level     : "STANDARD" | "ADMIN" | "SYSTEM"
                resource_sensitivity: "PUBLIC" | "INTERNAL" | "SENSITIVE" | "CRITICAL"
                process_blocklist  : bool (process is a known bad tool)
                url_risk           : 0–100 (optional)
                file_risk          : 0–100 (optional)

        Returns full decision dict.
        """
        matched_policy = None
        matched_decision = "ALLOW"   # Safe default if no policy matches
        matched_reason   = "No policy matched — default ALLOW for low-risk activity"

        # Combine default + custom, sort by priority
        all_policies = sorted(
            self._policies + self._custom_policies,
            key=lambda p: p.get("priority", 999)
        )

        for policy in all_policies:
            if not policy.get("enabled", True):
                continue
            if self._matches(policy, context):
                matched_policy  = policy
                matched_decision = policy.get("decision", "MONITOR").upper()
                matched_reason   = policy.get("reason", "Policy condition met")
                break

        # If overall risk is very low and no blocking policy matched → ALLOW
        if not matched_policy and context.get("overall_risk", 0) < 25:
            matched_decision = "ALLOW"
            matched_reason   = "Low overall risk — no policy violation detected"
        elif not matched_policy and context.get("overall_risk", 0) < 50:
            matched_decision = "MONITOR"
            matched_reason   = "Moderate risk — monitoring mode activated"

        decision = matched_decision.upper()
        if decision not in VALID_DECISIONS:
            decision = "MONITOR"

        return {
            "decision"        : decision,
            "reason"          : matched_reason,
            "matched_policy"  : matched_policy.get("id") if matched_policy else None,
            "policy_name"     : matched_policy.get("name") if matched_policy else "Default",
            "color"           : DECISION_COLORS.get(decision, "#6b7280"),
            "icon"            : DECISION_ICONS.get(decision, "❓"),
            "severity"        : DECISION_SEVERITY.get(decision, 0),
            "context_snapshot": {
                "overall_risk"        : context.get("overall_risk", 0),
                "device_trust"        : context.get("device_trust", 0),
                "app_trust"           : context.get("app_trust", 0),
                "process_risk"        : context.get("process_risk", 0),
                "resource_sensitivity": context.get("resource_sensitivity", "PUBLIC"),
                "identity_level"      : context.get("identity_level", "STANDARD"),
            },
            "evaluated_at"    : datetime.now(timezone.utc).isoformat(),
        }

    def add_policy(self, policy: dict) -> bool:
        """Add a custom policy at runtime."""
        required = {"id", "name", "conditions", "decision"}
        if not required.issubset(policy.keys()):
            log.warning(f"Policy missing required fields: {required - policy.keys()}")
            return False
        if policy["decision"].upper() not in VALID_DECISIONS:
            log.warning(f"Invalid decision: {policy['decision']}")
            return False
        self._custom_policies.append(policy)
        log.info(f"Custom policy added: {policy['id']} — {policy['name']}")
        return True

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a custom policy by ID."""
        before = len(self._custom_policies)
        self._custom_policies = [p for p in self._custom_policies if p.get("id") != policy_id]
        return len(self._custom_policies) < before

    def get_all_policies(self) -> list:
        """Return all active policies."""
        return self._policies + self._custom_policies

    def reload_policies(self) -> None:
        """Reload policies from JSON file."""
        self._load_policies()

    # ── Policy Matching ───────────────────────────────────────────────────────

    def _matches(self, policy: dict, context: dict) -> bool:
        """Check whether a policy's conditions are met by the context."""
        conditions = policy.get("conditions", {})

        # Overall risk thresholds
        overall_risk = float(context.get("overall_risk", 0))
        if "overall_risk_min" in conditions:
            if overall_risk < conditions["overall_risk_min"]:
                return False
        if "overall_risk_max" in conditions:
            if overall_risk > conditions["overall_risk_max"]:
                return False

        # Device trust threshold
        device_trust = float(context.get("device_trust", 100))
        if "device_trust_max" in conditions:
            if device_trust > conditions["device_trust_max"]:
                return False

        # App trust threshold
        app_trust = float(context.get("app_trust", 100))
        if "app_trust_max" in conditions:
            if app_trust > conditions["app_trust_max"]:
                return False

        # Process risk threshold
        process_risk = float(context.get("process_risk", 0))
        if "process_risk_min" in conditions:
            if process_risk < conditions["process_risk_min"]:
                return False
        if "process_risk_max" in conditions:
            if process_risk > conditions["process_risk_max"]:
                return False

        # Resource sensitivity
        if "resource_sensitivity" in conditions:
            resource_sens = context.get("resource_sensitivity", "PUBLIC")
            if resource_sens not in conditions["resource_sensitivity"]:
                return False

        # Identity level
        if "identity_level" in conditions:
            identity_level = context.get("identity_level", "STANDARD")
            if identity_level not in conditions["identity_level"]:
                return False

        # Blocklist flag
        if conditions.get("process_blocklist"):
            if not context.get("process_blocklist", False):
                return False

        return True

    # ── Policy Loading ────────────────────────────────────────────────────────

    def _load_policies(self) -> None:
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                self._policies = json.load(f)
            log.info(f"Loaded {len(self._policies)} ZT policies from {self._file}")
        except FileNotFoundError:
            log.warning(f"Policies file not found: {self._file} — using empty policy set")
            self._policies = []
        except json.JSONDecodeError as e:
            log.error(f"Invalid policies JSON: {e}")
            self._policies = []


# Singleton
policy_engine = PolicyEngine()

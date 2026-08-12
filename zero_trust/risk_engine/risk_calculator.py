"""
zero_trust/risk_engine/risk_calculator.py
==========================================
Multi-Signal Risk Score Calculator.

Aggregates all Zero Trust signals into a single Overall Risk Score (0–100)
and Trust Score (0–100).

Formula (configurable weights):
    Risk = w_identity * identity_risk
         + w_device   * device_risk
         + w_app      * app_risk
         + w_process  * process_risk
         + w_url      * url_risk
         + w_file     * file_risk
         + w_behavior * behavior_risk
         + w_network  * network_risk
         + w_history  * historical_risk

    Trust = 100 - Risk

Trust Levels:
    90–100  → TRUSTED
    70–89   → LOW_RISK
    50–69   → MODERATE_RISK
    30–49   → HIGH_RISK
    0–29    → UNTRUSTED

Public API:
    calc = RiskCalculator()
    result = calc.calculate(signals)
"""

import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("abtd.zero_trust.risk")

# Default weights (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "identity" : 0.15,
    "device"   : 0.20,
    "app"      : 0.15,
    "process"  : 0.15,
    "url"      : 0.10,
    "file"     : 0.10,
    "behavior" : 0.10,
    "network"  : 0.05,
}

# Trust level thresholds (trust score, not risk)
TRUST_LEVELS = [
    (90, "TRUSTED"),
    (70, "LOW_RISK"),
    (50, "MODERATE_RISK"),
    (30, "HIGH_RISK"),
    (0,  "UNTRUSTED"),
]


class RiskCalculator:
    """
    Calculates overall Zero Trust risk and trust scores from
    multiple input signals.
    """

    def __init__(self, weights: Optional[dict] = None):
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            log.warning(
                f"ZT risk weights sum to {total:.3f} (expected 1.0) — normalising"
            )
            for k in self.weights:
                self.weights[k] /= total

    # ── Public API ────────────────────────────────────────────────────────────

    def calculate(self, signals: dict) -> dict:
        """
        Calculate overall risk and trust from input signals.

        Args:
            signals: Dict with any subset of:
                identity_risk   : 0–100
                device_risk     : 0–100  (= 100 - device_trust_score)
                app_risk        : 0–100  (= 100 - app_trust_score)
                process_risk    : 0–100  (process_risk_score)
                url_risk        : 0–100  (threat_score from URL analysis)
                file_risk       : 0–100  (threat_score from file analysis)
                behavior_risk   : 0–100  (behavior anomaly score)
                network_risk    : 0–100  (network anomaly score)
                historical_risk : 0–100  (past incident score)

        Returns:
            {
                "overall_risk"   : 0–100,
                "trust_score"    : 0–100,
                "trust_level"    : "TRUSTED" | "LOW_RISK" | ...
                "signal_scores"  : {per-signal risk contributions},
                "weights"        : {applied weights},
                "calculated_at"  : ISO timestamp,
            }
        """
        signal_scores = {}
        weighted_sum  = 0.0
        total_weight  = 0.0

        signal_map = {
            "identity" : signals.get("identity_risk",  0),
            "device"   : signals.get("device_risk",    0),
            "app"      : signals.get("app_risk",       0),
            "process"  : signals.get("process_risk",   0),
            "url"      : signals.get("url_risk",       0),
            "file"     : signals.get("file_risk",      0),
            "behavior" : signals.get("behavior_risk",  0),
            "network"  : signals.get("network_risk",   0),
        }

        for signal_name, raw_value in signal_map.items():
            weight = self.weights.get(signal_name, 0.0)
            clamped = max(0, min(100, float(raw_value)))
            contribution = weight * clamped
            signal_scores[signal_name] = {
                "raw"          : clamped,
                "weight"       : weight,
                "contribution" : round(contribution, 2),
            }
            weighted_sum  += contribution
            total_weight  += weight

        # Normalise if not all signals were present
        if total_weight > 0 and total_weight < 0.99:
            overall_risk = weighted_sum / total_weight
        else:
            overall_risk = weighted_sum

        overall_risk = round(min(100, max(0, overall_risk)), 1)
        trust_score  = round(100 - overall_risk, 1)
        trust_level  = self._get_trust_level(trust_score)

        return {
            "overall_risk"  : overall_risk,
            "trust_score"   : trust_score,
            "trust_level"   : trust_level,
            "signal_scores" : signal_scores,
            "weights"       : self.weights.copy(),
            "calculated_at" : datetime.now(timezone.utc).isoformat(),
        }

    def update_weights(self, new_weights: dict) -> None:
        """Update risk weights at runtime."""
        self.weights.update(new_weights)
        self._validate_weights()

    @staticmethod
    def _get_trust_level(trust_score: float) -> str:
        for threshold, label in TRUST_LEVELS:
            if trust_score >= threshold:
                return label
        return "UNTRUSTED"

    @staticmethod
    def trust_to_risk(trust_score: float) -> float:
        """Convert trust score to risk score."""
        return max(0.0, min(100.0, 100.0 - trust_score))

    @staticmethod
    def risk_to_trust(risk_score: float) -> float:
        """Convert risk score to trust score."""
        return max(0.0, min(100.0, 100.0 - risk_score))


# Singleton with default weights
risk_calculator = RiskCalculator()

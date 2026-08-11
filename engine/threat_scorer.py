"""
engine/threat_scorer.py
========================
Adaptive Threat Score Fusion — Final layer of the ABTD pipeline.

Takes raw scores from each detection layer and fuses them into a
single 0–100 threat score using configurable weights from config.py.

Also classifies the threat level and recommends an action.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config


# ---------------------------------------------------------------------------
# Classification Labels
# ---------------------------------------------------------------------------

CLASSIFICATIONS = {
    "SAFE"       : {"color": "#22c55e", "icon": "✅", "action": "Allow"},
    "SUSPICIOUS" : {"color": "#f59e0b", "icon": "⚠️",  "action": "Warn user and monitor"},
    "MALICIOUS"  : {"color": "#ef4444", "icon": "🚫", "action": "Block and log"},
    "CRITICAL"   : {"color": "#7c3aed", "icon": "🔴", "action": "Block, quarantine, and alert"},
}

RECOMMENDED_ACTIONS = {
    "SAFE"       : "Continue normally. No threat detected.",
    "SUSPICIOUS" : "Proceed with caution. Avoid entering sensitive information.",
    "MALICIOUS"  : "Do not proceed. This site/file appears malicious. Block immediately.",
    "CRITICAL"   : "STOP. Quarantine this file/URL. Run a full system scan immediately.",
}


class ThreatScorer:
    """
    Fuses detection layer scores into a unified threat score.

    Inputs (each 0–100):
      - rf_score       : Random Forest classification probability × 100
      - anomaly_score  : Isolation Forest anomaly score (inverted, 0–100)
      - rule_score     : Rule engine heuristic score (0–100)
      - reputation_score: Reputation analysis score (0–100)

    Output:
      - threat_score      : int (0–100)
      - classification    : str (SAFE / SUSPICIOUS / MALICIOUS / CRITICAL)
      - recommended_action: str
      - confidence        : float (0.0–1.0)
    """

    def __init__(self):
        self.weights = config.SCORE_WEIGHTS
        self.thresholds = config.THRESHOLDS

    def fuse(
        self,
        rf_score        : float = 0.0,
        anomaly_score   : float = 0.0,
        rule_score      : float = 0.0,
        reputation_score: float = 0.0,
    ) -> dict:
        """
        Compute the adaptive threat score.

        All input scores must be in range [0, 100].

        Returns full scoring breakdown.
        """
        # Weighted sum
        raw_score = (
            rf_score         * self.weights["random_forest"]    +
            anomaly_score    * self.weights["isolation_forest"] +
            rule_score       * self.weights["rules"]            +
            reputation_score * self.weights["reputation"]
        )

        threat_score = round(min(max(raw_score, 0.0), 100.0))

        # Classify
        classification = self._classify(threat_score)

        # Confidence: distance from the nearest threshold boundary
        confidence = self._compute_confidence(threat_score, classification)

        return {
            "threat_score"       : threat_score,
            "classification"     : classification,
            "recommended_action" : RECOMMENDED_ACTIONS[classification],
            "confidence"         : round(confidence, 3),
            "color"              : CLASSIFICATIONS[classification]["color"],
            "icon"               : CLASSIFICATIONS[classification]["icon"],
            "layer_scores"       : {
                "random_forest"  : round(rf_score, 2),
                "anomaly"        : round(anomaly_score, 2),
                "rules"          : round(rule_score, 2),
                "reputation"     : round(reputation_score, 2),
            },
            "weights"            : self.weights,
        }

    def _classify(self, score: int) -> str:
        if score < self.thresholds["safe"]:
            return "SAFE"
        elif score < self.thresholds["suspicious"]:
            return "SUSPICIOUS"
        elif score < self.thresholds["malicious"]:
            return "MALICIOUS"
        else:
            return "CRITICAL"

    def _compute_confidence(self, score: int, classification: str) -> float:
        """
        Confidence = how far the score is from the nearest class boundary (0–1).
        Score right at a boundary = 0.0 confidence.
        Score far from any boundary = high confidence.
        """
        boundaries = sorted(self.thresholds.values())  # [25, 50, 75]
        max_dist = 25.0  # max distance from any boundary within a class

        min_dist = min(abs(score - b) for b in boundaries)
        return min(min_dist / max_dist, 1.0)


# Singleton
threat_scorer = ThreatScorer()

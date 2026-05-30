from typing import Dict
from schemas.common_event import CommonEvent


class RiskScorer:
    """
    Hybrid risk scoring engine combining:
        - Rule-based severity scoring
        - ML-based anomaly detection output

    Produces a unified risk score used for:
        - Alert prioritization
        - Dashboard visualization
        - Incident correlation severity ranking
    """

    def __init__(self, rule_weight: float = 0.6, ml_weight: float = 0.4):
        """
        Initialize weighting between rule-based and ML-based scoring.

        Args:
            rule_weight: Importance of deterministic rule severity
            ml_weight: Importance of anomaly detection score
        """
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight

    def calculate(self, event: CommonEvent) -> Dict:
        """
        Compute final risk score for a security event.

        Process:
            1. Normalize rule severity (0–10 → 0–1)
            2. Combine with ML anomaly score
            3. Compute weighted risk score
            4. Convert to UI-friendly scale (0–10)
            5. Assign risk category (LOW / MEDIUM / HIGH)

        Returns:
            Dict containing risk score, level, color, and event ID
        """

        # =========================================================
        # 1. RULE-BASED SCORE NORMALIZATION
        # =========================================================
        normalized_rule = event.severity / 10.0

        # =========================================================
        # 2. ML ANOMALY SCORE
        # =========================================================
        ml_score = getattr(event, 'anomaly_score', 0.0)

        # =========================================================
        # 3. HYBRID WEIGHTED RISK SCORE
        # =========================================================
        final_risk = (
            normalized_rule * self.rule_weight
        ) + (
            ml_score * self.ml_weight
        )

        # =========================================================
        # 4. SCALE TO UI RANGE (0–10)
        # =========================================================
        display_score = round(final_risk * 10, 2)

        # =========================================================
        # 5. RISK CLASSIFICATION
        # =========================================================
        if display_score < 3.0:
            level = "LOW"
            color = "green"
        elif display_score < 7.0:
            level = "MEDIUM"
            color = "orange"
        else:
            level = "HIGH"
            color = "red"

        return {
            "risk_score": display_score,
            "risk_level": level,
            "risk_color": color,
            "event_id": event.event_id
        }
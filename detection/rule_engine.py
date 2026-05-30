from typing import Dict, List
from schemas.common_event import CommonEvent
import config.settings as settings


class RuleEngine:
    """
    Stateful rule-based detection engine.

    Evaluates incoming security events using predefined heuristics
    and short-term user behavior history.

    Detects:
        - Authentication abuse (brute force / repeated failures)
        - Suspicious transactions (high-value transfers)
        - Network reconnaissance activity (scanning behavior)
    """

    def __init__(self):
        # In-memory per-user event history for behavioral detection
        self.user_history: Dict[str, List[CommonEvent]] = {}

    def evaluate(self, event: CommonEvent) -> Dict:
        """
        Evaluate a single event against rule-based security logic.

        Args:
            event: Incoming normalized security event.

        Returns:
            Dictionary containing:
                - alert (bool): whether event is suspicious
                - severity (int): risk score (0–10 scale)
                - reasons (List[str]): triggered rule explanations
                - event_id: original event identifier
        """

        severity = 0
        reasons = []

        # =========================================================
        # 1. UPDATE USER STATE
        # =========================================================
        if event.user_id not in self.user_history:
            self.user_history[event.user_id] = []

        self.user_history[event.user_id].append(event)

        # Keep only recent events for lightweight behavioral tracking
        self.user_history[event.user_id] = self.user_history[event.user_id][-10:]

        # =========================================================
        # 2. AUTHENTICATION RULES
        # =========================================================
        if event.event_type == "auth":

            # Explicit brute-force indicator flag
            if event.metadata.get("failed_burst"):
                severity = max(severity, 7)
                reasons.append("Brute force attempt (Flagged)")

            # Behavioral rule: repeated authentication failures
            recent_failures = [
                e for e in self.user_history[event.user_id]
                if e.event_type == "auth"
                and e.metadata.get("status") == "failure"
            ]

            if len(recent_failures) >= 3:
                severity = max(severity, 5)
                reasons.append(f"Multiple failed logins ({len(recent_failures)})")

        # =========================================================
        # 3. TRANSACTION RULES
        # =========================================================
        if event.event_type == "transaction":

            amount = event.metadata.get("amount", 0)

            # High-value transaction threshold
            if amount > getattr(settings, "HIGH_VALUE_TRANSACTION", 5000):
                severity = max(severity, 8)
                reasons.append(f"High-value transaction: ${amount}")

        # =========================================================
        # 4. NETWORK RULES
        # =========================================================
        if event.event_type == "network":

            # Detect scanning or suspicious network behavior
            if event.metadata.get("scan_activity") or event.severity >= 4:
                severity = max(severity, 6)
                reasons.append("Network scanning activity")

        # =========================================================
        # FINAL OUTPUT
        # =========================================================
        return {
            "alert": severity > 0,
            "severity": severity,
            "reasons": reasons,
            "event_id": event.event_id
        }
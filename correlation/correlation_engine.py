from typing import List, Dict
from datetime import datetime, timedelta
from schemas.common_event import CommonEvent


class CorrelationEngine:
    """
    Correlation engine for detecting multi-event attack patterns across time.

    Maintains per-user event history and applies temporal correlation rules
    to detect higher-level security incidents that cannot be identified
    from single events alone.
    """

    def __init__(self, window_minutes: int = 10):
        # In-memory state storing recent events per user
        self.user_state: Dict[str, List[CommonEvent]] = {}

        # Sliding window size for correlation analysis
        self.window_minutes = window_minutes

    def _clean_old_events(self, user_id: str):
        """
        Remove events outside the sliding time window.

        This prevents unbounded memory growth and ensures correlation
        logic only considers recent activity.
        """
        now = datetime.now()

        self.user_state[user_id] = [
            e for e in self.user_state[user_id]
            if (now - datetime.fromisoformat(e.timestamp)) < timedelta(minutes=self.window_minutes)
        ]

    def correlate(self, new_events: List[CommonEvent]) -> Dict:
        """
        Perform cross-event correlation to detect attack patterns.

        Detects multi-step attack scenarios such as:
            - Account takeover sequences
            - Impossible travel anomalies

        Args:
            new_events: Newly ingested batch of events.

        Returns:
            Dictionary containing detected incidents.
        """

        incidents = []

        # =========================================================
        # 1. Update persistent user state
        # =========================================================
        for e in new_events:
            self.user_state.setdefault(e.user_id, []).append(e)
            self._clean_old_events(e.user_id)

        # =========================================================
        # 2. Analyze behavioral patterns per user
        # =========================================================
        for user, history in self.user_state.items():

            # Pattern A: Account takeover sequence
            # (failed logins → success → high-value transaction)
            has_burst = any(
                e.event_type == "auth" and e.metadata.get("status") == "failure"
                for e in history
            )
            has_success = any(
                e.event_type == "auth" and e.metadata.get("status") == "success"
                for e in history
            )
            has_high_tx = any(
                e.event_type == "transaction" and e.metadata.get("amount", 0) > 5000
                for e in history
            )

            # Pattern B: Geographic anomaly (impossible travel)
            locations = list(
                set(
                    e.metadata.get("location")
                    for e in history
                    if e.metadata.get("location")
                )
            )

            # =========================================================
            # INCIDENT DETECTION RULES
            # =========================================================

            if has_burst and has_success and has_high_tx:
                incidents.append({
                    "user": user,
                    "type": "ACCOUNT_TAKEOVER",
                    "confidence": 0.95,
                    "description": (
                        f"User {user} experienced brute force login attempts "
                        f"followed by successful authentication and high-value transaction."
                    )
                })

            elif len(locations) > 1 and has_high_tx:
                incidents.append({
                    "user": user,
                    "type": "IMPOSSIBLE_TRAVEL",
                    "confidence": 0.80,
                    "description": (
                        f"User {user} activity observed across multiple locations: "
                        f"{locations}."
                    )
                })

        return {"incidents": incidents}
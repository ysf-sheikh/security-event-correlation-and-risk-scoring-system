import numpy as np
from sklearn.ensemble import IsolationForest
from schemas.common_event import CommonEvent
from typing import List


class AnomalyModel:
    """
    Unsupervised anomaly detection model using Isolation Forest.

    This model learns baseline behavior from historical security events
    and flags deviations as potential anomalies.

    Used for:
        - Detecting unusual authentication patterns
        - Identifying abnormal transaction behavior
        - Highlighting unexpected network or system activity
    """

    def __init__(self, contamination: float = 0.05):
        """
        Initialize the anomaly detection model.

        Args:
            contamination: Expected proportion of anomalies in the dataset.
                           Higher values make detection more sensitive.
        """
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False
        self.training_buffer = []

    def extract_features(self, event: CommonEvent) -> np.ndarray:
        """
        Convert a raw event into a numerical feature vector for ML processing.

        Feature Engineering:
            1. Authentication failure flag
            2. Transaction amount
            3. Event severity score
            4. Hour of event occurrence
        """

        # Feature 1: Authentication failure indicator
        failed = 1 if event.metadata.get("status") == "failure" else 0

        # Feature 2: Transaction amount (if applicable)
        amount = event.metadata.get("amount", 0)

        # Feature 3: Precomputed severity score
        severity = event.severity

        # Feature 4: Time-based behavior signal (hour of day)
        try:
            from datetime import datetime
            hour = datetime.fromisoformat(event.timestamp).hour
        except Exception:
            hour = 12  # Default fallback if timestamp parsing fails

        return np.array([failed, amount, severity, hour])

    def train(self, events: List[CommonEvent]):
        """
        Train the anomaly detection model on historical events.

        Args:
            events: List of baseline events representing normal behavior.

        Note:
            Requires a minimum dataset size for meaningful learning.
        """
        if len(events) < 10:
            return  # Insufficient data for training

        features = np.array([self.extract_features(e) for e in events])
        self.model.fit(features)
        self.is_trained = True

    def score(self, event: CommonEvent) -> float:
        """
        Compute anomaly score for a single event.

        Returns:
            float: Normalized anomaly score between 0 (normal) and 1 (high risk)
        """
        if not self.is_trained:
            return 0.0  # Model not ready

        features = self.extract_features(event).reshape(1, -1)

        # Raw anomaly score (higher negative values = more anomalous)
        raw_score = self.model.decision_function(features)[0]

        # Normalize into 0–1 risk scale
        normalized_score = np.clip((0.5 - raw_score), 0, 1)

        return float(normalized_score)
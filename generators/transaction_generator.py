import random
from schemas.common_event import CommonEvent


class TransactionEventGenerator:
    """
    Synthetic financial transaction event generator.

    Simulates realistic user spending behavior including:
        - Low-value everyday transactions
        - High-value suspicious transactions
        - Multi-location activity for correlation testing
    """

    def __init__(self):
        self.users = ["alice", "bob", "charlie", "david"]

        # Shared IP pool for cross-module correlation testing
        self.ip_pool = [
            "10.0.0.1",
            "10.0.0.2",
            "192.168.1.10",
            "172.16.0.5",
            "8.8.8.8"
        ]

        self.locations = ["UAE", "USA", "UK", "Germany", "Russia"]

    def generate(self) -> CommonEvent:
        """
        Generate a single synthetic transaction event.

        Returns:
            CommonEvent: A financial transaction containing:
                - user identity
                - transaction amount
                - location metadata
                - base severity score (risk hint)
        """

        # Randomly simulate user transaction context
        user = random.choice(self.users)
        ip = random.choice(self.ip_pool)
        loc = random.choice(self.locations)

        # Simulated transaction value (realistic financial range)
        amount = round(random.uniform(10, 10000), 2)

        # =========================================================
        # BASE RISK SCORING (PRE-ANALYSIS HINT)
        # =========================================================
        base_severity = 0

        if amount > 8000:
            base_severity = 5  # High-risk transaction
        elif amount > 5000:
            base_severity = 2  # Medium-risk transaction

        # Transaction metadata payload
        metadata = {
            "amount": amount,
            "currency": "USD",
            "location": loc,
            "merchant": "Global_Retail_Inc"
        }

        return CommonEvent(
            event_type="transaction",
            user_id=user,
            ip_address=ip,
            metadata=metadata,
            severity=base_severity
        )
import random
from typing import List
from schemas.common_event import CommonEvent


class AuthEventGenerator:
    """
    Synthetic authentication event generator.

    Simulates realistic login behavior for security testing:
        - Normal login success/failure patterns
        - Occasional brute-force attack bursts
        - Multi-location user activity
    """

    def __init__(self):
        self.users = ["alice", "bob", "charlie", "david"]
        self.ip_pool = ["10.0.0.1", "10.0.0.2", "192.168.1.10", "172.16.0.5"]
        self.locations = ["UAE", "USA", "UK", "Germany"]

    def generate(self) -> List[CommonEvent]:
        """
        Generate a batch of authentication events.

        Returns:
            List[CommonEvent]: One or more auth events representing:
                - Normal login attempt
                - Failed login
                - Brute-force burst simulation (rare)
        """

        events = []

        # Randomly select simulated user context
        user = random.choice(self.users)
        ip = random.choice(self.ip_pool)
        loc = random.choice(self.locations)

        # =========================================================
        # 10% CHANCE: BRUTE FORCE BURST SIMULATION
        # =========================================================
        if random.random() < 0.1:

            # Simulate multiple failed login attempts
            for _ in range(5):
                events.append(CommonEvent(
                    event_type="auth",
                    user_id=user,
                    ip_address=ip,
                    metadata={
                        "status": "failure",
                        "location": loc,
                        "reason": "invalid_password"
                    },
                    severity=3  # Elevated baseline severity for failed attempts
                ))

        else:
            # =========================================================
            # NORMAL LOGIN BEHAVIOR
            # =========================================================
            success = random.random() > 0.15

            events.append(CommonEvent(
                event_type="auth",
                user_id=user,
                ip_address=ip,
                metadata={
                    "status": "success" if success else "failure",
                    "location": loc
                },
                severity=0 if success else 1
            ))

        return events
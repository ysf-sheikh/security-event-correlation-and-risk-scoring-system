import random
from typing import List
from schemas.common_event import CommonEvent


class NetworkEventGenerator:
    """
    Synthetic network traffic generator.

    Simulates realistic and malicious network behavior including:
        - Normal internal network traffic
        - External traffic from unknown IPs
        - Port scanning activity (vertical scan simulation)
    """

    def __init__(self):
        # Internal trusted network IPs
        self.internal_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.10"]

        # External/untrusted IPs used to simulate threat actors
        self.external_ips = ["45.33.22.11", "185.22.14.5", "103.4.5.6"]

        # Common service ports found in enterprise environments
        self.common_ports = [80, 443, 22, 3306, 5432]

    def generate(self) -> List[CommonEvent]:
        """
        Generate a batch of synthetic network events.

        Returns:
            List[CommonEvent]: Network events representing either:
                - Normal traffic
                - Port scanning activity (rare malicious simulation)
        """

        events = []

        # 5% probability of simulating a port scan attack
        is_scan = random.random() < 0.05

        # Choose source IP based on behavior type
        source_ip = random.choice(
            self.external_ips if is_scan else self.internal_ips
        )

        # =========================================================
        # MALICIOUS BEHAVIOR: PORT SCANNING
        # =========================================================
        if is_scan:
            # Simulate vertical port scan from a single attacker IP
            start_port = random.randint(1000, 2000)

            for i in range(10):
                events.append(CommonEvent(
                    event_type="network",
                    user_id="system",
                    ip_address=source_ip,
                    metadata={
                        "port": start_port + i,
                        "action": "blocked",
                        "protocol": "TCP"
                    },
                    severity=4  # Elevated severity for scanning behavior
                ))

        # =========================================================
        # NORMAL NETWORK TRAFFIC
        # =========================================================
        else:
            events.append(CommonEvent(
                event_type="network",
                user_id="system",
                ip_address=source_ip,
                metadata={
                    "port": random.choice(self.common_ports),
                    "action": "allowed",
                    "protocol": "TCP"
                },
                severity=0
            ))

        return events
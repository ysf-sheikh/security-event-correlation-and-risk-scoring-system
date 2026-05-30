from dataclasses import dataclass, field, asdict
from datetime import datetime
import uuid
from typing import Optional, Any, Dict


@dataclass
class CommonEvent:
    """
    Standardized event schema used across the entire security pipeline.

    This is the core data structure shared between:
        - Event generators
        - Ingestion pipeline
        - Detection engines (rules + ML)
        - Correlation engine
        - Risk scoring system
        - Dashboard visualization

    It ensures all security telemetry follows a unified format.
    """

    # =========================================================
    # CORE EVENT IDENTIFIERS
    # =========================================================
    event_type: str        # 'auth', 'transaction', 'network'
    user_id: str
    ip_address: str

    # Timestamp of event creation (ISO format)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Unique event identifier for tracing across systems
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Source system generating the event
    source_system: str = "internal_gen"

    # =========================================================
    # FLEXIBLE EVENT PAYLOAD
    # =========================================================
    # Contains event-specific fields such as:
    # - auth: status, reason
    # - transaction: amount, merchant
    # - network: port, protocol
    metadata: Dict[str, Any] = field(default_factory=dict)

    # =========================================================
    # SECURITY SCORING FIELDS
    # =========================================================
    # Base severity assigned by generators or rule engine
    severity: int = 0

    # ML-based anomaly score (0–1 scale)
    anomaly_score: float = 0.0

    def to_dict(self):
        """
        Convert event object into dictionary format for:
            - logging
            - dashboard visualization
            - export pipelines
        """
        return asdict(self)
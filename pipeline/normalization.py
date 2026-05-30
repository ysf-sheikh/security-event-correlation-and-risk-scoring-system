from schemas.common_event import CommonEvent
from datetime import datetime


class Normalizer:
    """
    Event normalization layer for the security pipeline.

    Ensures all incoming events conform to a consistent format before
    being processed by detection, correlation, and ML systems.

    Responsibilities:
        - Validate required fields
        - Standardize formatting for correlation consistency
        - Sanitize missing or malformed values
        - Enforce severity boundaries
    """

    def normalize(self, event: CommonEvent) -> CommonEvent:
        """
        Normalize and sanitize a raw event.

        This step ensures downstream components (rules, ML, correlation)
        operate on consistent and reliable data.

        Args:
            event: Raw CommonEvent object

        Returns:
            Normalized CommonEvent object

        Raises:
            ValueError: If required critical fields are missing
        """

        # =========================================================
        # 1. REQUIRED FIELD VALIDATION
        # =========================================================
        if not event.event_type or not event.user_id:
            raise ValueError(f"Malformed event detected: {event.event_id}")

        # =========================================================
        # 2. STANDARDIZATION (CRITICAL FOR CORRELATION)
        # =========================================================
        # Normalize casing to ensure consistent matching across systems
        event.user_id = str(event.user_id).strip().lower()
        event.event_type = str(event.event_type).strip().lower()

        # =========================================================
        # 3. IP ADDRESS SANITIZATION
        # =========================================================
        # Replace missing or invalid IPs with safe fallback
        if not event.ip_address or event.ip_address == "N/A":
            event.ip_address = "127.0.0.1"

        # =========================================================
        # 4. SEVERITY NORMALIZATION
        # =========================================================
        # Ensure severity stays within expected bounds (0–10)
        try:
            event.severity = int(event.severity)
            event.severity = max(0, min(event.severity, 10))
        except (ValueError, TypeError):
            event.severity = 0

        # =========================================================
        # 5. METADATA SAFETY CHECK
        # =========================================================
        # Guarantee metadata is always a dictionary to prevent runtime errors
        if not isinstance(event.metadata, dict):
            event.metadata = {}

        return event
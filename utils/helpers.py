import uuid
from datetime import datetime
import logging
from typing import Any, Dict, Optional


"""
Central utility module for the Nexus security engine.

Provides:
    - ID generation utilities
    - Timestamp standardization
    - Safe dictionary access helpers
    - Centralized logging wrapper for SOC-style output
"""

# =========================================================
# CENTRALIZED LOGGING CONFIGURATION
# =========================================================
# This logger is shared across the entire system to maintain
# consistent SOC-style logging output.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger("NexusEngine")


def generate_uuid() -> str:
    """
    Generate a unique identifier for events, alerts, or incidents.

    Returns:
        str: UUID4 string
    """
    return str(uuid.uuid4())


def current_timestamp() -> str:
    """
    Generate a standardized ISO 8601 timestamp.

    Returns:
        str: Current time in ISO format
    """
    return datetime.now().isoformat()


def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Safely retrieve a value from a dictionary.

    Prevents KeyErrors and handles invalid input types gracefully.

    Args:
        data: Dictionary containing event or metadata fields
        key: Key to retrieve
        default: Fallback value if key is missing

    Returns:
        Any: Retrieved value or default
    """
    if not isinstance(data, dict):
        return default
    return data.get(key, default)


def log_event(message: str, level: str = "info"):
    """
    Central logging interface for the security engine.

    Used for:
        - SOC-style console logging
        - System monitoring
        - Debugging pipeline behavior

    Args:
        message: Log message
        level: Log level ("info", "warning", "error")
    """
    if level.lower() == "info":
        logger.info(message)
    elif level.lower() == "warning":
        logger.warning(message)
    elif level.lower() == "error":
        logger.error(message)
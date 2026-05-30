"""
NEXUS ENGINE CONFIGURATION

Centralized configuration for detection thresholds, pipeline behavior,
correlation logic, and risk scoring.

This file acts as the single source of truth for system tuning.
Adjusting these values directly impacts detection sensitivity and alerting behavior.
"""

# =========================================================
# PIPELINE SETTINGS
# =========================================================
EVENT_BATCH_SIZE = 50
SIMULATION_SPEED = 1.0  # Seconds between generator events

# =========================================================
# AUTHENTICATION DETECTION THRESHOLDS
# =========================================================
MAX_FAILED_LOGINS = 5
BRUTE_FORCE_WINDOW = 300  # Time window (seconds) for brute-force detection

# =========================================================
# TRANSACTION DETECTION THRESHOLDS
# =========================================================
HIGH_VALUE_TRANSACTION = 5000.00
CURRENCY_CODE = "USD"

# =========================================================
# NETWORK DETECTION THRESHOLDS
# =========================================================
PORT_SCAN_THRESHOLD = 20

# Common high-risk / sensitive service ports monitored for activity
SENSITIVE_PORTS = [22, 3306, 5432, 27017]  # SSH, MySQL, PostgreSQL, MongoDB

# =========================================================
# CORRELATION & MACHINE LEARNING SETTINGS
# =========================================================
VELOCITY_TIME_WINDOW = 60       # Time window for rapid movement detection
CORRELATION_WINDOW_MINS = 10    # Event correlation grouping window
ML_CONTAMINATION = 0.05         # Expected anomaly ratio for ML model training

# =========================================================
# RISK SCORING WEIGHTS
# =========================================================
RULE_WEIGHT = 0.6
ML_WEIGHT = 0.4
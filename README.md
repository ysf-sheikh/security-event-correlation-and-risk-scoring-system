# Nexus Engine – Security Event Correlation & Threat Detection System

## Overview

Nexus Engine is a simulated Security Operations Center (SOC) pipeline designed for real-time event ingestion, anomaly detection, rule-based analysis, and cross-event correlation.

It models how modern security platforms (SIEM/UEBA systems) process and analyze telemetry data from multiple sources such as authentication logs, financial transactions, and network traffic.

The system combines deterministic rules with machine learning to detect suspicious behavior and generate risk-based alerts.

---

## Key Features

### Multi-Source Event Simulation

- Authentication event generation (login attempts, brute-force simulation)
- Transaction event generation (fraud-like financial behavior)
- Network event generation (port scanning and traffic simulation)

### Event Processing Pipeline

- Normalization of raw events into a unified schema
- In-memory ingestion queue for real-time processing
- Batch retrieval for downstream analysis

### Detection Engine

- Rule-based detection for known attack patterns
- Machine learning anomaly detection using Isolation Forest
- Stateful correlation across multiple events

### Correlation Engine

- Detects multi-step attack patterns such as:
  - Account takeover sequences
  - Impossible travel behavior
  - Cross-event attack chains

### Risk Scoring System

- Hybrid scoring model combining:
  - Rule-based severity signals
  - Machine learning anomaly scores
- Outputs normalized risk levels (LOW, MEDIUM, HIGH)

### Visualization Dashboard

- Streamlit-based SOC dashboard
- Real-time event monitoring
- Risk distribution and incident tracking
- Interactive threat visualization

---

## System Architecture

The system is organized into the following layers:

1. Data Generation Layer
   - AuthEventGenerator
   - TransactionEventGenerator
   - NetworkEventGenerator

2. Ingestion Layer
   - IngestionPipeline
   - Normalizer

3. Detection Layer
   - RuleEngine
   - AnomalyModel (Isolation Forest)
   - CorrelationEngine

4. Scoring Layer
   - RiskScorer

5. Presentation Layer
   - Streamlit SOC dashboard

---

## Data Flow

1. Events are generated from simulated sources
2. Events are normalized into a unified schema
3. Events are queued in the ingestion pipeline
4. Rule engine evaluates deterministic security rules
5. ML model assigns anomaly scores
6. Correlation engine identifies multi-step attacks
7. Risk scorer combines signals into a final risk score
8. Dashboard visualizes results in real time

---

## Core Technologies

- Python 3.10+
- NumPy
- scikit-learn (Isolation Forest)
- Streamlit
- Pandas
- Plotly

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/ysf-sheikh/security-event-correlation-and-risk-scoring-system
cd security-event-correlation-and-risk-scoring-system
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the System

### Start the Dashboard

```bash
streamlit run app.py
```

### Run Core Pipeline (Optional CLI mode)

```bash
python main.py
```

## Example Use Cases

1. Security Monitoring
   - Detect brute-force login attempts
   - Identify unusual transaction behavior
   - Flag suspicious network scanning activity

2. Behavioral Analytics
   - Track user activity patterns over time
   - Detect deviations from baseline behavior
   - Correlate cross-system events

3. Threat Simulation
   - Multi-step attack chain modeling
   - Insider threat simulation
   - Cross-location anomaly detection

## Configuration

### System parameters are controlled via:

```bash
config/settings.py
```

## License

This project is intended for educational and research purposes only.

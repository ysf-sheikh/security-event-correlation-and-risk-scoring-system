import streamlit as st
import pandas as pd
import plotly.express as px
import time
import os
import sys

# =========================================================
# PATH SETUP (ENABLE LOCAL IMPORTS)
# =========================================================
# Ensures project root is accessible when running Streamlit directly
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, ".."))

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# =========================================================
# CORE SYSTEM IMPORTS
# =========================================================
from schemas.common_event import CommonEvent
from generators.auth_generator import AuthEventGenerator
from generators.transaction_generator import TransactionEventGenerator
from generators.network_generator import NetworkEventGenerator

from pipeline.ingestor import IngestionPipeline
from detection.rule_engine import RuleEngine
from correlation.correlation_engine import CorrelationEngine
from ml.anomaly_model import AnomalyModel
from scoring.risk_scorer import RiskScorer


# =========================================================
# STREAMLIT UI CONFIGURATION
# =========================================================
st.set_page_config(
    page_title="Security Event Correlation System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom dark theme styling for dashboard components
st.markdown("""
<style>
.main { background-color: #0e1117; }
.stMetric { background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 10px; }
.stDataFrame { border: 1px solid #30363d; border-radius: 10px; }
h1, h2, h3 { color: #58a6ff !important; font-family: 'Courier New'; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Security Event Correlation System")
st.caption("Real-time telemetry analysis, anomaly detection, and multi-vector incident correlation.")
st.divider()


# =========================================================
# SESSION STATE INITIALIZATION
# =========================================================
# Ensures system components persist across Streamlit reruns
if "pipeline" not in st.session_state:
    st.session_state.pipeline = IngestionPipeline()
    st.session_state.rule_engine = RuleEngine()
    st.session_state.corr_engine = CorrelationEngine()
    st.session_state.ml_model = AnomalyModel()
    st.session_state.scorer = RiskScorer()

    # Separate storage layers:
    # raw_events      → ML training + correlation logic
    # display_events  → UI-rendered enriched data
    # incidents       → correlated security incidents
    st.session_state.raw_events = []
    st.session_state.display_events = []
    st.session_state.incidents = []


# =========================================================
# SIDEBAR CONTROLS
# =========================================================
with st.sidebar:
    st.header("⚙️ SYSTEM CONTROLS")

    run_sim = st.toggle("ACTIVATE LIVE FEED", value=False)
    sim_speed = st.select_slider("POLLING INTERVAL", options=[0.5, 1.0, 2.0, 5.0], value=1.0)

    st.divider()

    status_icon = "🟢" if st.session_state.ml_model.is_trained else "🟡"
    st.write(f"{status_icon} ML Engine: {'Active' if st.session_state.ml_model.is_trained else 'Warm-up'}")

    if st.button("CLEAR LOGS"):
        st.session_state.raw_events = []
        st.session_state.display_events = []
        st.session_state.incidents = []


# =========================================================
# LIVE SIMULATION PIPELINE
# =========================================================
if run_sim:
    # Event generators for different telemetry sources
    auth_gen = AuthEventGenerator()
    tx_gen = TransactionEventGenerator()
    net_gen = NetworkEventGenerator()

    # Generate synthetic multi-source events
    events = [
        auth_gen.generate(),
        tx_gen.generate(),
        net_gen.generate()
    ]

    # Ingest events into pipeline buffer
    for event in events:
        st.session_state.pipeline.ingest(event)

    # Fetch processed batch from ingestion pipeline
    batch = st.session_state.pipeline.fetch_batch(10)

    # Train ML model only on sufficient raw data
    if (
        not st.session_state.ml_model.is_trained
        and len(st.session_state.raw_events) > 20
    ):
        st.session_state.ml_model.train(st.session_state.raw_events[-50:])

    # Process each event in batch
    for event in batch:

        # Rule-based detection
        rule_result = st.session_state.rule_engine.evaluate(event)

        # ML anomaly scoring
        event.anomaly_score = st.session_state.ml_model.score(event)

        # Risk scoring engine
        risk_result = st.session_state.scorer.calculate(event)

        # Store raw event for ML + correlation
        st.session_state.raw_events.append(event)

        # Enriched event for UI display only
        display_event = {
            **event.to_dict(),
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "risk_color": risk_result["risk_color"]
        }

        st.session_state.display_events.append(display_event)

    # Correlation engine processes raw events only
    corr_results = st.session_state.corr_engine.correlate(batch)
    if corr_results.get("incidents"):
        st.session_state.incidents.extend(corr_results["incidents"])


# =========================================================
# DASHBOARD METRICS
# =========================================================
m1, m2, m3, m4 = st.columns(4)

total_events = len(st.session_state.display_events)
high_risk = sum(1 for e in st.session_state.display_events if e["risk_level"] == "HIGH")

m1.metric("TOTAL TELEMETRY", total_events)
m2.metric("CRITICAL ALERTS", high_risk)
m3.metric("CORRELATED INCIDENTS", len(st.session_state.incidents))
m4.metric("ENGINE STATUS", "LIVE" if run_sim else "IDLE")


# =========================================================
# DASHBOARD TABS
# =========================================================
tab1, tab2 = st.tabs(["📊 THREAT OVERVIEW", "📡 RAW TELEMETRY"])


# =========================================================
# TAB 1: ANALYTICS VISUALIZATION
# =========================================================
with tab1:
    c1, c2 = st.columns([2, 1])

    if st.session_state.display_events:
        df = pd.DataFrame(st.session_state.display_events)

        with c1:
            st.subheader("Risk Propensity Over Time")

            fig = px.area(
                df,
                x="timestamp",
                y="risk_score",
                template="plotly_dark"
            )
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Active Incidents")

            if st.session_state.incidents:
                for inc in st.session_state.incidents[-3:]:
                    with st.expander(f"🚨 {inc['type']}"):
                        st.write(inc.get("description", "No details"))
                        st.progress(inc.get("confidence", 0))

        with c2:
            st.subheader("Event Distribution")

            fig2 = px.pie(df, names="event_type", template="plotly_dark")
            st.plotly_chart(fig2, use_container_width=True)

            st.subheader("Anomaly vs Severity")

            fig3 = px.scatter(
                df,
                x="severity",
                y="anomaly_score",
                color="risk_level",
                template="plotly_dark"
            )
            st.plotly_chart(fig3, use_container_width=True)


# =========================================================
# TAB 2: RAW EVENT STREAM
# =========================================================
with tab2:
    st.subheader("Live Event Stream")

    if st.session_state.display_events:
        st.dataframe(
            pd.DataFrame(st.session_state.display_events).tail(50),
            use_container_width=True
        )


# =========================================================
# AUTO REFRESH LOOP (SIMULATION MODE)
# =========================================================
if run_sim:
    time.sleep(sim_speed)
    st.rerun()
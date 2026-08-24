import streamlit as st
import pandas as pd
import time

from winotify import Notification, audio

from live_engine import LiveNetworkEngine


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Network Tool",
    page_icon="🌐",
    layout="wide"
)


# ============================================================
# NORMAL BASELINE
# ============================================================

PACKET_P95 = 730
BYTES_P95 = 774121


# ============================================================
# LEGITIMATE HIGH-VOLUME TRAFFIC
# ============================================================

LEGIT_HIGH_VOLUME_PACKET_LIMIT = 1000
LEGIT_HIGH_VOLUME_BYTES_LIMIT = 1000000

LEGIT_DESTINATION_LIMIT = 5
LEGIT_SOURCE_PORT_LIMIT = 5
LEGIT_DESTINATION_PORT_LIMIT = 5


# ============================================================
# SECURITY BOUNDARIES
# ============================================================

SECURITY_PACKET_LIMIT = 450
SECURITY_BYTES_LIMIT = 500000

# Strong source-port diversity.
SECURITY_SOURCE_PORT_LIMIT = 100

# Raised from 15 to 40.
# Normal browser traffic reached ~32 in testing.
SECURITY_DESTINATION_PORT_LIMIT = 40

# AI confidence boundary.
SECURITY_SCORE_LIMIT = -0.06


# ============================================================
# MULTI-WINDOW DETECTION
# ============================================================

MIN_ANOMALOUS_WINDOWS = 2

BURST_WINDOW_SECONDS = 6


# ============================================================
# NOTIFICATION COOLDOWN
# ============================================================

NOTIFICATION_COOLDOWN = 60


# ============================================================
# DASHBOARD REFRESH
# ============================================================

REFRESH_INTERVAL = 1000


# ============================================================
# SESSION STATE
# ============================================================

if "engine" not in st.session_state:
    st.session_state.engine = None

if "monitoring" not in st.session_state:
    st.session_state.monitoring = False

if "alert_history" not in st.session_state:
    st.session_state.alert_history = []

if "processed_sequences" not in st.session_state:
    st.session_state.processed_sequences = set()

if "last_notification_time" not in st.session_state:
    st.session_state.last_notification_time = 0

if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None


# ============================================================
# HEADER
# ============================================================

st.title("Network Tool")

st.caption(
    "AI-powered continuous network monitoring "
    "with contextual anomaly detection"
)


# ============================================================
# CREATE ENGINE
# ============================================================

def create_engine():

    if st.session_state.engine is None:

        st.session_state.engine = LiveNetworkEngine()


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    create_engine()

    if st.session_state.monitoring:
        return True

    try:

        print("=" * 60)
        print("START MONITORING REQUESTED")
        print("=" * 60)

        st.session_state.engine.start()

        st.session_state.monitoring = True

        st.session_state.processed_sequences = set()

        st.session_state.alert_history = []

        st.session_state.current_analysis = None

        st.session_state.last_notification_time = 0

        print("MONITORING STARTED SUCCESSFULLY")
        print("=" * 60)

        return True

    except Exception as e:

        st.session_state.monitoring = False

        print("=" * 60)
        print("MONITORING START FAILED")
        print("=" * 60)
        print(f"Error: {e}")
        print("=" * 60)

        st.error(
            f"Unable to start monitoring: {e}"
        )

        return False

# ============================================================
# STOP MONITORING
# ============================================================

def stop_monitoring():

    if st.session_state.engine is not None:

        try:

            st.session_state.engine.stop()

        except Exception as e:

            print(
                "Engine stop error:",
                e
            )

    st.session_state.monitoring = False


# ============================================================
# WINDOWS NOTIFICATION
# ============================================================

def send_notification(title, message):

    try:

        toast = Notification(
            app_id="Network Tool",
            title=title,
            msg=message
        )

        toast.set_audio(
            audio.Default,
            loop=False
        )

        toast.show()

        return True

    except Exception as e:

        print(
            "Notification error:",
            e
        )

        return False


# ============================================================
# TEST NOTIFICATION
# ============================================================

def test_notification():

    success = send_notification(

        "Network Tool",

        "Test notification: "
        "the Network Tool notification system "
        "is working correctly."

    )

    if success:

        st.success(
            "Network Tool notification sent successfully."
        )

    else:

        st.error(
            "Unable to send Windows notification."
        )


# ============================================================
# SECURITY INDICATOR
# ============================================================

def security_indicator(result):

    packet_count = float(
        result["packet_count"]
    )

    total_bytes = float(
        result["total_bytes"]
    )

    source_ports = int(
        result["unique_source_ports"]
    )

    destination_ports = int(
        result["unique_destination_ports"]
    )

    anomaly_score = float(
        result["anomaly_score"]
    )


    # --------------------------------------------------------
    # Strong security window
    # --------------------------------------------------------

    high_traffic = (

        packet_count >=
        SECURITY_PACKET_LIMIT

        and

        total_bytes >=
        SECURITY_BYTES_LIMIT

    )


    high_port_diversity = (

        source_ports >=
        SECURITY_SOURCE_PORT_LIMIT

        or

        destination_ports >=
        SECURITY_DESTINATION_PORT_LIMIT

    )


    strong_ai_signal = (

        anomaly_score <=
        SECURITY_SCORE_LIMIT

    )


    return (

        high_traffic

        and

        high_port_diversity

        and

        strong_ai_signal

    )


# ============================================================
# MULTI-WINDOW SECURITY DETECTION
# ============================================================

def detect_security_burst(history):

    if not history:

        return False, []


    # --------------------------------------------------------
    # Get recent windows
    # --------------------------------------------------------

    recent = history[-20:]


    # --------------------------------------------------------
    # Only AI anomaly windows
    # --------------------------------------------------------

    anomalies = [

        result

        for result in recent

        if result.get("status") == "Anomaly"

    ]


    if len(anomalies) < MIN_ANOMALOUS_WINDOWS:

        return False, []


    # --------------------------------------------------------
    # Take latest anomalous windows
    # --------------------------------------------------------

    recent_anomalies = anomalies[
        -MIN_ANOMALOUS_WINDOWS:
    ]


    # --------------------------------------------------------
    # Check time distance
    # --------------------------------------------------------

    try:

        times = [

            pd.to_datetime(
                item["time_window"]
            )

            for item in recent_anomalies

        ]

        time_difference = (

            times[-1]
            -
            times[0]

        ).total_seconds()

    except Exception:

        time_difference = 999


    if time_difference > BURST_WINDOW_SECONDS:

        return False, []


    # --------------------------------------------------------
    # At least one window must satisfy the strong
    # security boundary.
    # --------------------------------------------------------

    qualifying_windows = [

        item

        for item in recent_anomalies

        if security_indicator(item)

    ]


    if not qualifying_windows:

        return False, []


    # --------------------------------------------------------
    # Calculate maximum values
    # --------------------------------------------------------

    max_packets = max(

        int(item["packet_count"])

        for item in recent_anomalies

    )


    max_bytes = max(

        int(item["total_bytes"])

        for item in recent_anomalies

    )


    max_source_ports = max(

        int(item["unique_source_ports"])

        for item in recent_anomalies

    )


    max_destination_ports = max(

        int(item["unique_destination_ports"])

        for item in recent_anomalies

    )


    min_score = min(

        float(item["anomaly_score"])

        for item in recent_anomalies

    )


    # ========================================================
    # REASONS
    # ========================================================

    reasons = []


    if max_packets >= 1000:

        reasons.append(
            "Extremely high packet rate"
        )

    elif max_packets >= SECURITY_PACKET_LIMIT:

        reasons.append(
            "High packet rate"
        )


    if max_bytes >= 1000000:

        reasons.append(
            "Extremely high traffic volume"
        )

    elif max_bytes >= SECURITY_BYTES_LIMIT:

        reasons.append(
            "High traffic volume"
        )


    if max_source_ports >= 100:

        reasons.append(

            f"High source-port diversity "
            f"({max_source_ports})"

        )


    if max_destination_ports >= 40:

        reasons.append(

            f"High destination-port diversity "
            f"({max_destination_ports})"

        )


    reasons.append(

        f"AI anomaly score reached "
        f"{min_score:.4f}"

    )


    reasons.append(

        f"{len(recent_anomalies)} anomalous "
        f"windows detected in a short period"

    )


    return True, reasons


# ============================================================
# CONTEXTUAL TRAFFIC ANALYSIS
# ============================================================

def analyze_context(result, history):

    packet_count = float(
        result["packet_count"]
    )

    total_bytes = float(
        result["total_bytes"]
    )

    unique_destinations = int(
        result["unique_destinations"]
    )

    unique_source_ports = int(
        result["unique_source_ports"]
    )

    unique_destination_ports = int(
        result["unique_destination_ports"]
    )


    # ========================================================
    # LEGITIMATE HIGH-VOLUME TRAFFIC
    # ========================================================

    legitimate_high_volume = (

        packet_count >=
        LEGIT_HIGH_VOLUME_PACKET_LIMIT

        and

        total_bytes >=
        LEGIT_HIGH_VOLUME_BYTES_LIMIT

        and

        unique_destinations <=
        LEGIT_DESTINATION_LIMIT

        and

        unique_source_ports <=
        LEGIT_SOURCE_PORT_LIMIT

        and

        unique_destination_ports <=
        LEGIT_DESTINATION_PORT_LIMIT

    )


    if legitimate_high_volume:

        return {

            "risk":
                "High Traffic Activity",

            "reasons": [

                "Very high packet rate",

                "Very high traffic volume",

                "Low destination diversity",

                "Low source-port diversity",

                "Low destination-port diversity",

                "Pattern is consistent with "
                "legitimate intensive network activity"

            ],

            "notify":
                False

        }


    # ========================================================
    # MULTI-WINDOW SECURITY DETECTION
    # ========================================================

    security_event, security_reasons = (

        detect_security_burst(
            history
        )

    )


    if security_event:

        return {

            "risk":
                "Suspicious",

            "reasons":
                security_reasons,

            "notify":
                True

        }


    # ========================================================
    # SINGLE AI ANOMALY
    #
    # A single AI anomaly NEVER sends a notification.
    # ========================================================

    if result["status"] == "Anomaly":

        reasons = []


        if packet_count > PACKET_P95:

            reasons.append(

                "Traffic volume is above "
                "the normal baseline"

            )


        if total_bytes > BYTES_P95:

            reasons.append(

                "Traffic bytes are above "
                "the normal baseline"

            )


        if unique_destinations > 12:

            reasons.append(

                "Destination diversity is elevated"

            )


        if unique_source_ports > 20:

            reasons.append(

                "Source-port diversity is elevated"

            )


        if unique_destination_ports > 19:

            reasons.append(

                "Destination-port diversity is elevated"

            )


        if not reasons:

            reasons.append(

                "Traffic differs from the "
                "learned normal baseline"

            )


        return {

            "risk":
                "High Traffic Activity",

            "reasons":
                reasons,

            "notify":
                False

        }


    # ========================================================
    # HIGH TRAFFIC WITHOUT SECURITY EVIDENCE
    # ========================================================

    if (

        packet_count > PACKET_P95

        or

        total_bytes > BYTES_P95

    ):

        return {

            "risk":
                "High Traffic Activity",

            "reasons": [

                "Traffic is above the normal baseline",

                "No strong security evidence detected"

            ],

            "notify":
                False

        }


    # ========================================================
    # NORMAL
    # ========================================================

    return {

        "risk":
            "Normal",

        "reasons": [

            "Traffic appears normal"

        ],

        "notify":
            False

    }


# ============================================================
# PROCESS ONE RESULT
# ============================================================

def process_result(result, history):

    if result is None:

        return None


    sequence = result.get(
        "_sequence"
    )


    # --------------------------------------------------------
    # Don't process the same window twice
    # --------------------------------------------------------

    if sequence in st.session_state.processed_sequences:

        return None


    st.session_state.processed_sequences.add(
        sequence
    )


    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    analysis = analyze_context(

        result,

        history

    )


    st.session_state.current_analysis = (
        analysis
    )


    # ========================================================
    # SECURITY ALERT HISTORY
    # ========================================================

    if analysis["risk"] == "Suspicious":

        alert = {

            "time":
                result["time_window"],

            "risk":
                "Suspicious",

            "packet_count":
                result["packet_count"],

            "total_bytes":
                result["total_bytes"],

            "anomaly_score":
                result["anomaly_score"],

            "reason":
                ", ".join(
                    analysis["reasons"]
                )

        }


        # ----------------------------------------------------
        # Prevent duplicate rows
        # ----------------------------------------------------

        duplicate = any(

            item["time"] ==
            alert["time"]

            and

            item["packet_count"] ==
            alert["packet_count"]

            for item
            in st.session_state.alert_history

        )


        if not duplicate:

            st.session_state.alert_history.insert(

                0,

                alert

            )


        st.session_state.alert_history = (

            st.session_state.alert_history[:30]

        )


    # ========================================================
    # WINDOWS NOTIFICATION
    # ========================================================

    if (

        analysis["risk"] ==
        "Suspicious"

        and

        analysis["notify"]

    ):

        current_time = time.time()


        elapsed = (

            current_time
            -
            st.session_state.last_notification_time

        )


        if elapsed >= NOTIFICATION_COOLDOWN:

            success = send_notification(

                "Network Tool - Suspicious",

                "Unusual network activity detected. "
                "Open Network Tool to investigate."

            )


            if success:

                st.session_state.last_notification_time = (

                    current_time

                )


    return analysis


# ============================================================
# DISPLAY RISK
# ============================================================

def display_risk(analysis):

    if analysis is None:

        return


    risk = analysis["risk"]

    reasons = analysis["reasons"]


    if risk == "Normal":

        st.success(
            "NORMAL - Traffic appears normal."
        )


    elif risk == "High Traffic Activity":

        st.warning(

            "HIGH TRAFFIC ACTIVITY - "
            "Traffic is unusually intensive, "
            "but there is not enough evidence "
            "to classify it as a security threat."

        )


    elif risk == "Suspicious":

        st.error(

            "SUSPICIOUS - "
            "Strong combined security indicators detected."

        )


    if risk != "Normal":

        st.subheader(
            "Contextual Analysis"
        )


        for reason in reasons:

            st.write(
                f"- {reason}"
            )


# ============================================================
# LIVE DASHBOARD
# ============================================================

def show_live_dashboard():

    engine = (
        st.session_state.engine
    )


    if engine is None:

        st.info(

            "Start monitoring to begin "
            "capturing network traffic."

        )

        return


    # ========================================================
    # ENGINE STATUS
    # ========================================================

    try:

        status = (
            engine.get_status()
        )

    except Exception as e:

        st.error(

            f"Unable to read monitoring status: {e}"

        )

        return


    total_packets = (
        status["total_packets"]
    )

    total_windows = (
        status["total_windows"]
    )

    anomalies = (
        status["anomalies"]
    )


    # ========================================================
    # ANOMALY RATE
    # ========================================================

    if total_windows > 0:

        anomaly_rate = (

            anomalies
            /
            total_windows
            *
            100

        )

    else:

        anomaly_rate = 0


    # ========================================================
    # LIVE METRICS
    # ========================================================

    st.subheader(
        "Live Monitoring"
    )


    col1, col2, col3, col4 = (
        st.columns(4)
    )


    with col1:

        st.metric(
            "Packets Captured",
            total_packets
        )


    with col2:

        st.metric(
            "Traffic Windows",
            total_windows
        )


    with col3:

        st.metric(
            "AI Anomalies",
            anomalies
        )


    with col4:

        st.metric(
            "Anomaly Rate",
            f"{anomaly_rate:.1f}%"
        )


    st.divider()


    # ========================================================
    # MONITORING STATUS
    # ========================================================

    if st.session_state.monitoring:

        st.success(
            "MONITORING ACTIVE"
        )

    else:

        st.warning(
            "MONITORING STOPPED"
        )


    # ========================================================
    # RESULT HISTORY
    # ========================================================

    history = status.get(
        "result_history",
        []
    )


    # ========================================================
    # PROCESS NEW WINDOWS
    # ========================================================

    if history:

        for result in history:

            process_result(

                result,

                history

            )


    # ========================================================
    # LATEST RESULT
    # ========================================================

    latest = (
        status["last_result"]
    )


    if latest is None:

        st.info(
            "Waiting for network traffic..."
        )

        return


    # ========================================================
    # CURRENT ANALYSIS
    # ========================================================

    analysis = analyze_context(

        latest,

        history

    )


    st.session_state.current_analysis = (
        analysis
    )


    # ========================================================
    # LATEST TRAFFIC WINDOW
    # ========================================================

    st.subheader(
        "Latest Traffic Window"
    )


    display_risk(
        analysis
    )


    # ========================================================
    # CURRENT METRICS
    # ========================================================

    col1, col2, col3, col4 = (
        st.columns(4)
    )


    with col1:

        st.metric(
            "Packets",
            latest["packet_count"]
        )


    with col2:

        st.metric(
            "Total Bytes",
            f"{latest['total_bytes']:,}"
        )


    with col3:

        st.metric(
            "Anomaly Score",
            f"{latest['anomaly_score']:.4f}"
        )


    with col4:

        st.metric(
            "Context Risk",
            analysis["risk"]
        )


    # ========================================================
    # TRAFFIC DETAILS
    # ========================================================

    st.subheader(
        "Traffic Details"
    )


    latest_df = pd.DataFrame(
        [latest]
    )


    detail_columns = [

        "time_window",

        "packet_count",

        "total_bytes",

        "average_packet_size",

        "tcp_count",

        "udp_count",

        "unique_destinations",

        "unique_source_ports",

        "unique_destination_ports",

        "anomaly_score",

        "status"

    ]


    available_columns = [

        column

        for column in detail_columns

        if column in latest_df.columns

    ]


    st.dataframe(

        latest_df[
            available_columns
        ],

        width="stretch",

        hide_index=True

    )


# ============================================================
# SECURITY ALERT HISTORY
# ============================================================

def show_alert_history():

    st.divider()


    st.subheader(
        "Security Alert History"
    )


    alerts = (
        st.session_state.alert_history
    )


    if not alerts:

        st.info(

            "No suspicious security events detected."

        )

        return


    alert_df = pd.DataFrame(
        alerts
    )


    st.dataframe(

        alert_df,

        width="stretch",

        hide_index=True

    )


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "Network Tool"
)


# ============================================================
# TEST NOTIFICATION
# ============================================================

if st.sidebar.button(

    "TEST NOTIFICATION",

    width="stretch"

):

    test_notification()


# ============================================================
# START / STOP
# ============================================================

if st.session_state.monitoring:

    if st.sidebar.button(

        "STOP MONITORING",

        width="stretch"

    ):

        stop_monitoring()

        st.rerun()

else:

    if st.sidebar.button(

        "START MONITORING",

        type="primary",

        width="stretch"

    ):

        started = start_monitoring()

        if started:
            st.rerun()


# ============================================================
# CREDITS
# ============================================================

st.sidebar.divider()

st.sidebar.markdown(
    "### 👨‍💻 Developer"
)

st.sidebar.markdown(
    "**Soo6ya**"
)

st.sidebar.markdown(
    "AI Network Anomaly Detection"
)

st.sidebar.markdown(
    "[GitHub](https://github.com/soo6ya)"
)

st.sidebar.caption(
    "Network Tool • AI-based traffic monitoring"
)


# ============================================================
# MAIN DASHBOARD / AUTO REFRESH
# ============================================================

# Native Streamlit fragments replace the third-party
# streamlit-autorefresh component. This keeps the EXE
# self-contained and avoids frontend asset issues.

if st.session_state.monitoring:

    @st.fragment(run_every="1s")
    def live_refresh():

        show_live_dashboard()

        show_alert_history()

    live_refresh()

else:

    show_live_dashboard()

    show_alert_history()

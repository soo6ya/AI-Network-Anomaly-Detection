import time
import pandas as pd
import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = "network_anomaly_model.pkl"
OUTPUT_FILE = "live_ai_results.csv"

CAPTURE_SECONDS = 10


# ============================================================
# FEATURES USED BY THE TRAINED MODEL
# ============================================================

FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "average_packet_size",
    "tcp_count",
    "udp_count",
    "unique_destinations",
    "unique_source_ports",
    "unique_destination_ports",
    "ipv4_count",
    "ipv6_count",
    "packets_per_second",
    "bytes_per_second",
    "tcp_ratio",
    "udp_ratio"
]


# ============================================================
# START
# ============================================================

print("========================================")
print(" AI Network Live Anomaly Monitor")
print("========================================")
print()


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

try:

    saved_model = joblib.load(MODEL_FILE)

    model = saved_model["model"]
    feature_columns = saved_model["features"]

    print("AI model loaded successfully.")

except FileNotFoundError:

    print("ERROR: network_anomaly_model.pkl not found.")
    print("Make sure the trained model exists in this folder.")
    exit()

except Exception as e:

    print("ERROR loading model:")
    print(e)
    exit()


print()


# ============================================================
# PACKET STORAGE
# ============================================================

packets = []


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    # Ignore packets without IPv4/IPv6
    if not (
        packet.haslayer(IP)
        or packet.haslayer(IPv6)
    ):
        return


    # --------------------------------------------------------
    # IP addresses
    # --------------------------------------------------------

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    else:

        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst


    # --------------------------------------------------------
    # Protocol and ports
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:

        protocol = "OTHER"

        source_port = 0
        destination_port = 0


    # --------------------------------------------------------
    # Store packet
    # --------------------------------------------------------

    packets.append({

        "timestamp": time.time(),

        "source_ip": source_ip,

        "destination_ip": destination_ip,

        "protocol": protocol,

        "source_port": source_port,

        "destination_port": destination_port,

        "packet_size": len(packet)

    })


# ============================================================
# LIVE PACKET CAPTURE
# ============================================================

print(
    f"Capturing network traffic for "
    f"{CAPTURE_SECONDS} seconds..."
)

print(
    "Generate some network activity if needed."
)

print()


try:

    sniff(
        prn=packet_callback,
        timeout=CAPTURE_SECONDS,
        store=False
    )

except Exception as e:

    print("ERROR during packet capture:")
    print(e)
    exit()


print(
    f"Packets captured: {len(packets)}"
)


# ============================================================
# CHECK PACKETS
# ============================================================

if not packets:

    print()
    print("No packets captured.")

    print(
        "Check your network connection "
        "or capture permissions."
    )

    exit()


# ============================================================
# CREATE DATAFRAME
# ============================================================

df = pd.DataFrame(packets)


# ============================================================
# CONVERT TIMESTAMP
# ============================================================

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    unit="s"
)


# ============================================================
# CREATE 1-SECOND WINDOWS
# ============================================================

df["time_window"] = (
    df["timestamp"].dt.floor("s")
)


# ============================================================
# FEATURE ENGINEERING
# ============================================================

grouped = df.groupby(
    "time_window"
)


features = grouped.agg(

    packet_count=(
        "packet_size",
        "count"
    ),

    total_bytes=(
        "packet_size",
        "sum"
    ),

    average_packet_size=(
        "packet_size",
        "mean"
    ),

    tcp_count=(
        "protocol",
        lambda x:
        (x == "TCP").sum()
    ),

    udp_count=(
        "protocol",
        lambda x:
        (x == "UDP").sum()
    ),

    unique_destinations=(
        "destination_ip",
        "nunique"
    ),

    unique_source_ports=(
        "source_port",
        "nunique"
    ),

    unique_destination_ports=(
        "destination_port",
        "nunique"
    ),

    ipv4_count=(
        "source_ip",
        lambda x:
        (~x.astype(str)
         .str.contains(":")).sum()
    ),

    ipv6_count=(
        "source_ip",
        lambda x:
        x.astype(str)
        .str.contains(":")
        .sum()
    )

).reset_index()


# ============================================================
# DERIVED FEATURES
# ============================================================

features["packets_per_second"] = (
    features["packet_count"]
)

features["bytes_per_second"] = (
    features["total_bytes"]
)


# TCP ratio

features["tcp_ratio"] = (
    features["tcp_count"]
    /
    features["packet_count"]
)


# UDP ratio

features["udp_ratio"] = (
    features["udp_count"]
    /
    features["packet_count"]
)


# Prevent NaN values

features = features.fillna(0)


# ============================================================
# MACHINE LEARNING PREDICTION
# ============================================================

try:

    X = features[
        feature_columns
    ]

    # Prediction
    features["prediction"] = (
        model.predict(X)
    )

    # Convert prediction to status
    features["status"] = (
        features["prediction"].map({

            1: "Normal",

            -1: "Anomaly"

        })
    )

    # Anomaly score
    features["anomaly_score"] = (
        model.decision_function(X)
    )

except Exception as e:

    print()
    print("ERROR during AI prediction:")
    print(e)
    exit()


# ============================================================
# STATISTICS
# ============================================================

normal_count = (
    features["status"]
    == "Normal"
).sum()


anomaly_count = (
    features["status"]
    == "Anomaly"
).sum()


# ============================================================
# DISPLAY RESULTS
# ============================================================

print()

print("========================================")
print(" AI Detection Results")
print("========================================")

print(
    f"Traffic windows : "
    f"{len(features)}"
)

print(
    f"Normal          : "
    f"{normal_count}"
)

print(
    f"Anomalies       : "
    f"{anomaly_count}"
)


# ============================================================
# DISPLAY TRAFFIC ANALYSIS
# ============================================================

print()

print("Traffic analysis:")


display_columns = [

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


print(
    features[
        display_columns
    ].to_string(index=False)
)


# ============================================================
# SAVE RESULTS
# ============================================================

features.to_csv(
    OUTPUT_FILE,
    index=False
)


print()

print(
    f"Results saved to: "
    f"{OUTPUT_FILE}"
)


# ============================================================
# FINAL STATUS
# ============================================================

print()

if anomaly_count > 0:

    print(
        "WARNING: Anomalous traffic detected!"
    )

else:

    print(
        "Network traffic appears normal."
    )


print()
print("Live analysis completed.")
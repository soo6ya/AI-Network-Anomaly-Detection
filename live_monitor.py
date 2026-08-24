import time
import pandas as pd
from scapy.all import sniff, IP, IPv6, TCP, UDP

OUTPUT_FILE = "live_features.csv"
CAPTURE_TIME = 10

packets = []

print("========================================")
print(" AI Network Live Monitor")
print("========================================")
print(f"Capturing traffic for {CAPTURE_TIME} seconds...")
print()


def packet_callback(packet):
    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    else:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

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

    packets.append({
        "timestamp": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet)
    })


# Start capture
sniff(
    prn=packet_callback,
    timeout=CAPTURE_TIME,
    store=False
)

print()
print(f"Packets captured: {len(packets)}")

if len(packets) == 0:
    print("No packets captured.")
else:

    df = pd.DataFrame(packets)

    df.to_csv(
        "live_capture.csv",
        index=False
    )

    print("Saved: live_capture.csv")

    # ----------------------------------------
    # Feature engineering
    # ----------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    df["time_window"] = df["timestamp"].dt.floor("s")

    grouped = df.groupby("time_window")

    features = grouped.agg(
        packet_count=("packet_size", "count"),
        total_bytes=("packet_size", "sum"),
        average_packet_size=("packet_size", "mean"),
        tcp_count=("protocol",
                   lambda x: (x == "TCP").sum()),
        udp_count=("protocol",
                   lambda x: (x == "UDP").sum()),
        unique_destinations=("destination_ip",
                             "nunique"),
        unique_source_ports=("source_port",
                             "nunique"),
        unique_destination_ports=("destination_port",
                                  "nunique"),
        ipv4_count=("source_ip",
                    lambda x:
                    ~x.astype(str).str.contains(":")
                    .sum()),
        ipv6_count=("source_ip",
                    lambda x:
                    x.astype(str).str.contains(":")
                    .sum())
    ).reset_index()

    features["packets_per_second"] = (
        features["packet_count"]
    )

    features["bytes_per_second"] = (
        features["total_bytes"]
    )

    features["tcp_ratio"] = (
        features["tcp_count"] /
        features["packet_count"]
    )

    features["udp_ratio"] = (
        features["udp_count"] /
        features["packet_count"]
    )

    features = features.fillna(0)

    features.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"Created: {OUTPUT_FILE}"
    )

    print(
        f"Traffic windows: {len(features)}"
    )

    print()
    print("First few feature rows:")
    print(features.head())
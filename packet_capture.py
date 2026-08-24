from scapy.all import sniff, IP, IPv6, TCP, UDP
import csv
import os
from datetime import datetime

# Create captures folder if it doesn't exist
CAPTURE_DIR = "captures"
os.makedirs(CAPTURE_DIR, exist_ok=True)

# Create a unique filename for this capture session
session_time = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = os.path.join(
    CAPTURE_DIR,
    f"traffic_{session_time}.csv"
)

# Create CSV file and write header
with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_size"
    ])


def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_ip = ""
    destination_ip = ""
    protocol = "Other"
    source_port = ""
    destination_port = ""

    # IPv4
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    # IPv6
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    # TCP
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    # UDP
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    packet_size = len(packet)

    row = [
        timestamp,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size
    ]

    with open(OUTPUT_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(row)

    print(
        f"{timestamp} | "
        f"{source_ip} → {destination_ip} | "
        f"{protocol} | "
        f"{source_port} → {destination_port} | "
        f"{packet_size} bytes"
    )


print("========================================")
print(" AI Network Anomaly Detection")
print(" Network Traffic Collector")
print("========================================")
print(f"Saving traffic to: {OUTPUT_FILE}")
print("Press Ctrl+C to stop.")
print()

sniff(prn=process_packet, store=False)
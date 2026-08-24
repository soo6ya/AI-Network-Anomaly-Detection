import os
import time
from datetime import datetime

import pandas as pd
from scapy.all import sniff, IP, IPv6, TCP, UDP


# ============================================================
# CONFIGURATION
# ============================================================

OUTPUT_DIR = "training_captures\\normal_activity"

# Change this if you want a different duration.
DEFAULT_DURATION = 120


# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# PACKET STORAGE
# ============================================================

captured_packets = []


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    # Only collect IP traffic
    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        ip_version = 4

    elif packet.haslayer(IPv6):

        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
        ip_version = 6

    else:

        return


    # --------------------------------------------------------
    # Protocol
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

    captured_packets.append({

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        ),

        "source_ip": source_ip,

        "destination_ip": destination_ip,

        "protocol": protocol,

        "source_port": source_port,

        "destination_port": destination_port,

        "packet_size": len(packet),

        "ip_version": ip_version

    })


# ============================================================
# CAPTURE FUNCTION
# ============================================================

def capture_traffic(duration):

    global captured_packets

    captured_packets = []


    print()
    print("========================================")
    print(" Normal Activity Traffic Capture")
    print("========================================")
    print()

    print(
        f"Capture duration: {duration} seconds"
    )

    print()

    print(
        "Start your NORMAL network activity now."
    )

    print()

    print(
        "Examples:"
    )

    print(
        "- Browse websites"
    )

    print(
        "- Watch YouTube/video"
    )

    print(
        "- Run a speed test"
    )

    print(
        "- Download a normal file"
    )

    print()

    print(
        "Capture starting..."
    )

    print()


    start_time = time.time()


    try:

        sniff(
            prn=packet_callback,
            store=False,
            timeout=duration
        )

    except PermissionError:

        print()
        print(
            "ERROR: Administrator privileges are required."
        )

        return

    except Exception as e:

        print()
        print(
            "Capture error:",
            e
        )

        return


    elapsed = time.time() - start_time


    print()
    print(
        "Capture completed!"
    )

    print(
        f"Time captured: {elapsed:.1f} seconds"
    )

    print(
        f"Packets captured: {len(captured_packets)}"
    )


    # ========================================================
    # SAVE CSV
    # ========================================================

    if not captured_packets:

        print()
        print(
            "No packets were captured."
        )

        return


    df = pd.DataFrame(
        captured_packets
    )


    print()
    print(
        "Choose a name for this capture."
    )

    print(
        "Examples: browsing, streaming, speedtest, download"
    )

    print()


    activity_name = input(
        "Activity name: "
    ).strip()


    if not activity_name:

        activity_name = "normal_activity"


    # Remove unsafe filename characters

    safe_name = "".join(

        character
        for character in activity_name
        if character.isalnum()
        or character in ("_", "-")

    )


    if not safe_name:

        safe_name = "normal_activity"


    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


    filename = (
        f"{safe_name}_{timestamp}.csv"
    )


    output_file = os.path.join(
        OUTPUT_DIR,
        filename
    )


    df.to_csv(
        output_file,
        index=False
    )


    print()
    print(
        "========================================"
    )

    print(
        " Capture Saved"
    )

    print(
        "========================================"
    )

    print()

    print(
        f"Packets: {len(df)}"
    )

    print(
        f"File: {output_file}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print(
        "How many seconds should we capture?"
    )

    print(
        f"Recommended: {DEFAULT_DURATION} seconds"
    )

    print()


    duration_input = input(
        f"Duration [{DEFAULT_DURATION}]: "
    ).strip()


    if duration_input:

        try:

            duration = int(
                duration_input
            )

            if duration <= 0:

                raise ValueError

        except ValueError:

            print(
                "Invalid duration."
            )

            print(
                f"Using default: {DEFAULT_DURATION} seconds"
            )

            duration = DEFAULT_DURATION

    else:

        duration = DEFAULT_DURATION


    capture_traffic(
        duration
    )
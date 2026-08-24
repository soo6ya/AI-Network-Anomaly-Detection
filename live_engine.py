import time
import threading
import pandas as pd
import joblib

from scapy.all import (
    AsyncSniffer,
    IP,
    IPv6,
    TCP,
    UDP,
    get_if_list,
)


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = "network_anomaly_model.pkl"

WINDOW_SECONDS = 1

# Number of processed windows kept in memory.
# This prevents suspicious windows from disappearing
# before the dashboard can read them.
RESULT_HISTORY_LIMIT = 100


# ============================================================
# FEATURE COLUMNS
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
# LIVE NETWORK ENGINE
# ============================================================

class LiveNetworkEngine:

    def __init__(self):

        self.running = False

        self.packet_buffer = []

        self.lock = threading.Lock()

        self.model = None

        self.feature_columns = FEATURE_COLUMNS

        self.total_packets = 0

        self.total_windows = 0

        self.anomaly_count = 0

        # ----------------------------------------------------
        # Latest result
        # ----------------------------------------------------

        self.last_result = None

        # ----------------------------------------------------
        # IMPORTANT:
        # Keep every recent processed window.
        # The dashboard can now see anomalous windows even
        # when a newer normal window arrives.
        # ----------------------------------------------------

        self.result_history = []

        self.result_sequence = 0

        # ----------------------------------------------------
        # Main network sniffer
        # ----------------------------------------------------

        self.sniffer = None

        # ----------------------------------------------------
        # Loopback sniffers
        # ----------------------------------------------------

        self.loopback_sniffers = []

        self.processing_thread = None

        self.loopback_interfaces = []


    # ========================================================
    # LOAD MODEL
    # ========================================================

    def load_model(self):

        saved_model = joblib.load(
            MODEL_FILE
        )

        self.model = saved_model["model"]

        self.feature_columns = saved_model["features"]


    # ========================================================
    # FIND LOOPBACK INTERFACES
    # ========================================================

    def find_loopback_interfaces(self):

        loopbacks = []

        try:

            interfaces = get_if_list()

            for iface in interfaces:

                name = str(iface)

                name_lower = name.lower()

                if (
                    "loopback" in name_lower
                    or
                    (
                        "npcap" in name_lower
                        and
                        "loop" in name_lower
                    )
                ):

                    loopbacks.append(
                        iface
                    )

        except Exception as e:

            print(
                "Unable to enumerate interfaces:",
                e
            )

        return loopbacks


    # ========================================================
    # START MONITORING
    # ========================================================

    def start(self):

        if self.running:

            print(
                "Monitor is already running."
            )

            return


        # ----------------------------------------------------
        # Load AI model
        # ----------------------------------------------------

        self.load_model()


        # ----------------------------------------------------
        # Reset runtime state
        # ----------------------------------------------------

        self.running = True

        self.packet_buffer = []

        self.total_packets = 0

        self.total_windows = 0

        self.anomaly_count = 0

        self.last_result = None

        self.result_history = []

        self.result_sequence = 0

        self.sniffer = None

        self.loopback_sniffers = []


        print(
            "Starting network capture..."
        )


        # ----------------------------------------------------
        # Main network sniffer
        # ----------------------------------------------------

        try:

            self.sniffer = AsyncSniffer(

                prn=self._packet_callback,

                store=False

            )

            self.sniffer.start()

        except Exception as e:

            self.running = False

            print(
                "Main sniffer could not start:",
                e
            )

            raise


        # ----------------------------------------------------
        # Npcap Loopback
        # ----------------------------------------------------

        self.loopback_interfaces = (

            self.find_loopback_interfaces()

        )


        if self.loopback_interfaces:

            print(
                "Loopback interfaces detected:"
            )

            for iface in self.loopback_interfaces:

                print(
                    f" - {iface}"
                )


            for iface in self.loopback_interfaces:

                try:

                    loopback_sniffer = AsyncSniffer(

                        iface=iface,

                        prn=self._packet_callback,

                        store=False

                    )

                    loopback_sniffer.start()

                    self.loopback_sniffers.append(

                        loopback_sniffer

                    )

                    print(
                        f"Loopback capture started: {iface}"
                    )

                except Exception as e:

                    print(
                        f"Loopback capture could not start "
                        f"on {iface}: {e}"
                    )

        else:

            print(
                "WARNING: No Npcap Loopback Adapter "
                "was detected."
            )

            print(
                "127.0.0.1 traffic may not be captured."
            )


        # ----------------------------------------------------
        # Feature-processing thread
        # ----------------------------------------------------

        self.processing_thread = (

            threading.Thread(

                target=self._process_windows,

                daemon=True

            )

        )

        self.processing_thread.start()


        print(
            "Network monitoring started."
        )


    # ========================================================
    # STOP MONITORING
    # ========================================================

    def stop(self):

        if not self.running:

            print(
                "Monitor is already stopped."
            )

            return


        print(
            "Stopping network monitoring..."
        )


        # ----------------------------------------------------
        # Stop accepting new packets
        # ----------------------------------------------------

        self.running = False


        # ----------------------------------------------------
        # Stop main sniffer
        # ----------------------------------------------------

        if self.sniffer is not None:

            try:

                if self.sniffer.running:

                    self.sniffer.stop()

            except Exception as e:

                print(
                    "Main sniffer shutdown warning:",
                    e
                )

            finally:

                self.sniffer = None


        # ----------------------------------------------------
        # Stop loopback sniffers
        # ----------------------------------------------------

        for sniffer in self.loopback_sniffers:

            try:

                if sniffer.running:

                    sniffer.stop()

            except Exception as e:

                print(
                    "Loopback sniffer shutdown warning:",
                    e
                )


        self.loopback_sniffers = []


        # ----------------------------------------------------
        # Process remaining packets
        # ----------------------------------------------------

        self._process_current_window()


        # ----------------------------------------------------
        # Give processing thread time to exit
        # ----------------------------------------------------

        if (

            self.processing_thread is not None

            and

            self.processing_thread.is_alive()

        ):

            self.processing_thread.join(
                timeout=1.5
            )


        self.processing_thread = None


        print(
            "Network monitoring stopped."
        )


    # ========================================================
    # PACKET CALLBACK
    # ========================================================

    def _packet_callback(self, packet):

        if not self.running:

            return


        # ----------------------------------------------------
        # IPv4 / IPv6
        # ----------------------------------------------------

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


        # ----------------------------------------------------
        # Protocol
        # ----------------------------------------------------

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


        # ----------------------------------------------------
        # Store packet
        # ----------------------------------------------------

        packet_data = {

            "timestamp":
                time.time(),

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "protocol":
                protocol,

            "source_port":
                source_port,

            "destination_port":
                destination_port,

            "packet_size":
                len(packet),

            "ip_version":
                ip_version

        }


        with self.lock:

            self.packet_buffer.append(

                packet_data

            )

            self.total_packets += 1


    # ========================================================
    # PROCESS WINDOWS
    # ========================================================

    def _process_windows(self):

        while self.running:

            time.sleep(
                WINDOW_SECONDS
            )

            if self.running:

                self._process_current_window()


    # ========================================================
    # PROCESS CURRENT WINDOW
    # ========================================================

    def _process_current_window(self):

        with self.lock:

            packets = self.packet_buffer

            self.packet_buffer = []


        if not packets:

            return


        df = pd.DataFrame(
            packets
        )


        # ----------------------------------------------------
        # Basic features
        # ----------------------------------------------------

        packet_count = len(df)


        total_bytes = (

            df["packet_size"].sum()

        )


        average_packet_size = (

            df["packet_size"].mean()

        )


        tcp_count = (

            df["protocol"] == "TCP"

        ).sum()


        udp_count = (

            df["protocol"] == "UDP"

        ).sum()


        unique_destinations = (

            df["destination_ip"].nunique()

        )


        unique_source_ports = (

            df["source_port"].nunique()

        )


        unique_destination_ports = (

            df["destination_port"].nunique()

        )


        ipv4_count = (

            df["ip_version"] == 4

        ).sum()


        ipv6_count = (

            df["ip_version"] == 6

        ).sum()


        # ----------------------------------------------------
        # Derived features
        # ----------------------------------------------------

        packets_per_second = packet_count

        bytes_per_second = total_bytes


        if packet_count > 0:

            tcp_ratio = (

                tcp_count
                /
                packet_count

            )

            udp_ratio = (

                udp_count
                /
                packet_count

            )

        else:

            tcp_ratio = 0

            udp_ratio = 0


        # ----------------------------------------------------
        # Feature row
        # ----------------------------------------------------

        features = pd.DataFrame([{

            "packet_count":
                packet_count,

            "total_bytes":
                total_bytes,

            "average_packet_size":
                average_packet_size,

            "tcp_count":
                tcp_count,

            "udp_count":
                udp_count,

            "unique_destinations":
                unique_destinations,

            "unique_source_ports":
                unique_source_ports,

            "unique_destination_ports":
                unique_destination_ports,

            "ipv4_count":
                ipv4_count,

            "ipv6_count":
                ipv6_count,

            "packets_per_second":
                packets_per_second,

            "bytes_per_second":
                bytes_per_second,

            "tcp_ratio":
                tcp_ratio,

            "udp_ratio":
                udp_ratio

        }])


        # ----------------------------------------------------
        # AI prediction
        # ----------------------------------------------------

        X = features[
            self.feature_columns
        ]


        prediction = (

            self.model.predict(X)[0]

        )


        anomaly_score = (

            self.model
            .decision_function(X)[0]

        )


        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        if prediction == -1:

            status = "Anomaly"

            self.anomaly_count += 1

        else:

            status = "Normal"


        self.total_windows += 1


        # ----------------------------------------------------
        # Sequence number
        #
        # Every processed window gets a unique ID.
        # This lets the dashboard know exactly which
        # windows it has already processed.
        # ----------------------------------------------------

        self.result_sequence += 1


        # ----------------------------------------------------
        # Create result
        # ----------------------------------------------------

        result = {

            "_sequence":
                self.result_sequence,

            "time_window":

                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "packet_count":

                int(packet_count),

            "total_bytes":

                int(total_bytes),

            "average_packet_size":

                float(
                    average_packet_size
                ),

            "tcp_count":

                int(tcp_count),

            "udp_count":

                int(udp_count),

            "unique_destinations":

                int(
                    unique_destinations
                ),

            "unique_source_ports":

                int(
                    unique_source_ports
                ),

            "unique_destination_ports":

                int(
                    unique_destination_ports
                ),

            "anomaly_score":

                float(
                    anomaly_score
                ),

            "status":

                status

        }


        # ----------------------------------------------------
        # Store latest result
        # ----------------------------------------------------

        self.last_result = result


        # ----------------------------------------------------
        # IMPORTANT:
        # Store the result permanently in recent history.
        #
        # This fixes the Scenario 3 problem.
        # ----------------------------------------------------

        self.result_history.append(
            result.copy()
        )


        # Keep only recent results.

        if len(
            self.result_history
        ) > RESULT_HISTORY_LIMIT:

            self.result_history = (

                self.result_history[
                    -RESULT_HISTORY_LIMIT:
                ]

            )


        # ----------------------------------------------------
        # Console diagnostic
        # ----------------------------------------------------

        print(
            "Window:",
            result
        )


    # ========================================================
    # GET STATUS
    # ========================================================

    def get_status(self):

        return {

            "running":
                self.running,

            "total_packets":
                self.total_packets,

            "total_windows":
                self.total_windows,

            "anomalies":
                self.anomaly_count,

            "last_result":
                self.last_result,

            # ------------------------------------------------
            # NEW:
            # Dashboard receives all recent windows.
            # ------------------------------------------------

            "result_history":
                list(
                    self.result_history
                )

        }


# ============================================================
# TEST MODE
# ============================================================

if __name__ == "__main__":

    engine = LiveNetworkEngine()


    print(
        "========================================"
    )

    print(
        " AI Continuous Network Monitor"
    )

    print(
        "========================================"
    )

    print()


    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    engine.start()


    try:

        while True:

            time.sleep(2)


            status = (
                engine.get_status()
            )


            print(

                f"Packets: "
                f"{status['total_packets']} | "

                f"Windows: "
                f"{status['total_windows']} | "

                f"Anomalies: "
                f"{status['anomalies']}"

            )


            if status["last_result"]:

                print(
                    status["last_result"]
                )


    except KeyboardInterrupt:

        print()

        engine.stop()

        print()

        print(
            "Monitor stopped successfully."
        )
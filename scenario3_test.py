import socket
import random
import time


print("=" * 60)
print(" NETWORK TOOL - CONTROLLED SECURITY TEST")
print("=" * 60)
print()
print("Target: 127.0.0.1 (THIS COMPUTER ONLY)")
print("Generating high-volume + high-diversity traffic")
print()


TARGET_IP = "127.0.0.1"

# 40 different destination ports
DESTINATION_PORTS = list(
    range(20000, 20040)
)

PACKETS_PER_PORT = 45

PAYLOAD_SIZE = 1400


total_packets = 0
total_bytes = 0


for destination_port in DESTINATION_PORTS:

    for _ in range(PACKETS_PER_PORT):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:

            payload = random.randbytes(
                PAYLOAD_SIZE
            )

            sock.sendto(
                payload,
                (
                    TARGET_IP,
                    destination_port
                )
            )

            total_packets += 1
            total_bytes += len(payload)

        except Exception as e:

            print(
                f"Packet error: {e}"
            )

        finally:

            sock.close()


print()
print("=" * 60)
print(" CONTROLLED TEST COMPLETED")
print("=" * 60)
print()

print(
    f"Packets generated : {total_packets}"
)

print(
    f"Payload bytes     : {total_bytes:,}"
)

print(
    f"Destination ports : {len(DESTINATION_PORTS)}"
)

print()
print("Target was 127.0.0.1 only.")
print("Check Network Tool now.")
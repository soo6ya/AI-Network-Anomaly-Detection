from scapy.all import sniff

print("========================================")
print(" Live Network Capture Test")
print("========================================")
print("Capturing packets for 10 seconds...")
print()

def packet_callback(packet):
    if packet.haslayer("IP") or packet.haslayer("IPv6"):
        print(packet.summary())

sniff(
    prn=packet_callback,
    timeout=10,
    store=False
)

print()
print("Capture completed!")
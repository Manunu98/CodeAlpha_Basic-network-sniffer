from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    # Only process IP packets
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Map protocol numbers to names
        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, str(protocol))

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {src_ip} -> {dst_ip} | Protocol: {proto_name}")

        # Try to show payload if readable
        try:
            payload = bytes(packet[IP].payload)
            if payload:
                print("Payload:", payload[:80].decode(errors="ignore"))  # Show first 80 bytes
        except Exception as e:
            pass

print(" Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=process_packet, store=False)
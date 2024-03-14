from scapy.all import *

# Define enhanced rules and thresholds
PORT_SCAN_THRESHOLD = 5
SQL_INJECTION_SIGNATURES = ["'", "SELECT", "INSERT", "UPDATE", "DELETE"]

def packet_callback(packet):
    # Extract packet information
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        payload = str(packet[TCP].payload)
        
        # Rule: Detect port scans
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            print(f"Potential port scan detected from {src_ip} to {dst_ip} on port {dst_port}")
        
        # Rule: Detect SQL injection attempts
        for signature in SQL_INJECTION_SIGNATURES:
            if signature in payload:
                print(f"Potential SQL injection attempt detected from {src_ip} to {dst_ip}")
                break

# Capture packets and apply the packet_callback function
sniff(filter="tcp", prn=packet_callback, store=0, count=100)

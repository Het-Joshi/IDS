from scapy.all import *
import time

# Define detection rules and thresholds
RULES = {
    "SSH_Brute_Force": {"protocol": "TCP", "src_ports": [22], "dst_ports": [22]},  
    "HTTP_Traffic": {"protocol": "TCP", "src_ports": [80, 443], "dst_ports": [80, 443]},  
}

# Initialize log file
LOG_FILE = "ids_log.txt"
with open(LOG_FILE, "w") as f:
    f.write("")

# Callback function to process captured packets
def packet_callback(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    for rule_name, rule in RULES.items():
        if rule["protocol"] in packet and packet[rule["protocol"]].dport in rule["dst_ports"]:
            if packet[IP].src and packet[IP].dst:
                print(f"{timestamp} - {rule_name} detected from: {packet[IP].src}:{packet[rule['protocol']].sport} to {packet[IP].dst}:{packet[rule['protocol']].dport}")
                log_event(timestamp, rule_name, packet[IP].src, packet[IP].dst, packet[rule['protocol']].sport, packet[rule['protocol']].dport)

# Log event to file
def log_event(timestamp, rule_name, src_ip, dst_ip, src_port, dst_port):
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} - {rule_name} detected from: {src_ip}:{src_port} to {dst_ip}:{dst_port}\n")

# Main function to start packet capture
def start_capture():
    sniff(filter="tcp", prn=packet_callback, store=0, count=0)

# Console interface for interacting with the IDS
def console_interface():
    print("Simple IDS - Press Ctrl+C to exit.")
    print("Detection Rules:")
    for rule_name, rule in RULES.items():
        print(f"- {rule_name}: {rule}")

    try:
        start_capture()
    except KeyboardInterrupt:
        print("\nExiting...")

# Run console interface
if __name__ == "__main__":
    console_interface()

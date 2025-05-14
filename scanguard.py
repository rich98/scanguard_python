from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime, timedelta
import threading

# --------------------------
# Configuration Parameters
# --------------------------

SCAN_THRESHOLD = 10         # Minimum number of distinct destination ports considered a scan
TIME_WINDOW = 10            # Time window (in seconds) to observe port scan activity

# Dictionary to track scan activity
# Key: (source IP, destination IP)
# Value: List of tuples (timestamp, destination port)
scan_data = defaultdict(list)

# --------------------------
# Packet Processing Function
# --------------------------

def detect_scan(pkt):
    """
    Callback function invoked for each captured TCP packet.
    Analyzes SYN packets to detect potential port scans.
    """
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Check for SYN flag only (indicative of new connection attempt)
        if tcp_layer.flags == "S":
            now = datetime.now()
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport

            # Create a tracking key based on source and destination IPs
            key = (src_ip, dst_ip)

            # Record the timestamp and destination port
            scan_data[key].append((now, dst_port))

            # Remove entries that are outside the configured time window
            scan_data[key] = [
                (ts, port) for ts, port in scan_data[key]
                if now - ts < timedelta(seconds=TIME_WINDOW)
            ]

            # Extract unique destination ports scanned in the current window
            ports = set(port for ts, port in scan_data[key])

            # If the number of distinct ports exceeds the threshold, alert
            if len(ports) >= SCAN_THRESHOLD:
                port_list = sorted(ports)
                print(f"[!] Port scan detected from {src_ip} to {dst_ip} on destination ports: {port_list}")
                scan_data[key].clear()  # Clear data to prevent repeated alerts

# --------------------------
# Sniffing Thread Function
# --------------------------

def start_sniffing():
    """
    Initializes packet capture with a TCP filter and uses the detect_scan
    function to inspect each incoming packet.
    """
    print("[*] Monitoring network for port scans...")
    sniff(filter="tcp", prn=detect_scan, store=0)

# --------------------------
# Script Entry Point
# --------------------------

if __name__ == "__main__":
    # Run sniffing in a separate thread to keep the main thread responsive
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

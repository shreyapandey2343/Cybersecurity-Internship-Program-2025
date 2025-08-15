# ----------------------------------------
# Simple Network IDS (Beginner Friendly)
# Detects:
#  1. ICMP pings (echo request & reply)
#  2. TCP SYN attempts (connection starts)
#  3. Port scans (SYN, NULL, FIN scans)
#  4. Suspicious activity (ICMP floods, high-rate SYNs)
# ----------------------------------------

from scapy.all import rdpcap, IP, TCP, ICMP
from collections import defaultdict
import time

# ======== SETTINGS / THRESHOLDS ========
ICMP_FLOOD_LIMIT = 20       # Max pings from same IP before alert
SYN_SCAN_PORT_LIMIT = 10    # Ports contacted before SYN scan alert
TIME_WINDOW = 5             # Seconds to check for high-rate SYNs
HIGH_RATE_SYN_LIMIT = 15    # SYNs in TIME_WINDOW before alert

# ======== TRACKERS ========
icmp_counter = defaultdict(int)     # Count ICMP pings from each IP
syn_ports = defaultdict(set)        # Ports each IP tries to contact
syn_timestamps = defaultdict(list)  # When each IP sends SYN packets

# ======== DETECTION FUNCTIONS ========

def detect_icmp(pkt):
    """Detect ICMP ping requests and replies."""
    if pkt.haslayer(ICMP):
        # Echo request (ping)
        if pkt[ICMP].type == 8:
            icmp_counter[pkt[IP].src] += 1
            print(f"[ICMP] Ping request from {pkt[IP].src} to {pkt[IP].dst}")

            # Alert if too many pings from same IP
            if icmp_counter[pkt[IP].src] > ICMP_FLOOD_LIMIT:
                print(f"[ALERT] ICMP flood suspected from {pkt[IP].src}")

        # Echo reply (ping response)
        elif pkt[ICMP].type == 0:
            print(f"[ICMP] Ping reply from {pkt[IP].src} to {pkt[IP].dst}")

def detect_tcp(pkt):
    """Detect TCP SYN attempts, scans, and suspicious activity."""
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags

        # SYN packet (connection attempt)
        if flags == "S":
            print(f"[TCP] SYN attempt from {pkt[IP].src} to {pkt[IP].dst}:{pkt[TCP].dport}")

            # Track ports contacted by this IP
            syn_ports[pkt[IP].src].add(pkt[TCP].dport)
            if len(syn_ports[pkt[IP].src]) > SYN_SCAN_PORT_LIMIT:
                print(f"[ALERT] Possible SYN scan from {pkt[IP].src}")

            # Track timestamps to detect high-rate SYNs
            now = time.time()
            syn_timestamps[pkt[IP].src].append(now)

            # Keep only recent SYNs in the last TIME_WINDOW seconds
            recent = [t for t in syn_timestamps[pkt[IP].src] if now - t <= TIME_WINDOW]
            syn_timestamps[pkt[IP].src] = recent

            if len(recent) > HIGH_RATE_SYN_LIMIT:
                print(f"[ALERT] High-rate SYNs from {pkt[IP].src}")

        # NULL scan (no TCP flags set)
        elif flags == 0:
            print(f"[ALERT] NULL scan from {pkt[IP].src} to {pkt[IP].dst}:{pkt[TCP].dport}")

        # FIN scan (only FIN flag set)
        elif flags == "F":
            print(f"[ALERT] FIN scan from {pkt[IP].src} to {pkt[IP].dst}:{pkt[TCP].dport}")

# ======== MAIN FUNCTION ========

def main():
    # Ask user for PCAP file path
    pcap_file = input("Enter PCAP file path: ").strip()

    print(f"[*] Reading packets from {pcap_file}...")

    # Try reading the PCAP file
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print("[ERROR] File not found. Please check the path and try again.")
        return

    # Go through each packet and check for ICMP/TCP patterns
    for pkt in packets:
        if pkt.haslayer(IP):
            detect_icmp(pkt)
            detect_tcp(pkt)

    print("\n[+] Analysis complete.")

# ======== RUN SCRIPT ========
if __name__ == "__main__":
    main()

from collections import defaultdict
import time

# Thresholds for detecting suspicious activity
MAX_PACKETS_PER_IP = 100  # Threshold for DDoS-like behavior
MAX_PORTS_PER_IP = 50     # Threshold for port scanning

# Data structure to keep track of IP activity
ip_activity = defaultdict(lambda: {"ports": set(), "packet_count": 0, "last_seen": time.time()})

def detect_suspicious_activity():
    """Analyze stored packet data and detect any suspicious activity."""
    print("\n=== Suspicious Activity Report ===")
    current_time = time.time()
    
    for ip, activity in ip_activity.items():
        ports_scanned = len(activity["ports"])
        packet_count = activity["packet_count"]
        time_since_last_seen = current_time - activity["last_seen"]

        # Detect potential port scanning
        if ports_scanned > MAX_PORTS_PER_IP:
            print(f"Suspicious: {ip} might be performing a port scan (scanned {ports_scanned} ports).")

        # Detect potential DDoS behavior
        if packet_count > MAX_PACKETS_PER_IP and time_since_last_seen < 60:
            print(f"Suspicious: {ip} might be involved in a DDoS attack (sent {packet_count} packets).")

def track_ip_activity(packet):
    """Track IP activity from packets for detecting suspicious behavior."""
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        if packet.haslayer('TCP'):
            port = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            port = packet['UDP'].dport
        else:
            port = None
        
        # Update activity for the source IP
        ip_activity[ip_src]["packet_count"] += 1
        ip_activity[ip_src]["last_seen"] = time.time()
        if port:
            ip_activity[ip_src]["ports"].add(port)

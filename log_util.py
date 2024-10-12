import csv
from scapy.all import IP, TCP, UDP

LOG_FILE = "network_traffic_log.csv"

# Create the log file with headers if it doesn't exist
def initialize_log():
    with open(LOG_FILE, mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])

def log_packet(packet):
    """Log packet details to a CSV file."""
    with open(LOG_FILE, mode='a') as file:
        writer = csv.writer(file)
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                protocol = "Other"
                src_port = "N/A"
                dst_port = "N/A"
                
            writer.writerow([ip_src, ip_dst, protocol, src_port, dst_port])

# Initialize log file on import
initialize_log()

from scapy.all import IP, TCP, UDP, ICMP

def analyze_packet(packet):
    """Analyze and display key details about a packet."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")
        
        if TCP in packet:
            print(f"TCP Segment: Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Datagram: Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"ICMP Packet: Type: {packet[ICMP].type}")
        else:
            print("Other packet type")

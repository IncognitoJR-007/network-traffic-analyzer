from scapy.all import sniff

def capture_live_packets(interface, packet_handler, protocol_counter):
    """Capture live packets on the specified interface and call packet_handler for each packet."""
    sniff(iface=interface, prn=lambda packet: packet_handler(packet, protocol_counter), stop_filter=lambda x: stop_capture)

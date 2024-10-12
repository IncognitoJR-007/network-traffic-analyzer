from packet_capture import capture_live_packets
from packet_analysis import analyze_packet
from suspicious_activity import detect_suspicious_activity
from plot_util import update_plot
from log_util import log_packet

import threading

# Global flag to stop packet capturing
stop_capture = False

def packet_handler(packet, protocol_counter):
    analyze_packet(packet)
    log_packet(packet)
    update_plot(packet, protocol_counter)
    
def main():
    global stop_capture
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    
    print(f"Starting packet capture on {interface} (press Ctrl+C to stop)...")
    
    # Dictionary to count different protocols
    protocol_counter = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    
    # Run the packet capture in a separate thread
    capture_thread = threading.Thread(target=capture_live_packets, args=(interface, packet_handler, protocol_counter))
    capture_thread.start()
    
    try:
        while True:
            pass  # Keep the main thread alive to allow real-time graph updates
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        stop_capture = True
        capture_thread.join()

        # Detect suspicious activity
        detect_suspicious_activity()

if __name__ == "__main__":
    main()

import matplotlib.pyplot as plt
from scapy.all import TCP, UDP, ICMP

# Set up the real-time plot
plt.ion()
fig, ax = plt.subplots()
protocols = ["TCP", "UDP", "ICMP", "Other"]
protocol_count = [0, 0, 0, 0]
bars = ax.bar(protocols, protocol_count)

def update_plot(packet, protocol_counter):
    """Update the real-time plot with the latest packet's protocol."""
    if TCP in packet:
        protocol_counter["TCP"] += 1
    elif UDP in packet:
        protocol_counter["UDP"] += 1
    elif ICMP in packet:
        protocol_counter["ICMP"] += 1
    else:
        protocol_counter["Other"] += 1
    
    # Update the count and redraw the plot
    protocol_count[0] = protocol_counter["TCP"]
    protocol_count[1] = protocol_counter["UDP"]
    protocol_count[2] = protocol_counter["ICMP"]
    protocol_count[3] = protocol_counter["Other"]
    
    for i, bar in enumerate(bars):
        bar.set_height(protocol_count[i])
    
    plt.pause(0.1)

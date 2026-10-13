
from scapy.all import rdpcap, IP, TCP, UDP

# Read the PCAP file
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

# Set up counters and dictionaries
tcp_count = 0
udp_count = 0
packet_times = {}
suspicious_ips = []

# Sort packets by timestamp
packets = sorted(packets, key=lambda pkt: float(pkt.time))

# Go through all packets
for pkt in packets:

    # Only check IPv4 TCP or UDP packets
    if IP in pkt:

        if TCP in pkt:
            tcp_count = tcp_count + 1

        elif UDP in pkt:
            udp_count = udp_count + 1

        else:
            continue

        # Get the source IP and timestamp
        source_ip = pkt[IP].src
        timestamp = float(pkt.time)

        # Create a list for each source IP
        if source_ip not in packet_times:
            packet_times[source_ip] = []

        # Remove timestamps older than 5 seconds
        recent_times = []

        for t in packet_times[source_ip]:
            if timestamp - t <= 5:
                recent_times.append(t)

        # Add the current packet timestamp
        recent_times.append(timestamp)
        packet_times[source_ip] = recent_times

        # Check if the source has more than 20 packets
        if len(recent_times) > 20:

            # Only alert once for each IP
            if source_ip not in suspicious_ips:
                print("ALERT: Suspicious traffic from", source_ip)
                print("More than 20 packets within 5 seconds")

                suspicious_ips.append(source_ip)

# Print the final summary
print("\n--- IDS Summary ---")
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)
print("Number of suspicious IPs:", len(suspicious_ips))

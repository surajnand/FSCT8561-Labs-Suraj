
from scapy.all import rdpcap, IP, TCP, UDP

# Read the PCAP file
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

# Set up counters
tcp_count = 0
udp_count = 0
shown = 0

# Go through all packets
for pkt in packets:

    if TCP in pkt:
        tcp_count = tcp_count + 1

    if UDP in pkt:
        udp_count = udp_count + 1

    # Only display IPv4 TCP or UDP packets
    if IP in pkt:

        if TCP in pkt:
            if shown < 20:
                print("Source:", pkt[IP].src,
                      "Destination:", pkt[IP].dst,
                      "Protocol: TCP",
                      "Source port:", pkt[TCP].sport,
                      "Destination port:", pkt[TCP].dport)
                shown = shown + 1

        elif UDP in pkt:
            if shown < 20:
                print("Source:", pkt[IP].src,
                      "Destination:", pkt[IP].dst,
                      "Protocol: UDP",
                      "Source port:", pkt[UDP].sport,
                      "Destination port:", pkt[UDP].dport)
                shown = shown + 1

# Print the summary
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)

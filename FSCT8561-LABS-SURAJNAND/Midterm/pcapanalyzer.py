
from pathlib import Path
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

PCAP_FILE = (
    Path(__file__).resolve().parent
    / "FSCT8561_Operation_Sentinel_Traffic.pcap"
)


def analyze_pcap():
    if not PCAP_FILE.is_file():
        raise FileNotFoundError("PCAP file not found")

    packets = rdpcap(str(PCAP_FILE))

    protocol_counts = Counter()
    source_ips = Counter()
    destination_ports = Counter()
    tcp_syn_attempts = {}

    for packet in packets:
        if IP not in packet:
            protocol_counts["Other"] += 1
            continue

        source_ip = packet[IP].src
        source_ips[source_ip] += 1

        if TCP in packet:
            protocol_counts["TCP"] += 1
            destination_ports[packet[TCP].dport] += 1

            # Count initial TCP SYN packets without ACK
            flags = int(packet[TCP].flags)

            if flags & 0x02 and not flags & 0x10:
                if source_ip not in tcp_syn_attempts:
                    tcp_syn_attempts[source_ip] = set()

                tcp_syn_attempts[source_ip].add(
                    (packet[IP].dst, packet[TCP].dport)
                )

        elif UDP in packet:
            protocol_counts["UDP"] += 1
            destination_ports[packet[UDP].dport] += 1

        elif ICMP in packet:
            protocol_counts["ICMP"] += 1

        else:
            protocol_counts["Other"] += 1

    suspicious_sources = []

    for source_ip, targets in tcp_syn_attempts.items():
        if len(targets) >= 10:
            suspicious_sources.append({
                "source_ip": source_ip,
                "unique_destinations": len(targets),
                "reason": "Possible TCP port scanning"
            })

    return {
        "total_packets": len(packets),
        "protocol_counts": dict(protocol_counts),
        "top_source_ips": source_ips.most_common(5),
        "top_destination_ports": destination_ports.most_common(5),
        "suspicious_sources": suspicious_sources
    }


if __name__ == "__main__":
    import json

    try:
        results = analyze_pcap()
        print(json.dumps(results, indent=4))

    except (OSError, ValueError) as error:
        print("PCAP analysis failed:", error)

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime

#add packet calling function
def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S:%f")[:-3]

    if ARP in packet:
        print(f"[{timestamp}] ARP | "
              f"{packet[ARP].psrc} -> {packet[ARP].pdst}")

    elif IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)

        if TCP in packet:
            proto = "TCP"
            ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"

        elif UDP in packet:
            proto = "UDP"
            ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"

        elif ICMP in packet:
            proto = "ICMP"
            ports = "-"

        else:
            proto = f"IP/{protocol}"
            ports = "-"

        print(
            f"[{timestamp}] {proto:<8} "
            f"{src:<16} -> {dst:<16} "
            f"Ports: {ports:<12} "
            f"Length: {length}"
        )


print("=" * 80)
print("             PYTHON NETWORK SNIFFER")
print("=" * 80)
print("Capturing packets... Press CTRL+C to stop.\n")

try:
    sniff(prn=packet_callback, store=False)

except KeyboardInterrupt:
    print("\n\nSniffer stopped.")
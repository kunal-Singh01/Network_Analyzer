from scapy.all import sniff, IP, TCP, ARP
from logger import log_anomaly

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Example of detecting a SYN flood attack
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            log_anomaly(src_ip, dst_ip, "SYN flood attempt", f"SYN packet to {dst_ip}")
        
        # Example of detecting ARP spoofing
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            log_anomaly(src_ip, dst_ip, "ARP spoofing", f"ARP reply from {src_ip}")

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}")
    sniff(iface=interface, prn=analyze_packet, store=0)

if __name__ == "__main__":
    interface = "eth0"  # Replace with your network interface
    start_sniffing(interface)

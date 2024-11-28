import scapy.all as scapy
import sqlite3
from collections import defaultdict
import time
# Create or connect to the SQLite database
conn = sqlite3.connect('sniffed_packets.db')
cursor = conn.cursor()

# Create a table to store sniffed packet information (if it doesn't exist)
cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol INTEGER,
                    payload TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

# Dictionary to store traffic data for protocol analysis
traffic_data = defaultdict(int)

# Time interval for periodic reports (in seconds)
REPORT_INTERVAL = 10

# Track the last report time
last_report_time = time.time()

# Function to analyze and print HTTP and DNS traffic
def analyze_protocol(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Print packet info
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Analyze HTTP Traffic (Look for HTTP Requests)
        payload = None
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                decoded_payload = payload.decode('utf-8', 'ignore')
                if "HTTP" in decoded_payload:
                    print(f"HTTP Payload (first 50 characters): {decoded_payload[:50]}")
            except (UnicodeDecodeError, IndexError):
                pass  # Handle non-decodable payloads

        # Analyze DNS Queries (Port 53)
        if packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport == 53:
            print(f"DNS Query: {packet[scapy.IP].src} is querying {packet[scapy.IP].dst}")

        # Store packet data in the database
        store_packet_data(src_ip, dst_ip, protocol, payload)

    # Count traffic by protocol (for logging purposes)
    traffic_data[protocol] += 1
    if protocol == 6:  # TCP
        traffic_data['TCP'] += 1
    elif protocol == 17:  # UDP
        traffic_data['UDP'] += 1

# Function to store sniffed packet data in the SQLite database
def store_packet_data(src_ip, dst_ip, protocol, payload):
    # Insert packet data into the database
    cursor.execute('''INSERT INTO packets (src_ip, dst_ip, protocol, payload)
                      VALUES (?, ?, ?, ?)''', (src_ip, dst_ip, protocol, payload))
    conn.commit()

# Function to generate real-time statistical insights
def generate_report():
    global last_report_time
    current_time = time.time()

    # Generate a report every REPORT_INTERVAL seconds
    if current_time - last_report_time >= REPORT_INTERVAL:
        print("\n--- Real-Time Traffic Report ---")
        print(f"Total Packets Captured: {sum(traffic_data.values())}")

        # Print traffic data by protocol
        for protocol, count in traffic_data.items():
            if protocol != 'TCP' and protocol != 'UDP':  # Ignore these counters
                protocol_name = scapy.conf.l3types.get(protocol, str(protocol))
                print(f"Protocol {protocol_name}: {count} packets")

        # Detect anomalies: high volume of a specific protocol
        if traffic_data['UDP'] > 100:
            print("ALERT: Unusually high number of UDP packets detected!")

        if traffic_data['TCP'] > 100:
            print("ALERT: Unusually high number of TCP packets detected!")

        # Reset traffic data for next reporting period
        traffic_data.clear()
        last_report_time = current_time

# Function to handle packet callback with additional features
def packet_callback(packet):
    # Filter packets: You can customize the filter here
    if packet.haslayer(scapy.IP):
        # Analyze the protocol and log the traffic
        analyze_protocol(packet)

        # Generate a real-time report every REPORT_INTERVAL seconds
        generate_report()

# Function to start sniffing with a filter for specific protocols or ports (e.g., TCP/UDP traffic on port 80)
def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback, filter="ip", count=0)  # filter can be adjusted (e.g., "tcp", "udp", "port 80")

# Start the sniffing process
start_sniffing()

# Close the database connection when done
conn.close()

######################Packet Sniffing and Protocol Analysis#######################

This project is a Python-based packet sniffing tool built using the scapy library. It analyzes network traffic in real time, focusing on HTTP and DNS protocols, logs packet data into an SQLite database, and provides periodic statistical insights.

**Features**
1)Real-Time Packet Capture
--Captures packets over IP protocols.
--Analyzes HTTP and DNS traffic.

2)Packet Analysis
--Displays source/destination IPs and protocols for captured packets.
--Decodes and displays HTTP payloads.
--Identifies DNS queries.

3)SQLite Logging
--Stores captured packet details in an SQLite database for persistence.

4)Real-Time Traffic Reporting
--Provides periodic traffic insights.
--Detects anomalies, such as high-volume TCP/UDP traffic.


######Installation#######

**Prerequisites**

1)Python 3.x
2)Required Python libraries:
   --Scapy for packet sniffing.
   --SQLite3 (default in Python) for database management.
   
**Steps**

1)Clone the repository:

-- git clone https://github.com/kunal-Singh01/Network_Analyzer.git

-- cd Network_Analyzer

2)Install dependencies:

pip install scapy


**Usage**

1)Run the tool with superuser privileges (required for network sniffing):

sudo python sniffing_tool.py

2)The program will:

--Capture and display details of live packets.
--Log packets in the sniffed_packets.db database.
--Print periodic traffic reports every 10 seconds.
--Customize the sniffing filter by modifying the filter argument in the scapy.sniff call (e.g., "tcp port 80" for HTTP traffic).

**Real-Time Reporting**

--Traffic Insights: Displays total packets captured and counts per protocol.
--Anomaly Detection:
   --Alerts for high TCP/UDP traffic volumes.


**Customization**

--Filter Protocols/Ports:
   --Update the filter argument in scapy.sniff to target specific protocols or ports (e.g., "tcp and port 443" for HTTPS traffic).

--Report Interval:
   --Modify REPORT_INTERVAL (default: 10 seconds) to adjust the reporting frequency.

**Disclaimer**

This tool is for educational purposes only. Unauthorized use of packet sniffing tools may violate laws or regulations in your jurisdiction. Always ensure proper permissions before monitoring network traffic.

**License**

This project is licensed under the MIT License. See the LICENSE file for details.

**Contributing**

1)Fork the repository.
2)Create a new branch (feature/new-feature).
3)Commit changes and open a pull request.


**Example Output**
Console Output:

Source IP: 192.168.1.5 | Destination IP: 192.168.1.1 | Protocol: 6
HTTP Payload (first 50 characters): GET /index.html HTTP/1.1
DNS Query: 192.168.1.5 is querying 8.8.8.8

--- Real-Time Traffic Report ---
Total Packets Captured: 50
Protocol TCP: 30 packets
Protocol UDP: 20 packets
ALERT: Unusually high number of UDP packets detected!.



**Author**
Kunal Singh


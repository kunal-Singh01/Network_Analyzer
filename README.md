# Network_Analyzer

# MITM and Packet Sniffing Attacks: Impact, Analysis, and Countermeasure

## Project Overview

This project focuses on Man-in-the-Middle (MITM) and packet sniffing attacks, examining their **impact**, **detection methods**, and potential **countermeasures**. Packet sniffing, also known as *Network Analysis*, is an essential area in computer security, providing insight into network traffic by monitoring all outgoing and incoming data packets on a specific network. The project involves using a network analyzer tool to conduct surveillance on network packets under appropriate authorization.

## Objective

Our primary goal is to analyze internet traffic to understand the patterns, identify vulnerabilities, and implement effective countermeasures for packet sniffing attacks. With the necessary permissions from the university, we aim to assess a specific network ethically and responsibly.

## Project Features

- **Real-time Packet Monitoring**: Captures all packets traveling through the network, monitoring source and destination details.
- **Traffic Analysis**: Analyzes protocol types (e.g., TCP, UDP) and highlights any unusual or suspicious activity.
- **Report Generation**: Generates detailed reports based on traffic patterns, including potential MITM attacks.
- **Countermeasure Implementation**: Suggests or implements measures to protect against sniffing attacks, such as secure protocols or encryption.
- **Permission-based Operation**: Ensures ethical use of the network analyzer by requiring authorization for deployment.

## Technologies Used

- **Python**: For scripting packet capture and analysis.
- **Scapy**: To perform packet manipulation and network traffic analysis.
- **Matplotlib**: To visualize network traffic and trends.

## Installation Guide

1. **Install Dependencies**:
   - Python 3.x
   - Scapy
   - Matplotlib

   ```bash
   pip install scapy matplotlib
   ```

2. **Run the Analyzer**:
   ```bash
   python packet_analyzer.py
   ```

   Ensure you have the necessary permissions from network administrators before initiating traffic monitoring.

## Usage

- **Basic Packet Capture**: The analyzer captures all packets and logs relevant details to the console or a file.
- **Custom Filtering**: Specify protocols, IP addresses, or ports for a targeted analysis.
- **Report Submission**: After completing the analysis, submit your report to your supervising faculty members as per the university guidelines.

## Code Structure

- `packet_analyzer.py`: Main script to capture and analyze network packets.
- `report_generator.py`: Module for generating analysis reports and logging data.
- `visualization.py`: Module to visualize traffic patterns and trends.
  
## Example Output

Below are some sample outputs to help understand the expected results:

- **Traffic Summary**: Overview of the protocols and packet counts.
- **Potential Attacks Detected**: List of flagged activities suggesting a MITM attack.

## Contribution Guidelines

Contributions are welcome! Please fork the repository, make improvements, and submit a pull request. Feel free to open issues for bug reports, feature requests, or discussions.

## License

This project is licensed under the MIT License. Ensure that you comply with ethical and legal guidelines when using this tool on any network.

## Future Enhancements

- Add support for additional protocols.
- Enhance detection algorithms for MITM attacks.
- Integrate real-time alerting for suspicious activity.

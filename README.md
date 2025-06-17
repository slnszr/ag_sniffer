HEAD
# ag_sniffer

A simple Python network sniffer that captures web traffic (TCP port 80) and logs source and destination IP addresses and ports into a CSV file.

## Features

- Captures TCP packets on port 80 (HTTP traffic)
- Logs source IP, destination IP, source port, and destination port
- Saves logged data into `trafik_log.csv`

## Usage

Run the script with Python (requires `scapy` library):

```bash
python3 sniffer.py
=======
# Network Packet Sniffer

A simple Python-based TCP packet sniffer that logs traffic information and visualizes packet size distribution using Pandas and Matplotlib.

## Features

- Captures TCP packets using Scapy
- Logs source/destination IPs and ports to `trafik_log.csv`
- Visualizes packet size distribution with a histogram

## Requirements

- Python 3.x
- scapy
- pandas
- matplotlib

Install dependencies:
```bash
pip install scapy pandas matplotlib
7e77d12 (Initial commit with sniffer script)

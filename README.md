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

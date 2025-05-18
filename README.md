# Network Canary Monitor

## Overview

Network Canary Monitor is a Python-based tool designed to detect, log, and analyze **suspicious TCP connections** from local networks to specific ports (**9000-9010**). The system monitors traffic, logs suspicious activity, and reconstructs TCP streams for offline analysis.

## Features

- **Connection Monitoring** – Detects outbound TCP connections from local networks to designated ports.
- **Dual Logging** – Saves alerts in both **human-readable log files** and **structured JSON logs** for easy processing.
- **Stream Reassembly** – Reconstructs full TCP streams using sequence numbers for a complete analysis.
- **Payload Analysis** – Extracts and examines transmitted data, truncating large messages and computing **MD5 hashes**.
- **Interactive Interface Selection** – Allows users to select network interfaces dynamically for accurate sniffing.
- **Test Environment** – Includes a sample `client.py` and `server.py` for traffic simulation.

## Installation

To set up Network Canary Monitor, follow these steps:

1. **Clone the repository**
   ```bash
   git clone https://github.com/nabeeh779/The-Eavesdropping-Canary/tree/developx
   ```

2. **Install dependencies**
   ```bash
   pip install scapy netaddr
   ```

3. **Ensure you run with administrative privileges** for packet sniffing.

## Usage

Run the monitor with:
```bash
python run.py
```

1. You’ll be prompted to **select a network interface** for sniffing.
2. The monitor will **log suspicious connections** as they occur.
3. Logs are saved in:
   - `canary_alerts.log` (human-readable alerts)
   - `canary_alerts.json` (structured JSON for parsing)
   - `reassembled_streams.log` (complete TCP streams)

### Running the Test Environment

To simulate network activity, run **client and server scripts** inside the `server_client_test/` folder.

1. Start the **server** to listen for incoming connections:
   ```bash
   python server_client_test/server.py
   ```
2. Run the **client** to generate and send random data:
   ```bash
   python server_client_test/client.py
   ```

Network Canary Monitor will detect connections and log activity.

## How Suspicious Connections Are Identified

A TCP connection is flagged as **suspicious** if:
- It **originates** from a **local network**.
- It **targets TCP ports 9000-9010**.
- It contains **SYN, ACK, or transmitted payloads**.

## Logging Details

For each flagged connection, the system logs:
- **Source & Destination (IP:Port)**
- **Sequence Numbers** (Ordered for stream reassembly)
- **Timestamps** (Exact time of packet capture)
- **Payload Samples** (Truncated for readability, up to **500 chars**)
- **MD5 Hashes** (Ensuring full-stream integrity)

## Stream Reassembly

Once packets are logged, the tool reconstructs entire TCP conversations **offline** by sorting data based on sequence numbers.

## Requirements

- Python **3.6+**
- Scapy (Packet sniffing)
- netaddr (IP validation)
- Root/Admin privileges (Required for capturing network traffic)

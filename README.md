# Network Canary Monitor

A Python tool designed to detect, log, and analyze suspicious TCP connections from local networks to specific ports (9000-9010). 

## Features

- **Connection Monitoring:** Detects outgoing TCP connections from local networks to designated ports.
- **Dual Logging:** Keeps both human-readable and structured JSON logs for better analysis.
- **Stream Reassembly:** Sorts and reconstructs TCP streams to get a full picture of transmitted data.
- **Payload Analysis:** Extracts and examines payloads, truncating large messages while computing MD5 hashes for integrity checks.
- **Interactive Interface Selection:** Allows users to choose a network interface dynamically for accurate sniffing.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install scapy netaddr
   ```

## How to Use

Run the tool with:
```bash
python canary_monitor.py
```

What to expect:
1. You'll be prompted to select a network interface.
2. The tool will begin monitoring for suspicious connections.
3. Logs will be saved in:
   - `canary_alerts.log` (human-readable)
   - `canary_alerts.json` (structured for easier processing)
   - `reassembled_streams.log` (complete network conversations)

## How Suspicious Connections Are Identified

A connection is flagged if:
- It originates from a local network.
- It targets TCP ports 9000-9010.
- It contains SYN, ACK, or transmitted payloads.

## Logging Details

For each flagged connection, the tool logs:
- Source and destination IP addresses with ports.
- Sequence numbers to help reconstruct conversations.
- Exact timestamps for when packets were captured.
- Payload samples, truncated to 500 characters for readability.
- MD5 hashes of complete streams to ensure integrity.

## Stream Reassembly

Once packets are logged, the tool can reconstruct entire TCP conversations by sorting data based on sequence numbers. This allows for offline analysis rather than real-time packet inspection.

## Requirements

- Python 3.6 or newer
- Scapy for packet capture
- netaddr for IP/network validation
- Root or admin privileges for sniffing network traffic

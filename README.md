# Python Raw Socket Packet Sniffer

## Description
This project demonstrates a **simple Python-based raw socket packet sniffer** that captures and parses **IPv4 network traffic** in real time.

It manually decodes network packets without relying on high-level libraries, providing hands-on insight into **low-level network protocols**, packet structures, and traffic analysis. 

---

## Features

- Captures **raw IPv4 packets** using Python sockets
- Supports **ICMP, TCP, UDP, and DNS** traffic analysis
- Displays detailed packet information:
  - IP addresses, TTL, and protocol
  - TCP flags and sequence numbers
  - UDP ports and payload size
  - DNS query and response metadata
- Demonstrates low-level networking and packet inspection concepts

---

## Architecture

1. **Local Host / Client**
   - Generates network traffic (e.g., ping, browser requests).

2. **Raw Socket Sniffer (Python)**
   - Captures IPv4 packets using raw sockets (`AF_INET`, `SOCK_RAW`)
   - Parses the IPv4 header to identify protocol type
   - Routes packets to protocol-specific parsers:
     - ICMP
     - TCP
     - UDP
   - Performs DNS parsing for UDP traffic on port 53/5353

3. **Console Output**
   - Displays parsed packet information in real time for analysis

---

## Segments

- **IPv4 Packet Parser**
  - Extracts IP version, header length, TTL, protocol, source IP, and destination IP.

- **ICMP Parser**
  - Decodes ICMP packets including type, code, checksum, and payload.

- **TCP Parser**
  - Extracts source/destination ports, sequence and acknowledgment numbers.
  - Parses TCP flags (URG, ACK, PSH, RST, SYN, FIN).

- **UDP Parser**
  - Extracts source/destination ports, packet length, and payload data.

- **DNS Parser**
  - Parses DNS headers for UDP traffic on port 53 or 5353.
  - Extracts transaction ID, flags, question count, and answer records.
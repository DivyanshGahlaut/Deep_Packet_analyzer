# FlowSentry: Deep Packet Inspection & Traffic Filter

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the C++ code.

---

## Table of Contents
1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (FlowSentry Version)](#5-the-journey-of-a-packet-flowsentry-version)
6. [Deep Dive: Each Component](#6-deep-dive-each-component)
7. [How SNI & SSH Extraction Works](#7-how-sni--ssh-extraction-works)
8. [How Traffic Filtering Works](#8-how-traffic-filtering-works)
9. [Building and Running](#9-building-and-running)
10. [Understanding the Output & JSON Exporter](#10-understanding-the-output--json-exporter)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware, intrusion attempts, or unauthorized SSH tunnels

### What FlowSentry Does:
```
User Traffic (PCAP) ➔ [FlowSentry Engine] ➔ Filtered Traffic (PCAP)
                            │
                            ├─ Identifies apps (YouTube, Facebook, SSH, etc.)
                            ├─ Blocks based on source IP, app, or domain rules
                            ├─ Generates detailed reports
                            └─ Exports JSON reports for dashboard integrations
```

---

## 2. Networking Background

### The Network Stack (Layers)
When you visit a website or connect to a server, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS (SNI), DNS, SSH     │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure
Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The FlowKey (Five-Tuple)
A **connection** (or "flow") is uniquely identified by 5 values, grouped in a `FlowKey`:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | `192.168.1.100` | Who is sending |
| Destination IP | `172.217.14.206` | Where it's going |
| Source Port | `54321` | Sender's application identifier |
| Destination Port | `443` | Service being accessed (443 = HTTPS, 22 = SSH) |
| Protocol | `6` (TCP) | TCP or UDP |

**Why is this important?** 
- All packets with the same `FlowKey` belong to the same connection.
- If we block one packet of a connection, we must block all subsequent packets in that same flow.
- This is how we "track" conversations statefully.

### What is SNI?
**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:
1. Your browser sends a "Client Hello" message.
2. This message includes the domain name in **plaintext** (not encrypted yet!).
3. The server uses this to know which certificate to send.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Session ID
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ➔ FlowSentry extracts this!
```

---

## 3. Project Overview

FlowSentry acts as a deep packet filter. It ingests an input `.pcap` capture file, reconstructs flows, classifies them, drops packets matching block rules, and writes a filtered `.pcap` capture along with stats reports.

```
┌─────────────┐     ┌──────────────────────┐     ┌─────────────┐
│ Wireshark   │     │  FlowSentry Engine   │     │ Output      │
│ Capture     │ ──► │                      │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse Headers      │     │ (filtered)  │
└─────────────┘     │ - Classify (SNI/SSH) │     └─────────────┘
                    │ - Block Traffic      │
                    │ - Export JSON Report │
                    └──────────────────────┘
```

---

## 4. File Structure

```
FlowSentry/
├── include/                   # Header files
│   ├── sentry_types.h         # FlowKey, AppType, and connection states
│   ├── sentry_pcap_reader.h   # Binary PCAP file reader interface
│   ├── sentry_packet_parser.h # Ethernet/IP/TCP/UDP header parsing
│   ├── sentry_sni_extractor.h # Protocol Inspectors (TLS, HTTP, DNS, QUIC)
│   ├── sentry_rule_manager.h  # Traffic blocking configuration
│   ├── platform.h             # Cross-platform network byte order adapters
│   └── sentry_optional_compat.h # Compiler optional compatibility shims
│
├── src/                       # Implementations
│   ├── sentry_types.cpp       
│   ├── sentry_pcap_reader.cpp 
│   ├── sentry_packet_parser.cpp 
│   ├── sentry_sni_extractor.cpp 
│   ├── sentry_main.cpp             # Target: Detailed packet detail viewer
│   ├── sentry_engine_simple.cpp    # Target: Simple DPI engine with blocking/JSON output
│   └── sentry_inspector_simple.cpp # Target: Quick SNI list extractor
│
├── CMakeLists.txt             # CMake configuration
├── generate_test_pcap.py      # Python test PCAP capture generator
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (FlowSentry Version)

Here is how a packet flows through the main loop of the filter engine (`sentry_engine_simple.cpp`):

### Step 1: Read PCAP File
We open the capture using our `CaptureReader`:
```cpp
CaptureReader reader;
reader.open("capture.pcap");
```
- Open the file in binary mode.
- Read and validate the 24-byte PCAP global header.
- Detect endianness and configure byte swapping if needed.

### Step 2: Read Each Packet
```cpp
SentryRawPacket raw;
while (reader.readNextPacket(raw)) {
    // raw.data contains the bytes
    // raw.header contains timestamp and length
}
```

### Step 3: Parse Protocol Headers
We parse the packet layers:
```cpp
LayerParser::parse(raw, parsed);
```
Extracts MAC addresses, IP version, source and destination IPs, protocol type, TCP flags, sequence numbers, and payload offsets.

### Step 4: Lookup the FlowKey
```cpp
FlowKey key;
// Fill key with IPs, ports, and protocol
Flow& flow = flows[key];
```
If this is the first packet of a connection, a new `Flow` record is added to our tracking table.

### Step 5: Deep Packet Inspection (DPI)
If the application type is not yet classified:
- **TLS SNI**: If port is 443, parse handshake bytes for SNI.
- **HTTP Host**: If port is 80, search for `Host:` header in plaintext payload.
- **SSH Secure Shell**: If port is 22 or payload starts with the ASCII sequence `SSH-`, mark it as `AppType::SSH`.
- **DNS**: If port is 53, parse query domain name.

### Step 6: Apply Rules & Forward or Drop
```cpp
if (rules.isBlocked(key.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
    dropped++;
} else {
    forwarded++;
    output.write(...); // Write to output pcap
}
```

---

## 6. Deep Dive: Each Component

### A. CaptureReader (`sentry_pcap_reader.h/cpp`)
Reads raw packet byte arrays. Handles magic number detection (`0xa1b2c3d4` vs `0xd4c3b2a1`) to automatically swap byte order on little-endian platforms.

### B. LayerParser (`sentry_packet_parser.h/cpp`)
Inspects protocol layers. Standardizes network byte representations back to host format using `ntohs` and `ntohl`.

### C. PayloadInspector (`sentry_sni_extractor.h/cpp`)
Inspects raw payload bytes. Navigates TLS headers to extract the plaintext Server Name Indication (SNI) string. Also extracts HTTP Hosts and decodes DNS domain labels.

---

## 7. How SNI & SSH Extraction Works

### TLS Client Hello Layout
```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length
-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
... Skip random bytes, session ID, ciphers ...
-- Extensions --
Bytes X-X+1: Extensions Length
Find Extension Type: 0x0000 (SNI Extension)
  ➔ Extract: "www.youtube.com"
```

### SSH Banner Match
SSH connections initiate with a plaintext banner before encrypting. FlowSentry inspects the first 4 bytes of TCP payload for the signature:
```
Payload: "SSH-2.0-OpenSSH_8.2..."
Match:   "SSH-" ➔ Classifies connection as AppType::SSH
```

---

## 8. How Traffic Filtering Works

FlowSentry blocks traffic at the **flow level** (using connection states), rather than matching individual packets in isolation. 

```
Connection to YouTube (Blocked):
  Packet 1 (SYN)           ➔ No SNI yet ➔ FORWARDED
  Packet 2 (SYN-ACK)       ➔ No SNI yet ➔ FORWARDED
  Packet 3 (ACK)           ➔ No SNI yet ➔ FORWARDED
  Packet 4 (Client Hello)  ➔ SNI: www.youtube.com (Classified YOUTUBE)
                           ➔ Matches Block Rules!
                           ➔ Mark Flow as BLOCKED
                           ➔ DROPPED
  Packet 5 (Data)          ➔ Flow state is BLOCKED ➔ DROPPED
  Packet 6 (Data)          ➔ Flow state is BLOCKED ➔ DROPPED
```
Because subsequent packets (data) are dropped, the connection quickly times out on the client's device.

---

## 9. Building and Running

### Compilation
Build the executables using any compiler supporting C++11/C++14:

```bash
# Detailed packet viewer
g++ -std=c++14 -O2 -I include -o flow_sentry.exe src/sentry_main.cpp src/sentry_pcap_reader.cpp src/sentry_packet_parser.cpp

# Simple DPI filter engine
g++ -std=c++14 -O2 -I include -o flow_sentry_simple.exe src/sentry_engine_simple.cpp src/sentry_pcap_reader.cpp src/sentry_packet_parser.cpp src/sentry_sni_extractor.cpp src/sentry_types.cpp

# Quick SNI inspector
g++ -std=c++14 -O2 -I include -o flow_sentry_inspector.exe src/sentry_inspector_simple.cpp src/sentry_pcap_reader.cpp src/sentry_packet_parser.cpp src/sentry_sni_extractor.cpp src/sentry_types.cpp
```

### Generating Test Traffic
```powershell
python generate_test_pcap.py
```

### Running the Filtering Engine
```powershell
# Run the filter engine, block YouTube, and export a JSON report
.\flow_sentry_simple.exe test_dpi.pcap filtered.pcap --block-app YouTube --export-json report.json

# Block a specific IP and domain names
.\flow_sentry_simple.exe test_dpi.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain doubleclick.net
```

---

## 10. Understanding the Output & JSON Exporter

When running `flow_sentry_simple.exe`, you will see a console statistics table:

```
╔══════════════════════════════════════════════════════════════╗
║                      FLOWSENTRY REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                             ║
║ Forwarded:                  76                             ║
║ Dropped:                     1                             ║
║ Active Flows:               43                             ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                    ║
║ Unknown              16  20.8% ####                          ║
║ DNS                   4   5.2% #                             ║
║ YouTube               1   1.3%   (BLOCKED)                   ║
╚══════════════════════════════════════════════════════════════╝
```

### JSON Export Schema
Passing `--export-json report.json` writes detailed stats and connections to a file:
```json
{
  "total_packets": 77,
  "forwarded": 76,
  "dropped": 1,
  "active_flows": 43,
  "applications": [
    {
      "app": "HTTPS",
      "count": 39
    }
  ],
  "detected_domains": [
    {
      "domain": "www.youtube.com",
      "app": "YouTube"
    }
  ]
}
```
This output format allows FlowSentry to easily integrate with visualization dashboards or monitoring agents.

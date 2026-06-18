# DPI Engine — Deep Packet Inspection System

> Built from scratch in **C++17** — no external libraries. Reads PCAP captures, inspects TLS handshakes, extracts SNIs, detects weak encryption, and blocks domains/apps via CLI rules.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [What This Project Does](#2-what-this-project-does)
3. [Project Structure](#3-project-structure)
4. [How It Works — Packet Journey](#4-how-it-works--packet-journey)
5. [TLS Inspection & SNI Extraction](#5-tls-inspection--sni-extraction)
6. [Blocking Engine](#6-blocking-engine)
7. [Building & Running](#7-building--running)
8. [Sample Output](#8-sample-output)
9. [Key Concepts](#9-key-concepts)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** examines the *contents* of network packets — not just headers (IP/port), but the actual payload data.

| Technique        | What it sees              |
|-----------------|---------------------------|
| Simple Firewall  | Source IP, Destination IP |
| DPI Engine       | TLS version, domain name, cipher suite, app type |

### Real-World Uses
- **ISPs** — throttle or block BitTorrent, YouTube
- **Enterprises** — block social media on office networks
- **Parental Controls** — block adult/gaming domains
- **Security** — detect weak TLS, flag suspicious traffic

---

## 2. What This Project Does

```
input.pcap  →  [DPI Engine]  →  Terminal Report
                    │
                    ├── Parse Ethernet / IP / TCP headers
                    ├── Inspect TLS ClientHello
                    ├── Extract SNI (domain name)
                    ├── Detect weak TLS (TLS 1.0/1.1/1.2 + weak ciphers)
                    ├── Map domain → App (YouTube, Facebook, etc.)
                    ├── Apply blocking rules (--block / --block-app)
                    └── Generate structured report with app breakdown
```

### Unique Features vs Other DPI Projects
- ✅ **Weak TLS detection** — flags TLS 1.0/1.1/1.2 + known weak cipher suites
- ✅ **Cipher suite analysis** — identifies `RSA`, `CBC`, `NULL`, `EXPORT` ciphers
- ✅ **App-level classification** — maps SNI to YouTube / Facebook / Google / GitHub
- ✅ **CLI blocking rules** — `--block domain` and `--block-app AppName`
- ✅ **Fancy terminal UI** — box-drawn report with app breakdown + % bars
- ✅ **Zero dependencies** — pure C++17, no libpcap, no Boost

---

## 3. Project Structure

```
packet_analyzerr/
├── include/
│   ├── types.h              # FiveTuple, AppType, RawPacket structs
│   ├── pcap_reader.h        # PCAP file reader interface
│   ├── packet_parser.h      # Ethernet / IP / TCP parser interface
│   ├── sni_extractor.h      # TLS SNI extractor interface
│   └── tls_inspector.h      # TLS version + cipher inspector interface
│
├── src/
│   ├── main.cpp             # Entry point, flow engine, report UI
│   ├── pcap_reader.cpp      # PCAP binary file parsing
│   ├── packet_parser.cpp    # Protocol header parsing
│   ├── sni_extractor.cpp    # TLS ClientHello SNI extraction
│   └── tls_inspector.cpp    # TLS version + weak cipher detection
│
├── test.pcap                # Sample capture (TLS 1.2, YouTube traffic)
├── create_test.py           # Python script to generate test PCAPs
└── README.md
```

---

## 4. How It Works — Packet Journey

Every packet goes through this pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│  PCAP File                                                      │
│  [Global Header 24B] [Pkt Header 16B] [Pkt Data] [Pkt Header]  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ PcapReader::readNextPacket()
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Raw Packet bytes                                               │
│  [Ethernet 14B] [IP 20B] [TCP 20B] [Payload →]                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ PacketParser::parse()
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  ParsedPacket                                                   │
│  src_ip, dst_ip, src_port, dst_port, protocol, payload         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ FiveTuple hash → flows map
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Flow Lookup (unordered_map<FiveTuple, Flow>)                   │
│  Each unique connection → one Flow entry                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ if dst_port == 443
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  TLS Inspection                                                 │
│  TLSInspector::inspect() → version, ciphers, weak flag         │
│  SNIExtractor::extract() → "www.youtube.com"                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌──────────────┐     ┌─────────────┐
│  BLOCKED     │     │  FORWARDED  │
│  dropped++   │     │  forwarded++│
└──────────────┘     └─────────────┘
```

### The Five-Tuple

Every network connection is uniquely identified by 5 values:

| Field            | Example          | Purpose                         |
|-----------------|------------------|---------------------------------|
| Source IP        | 192.168.1.100    | Who is sending                  |
| Destination IP   | 172.217.14.206   | Where it's going                |
| Source Port      | 54321            | Sender's application port       |
| Destination Port | 443              | Service (443 = HTTPS)           |
| Protocol         | 6 (TCP)          | TCP or UDP                      |

All packets with the same 5-tuple belong to the **same connection (flow)**. The engine tracks each flow separately so blocking a connection blocks all its future packets too.

---

## 5. TLS Inspection & SNI Extraction

### Why SNI?

Even though HTTPS encrypts the data, the **domain name is sent in plaintext** during the TLS handshake (ClientHello). This is called **SNI — Server Name Indication**.

```
TLS ClientHello:
├── Content Type: 0x16 (Handshake)
├── Version: TLS 1.2
├── Handshake Type: 0x01 (ClientHello)
└── Extensions:
    └── SNI (type 0x0000):
        └── server_name: "www.youtube.com"  ← extracted here
```

### Weak TLS Detection

The engine flags connections as **WEAK** if:
- TLS version is **1.0** or **1.1** (deprecated)
- TLS 1.2 is used with known weak cipher suites

Weak cipher patterns detected:
```
TLS_RSA_WITH_*          (no forward secrecy)
*_WITH_*_CBC_*          (CBC padding oracle risk)
*_WITH_RC4_*            (broken cipher)
*_EXPORT_*              (intentionally weakened)
*_WITH_NULL_*           (no encryption at all)
TLS_RSA_WITH_3DES_*     (SWEET32 attack)
```

---

## 6. Blocking Engine

### CLI Rule Types

| Flag            | Example                    | Effect                          |
|----------------|----------------------------|---------------------------------|
| `--block`       | `--block youtube`          | Block any SNI containing "youtube" |
| `--block-app`   | `--block-app Facebook`     | Block by app classification     |

### How Blocking Works (Flow-Level)

```
Packet 1 (SYN)           → SNI unknown yet → FORWARD
Packet 2 (ClientHello)   → SNI: www.youtube.com → BLOCKED ← rule matched
Packet 3 (Data)          → flow.blocked = true → DROPPED
Packet 4 (Data)          → flow.blocked = true → DROPPED
```

Once a flow is marked blocked, **all future packets** of that connection are dropped automatically — no re-inspection needed.

---

## 7. Building & Running

### Prerequisites
- **Windows**: MinGW-w64 GCC 13+ ([winlibs.com](https://winlibs.com))
- **Linux/macOS**: GCC 11+ or Clang 14+
- C++17 support required

### Build

```bash
g++ -std=c++17 -I include -o dpi_engine \
    src/main.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/tls_inspector.cpp
```

### Run

```bash
# Basic analysis
./dpi_engine test.pcap

# Block a domain
./dpi_engine test.pcap --block youtube

# Block by app name
./dpi_engine test.pcap --block-app Facebook

# Multiple rules
./dpi_engine test.pcap --block youtube --block tiktok --block-app Facebook
```

### Generate Test PCAP

```bash
python3 create_test.py
# Creates test.pcap with sample TLS traffic
```

---

## 8. Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║          DPI ENGINE v2.0  -  Deep Packet Inspection          ║
║  Built with C++17  |  github.com/karaanraj/packet-analyzer   ║
╠══════════════════════════════════════════════════════════════╣
║                    ACTIVE BLOCKING RULES                     ║
║                        [Domain] youtube                      ║
╠══════════════════════════════════════════════════════════════╣
║                    Processing: test.pcap                     ║
╚══════════════════════════════════════════════════════════════╝

[TLS] ClientHello | Version: TLS 1.2 ⚠ WEAK TLS
         Cipher: TLS_RSA_WITH_AES_128_CBC_SHA [WEAK]
[SNI] www.youtube.com -> YouTube [BLOCKED]

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets  :                                            1 ║
║ TCP Packets    :                                            1 ║
║ UDP Packets    :                                            0 ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded      :                                            0 ║
║ Dropped        :                                            1 ║
║ Weak TLS conns :                                            1 ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║    YouTube        1  100.0%  #################### (BLOCKED)  ║
╠══════════════════════════════════════════════════════════════╣
║                   DETECTED DOMAINS / SNIs                    ║
╠══════════════════════════════════════════════════════════════╣
║              www.youtube.com -> YouTube [BLOCKED]            ║
║                       TLS: TLS 1.2 (WEAK)                    ║
║           Cipher: TLS_RSA_WITH_AES_128_CBC_SHA [WEAK]        ║
╚══════════════════════════════════════════════════════════════╝
Done. Happy hacking!
```

---

## 9. Key Concepts

### Network Packet Structure
```
┌──────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                   │
│  ├── Destination MAC (6B)                    │
│  ├── Source MAC (6B)                         │
│  └── EtherType: 0x0800 = IPv4 (2B)          │
│ ┌────────────────────────────────────────┐   │
│ │ IP Header (20 bytes)                   │   │
│ │  ├── Protocol: 6=TCP, 17=UDP           │   │
│ │  ├── Source IP (4B)                    │   │
│ │  └── Destination IP (4B)              │   │
│ │ ┌──────────────────────────────────┐   │   │
│ │ │ TCP Header (20 bytes)            │   │   │
│ │ │  ├── Source Port (2B)            │   │   │
│ │ │  ├── Destination Port (2B)       │   │   │
│ │ │  └── Flags: SYN/ACK/FIN         │   │   │
│ │ │ ┌──────────────────────────────┐ │   │   │
│ │ │ │ Payload (TLS ClientHello)    │ │   │   │
│ │ │ │  └── SNI: "youtube.com"      │ │   │   │
│ │ │ └──────────────────────────────┘ │   │   │
│ │ └──────────────────────────────────┘   │   │
│ └────────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

### Network Byte Order
Network protocols use **big-endian** byte order. The code converts using:
```cpp
uint16_t port = ntohs(*(uint16_t*)(data + offset));  // 16-bit
uint32_t ip   = ntohl(*(uint32_t*)(data + offset));  // 32-bit
```

### FiveTuple Hashing
Custom hash for `unordered_map` using boost-style combining:
```cpp
h ^= std::hash<uint32_t>{}(t.src_ip) + 0x9e3779b9 + (h<<6) + (h>>2);
```
The magic constant `0x9e3779b9` is derived from the golden ratio — it spreads bits uniformly to minimize hash collisions.

---

## Author

**Karan Raj** — CS Final Year, AKGEC Ghaziabad  
GitHub: [github.com/karaanraj](https://github.com/karaanraj)  
LinkedIn: [linkedin.com/in/karanraj2412](https://linkedin.com/in/karanraj2412)  
LeetCode: [leetcode.com/karanraj_2412](https://leetcode.com/karanraj_2412)
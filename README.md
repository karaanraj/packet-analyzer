# Packet Analyzer - Deep Packet Inspection Engine

A network packet analyzer built in C++ that performs Deep Packet Inspection (DPI) on PCAP files.

## What it does
- Reads PCAP network capture files
- Parses Ethernet, IP, and TCP headers from raw bytes
- Extracts TLS SNI (Server Name Indication) from Client Hello handshakes
- Classifies traffic by application (YouTube, Facebook, Google, GitHub)
- Blocks specified domains and generates traffic reports

## How to compile
```bash
g++ -std=c++17 -I include src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/main.cpp -o dpi_engine
```

## How to run
```bash
# Basic usage
./dpi_engine input.pcap

# With domain blocking
./dpi_engine input.pcap --block youtube --block facebook
```

## Project Structure
- `include/` - Header files
- `src/` - Source files

## Technologies
- C++17
- Raw socket/binary parsing
- TLS protocol analysis
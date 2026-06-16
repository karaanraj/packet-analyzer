#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

// The 24-byte header at the start of every PCAP file
struct PcapGlobalHeader {
    uint32_t magic_number;   // always 0xa1b2c3d4, confirms it's a valid PCAP
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;        // max packet size
    uint32_t network;        // 1 = Ethernet
};

// 16-byte header before EACH packet
struct PcapPacketHeader {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // how many bytes saved in file
    uint32_t orig_len;       // original packet size
};

// One raw packet (header + actual bytes)
struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

// The class that reads PCAP files
class PcapReader {
public:
    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& packet);
    void close();

private:
    std::ifstream file_;
};
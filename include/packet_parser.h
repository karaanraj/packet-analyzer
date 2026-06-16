#pragma once
#include <cstdint>
#include <string>
#include "../include/pcap_reader.h"

// This struct holds everything we extract from a packet
struct ParsedPacket {
    // IP layer
    std::string src_ip;
    std::string dst_ip;
    uint8_t     protocol;    // 6=TCP, 17=UDP

    // Transport layer
    uint16_t src_port;
    uint16_t dst_port;

    // Flags
    bool has_tcp = false;
    bool has_udp = false;

    // Payload (the actual data inside)
    const uint8_t* payload     = nullptr;
    uint32_t       payload_len = 0;
};

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
};
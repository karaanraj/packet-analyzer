#include "../include/packet_parser.h"
#include <iostream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
#endif

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    const uint8_t* data = raw.data.data();
    uint32_t len = raw.data.size();

    if (len < 14) return false;

    // Ethernet header - check EtherType
    uint16_t ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800) return false;

    // IP header starts at byte 14
    if (len < 34) return false;
    const uint8_t* ip = data + 14;

    uint8_t ip_header_len = (ip[0] & 0x0F) * 4;
    parsed.protocol = ip[9];

    // Extract IPs manually (works on both Windows and Linux)
    char src_buf[16], dst_buf[16];
    snprintf(src_buf, sizeof(src_buf), "%d.%d.%d.%d",
             ip[12], ip[13], ip[14], ip[15]);
    snprintf(dst_buf, sizeof(dst_buf), "%d.%d.%d.%d",
             ip[16], ip[17], ip[18], ip[19]);
    parsed.src_ip = src_buf;
    parsed.dst_ip = dst_buf;

    const uint8_t* transport = ip + ip_header_len;

    if (parsed.protocol == 6) {  // TCP
        if (len < 14 + ip_header_len + 20u) return false;

        parsed.src_port = (transport[0] << 8) | transport[1];
        parsed.dst_port = (transport[2] << 8) | transport[3];

        uint8_t tcp_header_len = ((transport[12] >> 4) & 0x0F) * 4;

        parsed.payload     = transport + tcp_header_len;
        parsed.payload_len = len - (14 + ip_header_len + tcp_header_len);
        parsed.has_tcp     = true;

    } else if (parsed.protocol == 17) {  // UDP
        if (len < 14 + ip_header_len + 8u) return false;

        parsed.src_port = (transport[0] << 8) | transport[1];
        parsed.dst_port = (transport[2] << 8) | transport[3];

        parsed.payload     = transport + 8;
        parsed.payload_len = len - (14 + ip_header_len + 8);
        parsed.has_udp     = true;
    }

    return true;
}
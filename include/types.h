#pragma once
#include <string>
#include <cstdint>

// Uniquely identifies a network conversation
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

// What app is this traffic from?
enum class AppType {
    UNKNOWN,
    YOUTUBE,
    FACEBOOK,
    GOOGLE,
    GITHUB,
    DNS
};
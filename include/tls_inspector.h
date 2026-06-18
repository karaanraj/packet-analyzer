#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct TLSInfo {
    bool        is_tls         = false;

    // Record layer
    uint8_t     record_type    = 0;   // 0x16 = Handshake
    std::string tls_version;          // "TLS 1.0" / "TLS 1.2" / "TLS 1.3"
    bool        is_weak        = false; // true if TLS 1.0 or 1.1

    // Handshake
    std::string handshake_type;       // "ClientHello" / "ServerHello"

    // ClientHello specific
    std::vector<std::string> cipher_suites;  // human-readable names
    bool        has_sni        = false;
};

class TLSInspector {
public:
    static TLSInfo inspect(const uint8_t* payload, size_t length);

private:
    static std::string parseTLSVersion(uint8_t major, uint8_t minor);
    static std::string cipherSuiteName(uint16_t code);
    static std::string handshakeTypeName(uint8_t type);
};
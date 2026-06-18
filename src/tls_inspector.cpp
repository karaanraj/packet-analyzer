#include "tls_inspector.h"

static uint16_t read2(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// ─── Version string ───────────────────────────────────────────────────────────
std::string TLSInspector::parseTLSVersion(uint8_t major, uint8_t minor) {
    if (major == 3) {
        switch (minor) {
            case 1: return "TLS 1.0";
            case 2: return "TLS 1.1";
            case 3: return "TLS 1.2";
            case 4: return "TLS 1.3";
        }
    }
    return "Unknown";
}

// ─── Handshake type string ────────────────────────────────────────────────────
std::string TLSInspector::handshakeTypeName(uint8_t type) {
    switch (type) {
        case 1:  return "ClientHello";
        case 2:  return "ServerHello";
        case 11: return "Certificate";
        case 12: return "ServerKeyExchange";
        case 14: return "ServerHelloDone";
        case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        default: return "Unknown(" + std::to_string(type) + ")";
    }
}

// ─── Common cipher suite names ────────────────────────────────────────────────
std::string TLSInspector::cipherSuiteName(uint16_t code) {
    switch (code) {
        // TLS 1.3 suites
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";

        // TLS 1.2 strong suites
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";

        // Weak / deprecated suites
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA [WEAK]";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA [WEAK]";
        case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA [WEAK]";
        case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA [WEAK]";
        case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5 [WEAK]";

        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%04X", code);
            return std::string(buf);
        }
    }
}

// ─── Main inspection logic ────────────────────────────────────────────────────
TLSInfo TLSInspector::inspect(const uint8_t* data, size_t len) {
    TLSInfo info;

    // Minimum TLS record header: 5 bytes
    if (len < 5) return info;

    // Content type must be Handshake (0x16)
    if (data[0] != 0x16) return info;

    info.is_tls      = true;
    info.record_type = data[0];

    // Record-layer TLS version (bytes 1-2)
    info.tls_version = parseTLSVersion(data[1], data[2]);
    if (data[1] == 3 && (data[2] == 1 || data[2] == 2)) {
        info.is_weak = true;
    }

    // Handshake header starts at byte 5
    if (len < 6) return info;
    info.handshake_type = handshakeTypeName(data[5]);

    // We only do deep parsing for ClientHello (type = 1)
    if (data[5] != 0x01) return info;

    // ClientHello layout:
    // [0]     record type  (1 byte)
    // [1-2]   record version (2 bytes)
    // [3-4]   record length  (2 bytes)
    // [5]     handshake type (1 byte)
    // [6-8]   handshake length (3 bytes)
    // [9-10]  client version (2 bytes)  ← actual TLS version in TLS 1.2-
    // [11-42] random (32 bytes)
    // [43]    session id length

    if (len < 43) return info;

    // Client-advertised version (overrides record layer for TLS 1.2 and below)
    std::string client_ver = parseTLSVersion(data[9], data[10]);
    if (!client_ver.empty() && client_ver != "Unknown") {
        info.tls_version = client_ver;
        if (data[9] == 3 && (data[10] == 1 || data[10] == 2)) {
            info.is_weak = true;
        }
    }

    size_t pos = 43;

    // Session ID
    if (pos >= len) return info;
    uint8_t session_len = data[pos++];
    pos += session_len;

    // Cipher suites
    if (pos + 2 > len) return info;
    uint16_t cipher_len = read2(data + pos);
    pos += 2;

    uint16_t num_ciphers = cipher_len / 2;
    for (uint16_t i = 0; i < num_ciphers && pos + 2 <= len; i++) {
        uint16_t code = read2(data + pos);
        pos += 2;
        // Skip GREASE values (0xXAXA pattern)
        if ((code & 0x0F0F) == 0x0A0A) continue;
        info.cipher_suites.push_back(cipherSuiteName(code));
    }

    // Compression methods
    if (pos >= len) return info;
    uint8_t comp_len = data[pos++];
    pos += comp_len;

    // Extensions
    if (pos + 2 > len) return info;
    uint16_t ext_total = read2(data + pos);
    pos += 2;
    size_t ext_end = pos + ext_total;

    while (pos + 4 <= ext_end && pos + 4 <= len) {
        uint16_t ext_type = read2(data + pos);
        uint16_t ext_len  = read2(data + pos + 2);
        pos += 4;

        // Extension type 0x0000 = SNI
        if (ext_type == 0x0000) {
            info.has_sni = true;
        }

        // Extension type 0x002B = supported_versions (TLS 1.3 advertises here)
        if (ext_type == 0x002B && pos + ext_len <= len) {
            // List of supported versions
            uint8_t sv_len = data[pos];
            for (uint8_t i = 1; i + 1 < sv_len && pos + i + 1 < len; i += 2) {
                if (data[pos + i] == 0x03 && data[pos + i + 1] == 0x04) {
                    info.tls_version = "TLS 1.3";
                    info.is_weak     = false;
                    break;
                }
            }
        }

        pos += ext_len;
    }

    return info;
}
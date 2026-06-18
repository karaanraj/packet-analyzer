#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include "../include/pcap_reader.h"
#include "../include/packet_parser.h"
#include "../include/sni_extractor.h"
#include "../include/types.h"
#include "../include/tls_inspector.h" // ← NEW

struct Flow {
    std::string sni;
    AppType     app     = AppType::UNKNOWN;
    bool        blocked = false;

    // TLS metadata (new)
    std::string              tls_version;
    bool                     tls_weak    = false;
    std::vector<std::string> cipher_suites;
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(t.src_ip)   + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint32_t>{}(t.dst_ip)   + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint16_t>{}(t.src_port) + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint16_t>{}(t.dst_port) + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint8_t>{}(t.protocol)  + 0x9e3779b9 + (h<<6) + (h>>2);
        return h;
    }
};

struct FiveTupleEqual {
    bool operator()(const FiveTuple& a, const FiveTuple& b) const {
        return a.src_ip == b.src_ip && a.dst_ip == b.dst_ip &&
               a.src_port == b.src_port && a.dst_port == b.dst_port &&
               a.protocol == b.protocol;
    }
};

AppType sniToApp(const std::string& sni) {
    if (sni.find("youtube")  != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("google")   != std::string::npos) return AppType::GOOGLE;
    if (sni.find("github")   != std::string::npos) return AppType::GITHUB;
    return AppType::UNKNOWN;
}

bool isBlocked(const std::string& sni,
               const std::unordered_set<std::string>& blocked_domains) {
    for (const auto& domain : blocked_domains) {
        if (sni.find(domain) != std::string::npos) return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: dpi_engine <input.pcap> [--block domain]\n";
        std::cout << "Example: dpi_engine test.pcap --block youtube\n";
        return 1;
    }

    std::unordered_set<std::string> blocked_domains;
    for (int i = 2; i < argc - 1; i++) {
        if (std::string(argv[i]) == "--block") {
            blocked_domains.insert(argv[i+1]);
            std::cout << "[Rule] Blocking: " << argv[i+1] << "\n";
        }
    }

    PcapReader reader;
    if (!reader.open(argv[1])) return 1;

    std::unordered_map<FiveTuple, Flow, FiveTupleHash, FiveTupleEqual> flows;

    int total = 0, forwarded = 0, dropped = 0;
    int tcp_count = 0, udp_count = 0;
    int weak_tls_count = 0;   // ← NEW: track weak TLS connections
    RawPacket raw;

    while (reader.readNextPacket(raw)) {
        total++;

        ParsedPacket parsed;
        if (!PacketParser::parse(raw, parsed)) {
            forwarded++;
            continue;
        }

        if (parsed.has_tcp) tcp_count++;
        if (parsed.has_udp) udp_count++;

        FiveTuple tuple;
        tuple.src_ip   = 0;
        tuple.dst_ip   = 0;
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dst_port;
        tuple.protocol = parsed.protocol;

        Flow& flow = flows[tuple];

        // ── TLS Inspection (port 443) ──────────────────────────────────────
        if (parsed.dst_port == 443 && parsed.payload_len > 5) {

            // 1. Deep TLS inspection (version, ciphers, handshake type)
            TLSInfo tls = TLSInspector::inspect(parsed.payload, parsed.payload_len);

            if (tls.is_tls && flow.tls_version.empty()) {
                flow.tls_version  = tls.tls_version;
                flow.tls_weak     = tls.is_weak;
                flow.cipher_suites = tls.cipher_suites;

                std::cout << "[TLS] " << tls.handshake_type
                          << " | Version: " << tls.tls_version;

                if (tls.is_weak) {
                    std::cout << " ⚠ WEAK TLS";
                    weak_tls_count++;
                }
                std::cout << "\n";

                // Print cipher suites (first 3 only to avoid noise)
                int shown = 0;
                for (const auto& cs : tls.cipher_suites) {
                    if (shown++ >= 3) { std::cout << "         ...\n"; break; }
                    std::cout << "         Cipher: " << cs << "\n";
                }
            }

            // 2. SNI extraction (existing logic, unchanged)
            auto sni = SNIExtractor::extract(parsed.payload, parsed.payload_len);
            if (sni.found && flow.sni.empty()) {
                flow.sni = sni.value;
                flow.app = sniToApp(sni.value);
                std::cout << "[SNI] " << sni.value;

                if (isBlocked(flow.sni, blocked_domains)) {
                    flow.blocked = true;
                    std::cout << " → BLOCKED";
                }
                std::cout << "\n";
            }
        }

        // ── Forward / Drop ─────────────────────────────────────────────────
        if (flow.blocked) {
            dropped++;
            std::cout << "[DROPPED] packet to " << flow.sni << "\n";
        } else {
            forwarded++;
        }
    }

    reader.close();

    // ── Report ─────────────────────────────────────────────────────────────
    std::cout << "\n==================================\n";
    std::cout << "          DPI REPORT              \n";
    std::cout << "==================================\n";
    std::cout << "Total packets    : " << total          << "\n";
    std::cout << "TCP packets      : " << tcp_count      << "\n";
    std::cout << "UDP packets      : " << udp_count      << "\n";
    std::cout << "Forwarded        : " << forwarded      << "\n";
    std::cout << "Dropped          : " << dropped        << "\n";
    std::cout << "Weak TLS conns   : " << weak_tls_count << "\n";   // ← NEW
    std::cout << "==================================\n";
    std::cout << "       Detected Flows             \n";
    std::cout << "==================================\n";

    for (auto& [tuple, flow] : flows) {
        if (!flow.sni.empty()) {
            std::cout << "  Domain  : " << flow.sni;
            if (flow.blocked) std::cout << " (BLOCKED)";
            std::cout << "\n";

            if (!flow.tls_version.empty()) {
                std::cout << "  TLS Ver : " << flow.tls_version;
                if (flow.tls_weak) std::cout << " ⚠ WEAK";
                std::cout << "\n";
            }

            if (!flow.cipher_suites.empty()) {
                std::cout << "  Cipher  : " << flow.cipher_suites[0] << "\n";
            }

            std::cout << "  ──────────────────────────────\n";
        }
    }

    std::cout << "==================================\n";
    return 0;
}
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include "../include/pcap_reader.h"
#include "../include/packet_parser.h"
#include "../include/sni_extractor.h"
#include "../include/types.h"
#include "../include/tls_inspector.h"

// ── Data Structures ────────────────────────────────────────────────────────

struct Flow {
    std::string              sni;
    AppType                  app          = AppType::UNKNOWN;
    bool                     blocked      = false;
    std::string              tls_version;
    bool                     tls_weak     = false;
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

// ── Helper Functions ───────────────────────────────────────────────────────

AppType sniToApp(const std::string& sni) {
    if (sni.find("youtube")   != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("facebook")  != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("google")    != std::string::npos) return AppType::GOOGLE;
    if (sni.find("github")    != std::string::npos) return AppType::GITHUB;
    if (sni.find("twitter")   != std::string::npos) return AppType::UNKNOWN;
    if (sni.find("instagram") != std::string::npos) return AppType::UNKNOWN;
    if (sni.find("netflix")   != std::string::npos) return AppType::UNKNOWN;
    if (sni.find("tiktok")    != std::string::npos) return AppType::UNKNOWN;
    return AppType::UNKNOWN;
}

std::string appTypeToString(AppType app) {
    switch (app) {
        case AppType::YOUTUBE:  return "YouTube";
        case AppType::FACEBOOK: return "Facebook";
        case AppType::GOOGLE:   return "Google";
        case AppType::GITHUB:   return "GitHub";
        default:                return "Unknown";
    }
}

bool isBlocked(const std::string& sni,
               const std::unordered_set<std::string>& blocked_domains) {
    for (const auto& domain : blocked_domains) {
        if (sni.find(domain) != std::string::npos) return true;
    }
    return false;
}

// ── Box Drawing Helpers ────────────────────────────────────────────────────

const int BOX_WIDTH = 62;

void printTop() {
    std::cout << "\xC9";
    for (int i = 0; i < BOX_WIDTH; i++) std::cout << "\xCD";
    std::cout << "\xBB\n";
}

void printBottom() {
    std::cout << "\xC8";
    for (int i = 0; i < BOX_WIDTH; i++) std::cout << "\xCD";
    std::cout << "\xBC\n";
}

void printSep() {
    std::cout << "\xCC";
    for (int i = 0; i < BOX_WIDTH; i++) std::cout << "\xCD";
    std::cout << "\xB9\n";
}

void printLine(const std::string& left, const std::string& right = "") {
    std::string content;
    if (right.empty()) {
        // Centered
        int pad = (BOX_WIDTH - (int)left.size()) / 2;
        content = std::string(pad, ' ') + left;
        content += std::string(BOX_WIDTH - content.size(), ' ');
    } else {
        // Left + right aligned
        content = " " + left;
        int spaces = BOX_WIDTH - 1 - (int)left.size() - (int)right.size();
        if (spaces < 1) spaces = 1;
        content += std::string(spaces, ' ') + right;
    }
    std::cout << "\xBA" << content << "\xBA\n";
}

void printEmpty() {
    std::cout << "\xBA" << std::string(BOX_WIDTH, ' ') << "\xBA\n";
}

// ── Main ───────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: dpi_engine <input.pcap> [--block domain] [--block-app appname]\n";
        std::cout << "Example: dpi_engine test.pcap --block youtube --block-app Facebook\n";
        return 1;
    }

    // ── Parse CLI args ─────────────────────────────────────────────────────
    std::unordered_set<std::string> blocked_domains;
    std::unordered_set<std::string> blocked_apps;

    for (int i = 2; i < argc - 1; i++) {
        if (std::string(argv[i]) == "--block") {
            std::string d = argv[i+1];
            blocked_domains.insert(d);
        }
        if (std::string(argv[i]) == "--block-app") {
            std::string a = argv[i+1];
            // lowercase for comparison
            std::string al = a;
            std::transform(al.begin(), al.end(), al.begin(), ::tolower);
            blocked_apps.insert(al);
        }
    }

    // ── Header Banner ──────────────────────────────────────────────────────
    printTop();
    printLine("DPI ENGINE v2.0  -  Deep Packet Inspection");
    printLine("Built with C++17  |  github.com/karaanraj/packet-analyzer");
    printSep();

    // Print active rules
    if (!blocked_domains.empty() || !blocked_apps.empty()) {
        printLine("ACTIVE BLOCKING RULES");
        for (const auto& d : blocked_domains)
            printLine("  [Domain] " + d);
        for (const auto& a : blocked_apps)
            printLine("  [App]    " + a);
        printSep();
    }

    printLine("Processing: " + std::string(argv[1]));
    printBottom();
    std::cout << "\n";

    // ── Open PCAP ──────────────────────────────────────────────────────────
    PcapReader reader;
    if (!reader.open(argv[1])) return 1;

    std::unordered_map<FiveTuple, Flow, FiveTupleHash, FiveTupleEqual> flows;
    std::unordered_map<std::string, int> app_counts;   // app name → count
    std::unordered_set<std::string>      blocked_set;  // track blocked apps

    int total = 0, forwarded = 0, dropped = 0;
    int tcp_count = 0, udp_count = 0, weak_tls_count = 0;
    RawPacket raw;

    // ── Packet Loop ────────────────────────────────────────────────────────
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

        // ── TLS Inspection ─────────────────────────────────────────────────
        if (parsed.dst_port == 443 && parsed.payload_len > 5) {

            TLSInfo tls = TLSInspector::inspect(parsed.payload, parsed.payload_len);

            if (tls.is_tls && flow.tls_version.empty()) {
                flow.tls_version   = tls.tls_version;
                flow.tls_weak      = tls.is_weak;
                flow.cipher_suites = tls.cipher_suites;

                std::cout << "[TLS] " << tls.handshake_type
                          << " | Version: " << tls.tls_version;
                if (tls.is_weak) {
                    std::cout << " \x1A WEAK TLS";
                    weak_tls_count++;
                }
                std::cout << "\n";

                int shown = 0;
                for (const auto& cs : tls.cipher_suites) {
                    if (shown++ >= 3) { std::cout << "         ...\n"; break; }
                    std::cout << "         Cipher: " << cs << "\n";
                }
            }

            // ── SNI Extraction ─────────────────────────────────────────────
            auto sni = SNIExtractor::extract(parsed.payload, parsed.payload_len);
            if (sni.found && flow.sni.empty()) {
                flow.sni = sni.value;
                flow.app = sniToApp(sni.value);
                std::string appName = appTypeToString(flow.app);

                std::cout << "[SNI] " << sni.value
                          << " -> " << appName;

                // Check domain block
                if (isBlocked(flow.sni, blocked_domains)) {
                    flow.blocked = true;
                }

                // Check app block
                std::string appLower = appName;
                std::transform(appLower.begin(), appLower.end(), appLower.begin(), ::tolower);
                if (blocked_apps.count(appLower)) {
                    flow.blocked = true;
                }

                if (flow.blocked) {
                    std::cout << " [BLOCKED]";
                    blocked_set.insert(appName);
                }
                std::cout << "\n";

                // Count app
                app_counts[appName]++;
            }
        }

        // ── Forward / Drop ─────────────────────────────────────────────────
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
        }
    }

    reader.close();

    // ── REPORT ─────────────────────────────────────────────────────────────
    std::cout << "\n";
    printTop();
    printLine("PROCESSING REPORT");
    printSep();
    printLine("Total Packets  :", std::to_string(total));
    printLine("TCP Packets    :", std::to_string(tcp_count));
    printLine("UDP Packets    :", std::to_string(udp_count));
    printSep();
    printLine("Forwarded      :", std::to_string(forwarded));
    printLine("Dropped        :", std::to_string(dropped));
    printLine("Weak TLS conns :", std::to_string(weak_tls_count));
    printSep();

    // ── App Breakdown ───────────────────────────────────────────────────────
    printLine("APPLICATION BREAKDOWN");
    printSep();

    if (app_counts.empty()) {
        printLine("  No application traffic detected.");
    } else {
        // Sort by count descending
        std::vector<std::pair<std::string,int>> sorted(app_counts.begin(), app_counts.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](auto& a, auto& b){ return a.second > b.second; });

        for (auto& [app, count] : sorted) {
            float pct = total > 0 ? (count * 100.0f / total) : 0;
            int   bar = (int)(pct / 5);  // each # = 5%

            std::string bar_str(bar, '#');
            std::string blocked_tag = blocked_set.count(app) ? " (BLOCKED)" : "";

            // Format: "YouTube       4  5.2% ## (BLOCKED)"
            std::ostringstream line;
            line << app << std::string(12 - app.size(), ' ')
                 << std::setw(4) << count << "  "
                 << std::fixed << std::setprecision(1) << pct << "%"
                 << "  " << bar_str << blocked_tag;

            printLine("  " + line.str());
        }
    }

    printSep();

    // ── Detected Flows ──────────────────────────────────────────────────────
    printLine("DETECTED DOMAINS / SNIs");
    printSep();

    bool any = false;
    for (auto& [tuple, flow] : flows) {
        if (!flow.sni.empty()) {
            any = true;
            std::string appName = appTypeToString(flow.app);
            std::string tag     = flow.blocked ? " [BLOCKED]" : "";
            printLine("  " + flow.sni + " -> " + appName + tag);

            if (!flow.tls_version.empty()) {
                std::string weak = flow.tls_weak ? " (WEAK)" : "";
                printLine("    TLS: " + flow.tls_version + weak);
            }
            if (!flow.cipher_suites.empty()) {
                printLine("    Cipher: " + flow.cipher_suites[0]);
            }
            printEmpty();
        }
    }
    if (!any) printLine("  No SNIs detected.");

    printBottom();
    std::cout << "\nDone. Happy hacking!\n";
    return 0;
}
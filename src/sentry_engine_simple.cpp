#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <unordered_set>
#include <algorithm>
#include <cstring>

#include "sentry_pcap_reader.h"
#include "sentry_packet_parser.h"
#include "sentry_sni_extractor.h"
#include "sentry_types.h"

using namespace FlowSentry;

struct Flow {
    FlowKey key;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

class SentryRules {
public:
    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;
    
    void blockIP(const std::string& ip) {
        uint32_t addr = parseIP(ip);
        blocked_ips.insert(addr);
        std::cout << "[Sentry Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        AppType type = nameToAppType(app);
        if (type != AppType::UNKNOWN) {
            blocked_apps.insert(type);
            std::cout << "[Sentry Rules] Blocked app: " << app << "\n";
        } else {
            std::cerr << "[Sentry Rules] Unknown app name: " << app << "\n";
        }
    }
    
    void blockDomain(const std::string& domain) {
        blocked_domains.push_back(domain);
        std::cout << "[Sentry Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(src_ip)) return true;
        if (blocked_apps.count(app)) return true;
        for (const auto& dom : blocked_domains) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }
    
private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
};

void printUsage(const char* prog) {
    std::cout << R"(
FlowSentry DPI Engine v1.0
==========================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, SSH, etc.)
  --block-domain <dom>   Block domain (substring match)
  --export-json <file>   Export statistics to JSON report file

Example:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --export-json report.json
)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    std::string json_export_path = "";
    
    SentryRules rules;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            rules.blockIP(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            rules.blockApp(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.blockDomain(argv[++i]);
        } else if (arg == "--export-json" && i + 1 < argc) {
            json_export_path = argv[++i];
        }
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    FLOWSENTRY DPI ENGINE                     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    CaptureReader reader;
    if (!reader.open(input_file)) {
        return 1;
    }
    
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Cannot open output file\n";
        return 1;
    }
    
    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;
    
    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    std::unordered_map<AppType, uint64_t> app_stats;
    
    SentryRawPacket raw;
    SentryPacket parsed;
    
    std::cout << "[FlowSentry] Inspecting traffic...\n";
    
    while (reader.readNextPacket(raw)) {
        total_packets++;
        
        if (!LayerParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
        
        FlowKey key;
        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0;
            int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };
        
        key.src_ip = parseIP(parsed.src_ip);
        key.dst_ip = parseIP(parsed.dest_ip);
        key.src_port = parsed.src_port;
        key.dst_port = parsed.dest_port;
        key.protocol = parsed.protocol;
        
        Flow& flow = flows[key];
        if (flow.packets == 0) {
            flow.key = key;
        }
        flow.packets++;
        flow.bytes += raw.data.size();
        
        // SSH classification (added banner-based and port-based detection)
        if (flow.app_type == AppType::UNKNOWN && 
            (parsed.dest_port == 22 || parsed.src_port == 22)) {
            flow.app_type = AppType::SSH;
            flow.sni = "SSH Connection";
        }
        if (flow.app_type == AppType::UNKNOWN && parsed.has_tcp && parsed.payload_length >= 4) {
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
            payload_offset += tcp_offset * 4;
            if (payload_offset + 4 <= raw.data.size()) {
                if (std::memcmp(raw.data.data() + payload_offset, "SSH-", 4) == 0) {
                    flow.app_type = AppType::SSH;
                    flow.sni = "SSH Secure Shell";
                }
            }
        }
        
        // TLS SNI extraction
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) && 
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {
            
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            
            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;
                
                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    if (payload_len > 5) {
                        auto sni = PayloadInspector::extract(raw.data.data() + payload_offset, payload_len);
                        if (sni) {
                            flow.sni = *sni;
                            flow.app_type = sniToAppType(*sni);
                        }
                    }
                }
            }
        }
        
        // HTTP Host extraction
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {
            
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            
            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;
                
                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    auto host = HttpHostInspector::extract(raw.data.data() + payload_offset, payload_len);
                    if (host) {
                        flow.sni = *host;
                        flow.app_type = sniToAppType(*host);
                    }
                }
            }
        }
        
        // DNS classification
        if (flow.app_type == AppType::UNKNOWN && 
            (parsed.dest_port == 53 || parsed.src_port == 53)) {
            flow.app_type = AppType::DNS;
        }
        
        // Fallbacks
        if (flow.app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443) flow.app_type = AppType::HTTPS;
            else if (parsed.dest_port == 80) flow.app_type = AppType::HTTP;
        }
        
        // Rules matching
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(key.src_ip, flow.app_type, flow.sni);
            if (flow.blocked) {
                std::cout << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                          << " (" << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) std::cout << ": " << flow.sni;
                std::cout << ")\n";
            }
        }
        
        app_stats[flow.app_type]++;
        
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec = raw.header.ts_sec;
            pkt_hdr.ts_usec = raw.header.ts_usec;
            pkt_hdr.incl_len = raw.data.size();
            pkt_hdr.orig_len = raw.data.size();
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }
    
    reader.close();
    output.close();
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      FLOWSENTRY REPORT                       ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Packets:      " << std::setw(10) << total_packets << "                             ║\n";
    std::cout << "║ Forwarded:          " << std::setw(10) << forwarded << "                             ║\n";
    std::cout << "║ Dropped:            " << std::setw(10) << dropped << "                             ║\n";
    std::cout << "║ Active Flows:       " << std::setw(10) << flows.size() << "                             ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║                    APPLICATION BREAKDOWN                     ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        const auto& app = pair.first;
        const auto& count = pair.second;
        double pct = 100.0 * count / total_packets;
        int bar_len = static_cast<int>(pct / 5);
        std::string bar(bar_len, '#');
        
        std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << count
                  << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                  << std::setw(20) << std::left << bar << "  ║\n";
    }
    
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    std::cout << "\n[Detected Domains/Hosts]\n";
    std::unordered_map<std::string, AppType> unique_snis;
    for (const auto& pair : flows) {
        const auto& flow = pair.second;
        if (!flow.sni.empty()) {
            unique_snis[flow.sni] = flow.app_type;
        }
    }
    for (const auto& pair : unique_snis) {
        const auto& sni = pair.first;
        const auto& app = pair.second;
        std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
    }
    
    // JSON Report Export
    if (!json_export_path.empty()) {
        std::ofstream json_file(json_export_path);
        if (json_file.is_open()) {
            json_file << "{\n";
            json_file << "  \"total_packets\": " << total_packets << ",\n";
            json_file << "  \"forwarded\": " << forwarded << ",\n";
            json_file << "  \"dropped\": " << dropped << ",\n";
            json_file << "  \"active_flows\": " << flows.size() << ",\n";
            json_file << "  \"applications\": [\n";
            for (size_t i = 0; i < sorted_apps.size(); i++) {
                json_file << "    {\n";
                json_file << "      \"app\": \"" << appTypeToString(sorted_apps[i].first) << "\",\n";
                json_file << "      \"count\": " << sorted_apps[i].second << "\n";
                json_file << "    }" << (i + 1 < sorted_apps.size() ? "," : "") << "\n";
            }
            json_file << "  ],\n";
            json_file << "  \"detected_domains\": [\n";
            size_t idx = 0;
            for (auto it = unique_snis.begin(); it != unique_snis.end(); ++it) {
                json_file << "    {\n";
                json_file << "      \"domain\": \"" << it->first << "\",\n";
                json_file << "      \"app\": \"" << appTypeToString(it->second) << "\"\n";
                json_file << "    }" << (++idx < unique_snis.size() ? "," : "") << "\n";
            }
            json_file << "  ]\n";
            json_file << "}\n";
            json_file.close();
            std::cout << "\nJSON statistics report exported to: " << json_export_path << "\n";
        } else {
            std::cerr << "Error: Could not write JSON statistics to " << json_export_path << "\n";
        }
    }
    
    std::cout << "\nOutput written to: " << output_file << "\n";
    return 0;
}

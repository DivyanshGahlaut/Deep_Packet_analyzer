#include <iostream>
#include <iomanip>
#include <ctime>
#include "sentry_pcap_reader.h"
#include "sentry_packet_parser.h"

using namespace FlowSentry;

void printPacketSummary(const SentryPacket& pkt, int packet_num) {
    std::time_t time = pkt.timestamp_sec;
    std::tm* tm = std::localtime(&time);
    
    std::cout << "\n--- [FlowSentry] Packet #" << packet_num << " ---\n";
    std::cout << "Time: " << std::put_time(tm, "%Y-%m-%d %H:%M:%S") 
              << "." << std::setfill('0') << std::setw(6) << pkt.timestamp_usec << "\n";
    
    std::cout << "[Ethernet Header]\n";
    std::cout << "  Source MAC:      " << pkt.src_mac << "\n";
    std::cout << "  Destination MAC: " << pkt.dest_mac << "\n";
    std::cout << "  EtherType:       0x" << std::hex << std::setfill('0') 
              << std::setw(4) << pkt.ether_type << std::dec;
    
    if (pkt.ether_type == EtherType::IPv4) {
        std::cout << " (IPv4)";
    } else if (pkt.ether_type == EtherType::IPv6) {
        std::cout << " (IPv6)";
    } else if (pkt.ether_type == EtherType::ARP) {
        std::cout << " (ARP)";
    }
    std::cout << "\n";
    
    if (pkt.has_ip) {
        std::cout << "[IPv" << static_cast<int>(pkt.ip_version) << " Header]\n";
        std::cout << "  Source IP:      " << pkt.src_ip << "\n";
        std::cout << "  Destination IP: " << pkt.dest_ip << "\n";
        std::cout << "  Protocol:       " << LayerParser::protocolToString(pkt.protocol) << "\n";
        std::cout << "  TTL:            " << static_cast<int>(pkt.ttl) << "\n";
    }
    
    if (pkt.has_tcp) {
        std::cout << "[TCP Header]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
        std::cout << "  Sequence Number:  " << pkt.seq_number << "\n";
        std::cout << "  Ack Number:       " << pkt.ack_number << "\n";
        std::cout << "  Flags:            " << LayerParser::tcpFlagsToString(pkt.tcp_flags) << "\n";
    }
    
    if (pkt.has_udp) {
        std::cout << "[UDP Header]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
    }
    
    if (pkt.payload_length > 0) {
        std::cout << "[Payload Data]\n";
        std::cout << "  Length: " << pkt.payload_length << " bytes\n";
        
        std::cout << "  Preview: ";
        size_t preview_len = std::min(pkt.payload_length, static_cast<size_t>(32));
        for (size_t i = 0; i < preview_len; i++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) 
                      << static_cast<int>(pkt.payload_data[i]) << " ";
        }
        if (pkt.payload_length > 32) {
            std::cout << "...";
        }
        std::cout << std::dec << "\n";
    }
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <pcap_file> [max_packets]\n";
    std::cout << "\nArguments:\n";
    std::cout << "  pcap_file   - Path to a .pcap file captured by Wireshark\n";
    std::cout << "  max_packets - (Optional) Maximum number of packets to display\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " capture.pcap\n";
    std::cout << "  " << program_name << " capture.pcap 10\n";
}

int main(int argc, char* argv[]) {
    std::cout << "┌────────────────────────────────────┐\n";
    std::cout << "│     FlowSentry Packet Viewer       │\n";
    std::cout << "└────────────────────────────────────┘\n\n";
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string filename = argv[1];
    int max_packets = -1;
    
    if (argc >= 3) {
        max_packets = std::stoi(argv[2]);
    }
    
    CaptureReader reader;
    if (!reader.open(filename)) {
        return 1;
    }
    
    std::cout << "\n--- Reading packets ---\n";
    
    SentryRawPacket raw_packet;
    SentryPacket parsed_packet;
    int packet_count = 0;
    int parse_errors = 0;
    
    while (reader.readNextPacket(raw_packet)) {
        packet_count++;
        
        if (LayerParser::parse(raw_packet, parsed_packet)) {
            printPacketSummary(parsed_packet, packet_count);
        } else {
            std::cerr << "Warning: Failed to parse packet #" << packet_count << "\n";
            parse_errors++;
        }
        
        if (max_packets > 0 && packet_count >= max_packets) {
            std::cout << "\n(Stopped after " << max_packets << " packets)\n";
            break;
        }
    }
    
    std::cout << "\n====================================\n";
    std::cout << "Summary:\n";
    std::cout << "  Total packets read:  " << packet_count << "\n";
    std::cout << "  Parse errors:        " << parse_errors << "\n";
    std::cout << "====================================\n";
    
    reader.close();
    return 0;
}

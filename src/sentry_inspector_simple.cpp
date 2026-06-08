#include <iostream>
#include "sentry_pcap_reader.h"
#include "sentry_packet_parser.h"
#include "sentry_sni_extractor.h"
#include "sentry_types.h"

using namespace FlowSentry;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }
    
    CaptureReader reader;
    if (!reader.open(argv[1])) {
        return 1;
    }
    
    SentryRawPacket raw;
    SentryPacket parsed;
    int count = 0;
    int tls_count = 0;
    
    std::cout << "Processing packets...\n";
    
    while (reader.readNextPacket(raw)) {
        count++;
        
        if (!LayerParser::parse(raw, parsed)) {
            continue;
        }
        
        if (!parsed.has_ip) continue;
        
        std::cout << "Packet " << count << ": " 
                  << parsed.src_ip << ":" << parsed.src_port
                  << " -> " << parsed.dest_ip << ":" << parsed.dest_port;
        
        if (parsed.has_tcp && parsed.dest_port == 443 && parsed.payload_length > 0) {
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
            payload_offset += tcp_offset * 4;
            
            if (payload_offset < raw.data.size()) {
                size_t payload_len = raw.data.size() - payload_offset;
                auto sni = PayloadInspector::extract(raw.data.data() + payload_offset, payload_len);
                if (sni) {
                    std::cout << " [SNI: " << *sni << "]";
                    tls_count++;
                }
            }
        }
        
        std::cout << "\n";
    }
    
    std::cout << "\nTotal packets: " << count << "\n";
    std::cout << "SNI extracted: " << tls_count << "\n";
    
    reader.close();
    return 0;
}

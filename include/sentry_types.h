#ifndef SENTRY_TYPES_H
#define SENTRY_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include "sentry_optional_compat.h"

namespace FlowSentry {

// ============================================================================
// FlowKey: Uniquely identifies a connection/flow (5-tuple)
// ============================================================================
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;  // TCP=6, UDP=17
    
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    // Create reverse flow key (for matching bidirectional flows)
    FlowKey reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;
};

// Hash function for FlowKey (used for flow tracking)
struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(key.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(key.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(key.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(key.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(key.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    SSH,
    // Specific applications (detected via SNI)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT  // Keep this last for counting
};

std::string appTypeToString(AppType type);
AppType nameToAppType(const std::string& name);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Sentry Action (what to do with the packet)
// ============================================================================
enum class SentryAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
};

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================
struct Connection {
    FlowKey key;
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;  // Server Name Indication (if detected)
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    SentryAction action = SentryAction::FORWARD;
    
    // For TCP state tracking
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
};

// ============================================================================
// Packet wrapper for flow tracking
// ============================================================================
struct PacketJob {
    uint32_t packet_id;
    FlowKey key;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload_data = nullptr;
    
    // Timestamps
    uint32_t ts_sec;
    uint32_t ts_usec;
};

// ============================================================================
// Statistics
// ============================================================================
struct SentryStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    SentryStats() = default;
    SentryStats(const SentryStats&) = delete;
    SentryStats& operator=(const SentryStats&) = delete;
};

} // namespace FlowSentry

#endif // SENTRY_TYPES_H

#ifndef SENTRY_SNI_EXTRACTOR_H
#define SENTRY_SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <vector>
#include "sentry_optional_compat.h"

namespace FlowSentry {

// ============================================================================
// PayloadInspector - Parses TLS Client Hello to extract Server Name Indication
// ============================================================================
class PayloadInspector {
public:
    // Extract SNI from a TLS Client Hello packet
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Check if this looks like a TLS Client Hello
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    
    // Extract all extensions (for debugging/logging)
    static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

private:
    // TLS Constants
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;
    
    // Helper to read big-endian values
    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

// ============================================================================
// QuicInspector - For QUIC/HTTP3 traffic
// ============================================================================
class QuicInspector {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isQUICInitial(const uint8_t* payload, size_t length);
};

// ============================================================================
// HttpHostInspector (for unencrypted HTTP)
// ============================================================================
class HttpHostInspector {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

// ============================================================================
// DnsInspector (to extract domain query names)
// ============================================================================
class DnsInspector {
public:
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace FlowSentry

#endif // SENTRY_SNI_EXTRACTOR_H

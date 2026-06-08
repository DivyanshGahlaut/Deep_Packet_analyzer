#ifndef SENTRY_RULE_MANAGER_H
#define SENTRY_RULE_MANAGER_H

#include "sentry_types.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <vector>
#include <fstream>
#include "sentry_optional_compat.h"

namespace FlowSentry {

// ============================================================================
// SentryRulesManager - Manages filtering and blocking rules
// ============================================================================
class SentryRulesManager {
public:
    SentryRulesManager() = default;
    
    // ========== IP Blocking ==========
    void blockIP(uint32_t ip);
    void blockIP(const std::string& ip);
    void unblockIP(uint32_t ip);
    void unblockIP(const std::string& ip);
    bool isIPBlocked(uint32_t ip) const;
    std::vector<std::string> getBlockedIPs() const;
    
    // ========== Application Blocking ==========
    void blockApp(AppType app);
    void unblockApp(AppType app);
    bool isAppBlocked(AppType app) const;
    std::vector<AppType> getBlockedApps() const;
    
    // ========== Domain Blocking ==========
    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;
    std::vector<std::string> getBlockedDomains() const;
    
    // ========== Port Blocking ==========
    void blockPort(uint16_t port);
    void unblockPort(uint16_t port);
    bool isPortBlocked(uint16_t port) const;
    
    // ========== Combined Check ==========
    struct FilterReason {
        enum Type { IP, APP, DOMAIN, PORT } type;
        std::string detail;
    };
    
    std::optional<FilterReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain) const;
    
    // ========== Rule Persistence ==========
    bool saveRules(const std::string& filename) const;
    bool loadRules(const std::string& filename);
    void clearAll();
    
    // ========== Statistics ==========
    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
    };
    
    RuleStats getStats() const;

private:
    mutable std::shared_mutex ip_mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    
    mutable std::shared_mutex app_mutex_;
    std::unordered_set<AppType> blocked_apps_;
    
    mutable std::shared_mutex domain_mutex_;
    std::unordered_set<std::string> blocked_domains_;
    std::vector<std::string> domain_patterns_;  // For wildcard matching
    
    mutable std::shared_mutex port_mutex_;
    std::unordered_set<uint16_t> blocked_ports_;
    
    static uint32_t parseIP(const std::string& ip);
    static std::string ipToString(uint32_t ip);
    static bool domainMatchesPattern(const std::string& domain, const std::string& pattern);
};

} // namespace FlowSentry

#endif // SENTRY_RULE_MANAGER_H

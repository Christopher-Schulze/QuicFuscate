#pragma once

/**
 * @file DoH.hpp
 * @brief DNS-over-HTTPS Stealth Integration - Simplified and Unified
 * 
 * This file consolidates DNS-over-HTTPS functionality with stealth features
 * for QuicFuscate operations. It provides a clean, simple interface for
 * DNS resolution with built-in stealth capabilities.
 */

#include "QuicFuscate_Stealth.hpp"
#include "uTLS.hpp"
#include "anti_fingerprinting.hpp"
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <optional>
#include <future>
#include <chrono>

namespace quicfuscate::stealth {

/**
 * @brief DNS resolver types
 */
enum class DNSResolverType {
    SYSTEM,    ///< System DNS resolver
    DOH,       ///< DNS-over-HTTPS
    DOQ,       ///< DNS-over-QUIC
    DOT        ///< DNS-over-TLS
};

/**
 * @brief DNS record types
 */
enum class DNSRecordType {
    A,      ///< IPv4 address
    AAAA,   ///< IPv6 address
    CNAME,  ///< Canonical name
    MX,     ///< Mail exchange
    TXT,    ///< Text record
    NS,     ///< Nameserver
    SOA,    ///< Start of Authority
    PTR,    ///< Pointer
    SRV,    ///< Service
    CAA     ///< Certification Authority Authorization
};

/**
 * @brief Browser profile for DNS requests
 */
enum class BrowserProfile {
    CHROME_WINDOWS,
    CHROME_MACOS,
    FIREFOX_WINDOWS,
    FIREFOX_MACOS,
    SAFARI_MACOS,
    EDGE_WINDOWS,
    RANDOM
};

/**
 * @brief DNS query result
 */
struct DNSResult {
    std::string domain;
    DNSRecordType type;
    std::vector<std::string> addresses;
    uint32_t ttl;
    std::chrono::steady_clock::time_point timestamp;
    bool success;
    std::string error_message;
};

/**
 * @brief DoH configuration
 */
struct DoHConfig {
    std::string doh_server = "https://1.1.1.1/dns-query";  // Cloudflare DoH
    std::string backup_server = "https://8.8.8.8/dns-query"; // Google DoH
    BrowserProfile browser_profile = BrowserProfile::CHROME_WINDOWS;
    bool enable_stealth = true;
    bool enable_caching = true;
    bool randomize_queries = true;
    uint32_t timeout_ms = 5000;
    uint32_t max_retries = 3;
    bool use_http3 = true;
    bool enable_padding = true;
};

/**
 * @brief Unified DNS-over-HTTPS client with stealth capabilities
 */
class DoHClient {
public:
    DoHClient();
    ~DoHClient() = default;
    
    /**
     * @brief Initialize DoH client with configuration
     */
    bool initialize(const DoHConfig& config);
    
    /**
     * @brief Resolve domain name
     */
    std::future<DNSResult> resolve_async(const std::string& domain, 
                                        DNSRecordType type = DNSRecordType::A);
    
    /**
     * @brief Synchronous resolve
     */
    DNSResult resolve(const std::string& domain, 
                     DNSRecordType type = DNSRecordType::A);
    
    /**
     * @brief Batch resolve multiple domains
     */
    std::vector<std::future<DNSResult>> resolve_batch(const std::vector<std::string>& domains,
                                                     DNSRecordType type = DNSRecordType::A);
    
    /**
     * @brief Clear DNS cache
     */
    void clear_cache();
    
    /**
     * @brief Set custom DoH server
     */
    void set_doh_server(const std::string& server_url);
    
    /**
     * @brief Enable/disable stealth mode
     */
    void set_stealth_enabled(bool enabled);
    
    /**
     * @brief Get cache statistics
     */
    std::map<std::string, uint64_t> get_cache_stats() const;
    
private:
    DoHConfig config_;
    std::unique_ptr<QuicFuscateUnified> quicfuscate_engine_;
    std::unique_ptr<AntiFingerprinting> anti_fingerprint_;
    
    // DNS cache
    mutable std::mutex cache_mutex_;
    std::map<std::string, DNSResult> dns_cache_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    uint64_t queries_sent_;
    uint64_t cache_hits_;
    uint64_t cache_misses_;
    
    /**
     * @brief Create DoH query packet
     */
    std::vector<uint8_t> create_doh_query(const std::string& domain, DNSRecordType type);
    
    /**
     * @brief Parse DoH response
     */
    DNSResult parse_doh_response(const std::vector<uint8_t>& response, 
                                const std::string& domain, DNSRecordType type);
    
    /**
     * @brief Generate browser-specific headers
     */
    std::map<std::string, std::string> generate_headers();
    
    /**
     * @brief Check cache for existing result
     */
    std::optional<DNSResult> check_cache(const std::string& domain, DNSRecordType type);
    
    /**
     * @brief Store result in cache
     */
    void store_in_cache(const DNSResult& result);
    
    /**
     * @brief Apply stealth techniques to query
     */
    void apply_stealth_techniques(std::vector<uint8_t>& query);
};

/**
 * @brief Global DoH client instance
 */
extern std::unique_ptr<DoHClient> g_doh_client;

/**
 * @brief Initialize global DoH client
 */
bool initialize_doh(const DoHConfig& config = DoHConfig{});

/**
 * @brief Quick resolve function using global client
 */
DNSResult quick_resolve(const std::string& domain, DNSRecordType type = DNSRecordType::A);

/**
 * @brief Shutdown DoH client
 */
void shutdown_doh();

} // namespace quicfuscate::stealth

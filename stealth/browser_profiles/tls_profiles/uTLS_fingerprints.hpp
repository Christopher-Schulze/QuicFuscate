/**
 * @file uTLS_fingerprints.hpp
 * @brief uTLS fingerprints for QuicFuscate stealth operations
 * 
 * This file consolidates all browser fingerprinting and TLS profile 
 * functionality into a single unified interface.
 */

#ifndef UTLS_FINGERPRINTS_HPP
#define UTLS_FINGERPRINTS_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <random>
#include <chrono>
#include <unordered_map>
#include "../../QuicFuscate_Stealth.hpp"
#include "../../uTLS.hpp"

namespace quicfuscate::stealth {

/**
 * @brief Browser types for fingerprinting
 */
enum class BrowserType {
    CHROME_LATEST,
    CHROME_STABLE,
    FIREFOX_LATEST,
    FIREFOX_ESR,
    SAFARI_LATEST,
    EDGE_LATEST,
    OPERA_LATEST,
    UNKNOWN
};

/**
 * @brief Operating system types
 */
enum class OperatingSystem {
    WINDOWS_10,
    WINDOWS_11,
    MACOS_MONTEREY,
    MACOS_VENTURA,
    UBUNTU_20_04,
    UBUNTU_22_04,
    UNKNOWN
};

/**
 * @brief TLS cipher suite information
 */
struct CipherSuite {
    uint16_t id;
    std::string name;
    bool is_secure;
    int priority;
};

/**
 * @brief TLS extension information
 */
struct TLSExtension {
    uint16_t type;
    std::vector<uint8_t> data;
    bool is_critical;
};

/**
 * @brief Browser fingerprint data
 */
struct BrowserFingerprint {
    BrowserType browser;
    OperatingSystem os;
    std::string user_agent;
    std::vector<std::string> accept_languages;
    std::vector<std::string> accept_encodings;
    std::map<std::string, std::string> default_headers;
    std::vector<CipherSuite> cipher_suites;
    std::vector<TLSExtension> tls_extensions;
    std::vector<std::string> alpn_protocols;
    
    // HTTP/3 specific
    std::map<std::string, uint64_t> http3_settings;
    std::vector<std::string> qpack_static_table_entries;
    uint32_t max_header_list_size;
    uint32_t initial_window_size;
    
    // Timing characteristics
    uint32_t min_request_interval_ms;
    uint32_t max_request_interval_ms;
    double connection_reuse_probability;
};

/**
 * @brief Fake headers generator for HTTP/3 masquerading
 */
class FakeHeaders {
public:
    FakeHeaders();
    ~FakeHeaders() = default;
    
    /**
     * @brief Generate fake headers for a specific browser profile
     */
    std::map<std::string, std::string> generate_headers(
        BrowserType browser,
        OperatingSystem os,
        const std::string& target_domain = ""
    );
    
    /**
     * @brief Inject fake headers into QPACK-encoded header block
     */
    std::vector<uint8_t> inject_fake_headers_qpack(
        const std::vector<uint8_t>& original_headers,
        BrowserType browser
    );
    
    /**
     * @brief Generate realistic HTTP/3 settings
     */
    std::map<std::string, uint64_t> generate_http3_settings(BrowserType browser);
    
private:
    std::mt19937 rng_;
    std::unique_ptr<QpackCodec> qpack_codec_;
    
    std::map<std::string, std::string> get_chrome_headers(OperatingSystem os);
    std::map<std::string, std::string> get_firefox_headers(OperatingSystem os);
    std::map<std::string, std::string> get_safari_headers(OperatingSystem os);
    std::map<std::string, std::string> get_edge_headers(OperatingSystem os);
};

// Forward declaration of UTLSImplementation from uTLS.hpp
class UTLSImplementation;

/**
 * @brief uTLS profiles for TLS fingerprinting evasion
 * This is a wrapper around the new UTLSImplementation for backward compatibility
 */
class UTLSProfiles {
public:
    UTLSProfiles();
    ~UTLSProfiles() = default;
    
    /**
     * @brief Get TLS configuration for specific browser
     */
    std::vector<CipherSuite> get_cipher_suites(BrowserType browser);
    
    /**
     * @brief Get TLS extensions for specific browser
     */
    std::vector<TLSExtension> get_tls_extensions(BrowserType browser, OperatingSystem os);
    
    /**
     * @brief Generate randomized TLS ClientHello
     */
    std::vector<uint8_t> generate_client_hello(
        BrowserType browser,
        OperatingSystem os,
        const std::string& server_name
    );
    
    /**
     * @brief Apply browser-specific TLS configuration
     */
    bool apply_browser_profile(void* ssl_ctx, BrowserType browser);
    
private:
    std::unique_ptr<UTLSImplementation> utls_implementation_;
    std::mt19937 rng_;
    
    void initialize_utls_implementation();
    BrowserType map_to_browser_type(BrowserType browser);
    OperatingSystem map_to_operating_system(OperatingSystem os);
};

/**
 * @brief Browser fingerprint factory
 */
class BrowserFingerprintFactory {
public:
    static BrowserFingerprintFactory& instance();
    
    /**
     * @brief Get fingerprint for specific browser and OS combination
     */
    BrowserFingerprint get_fingerprint(BrowserType browser, OperatingSystem os);
    
    /**
     * @brief Get random fingerprint from available profiles
     */
    BrowserFingerprint get_random_fingerprint();
    
    /**
     * @brief Register custom fingerprint
     */
    void register_fingerprint(const BrowserFingerprint& fingerprint);
    
    /**
     * @brief Get all available browser types
     */
    std::vector<BrowserType> get_available_browsers() const;
    
private:
    BrowserFingerprintFactory();
    
    std::map<std::pair<BrowserType, OperatingSystem>, BrowserFingerprint> fingerprints_;
    std::mt19937 rng_;
    
    void initialize_default_fingerprints();
    BrowserFingerprint create_chrome_fingerprint(OperatingSystem os);
    BrowserFingerprint create_firefox_fingerprint(OperatingSystem os);
    BrowserFingerprint create_safari_fingerprint(OperatingSystem os);
    BrowserFingerprint create_edge_fingerprint(OperatingSystem os);
};

/**
 * @brief Unified browser profiles manager
 */
class BrowserProfilesManager {
public:
    BrowserProfilesManager();
    ~BrowserProfilesManager() = default;
    
    /**
     * @brief Initialize with specific browser profile
     */
    bool initialize(BrowserType browser, OperatingSystem os);
    
    /**
     * @brief Get current browser fingerprint
     */
    const BrowserFingerprint& get_current_fingerprint() const;
    
    /**
     * @brief Generate headers for current profile
     */
    std::map<std::string, std::string> generate_headers(const std::string& domain = "");
    
    /**
     * @brief Get TLS configuration for current profile
     */
    std::vector<CipherSuite> get_cipher_suites();
    std::vector<TLSExtension> get_tls_extensions();
    
    /**
     * @brief Rotate to new browser profile
     */
    void rotate_profile();
    
    /**
     * @brief Check if profile rotation is needed
     */
    bool should_rotate_profile() const;
    
private:
    BrowserFingerprint current_fingerprint_;
    std::unique_ptr<FakeHeaders> fake_headers_;
    std::unique_ptr<UTLSProfiles> utls_profiles_;
    std::chrono::steady_clock::time_point last_rotation_;
    std::chrono::minutes rotation_interval_;
    std::mt19937 rng_;
    
    bool is_initialized_;
};

} // namespace quicfuscate::stealth

#endif // UTLS_FINGERPRINTS_HPP
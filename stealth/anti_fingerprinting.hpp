#ifndef ANTI_FINGERPRINTING_HPP
#define ANTI_FINGERPRINTING_HPP

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <random>
#include "browser_profiles/fingerprints/browser_fingerprints.hpp"
#include "FakeTLS.hpp"
#include "uTLS.hpp"
#include "XOR_Obfuscation.hpp"
#include "DomainFronting.hpp"
#include "QuicFuscate_Stealth.hpp"

namespace quicfuscate::stealth {

/**
 * @brief Fingerprinting detection methods
 */
enum class FingerprintingMethod {
    TLS_FINGERPRINTING,
    HTTP_HEADER_ANALYSIS,
    TIMING_ANALYSIS,
    PACKET_SIZE_ANALYSIS,
    FLOW_PATTERN_ANALYSIS,
    ALPN_NEGOTIATION,
    CIPHER_SUITE_ORDERING,
    EXTENSION_ORDERING,
    CERTIFICATE_TRANSPARENCY,
    SNI_ANALYSIS,
    QUIC_TRANSPORT_PARAMS,
    HTTP3_SETTINGS_ANALYSIS,
    QPACK_TABLE_ANALYSIS,
    STREAM_PRIORITIZATION,
    CONNECTION_MIGRATION_PATTERNS
};

/**
 * @brief Anti-fingerprinting techniques
 */
enum class AntiFingerprinting {
    RANDOMIZE_TLS_EXTENSIONS,
    MIMIC_BROWSER_BEHAVIOR,
    RANDOMIZE_PACKET_TIMING,
    NORMALIZE_PACKET_SIZES,
    RANDOMIZE_CIPHER_ORDER,
    FAKE_CERTIFICATE_VALIDATION,
    RANDOMIZE_ALPN_ORDER,
    SPOOF_USER_AGENT,
    RANDOMIZE_HTTP_HEADERS,
    TRAFFIC_PADDING,
    CONNECTION_POOLING,
    DECOY_CONNECTIONS,
    TIMING_OBFUSCATION,
    FLOW_CAMOUFLAGE
};

/**
 * @brief Fingerprinting evasion configuration
 */
struct AntiFingerprinting {
    bool enable_tls_randomization = true;
    bool enable_header_randomization = true;
    bool enable_timing_randomization = true;
    bool enable_packet_padding = true;
    bool enable_flow_obfuscation = true;
    bool enable_browser_mimicry = true;
    bool enable_decoy_traffic = false;
    
    // TLS-specific settings
    bool randomize_extension_order = true;
    bool randomize_cipher_order = false;
    bool add_fake_extensions = true;
    bool randomize_session_tickets = true;
    
    // HTTP-specific settings
    bool randomize_header_order = true;
    bool add_fake_headers = true;
    bool randomize_user_agent = true;
    bool mimic_browser_headers = true;
    
    // Timing settings
    uint32_t min_request_delay_ms = 10;
    uint32_t max_request_delay_ms = 500;
    bool randomize_connection_timing = true;
    
    // Traffic padding
    uint32_t min_padding_size = 0;
    uint32_t max_padding_size = 1024;
    double padding_probability = 0.3;
    
    // Browser profile rotation
    bool auto_rotate_profiles = true;
    uint32_t profile_rotation_interval_minutes = 30;
    std::vector<BrowserType> allowed_browsers;
};

/**
 * @brief Fingerprinting detection result
 */
struct FingerprintingDetection {
    FingerprintingMethod method;
    double confidence_score = 0.0;
    std::string description;
    std::vector<std::string> indicators;
    std::chrono::steady_clock::time_point detected_at;
    std::string mitigation_suggestion;
};

/**
 * @brief Anti-fingerprinting statistics
 */
struct AntiFingerprinting {
    uint64_t total_connections = 0;
    uint64_t fingerprinting_attempts_detected = 0;
    uint64_t fingerprinting_attempts_blocked = 0;
    uint64_t browser_profiles_rotated = 0;
    uint64_t fake_headers_injected = 0;
    uint64_t timing_randomizations = 0;
    uint64_t packet_padding_applied = 0;
    std::map<FingerprintingMethod, uint64_t> detection_counts;
    std::map<AntiFingerprinting, uint64_t> technique_usage;
    double average_evasion_success_rate = 0.0;
};

/**
 * @brief Traffic pattern analysis
 */
struct TrafficPattern {
    std::vector<uint32_t> packet_sizes;
    std::vector<uint64_t> inter_packet_delays_us;
    std::vector<std::string> request_headers;
    std::string tls_fingerprint;
    std::string http_fingerprint;
    uint64_t connection_duration_ms = 0;
    uint32_t total_bytes_sent = 0;
    uint32_t total_bytes_received = 0;
};

/**
 * @brief Advanced anti-fingerprinting engine
 */
class AntiFingerprinting {
public:
    /**
     * @brief Create a new AntiFingerprinting instance
     * @param config Initial configuration
     * @return std::unique_ptr to AntiFingerprinting instance
     */
    static std::unique_ptr<AntiFingerprinting> create(const AntiFingerprinting& config = {});

    /**
     * @brief Virtual destructor
     */
    virtual ~AntiFingerprinting() = default;

    /**
     * @brief Analyze traffic for fingerprinting attempts
     * @param pattern Traffic pattern to analyze
     * @return Vector of detected fingerprinting attempts
     */
    virtual std::vector<FingerprintingDetection> analyze_traffic(const TrafficPattern& pattern) = 0;

    /**
     * @brief Apply anti-fingerprinting techniques to TLS configuration
     * @param ssl_ctx OpenSSL context to modify
     * @param browser_profile Target browser profile
     * @return true if successful
     */
    virtual bool apply_tls_anti_fingerprinting(SSL_CTX* ssl_ctx, BrowserType browser_profile) = 0;

    /**
     * @brief Apply anti-fingerprinting techniques to HTTP headers
     * @param headers Original headers
     * @param browser_profile Target browser profile
     * @return Modified headers with anti-fingerprinting applied
     */
    virtual std::map<std::string, std::string> apply_header_anti_fingerprinting(
        const std::map<std::string, std::string>& headers, BrowserType browser_profile) = 0;

    /**
     * @brief Generate randomized packet timing
     * @param base_delay_ms Base delay in milliseconds
     * @return Randomized delay in milliseconds
     */
    virtual uint32_t generate_randomized_timing(uint32_t base_delay_ms) = 0;

    /**
     * @brief Apply packet padding for size normalization
     * @param packet_data Original packet data
     * @param target_size Target packet size (0 for random)
     * @return Padded packet data
     */
    virtual std::vector<uint8_t> apply_packet_padding(const std::vector<uint8_t>& packet_data, 
                                                      uint32_t target_size = 0) = 0;

    /**
     * @brief Generate decoy traffic to confuse fingerprinting
     * @param connection_context Context for generating realistic decoy traffic
     * @return Decoy traffic data
     */
    virtual std::vector<std::vector<uint8_t>> generate_decoy_traffic(
        const std::string& connection_context) = 0;

    /**
     * @brief Rotate browser profile for anti-fingerprinting
     * @param force_rotation Force rotation even if interval hasn't passed
     * @return New browser profile
     */
    virtual BrowserType rotate_browser_profile(bool force_rotation = false) = 0;

    /**
     * @brief Check if fingerprinting evasion is needed
     * @param traffic_pattern Current traffic pattern
     * @return true if evasion techniques should be applied
     */
    virtual bool should_apply_evasion(const TrafficPattern& traffic_pattern) = 0;

    /**
     * @brief Update anti-fingerprinting configuration
     * @param config New configuration
     */
    virtual void update_config(const AntiFingerprinting& config) = 0;

    /**
     * @brief Get current anti-fingerprinting configuration
     * @return Current configuration
     */
    virtual AntiFingerprinting get_config() const = 0;

    /**
     * @brief Get anti-fingerprinting statistics
     * @return Current statistics
     */
    virtual AntiFingerprinting get_statistics() const = 0;

    /**
     * @brief Reset statistics counters
     */
    virtual void reset_statistics() = 0;

    /**
     * @brief Enable or disable anti-fingerprinting
     * @param enabled true to enable, false to disable
     */
    virtual void set_enabled(bool enabled) = 0;

    /**
     * @brief Check if anti-fingerprinting is enabled
     * @return true if enabled
     */
    virtual bool is_enabled() const = 0;

    /**
     * @brief Train fingerprinting detection models
     * @param training_data Vector of known traffic patterns
     * @param labels Corresponding labels (fingerprinted/clean)
     * @return true if training was successful
     */
    virtual bool train_detection_models(const std::vector<TrafficPattern>& training_data,
                                       const std::vector<bool>& labels) = 0;

    /**
     * @brief Export fingerprinting detection rules
     * @return Serialized detection rules
     */
    virtual std::string export_detection_rules() const = 0;

    /**
     * @brief Import fingerprinting detection rules
     * @param rules Serialized detection rules
     * @return true if import was successful
     */
    virtual bool import_detection_rules(const std::string& rules) = 0;
};

/**
 * @brief TLS fingerprint randomizer
 */
class TLSFingerprintRandomizer {
public:
    virtual ~TLSFingerprintRandomizer() = default;
    
    /**
     * @brief Randomize TLS extension order
     * @param ssl_ctx OpenSSL context
     * @return true if successful
     */
    virtual bool randomize_extension_order(SSL_CTX* ssl_ctx) = 0;
    
    /**
     * @brief Add fake TLS extensions
     * @param ssl_ctx OpenSSL context
     * @param browser_profile Target browser profile
     * @return true if successful
     */
    virtual bool add_fake_extensions(SSL_CTX* ssl_ctx, BrowserType browser_profile) = 0;
    
    /**
     * @brief Randomize cipher suite order
     * @param ssl_ctx OpenSSL context
     * @return true if successful
     */
    virtual bool randomize_cipher_order(SSL_CTX* ssl_ctx) = 0;
};

/**
 * @brief HTTP fingerprint randomizer
 */
class HTTPFingerprintRandomizer {
public:
    virtual ~HTTPFingerprintRandomizer() = default;
    
    /**
     * @brief Randomize HTTP header order
     * @param headers Original headers
     * @return Headers with randomized order
     */
    virtual std::map<std::string, std::string> randomize_header_order(
        const std::map<std::string, std::string>& headers) = 0;
    
    /**
     * @brief Add fake HTTP headers
     * @param headers Original headers
     * @param browser_profile Target browser profile
     * @return Headers with fake headers added
     */
    virtual std::map<std::string, std::string> add_fake_headers(
        const std::map<std::string, std::string>& headers, BrowserType browser_profile) = 0;
    
    /**
     * @brief Generate randomized User-Agent
     * @param base_browser Browser to base User-Agent on
     * @return Randomized User-Agent string
     */
    virtual std::string generate_randomized_user_agent(BrowserType base_browser) = 0;
};

/**
 * @brief Utility functions for anti-fingerprinting
 */
namespace anti_fingerprinting_utils {
    /**
     * @brief Convert fingerprinting method enum to string
     * @param method Fingerprinting method
     * @return String representation
     */
    std::string method_to_string(FingerprintingMethod method);
    
    /**
     * @brief Convert anti-fingerprinting technique enum to string
     * @param technique Anti-fingerprinting technique
     * @return String representation
     */
    std::string technique_to_string(AntiFingerprinting technique);
    
    /**
     * @brief Calculate traffic pattern similarity
     * @param pattern1 First traffic pattern
     * @param pattern2 Second traffic pattern
     * @return Similarity score (0.0 to 1.0)
     */
    double calculate_pattern_similarity(const TrafficPattern& pattern1, const TrafficPattern& pattern2);
    
    /**
     * @brief Generate random bytes for padding
     * @param size Number of bytes to generate
     * @return Random byte vector
     */
    std::vector<uint8_t> generate_random_padding(uint32_t size);
    
    /**
     * @brief Validate anti-fingerprinting configuration
     * @param config Configuration to validate
     * @return true if configuration is valid
     */
    bool validate_config(const AntiFingerprinting& config);
    
    /**
     * @brief Get recommended anti-fingerprinting techniques for threat level
     * @param threat_level Threat level (0.0 to 1.0)
     * @return Recommended techniques
     */
    std::vector<AntiFingerprinting> get_recommended_techniques(double threat_level);
}

} // namespace quicfuscate::stealth

#endif // ANTI_FINGERPRINTING_HPP

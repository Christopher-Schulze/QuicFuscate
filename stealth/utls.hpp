#ifndef UTLS_HPP
#define UTLS_HPP

#include <string>
#include <vector>
#include <memory>
#include <random>
#include <mutex>
#include <thread>
#include <chrono>
#include <map>
#include <algorithm>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <dlfcn.h>
#include <cstring>

// Forward declarations
struct quiche_config;
struct quiche_conn;
struct sockaddr;
typedef unsigned int socklen_t;

namespace quicfuscate {

// ========== INTEGRATED UTLSClientConfigurator TYPES ==========

// Definition der unterstützten Browser-Fingerprint-Typen
enum class BrowserFingerprint {
    // Desktop-Browser (neueste Versionen)
    CHROME_LATEST,         // Chrome neueste Version (120+, Mai 2024)
    FIREFOX_LATEST,        // Firefox neueste Version (125+, Mai 2024)
    SAFARI_LATEST,         // Safari neueste Version (17+, Mai 2024)
    EDGE_CHROMIUM,         // Microsoft Edge Chromium (123+, Mai 2024)
    BRAVE_LATEST,          // Brave Browser (neueste Version)
    OPERA_LATEST,          // Opera Browser (neueste Version)
    
    // Ältere Versionen für Kompatibilität
    CHROME_70,             // Chrome 70 (für Legacy-Systeme)
    FIREFOX_63,            // Firefox 63 (für Legacy-Systeme)
    
    // Mobile Browser
    CHROME_ANDROID,        // Chrome für Android
    SAFARI_IOS,            // Safari für iOS
    SAMSUNG_BROWSER,       // Samsung Internet Browser
    FIREFOX_MOBILE,        // Firefox für Mobile
    EDGE_MOBILE,           // Edge für Mobile
    
    // Spezialisierte Clients
    OUTLOOK,               // Microsoft Outlook Client
    THUNDERBIRD,           // Mozilla Thunderbird
    CURL,                  // cURL-ähnlicher Client
    
    // Spezielle Werte
    RANDOMIZED,            // Zufällige Auswahl aus verfügbaren Profilen
    CUSTOM                 // Benutzerdefiniertes Profil
};

// Browser type enumeration
enum class BrowserType {
    CHROME,
    FIREFOX,
    SAFARI,
    EDGE,
    BRAVE,
    OPERA,
    SAMSUNG,
    UNKNOWN
};

// Operating system enumeration
enum class OperatingSystem {
    WINDOWS,
    MACOS,
    LINUX,
    ANDROID,
    IOS,
    UNKNOWN
};

// Rotation strategy enumeration
enum class RotationStrategy {
    SEQUENTIAL,
    RANDOM,
    TIME_BASED,
    CONNECTION_BASED
};

// Struktur für TLS-Cipher-Suites
struct CipherSuite {
    uint16_t id;
    std::string name;
    bool is_grease;
    
    CipherSuite(uint16_t suite_id, const std::string& suite_name, bool grease = false)
        : id(suite_id), name(suite_name), is_grease(grease) {}
};

// Struktur für TLS-Extensions
struct TLSExtension {
    uint16_t type;
    std::vector<uint8_t> data;
    bool is_grease;
    
    TLSExtension(uint16_t ext_type, const std::vector<uint8_t>& ext_data, bool grease = false)
        : type(ext_type), data(ext_data), is_grease(grease) {}
};

// Struktur für Elliptic Curve Groups
struct ECGroup {
    uint16_t id;
    std::string name;
    bool is_grease;
    
    ECGroup(uint16_t group_id, const std::string& group_name, bool grease = false)
        : id(group_id), name(group_name), is_grease(grease) {}
};

// Struktur für Signature Algorithms
struct SignatureAlgorithm {
    uint16_t id;
    std::string name;
    bool is_grease;
    
    SignatureAlgorithm(uint16_t alg_id, const std::string& alg_name, bool grease = false)
        : id(alg_id), name(alg_name), is_grease(grease) {}
};

// Struktur für ALPN-Protokolle
struct ALPNProtocol {
    std::string name;
    uint8_t length;
    
    ALPNProtocol(const std::string& protocol_name)
        : name(protocol_name), length(static_cast<uint8_t>(protocol_name.length())) {}
};

// Struktur für ein vollständiges Browser-Fingerprint-Profil
struct FingerprintProfile {
    BrowserFingerprint type;
    std::string user_agent;
    std::vector<CipherSuite> cipher_suites;
    std::vector<TLSExtension> extensions;
    std::vector<ECGroup> ec_groups;
    std::vector<SignatureAlgorithm> signature_algorithms;
    std::vector<ALPNProtocol> alpn_protocols;
    uint16_t tls_version_min;
    uint16_t tls_version_max;
    bool supports_session_tickets;
    bool supports_early_data;
    bool supports_psk;
    std::map<std::string, std::string> additional_headers;
    
    // GREASE-Konfiguration
    bool use_grease;
    std::vector<uint16_t> grease_cipher_suites;
    std::vector<uint16_t> grease_extensions;
    std::vector<uint16_t> grease_ec_groups;
    std::vector<uint16_t> grease_signature_algorithms;
    
    FingerprintProfile()
        : type(BrowserFingerprint::CHROME_LATEST),
          tls_version_min(0x0303), // TLS 1.2
          tls_version_max(0x0304), // TLS 1.3
          supports_session_tickets(true),
          supports_early_data(false),
          supports_psk(false),
          use_grease(true) {}
};

// Struktur für Session-Ticket-Konfiguration
struct SessionTicketConfig {
    bool enabled;
    uint32_t lifetime_hint;
    std::vector<uint8_t> ticket_key;
    std::string ticket_file_path;
    bool auto_save;
    
    SessionTicketConfig()
        : enabled(true),
          lifetime_hint(7200), // 2 Stunden
          auto_save(true) {}
};

// Struktur für PSK-Konfiguration
struct PSKConfig {
    bool enabled;
    std::string identity;
    std::vector<uint8_t> key;
    std::string cipher_suite;
    uint32_t max_early_data;
    
    PSKConfig()
        : enabled(false),
          max_early_data(0) {}
};

// ========== QUICHE WRAPPER TYPES ==========

// SSL_QUIC_METHOD structure for QUIC integration
struct SSL_QUIC_METHOD {
    int (*set_read_secret)(SSL *ssl, int level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
    int (*set_write_secret)(SSL *ssl, int level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
    int (*add_handshake_data)(SSL *ssl, int level, const uint8_t *data, size_t len);
    int (*flush_flight)(SSL *ssl);
    int (*send_alert)(SSL *ssl, int level, uint8_t alert);
};

// ========== FINGERPRINT ROTATOR TYPES ==========

// Forward declaration for UTLSClientConfigurator
class UTLSClientConfigurator;

// Fingerprint rotator class for automatic rotation of TLS fingerprints
class FingerprintRotator {
public:
    // Constructors
    FingerprintRotator();
    FingerprintRotator(const std::vector<BrowserFingerprint>& fingerprints, 
                      RotationStrategy strategy = RotationStrategy::RANDOM,
                      std::chrono::minutes rotation_interval = std::chrono::minutes(60));
    
    // Destructor
    ~FingerprintRotator();
    
    // Rotation control
    void start_rotation();
    void stop_rotation();
    
    // Fingerprint management
    void add_fingerprint(BrowserFingerprint fingerprint);
    void remove_fingerprint(BrowserFingerprint fingerprint);
    void set_fingerprints(const std::vector<BrowserFingerprint>& fingerprints);
    
    // Configuration
    void set_strategy(RotationStrategy strategy);
    void set_rotation_interval(std::chrono::minutes interval);
    
    // Current state
    BrowserFingerprint get_current_fingerprint();
    BrowserFingerprint rotate_to_next();
    
    // Apply to configurator
    bool apply_to_configurator(UTLSClientConfigurator& configurator, const std::string& hostname);
    
private:
    std::vector<BrowserFingerprint> fingerprints_;
    size_t current_index_;
    BrowserFingerprint current_fingerprint_;
    RotationStrategy strategy_;
    std::chrono::minutes rotation_interval_;
    std::chrono::steady_clock::time_point last_rotation_;
    
    // Threading
    std::thread rotation_thread_;
    std::mutex mutex_;
    bool rotation_active_;
    
    // Random number generation
    std::mt19937 rng_;
    
    // Helper methods
    void rotation_thread_function();
    BrowserFingerprint select_next_fingerprint();
    BrowserFingerprint get_time_based_fingerprint();
};

// ========== SESSION MANAGEMENT ==========

// Session manager for handling TLS session tickets
class SessionManager {
public:
    bool save_session_ticket(const std::string& hostname, const std::vector<uint8_t>& ticket);
    bool load_session_ticket(const std::string& hostname, std::vector<uint8_t>& ticket);
    void clear_session_tickets();
    size_t get_session_count() const;
    
private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<uint8_t>> session_tickets_;
};

// ========== STATISTICS ==========

// Handshake statistics structure
struct HandshakeStats {
    uint64_t total_handshakes = 0;
    uint64_t successful_handshakes = 0;
    uint64_t failed_handshakes = 0;
    double average_handshake_time = 0.0;
    std::chrono::steady_clock::time_point last_handshake;
};

// ========== ADVANCED CONFIGURATION ==========

// Certificate pinning configuration
struct CertificatePinning {
    bool enabled = false;
    std::vector<std::string> sha256_pins;
    std::vector<std::string> sha1_pins;
    bool allow_backup_pins = true;
};

// Advanced TLS configuration
struct AdvancedTLSConfig {
    bool enable_ocsp_stapling = true;
    bool enable_sct = false;
    bool enable_compression = false;
    uint32_t max_fragment_length = 0;
    bool enable_false_start = false;
    bool enable_channel_id = false;
};

// ========== UTLS CLIENT CONFIGURATOR ==========

// Main UTLSClientConfigurator class - consolidated from tls/uTLS_client_configurator.hpp
class UTLSClientConfigurator {
public:
    // Constructors and destructor
    UTLSClientConfigurator();
    ~UTLSClientConfigurator();
    
    // Initialization methods
    bool initialize(BrowserFingerprint fingerprint, const std::string& hostname, 
                   const char* ca_cert_path = nullptr, bool use_session_tickets = true);
    bool initialize(const std::string& fingerprint_profile_name, const std::string& hostname,
                   const char* ca_cert_path = nullptr, bool use_session_tickets = true);
    
    // Fingerprint management
    static std::string fingerprint_to_string(BrowserFingerprint fingerprint);
    static BrowserFingerprint string_to_fingerprint(const std::string& fingerprint_str);
    
    // Configuration methods
    bool apply_fingerprint_profile(BrowserFingerprint fingerprint);
    bool set_sni(const std::string& hostname);
    bool configure_for_quiche(quiche_config* config);
    
    // SSL/TLS methods
    SSL_CTX* get_ssl_ctx() const { return ssl_ctx_; }
    SSL* get_ssl_connection() const { return ssl_conn_; }
    quiche_config* get_quiche_config() const { return q_config_; }
    
    // Extension generation methods
    void generate_server_name_indication(unsigned char** out, size_t* outlen, const std::string& hostname);
    void generate_alpn_extension(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_supported_groups(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_signature_algorithms(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_supported_versions(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_psk_modes(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_key_share(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_ec_point_formats(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint);
    void generate_random_extension_data(unsigned char** out, size_t* outlen, unsigned int ext_type);
    
    // Session management
    bool enable_session_tickets(bool enable);
    bool save_session_ticket(const std::string& hostname, const std::vector<uint8_t>& ticket);
    bool load_session_ticket(const std::string& hostname, std::vector<uint8_t>& ticket);
    
    // Error handling
    std::string get_last_error() const { return last_error_; }
    
    // Static callback functions
    static int new_session_callback(SSL* ssl, SSL_SESSION* session);
    static void log_ssl_errors(const std::string& context);
    
private:
    // Member variables
    BrowserFingerprint current_fingerprint_;
    std::string current_hostname_;
    bool use_session_tickets_;
    SSL_CTX* ssl_ctx_;
    SSL* ssl_conn_;
    quiche_config* q_config_;
    std::string last_error_;
    
    // Helper methods
    void cleanup();
    bool setup_ssl_context();
    bool setup_quiche_config();
    void configure_cipher_suites(BrowserFingerprint fingerprint);
    void configure_extensions(BrowserFingerprint fingerprint);
};

// ========== QUICHE WRAPPER FUNCTIONS ==========

// Function declarations for quiche wrapper
extern "C" {
    const SSL_QUIC_METHOD* quiche_ssl_get_quic_method();
    quiche_conn* quiche_conn_new_with_tls_ctx(const uint8_t *scid, size_t scid_len,
                                             const uint8_t *odcid, size_t odcid_len,
                                             const struct sockaddr *local, socklen_t local_len,
                                             const struct sockaddr *peer, socklen_t peer_len,
                                             const quiche_config *config, void *ssl_ctx);
    int quiche_conn_set_sni(quiche_conn *conn, const char *sni);
}

// ========== UTLS MANAGER ==========

/**
 * @brief Implementation of uTLS (Undetectable TLS) for stealth QUIC connections.
 * This class allows customizing TLS ClientHello messages to mimic specific
 * browser fingerprints, making it harder to detect VPN traffic.
 */
class UTLSImplementation {
public:
    // Constructor
    explicit UTLSImplementation(BrowserType browser_type = BrowserType::CHROME, 
                              OperatingSystem os = OperatingSystem::WINDOWS_10);
    
    // Destructor
    ~UTLSImplementation();
    
    // Cleanup method
    void cleanup();
    
    // Initialize the uTLS system
    void initialize();
    
    // Set browser type and refresh fingerprint
    void set_browser_type(BrowserType browser_type);
    
    // Set operating system and refresh fingerprint
    void set_operating_system(OperatingSystem os);
    
    // Generate a ClientHello message that mimics the specified browser
    std::vector<uint8_t> generate_client_hello(const std::string& server_name = "");
    
    // Configure for QUICHE integration
    bool configure_for_quiche(quiche_config* config);
    
    // Set custom fingerprint profile
    bool set_custom_fingerprint(const FingerprintProfile& profile);
    
    // Get available browser fingerprints
    std::vector<BrowserFingerprint> get_available_fingerprints() const;
    
    // Randomize current fingerprint
    bool randomize_fingerprint();
    
    // Configure SSL connection with hostname
    bool configure_ssl_connection(SSL* ssl, const std::string& hostname);
    
    // Apply fingerprint to SSL connection
    bool apply_fingerprint_to_ssl(SSL* ssl);
    
    // Enable session tickets
    bool enable_session_tickets(bool enable);
    
    // Configure session tickets
    bool configure_session_tickets(const SessionTicketConfig& config);
    
    // Save session ticket for hostname
    bool save_session_ticket(const std::string& hostname, const std::vector<uint8_t>& ticket);
    
    // Load session ticket for hostname
    bool load_session_ticket(const std::string& hostname, std::vector<uint8_t>& ticket);
    
    // Configure PSK settings
    bool configure_psk(const PSKConfig& config);
    
    // Add PSK identity
    bool add_psk_identity(const std::string& identity, const std::vector<uint8_t>& key);
    
    // Configure certificate pinning
    bool configure_certificate_pinning(const CertificatePinning& config);
    
    // Verify certificate pin
    bool verify_certificate_pin(X509* cert);
    
    // Configure advanced TLS settings
    bool configure_advanced_tls(const AdvancedTLSConfig& config);
    
    // Enable early data (0-RTT)
    bool enable_early_data(bool enable);
    
    // Set cipher suites by name
    bool set_cipher_suites(const std::vector<std::string>& cipher_names);
    
    // Add single cipher suite
    bool add_cipher_suite(const std::string& cipher_name);
    
    // Get supported cipher suites
    std::vector<std::string> get_supported_cipher_suites() const;
    
private:
    // Implementation details - defined in the cpp file
    BrowserType browser_type_;
    OperatingSystem os_;
    BrowserFingerprint current_fingerprint_;
    FingerprintProfile current_profile_;
    std::shared_ptr<SessionManager> session_manager_;
    bool use_session_tickets_;
    bool debug_logging_enabled_;
    int log_level_;
    SSL_CTX* ssl_ctx_;
    SSL* ssl_conn_;
    quiche_config* q_config_;
    std::string current_hostname_;
    std::string last_error_;
    
    // Random number generation
    std::random_device random_device_;
    std::mt19937 random_engine_;
    
    // Fingerprint data
    std::shared_ptr<void> fingerprint_;
    
    // Session ticket configuration
    SessionTicketConfig session_config_;
    
    // PSK configuration
    PSKConfig psk_config_;
    
    // Certificate pinning configuration
    CertificatePinning cert_pinning_;
    
    // Advanced TLS configuration
    AdvancedTLSConfig advanced_config_;
    
    // Static flag for OpenSSL initialization
    static bool openssl_initialized_;
    
    // Helper methods
    void initialize_fingerprint_profile(BrowserFingerprint fingerprint);
    bool apply_fingerprint_to_quiche();
    void configure_cipher_suites(SSL* ssl);
    void configure_tls_extensions(SSL* ssl);
    void configure_signature_algorithms(SSL* ssl);
    void configure_supported_groups(SSL* ssl);
    void configure_alpn(SSL* ssl);
    void apply_browser_specific_modifications(std::vector<uint8_t>& client_hello);
    void apply_chrome_modifications(std::vector<uint8_t>& client_hello);
    void apply_firefox_modifications(std::vector<uint8_t>& client_hello);
    void apply_safari_modifications(std::vector<uint8_t>& client_hello);
    void apply_edge_modifications(std::vector<uint8_t>& client_hello);
    size_t find_extensions_offset(const std::vector<uint8_t>& client_hello);
    void reorder_extensions(std::vector<uint8_t>& client_hello, size_t extensions_offset,
                          const std::vector<uint16_t>& priority_extensions);
    void replace_ec_point_formats(std::vector<uint8_t>& client_hello, 
                                const std::vector<uint8_t>& formats);
    void ensure_extension_exists(std::vector<uint8_t>& client_hello, uint16_t ext_type);
    uint16_t cipher_name_to_id(const std::string& name);
    std::vector<std::string> get_alpn_protocols() const;
};

/**
 * Factory function to create a uTLS implementation for a specific browser
 */
std::shared_ptr<UTLSImplementation> create_utls_implementation(
    BrowserType browser_type, OperatingSystem os);

// Close the namespace
}

// End of file
#endif // UTLS_HPP
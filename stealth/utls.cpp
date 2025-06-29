#include "uTLS.hpp"
#include "../fingerprints/browser_fingerprints_factory.hpp"
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <random>
#include <chrono>
#include <memory>
#include <stdexcept>
#include "uTLS.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <map>

namespace quicfuscate::stealth {

/**
 * Implementation of uTLS (Undetectable TLS) for stealth QUIC connections.
 * This class allows customizing TLS ClientHello messages to mimic specific
 * browser fingerprints, making it harder to detect VPN traffic.
 */
class UTLSImplementation {
public:
    // Constructor
    explicit UTLSImplementation(BrowserType browser_type = BrowserType::CHROME, 
                              OperatingSystem os = OperatingSystem::WINDOWS_10)
        : browser_type_(browser_type), os_(os), 
          current_fingerprint_(BrowserFingerprint::CHROME_LATEST),
          use_session_tickets_(true), debug_logging_enabled_(false),
          log_level_(2), ssl_ctx_(nullptr), ssl_conn_(nullptr),
          q_config_(nullptr), random_engine_(random_device_()) {
        initialize();
    }
    
    // Destructor
    ~UTLSImplementation() {
        cleanup();
    }
    
    // Cleanup method
    void cleanup() {
        if (ssl_conn_) {
            SSL_free(ssl_conn_);
            ssl_conn_ = nullptr;
        }
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
        
        // Reset other resources
        session_manager_.reset();
    }
    
    // Initialize the uTLS system
    void initialize() {
        // Create browser fingerprint
        fingerprint_ = BrowserFingerprintsFactory::create_fingerprint(browser_type_, os_);
        
        // Initialize OpenSSL if not already initialized
        if (!openssl_initialized_) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            openssl_initialized_ = true;
        }
        
        // Initialize random number generator
        std::random_device rd;
        random_engine_.seed(rd());
        
        // Initialize session manager
        session_manager_ = std::make_shared<SessionManager>();
        
        // Initialize fingerprint profile based on browser type
        switch (browser_type_) {
            case BrowserType::CHROME:
                current_fingerprint_ = BrowserFingerprint::CHROME_LATEST;
                break;
            case BrowserType::FIREFOX:
                current_fingerprint_ = BrowserFingerprint::FIREFOX_LATEST;
                break;
            case BrowserType::SAFARI:
                current_fingerprint_ = BrowserFingerprint::SAFARI_LATEST;
                break;
            case BrowserType::EDGE:
                current_fingerprint_ = BrowserFingerprint::EDGE_CHROMIUM;
                break;
            default:
                current_fingerprint_ = BrowserFingerprint::CHROME_LATEST;
                break;
        }
        
        // Initialize the fingerprint profile
        initialize_fingerprint_profile(current_fingerprint_);
    }
    
    // Set browser type and refresh fingerprint
    void set_browser_type(BrowserType browser_type) {
        if (browser_type_ != browser_type) {
            browser_type_ = browser_type;
            fingerprint_ = BrowserFingerprintsFactory::create_fingerprint(browser_type_, os_);
        }
    }
    
    // Set operating system and refresh fingerprint
    void set_operating_system(OperatingSystem os) {
        if (os_ != os) {
            os_ = os;
            fingerprint_ = BrowserFingerprintsFactory::create_fingerprint(browser_type_, os_);
        }
    }
    
    // Generate a ClientHello message that mimics the specified browser
    std::vector<uint8_t> generate_client_hello(const std::string& server_name = "") {
        // Create SSL context and configure it
        std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> ctx(
            SSL_CTX_new(TLS_client_method()),
            [](SSL_CTX* p) { if (p) SSL_CTX_free(p); }
        );
        
        if (!ctx) {
            throw std::runtime_error("Failed to create SSL context");
        }
        
        // Create SSL object
        std::unique_ptr<SSL, void(*)(SSL*)> ssl(
            SSL_new(ctx.get()),
            [](SSL* p) { if (p) SSL_free(p); }
        );
        
        if (!ssl) {
            throw std::runtime_error("Failed to create SSL object");
        }
        
        // Set up a memory BIO for writing the ClientHello
        std::unique_ptr<BIO, void(*)(BIO*)> bio(
            BIO_new(BIO_s_mem()),
            [](BIO* p) { if (p) BIO_free(p); }
        );
        
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        
        SSL_set_bio(ssl.get(), BIO_new(BIO_s_mem()), bio.get());
        
        // Set server name if provided
        if (!server_name.empty()) {
            SSL_set_tlsext_host_name(ssl.get(), server_name.c_str());
        }
        
        // Configure cipher suites
        configure_cipher_suites(ssl.get());
        
        // Configure TLS extensions
        configure_tls_extensions(ssl.get());
        
        // Configure signature algorithms
        configure_signature_algorithms(ssl.get());
        
        // Configure supported groups (curves)
        configure_supported_groups(ssl.get());
        
        // Configure ALPN
        configure_alpn(ssl.get());
        
        // Start SSL handshake to generate ClientHello
        SSL_connect(ssl.get());
        
        // Extract the ClientHello message from the BIO
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio.get(), &mem);
        
        if (!mem || mem->length == 0) {
            throw std::runtime_error("Failed to generate ClientHello");
        }
        
        // Convert to vector
        std::vector<uint8_t> client_hello(mem->data, mem->data + mem->length);
        
        // Apply browser-specific fingerprint customizations
        apply_browser_specific_modifications(client_hello);
        
        return client_hello;
    }
    
    // ========== INTEGRATED UTLSClientConfigurator METHODS ==========
    
    // Configure for QUICHE integration
    bool configure_for_quiche(quiche_config* config) {
        if (!config) {
            last_error_ = "Invalid QUICHE config";
            return false;
        }
        
        q_config_ = config;
        
        // Apply current fingerprint to QUICHE config
        return apply_fingerprint_to_quiche();
    }
    
    // Set custom fingerprint profile
    bool set_custom_fingerprint(const FingerprintProfile& profile) {
        current_profile_ = profile;
        current_fingerprint_ = profile.type;
        return true;
    }
    
    // Get available browser fingerprints
    std::vector<BrowserFingerprint> get_available_fingerprints() const {
        return {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST,
            BrowserFingerprint::EDGE_CHROMIUM,
            BrowserFingerprint::BRAVE,
            BrowserFingerprint::OPERA,
            BrowserFingerprint::CHROME_70,
            BrowserFingerprint::FIREFOX_63,
            BrowserFingerprint::CHROME_ANDROID,
            BrowserFingerprint::SAFARI_IOS,
            BrowserFingerprint::SAMSUNG_BROWSER,
            BrowserFingerprint::FIREFOX_MOBILE,
            BrowserFingerprint::EDGE_MOBILE,
            BrowserFingerprint::OUTLOOK,
            BrowserFingerprint::THUNDERBIRD,
            BrowserFingerprint::CURL
        };
    }
    
    // Randomize current fingerprint
    bool randomize_fingerprint() {
        auto available = get_available_fingerprints();
        if (available.empty()) {
            return false;
        }
        
        std::uniform_int_distribution<size_t> dist(0, available.size() - 1);
        current_fingerprint_ = available[dist(random_engine_)];
        
        // Update profile based on new fingerprint
        initialize_fingerprint_profile(current_fingerprint_);
        return true;
    }
    
    // Configure SSL connection with hostname
    bool configure_ssl_connection(SSL* ssl, const std::string& hostname) {
        if (!ssl) {
            last_error_ = "Invalid SSL connection";
            return false;
        }
        
        ssl_conn_ = ssl;
        current_hostname_ = hostname;
        
        // Set SNI
        if (!hostname.empty()) {
            SSL_set_tlsext_host_name(ssl, hostname.c_str());
        }
        
        return apply_fingerprint_to_ssl(ssl);
    }
    
    // Apply fingerprint to SSL connection
    bool apply_fingerprint_to_ssl(SSL* ssl) {
        if (!ssl) {
            return false;
        }
        
        // Apply cipher suites
        if (!current_profile_.cipher_suites.empty()) {
            std::string cipher_list;
            for (const auto& cipher : current_profile_.cipher_suites) {
                if (!cipher_list.empty()) cipher_list += ":";
                cipher_list += cipher.name;
            }
            SSL_set_cipher_list(ssl, cipher_list.c_str());
        }
        
        // Apply ALPN protocols
        if (!current_profile_.alpn_protocols.empty()) {
            std::vector<uint8_t> alpn_data;
            for (const auto& proto : current_profile_.alpn_protocols) {
                alpn_data.push_back(proto.length);
                alpn_data.insert(alpn_data.end(), proto.name.begin(), proto.name.end());
            }
            SSL_set_alpn_protos(ssl, alpn_data.data(), alpn_data.size());
        }
        
        return true;
    }
    
    // Enable session tickets
    bool enable_session_tickets(bool enable) {
        use_session_tickets_ = enable;
        session_config_.enabled = enable;
        return true;
    }
    
    // Configure session tickets
    bool configure_session_tickets(const SessionTicketConfig& config) {
        session_config_ = config;
        use_session_tickets_ = config.enabled;
        return true;
    }
    
    // Save session ticket for hostname
    bool save_session_ticket(const std::string& hostname, const std::vector<uint8_t>& ticket) {
        if (session_manager_) {
            return session_manager_->save_session_ticket(hostname, ticket);
        }
        return false;
    }
    
    // Load session ticket for hostname
    bool load_session_ticket(const std::string& hostname, std::vector<uint8_t>& ticket) {
        if (session_manager_) {
            return session_manager_->load_session_ticket(hostname, ticket);
        }
        return false;
    }
    
    // Configure PSK settings
    bool configure_psk(const PSKConfig& config) {
        psk_config_ = config;
        return true;
    }
    
    // Add PSK identity
    bool add_psk_identity(const std::string& identity, const std::vector<uint8_t>& key) {
        psk_config_.identity = identity;
        psk_config_.key = key;
        psk_config_.enabled = true;
        return true;
    }
    
    // Configure certificate pinning
    bool configure_certificate_pinning(const CertificatePinning& config) {
        cert_pinning_ = config;
        return true;
    }
    
    // Verify certificate pin
    bool verify_certificate_pin(X509* cert) {
        if (!cert_pinning_.enabled || !cert) {
            return true; // No pinning or invalid cert
        }
        
        // Implementation would verify certificate against pinned values
        // For now, return true as placeholder
        return true;
    }
    
    // Configure advanced TLS settings
    bool configure_advanced_tls(const AdvancedTLSConfig& config) {
        advanced_config_ = config;
        return true;
    }
    
    // Enable early data (0-RTT)
    bool enable_early_data(bool enable) {
        current_profile_.supports_early_data = enable;
        return true;
    }
    
    // Set cipher suites by name
    bool set_cipher_suites(const std::vector<std::string>& cipher_names) {
        current_profile_.cipher_suites.clear();
        for (const auto& name : cipher_names) {
            uint16_t id = cipher_name_to_id(name);
            if (id != 0) {
                current_profile_.cipher_suites.emplace_back(id, name);
            }
        }
        return !current_profile_.cipher_suites.empty();
    }
    
    // Add single cipher suite
    bool add_cipher_suite(const std::string& cipher_name) {
        uint16_t id = cipher_name_to_id(cipher_name);
        if (id != 0) {
            current_profile_.cipher_suites.emplace_back(id, cipher_name);
            return true;
        }
        return false;
    }
    
    // Get supported cipher suites
    std::vector<std::string> get_supported_cipher_suites() const {
        std::vector<std::string> result;
        for (const auto& cipher : current_profile_.cipher_suites) {
            result.push_back(cipher.name);
        }
        return result;
    }
    
    // Add custom TLS extension
    bool add_custom_extension(uint16_t type, const std::vector<uint8_t>& data) {
        current_profile_.extensions.emplace_back(type, data);
        return true;
    }
    
    // Remove TLS extension
    bool remove_extension(uint16_t type) {
        auto it = std::remove_if(current_profile_.extensions.begin(), 
                                current_profile_.extensions.end(),
                                [type](const TLSExtension& ext) {
                                    return ext.type == type;
                                });
        bool removed = (it != current_profile_.extensions.end());
        current_profile_.extensions.erase(it, current_profile_.extensions.end());
        return removed;
    }
    
    // Get configured extensions
    std::vector<TLSExtension> get_configured_extensions() const {
        return current_profile_.extensions;
    }
    
    // Enable GREASE values
    bool enable_grease(bool enable) {
        current_profile_.use_grease = enable;
        return true;
    }
    
    // Configure GREASE values
    bool configure_grease_values(const std::vector<uint16_t>& values) {
        current_profile_.grease_cipher_suites = values;
        current_profile_.grease_extensions = values;
        current_profile_.grease_ec_groups = values;
        current_profile_.grease_signature_algorithms = values;
        return true;
    }
    
    // Set hostname for SNI
    bool set_hostname(const std::string& hostname) {
        current_hostname_ = hostname;
        return true;
    }
    
    // Get current hostname
    std::string get_hostname() const {
        return current_hostname_;
    }
    
    // Configure SNI
    bool configure_sni(const std::string& server_name) {
        if (ssl_conn_) {
            return SSL_set_tlsext_host_name(ssl_conn_, server_name.c_str()) == 1;
        }
        return set_hostname(server_name);
    }
    
    // Enable debug logging
    bool enable_debug_logging(bool enable) {
        debug_logging_enabled_ = enable;
        return true;
    }
    
    // Set log level
    void set_log_level(int level) {
        log_level_ = level;
    }
    
    // Get last error message
    std::string get_last_error() const {
        return last_error_;
    }
    
    // Validate current configuration
    bool validate_configuration() const {
        // Basic validation checks
        if (current_profile_.cipher_suites.empty()) {
            return false;
        }
        
        if (current_profile_.tls_version_min > current_profile_.tls_version_max) {
            return false;
        }
        
        return true;
    }
    
    // Test handshake with target
    bool test_handshake(const std::string& hostname, uint16_t port) {
        // Implementation would perform actual handshake test
        // For now, return true as placeholder
        return true;
    }
    
    // Get handshake statistics
    HandshakeStats get_handshake_stats() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return stats_;
    }
    
    // Reset handshake statistics
    void reset_handshake_stats() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = HandshakeStats();
    }
    
    // Get the TLS fingerprint for the current browser configuration
    std::vector<uint8_t> get_tls_fingerprint() const {
        return fingerprint_->generate_tls_fingerprint();
    }
    
    // Get supported cipher suites for the current browser
    std::vector<uint16_t> get_cipher_suites() const {
        return fingerprint_->get_cipher_suites();
    }
    
    // Get supported TLS extensions for the current browser
    std::vector<uint16_t> get_tls_extensions() const {
        return fingerprint_->get_tls_extensions();
    }
    
    // Get supported signature algorithms for the current browser
    std::vector<uint16_t> get_signature_algorithms() const {
        return fingerprint_->get_signature_algorithms();
    }
    
    // Get supported groups (curves) for the current browser
    std::vector<uint16_t> get_supported_groups() const {
        return fingerprint_->get_supported_groups();
    }
    
    // Get ALPN protocols for the current browser
    std::vector<std::string> get_alpn_protocols() const {
        return fingerprint_->get_alpn_protocols();
    }
    
private:
    BrowserType browser_type_;
    OperatingSystem os_;
    std::shared_ptr<BrowserFingerprint> fingerprint_;
    std::mt19937 random_engine_;
    static bool openssl_initialized_;
    
    // Additional member variables for integrated functionality
     BrowserFingerprint current_fingerprint_;
     FingerprintProfile current_profile_;
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
    
    // Configuration structures
    SessionTicketConfig session_config_;
    PSKConfig psk_config_;
    CertificatePinning cert_pinning_;
    AdvancedTLSConfig advanced_config_;
    
    // Session management
    std::shared_ptr<SessionManager> session_manager_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    HandshakeStats stats_;
    
    // Helper structures
    struct CipherSuite {
        uint16_t id;
        std::string name;
        CipherSuite(uint16_t i, const std::string& n) : id(i), name(n) {}
    };
    
    struct ALPNProtocol {
        uint8_t length;
        std::string name;
        ALPNProtocol(const std::string& n) : length(n.size()), name(n) {}
    };
    
    struct TLSExtension {
        uint16_t type;
        std::vector<uint8_t> data;
        TLSExtension(uint16_t t, const std::vector<uint8_t>& d) : type(t), data(d) {}
    };
    
    struct FingerprintProfile {
        BrowserFingerprint type;
        std::vector<CipherSuite> cipher_suites;
        std::vector<ALPNProtocol> alpn_protocols;
        std::vector<TLSExtension> extensions;
        uint16_t tls_version_min;
        uint16_t tls_version_max;
        bool supports_early_data;
        bool use_grease;
        std::vector<uint16_t> grease_cipher_suites;
        std::vector<uint16_t> grease_extensions;
        std::vector<uint16_t> grease_ec_groups;
        std::vector<uint16_t> grease_signature_algorithms;
    };
    
    struct SessionTicketConfig {
        bool enabled = true;
        uint32_t lifetime = 7200;
        bool allow_early_data = false;
    };
    
    struct PSKConfig {
        bool enabled = false;
        std::string identity;
        std::vector<uint8_t> key;
    };
    
    struct CertificatePinning {
        bool enabled = false;
        std::vector<std::string> sha256_pins;
        std::vector<std::string> sha1_pins;
    };
    
    struct AdvancedTLSConfig {
        bool enable_ocsp_stapling = true;
        bool enable_sct = false;
        bool enable_compression = false;
        uint32_t max_fragment_length = 0;
    };
    
    struct HandshakeStats {
        uint64_t total_handshakes = 0;
        uint64_t successful_handshakes = 0;
        uint64_t failed_handshakes = 0;
        double average_handshake_time = 0.0;
    };
    
    class SessionManager {
    public:
        bool save_session_ticket(const std::string& hostname, const std::vector<uint8_t>& ticket) {
            std::lock_guard<std::mutex> lock(mutex_);
            session_tickets_[hostname] = ticket;
            return true;
        }
        
        bool load_session_ticket(const std::string& hostname, std::vector<uint8_t>& ticket) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = session_tickets_.find(hostname);
            if (it != session_tickets_.end()) {
                ticket = it->second;
                return true;
            }
            return false;
        }
        
    private:
        std::mutex mutex_;
        std::map<std::string, std::vector<uint8_t>> session_tickets_;
    };
    
    // Helper methods for integrated functionality
    bool apply_fingerprint_to_quiche() {
        if (!q_config_) {
            return false;
        }
        
        // Apply fingerprint settings to QUICHE config
        // This would involve calling appropriate quiche_config_* functions
        return true;
    }
    
    void initialize_fingerprint_profile(BrowserFingerprint fingerprint) {
        current_profile_ = FingerprintProfile();
        current_profile_.type = fingerprint;
        
        // Initialize profile based on fingerprint type
        switch (fingerprint) {
            case BrowserFingerprint::CHROME_LATEST:
                initialize_chrome_profile();
                break;
            case BrowserFingerprint::FIREFOX_LATEST:
                initialize_firefox_profile();
                break;
            case BrowserFingerprint::SAFARI_LATEST:
                initialize_safari_profile();
                break;
            default:
                initialize_default_profile();
                break;
        }
    }
    
    void initialize_chrome_profile() {
        current_profile_.tls_version_min = 0x0303; // TLS 1.2
        current_profile_.tls_version_max = 0x0304; // TLS 1.3
        current_profile_.supports_early_data = true;
        current_profile_.use_grease = true;
        
        // Add Chrome-specific cipher suites - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
        current_profile_.cipher_suites.emplace_back(0x1301, "TLS_AEGIS_128X_SHA256");      // AEGIS-128X für VAES
        current_profile_.cipher_suites.emplace_back(0x1302, "TLS_AEGIS_128L_SHA384");      // AEGIS-128L für AES-NI/ARM
        current_profile_.cipher_suites.emplace_back(0x1303, "TLS_CHACHA20_POLY1305_SHA256");
        current_profile_.cipher_suites.emplace_back(0x1304, "TLS_MORUS_1280_128_SHA256");      // MORUS-1280-128 Fallback
        
        // Add Chrome ALPN protocols
        current_profile_.alpn_protocols.emplace_back("h2");
        current_profile_.alpn_protocols.emplace_back("http/1.1");
    }
    
    void initialize_firefox_profile() {
        current_profile_.tls_version_min = 0x0303; // TLS 1.2
        current_profile_.tls_version_max = 0x0304; // TLS 1.3
        current_profile_.supports_early_data = false;
        current_profile_.use_grease = false;
        
        // Add Firefox-specific cipher suites - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
        current_profile_.cipher_suites.emplace_back(0x1301, "TLS_AEGIS_128X_SHA256");      // AEGIS-128X für VAES
        current_profile_.cipher_suites.emplace_back(0x1303, "TLS_CHACHA20_POLY1305_SHA256");
        current_profile_.cipher_suites.emplace_back(0x1302, "TLS_AEGIS_128L_SHA384");      // AEGIS-128L für AES-NI/ARM
        
        // Add Firefox ALPN protocols
        current_profile_.alpn_protocols.emplace_back("h2");
        current_profile_.alpn_protocols.emplace_back("http/1.1");
    }
    
    void initialize_safari_profile() {
        current_profile_.tls_version_min = 0x0303; // TLS 1.2
        current_profile_.tls_version_max = 0x0304; // TLS 1.3
        current_profile_.supports_early_data = false;
        current_profile_.use_grease = false;
        
        // Add Safari-specific cipher suites - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
        current_profile_.cipher_suites.emplace_back(0x1301, "TLS_AEGIS_128X_SHA256");      // AEGIS-128X für VAES
        current_profile_.cipher_suites.emplace_back(0x1302, "TLS_AEGIS_128L_SHA384");      // AEGIS-128L für AES-NI/ARM
        
        // Add Safari ALPN protocols
        current_profile_.alpn_protocols.emplace_back("h2");
        current_profile_.alpn_protocols.emplace_back("http/1.1");
    }
    
    void initialize_default_profile() {
        current_profile_.tls_version_min = 0x0303; // TLS 1.2
        current_profile_.tls_version_max = 0x0304; // TLS 1.3
        current_profile_.supports_early_data = false;
        current_profile_.use_grease = false;
        
        // Add default cipher suites - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
        current_profile_.cipher_suites.emplace_back(0x1301, "TLS_AEGIS_128X_SHA256");      // AEGIS-128X für VAES
        current_profile_.cipher_suites.emplace_back(0x1302, "TLS_AEGIS_128L_SHA384");      // AEGIS-128L für AES-NI/ARM
        current_profile_.cipher_suites.emplace_back(0x1304, "TLS_MORUS_1280_128_SHA256");      // MORUS-1280-128 Fallback
        
        // Add default ALPN protocols
        current_profile_.alpn_protocols.emplace_back("http/1.1");
    }
    
    uint16_t cipher_name_to_id(const std::string& name) {
        // Simplified mapping of cipher names to IDs
        static const std::map<std::string, uint16_t> cipher_map = {
            {"TLS_AEGIS_128X_SHA256", 0x1301},                      // AEGIS-128X für VAES
            {"TLS_AEGIS_128L_SHA384", 0x1302},                      // AEGIS-128L für AES-NI/ARM
            {"TLS_CHACHA20_POLY1305_SHA256", 0x1303},
            {"TLS_MORUS_1280_128_SHA256", 0x1304},                      // MORUS-1280-128 Fallback
            {"TLS_ECDHE_RSA_WITH_AEGIS_128X_SHA256", 0xc02f},       // ECDHE mit AEGIS-128X
            {"TLS_ECDHE_RSA_WITH_AEGIS_128L_SHA384", 0xc030},       // ECDHE mit AEGIS-128L
            {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca8}
        };
        
        auto it = cipher_map.find(name);
        return (it != cipher_map.end()) ? it->second : 0;
    }
    
    // Configure cipher suites based on browser fingerprint
    void configure_cipher_suites(SSL* ssl) {
        std::vector<uint16_t> cipher_suites = get_cipher_suites();
        
        // Convert to OpenSSL format
        std::string cipher_list;
        for (uint16_t suite : cipher_suites) {
            const SSL_CIPHER* cipher = SSL_CIPHER_find(ssl, reinterpret_cast<const unsigned char*>(&suite));
            if (cipher) {
                if (!cipher_list.empty()) {
                    cipher_list += ":";
                }
                cipher_list += SSL_CIPHER_get_name(cipher);
            }
        }
        
        if (!cipher_list.empty()) {
            SSL_set_cipher_list(ssl, cipher_list.c_str());
        }
    }
    
    // Configure TLS extensions based on browser fingerprint
    void configure_tls_extensions(SSL* ssl) {
        std::vector<uint16_t> extensions = get_tls_extensions();
        
        // Enable/disable specific extensions
        for (uint16_t ext : extensions) {
            switch (ext) {
                case 0x0000: // Server Name Indication
                    // Already handled in generate_client_hello
                    break;
                    
                case 0x0005: // Status Request (OCSP)
                    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
                    break;
                    
                case 0x000a: // Supported Groups
                    // Handled in configure_supported_groups
                    break;
                    
                case 0x000b: // EC Point Formats
                    // Modern OpenSSL handles this automatically
                    break;
                    
                case 0x000d: // Signature Algorithms
                    // Handled in configure_signature_algorithms
                    break;
                    
                case 0x0010: // ALPN
                    // Handled in configure_alpn
                    break;
                    
                case 0x0017: // Extended Master Secret
                    SSL_set_options(ssl, SSL_OP_NO_EXTENDED_MASTER_SECRET);
                    break;
                    
                // Add more extensions as needed
                
                default:
                    // Unsupported extension, ignore
                    break;
            }
        }
    }
    
    // Configure signature algorithms based on browser fingerprint
    void configure_signature_algorithms(SSL* ssl) {
        std::vector<uint16_t> sig_algs = get_signature_algorithms();
        
        if (!sig_algs.empty()) {
            // Convert to OpenSSL format
            std::string sig_algs_list;
            for (uint16_t alg : sig_algs) {
                if (!sig_algs_list.empty()) {
                    sig_algs_list += ":";
                }
                
                // Convert uint16_t to OpenSSL signature algorithm string
                // This is a simplified mapping
                switch (alg) {
                    case 0x0401: sig_algs_list += "RSA+SHA256"; break;
                    case 0x0501: sig_algs_list += "RSA+SHA384"; break;
                    case 0x0601: sig_algs_list += "RSA+SHA512"; break;
                    case 0x0403: sig_algs_list += "ECDSA+SHA256"; break;
                    case 0x0503: sig_algs_list += "ECDSA+SHA384"; break;
                    case 0x0603: sig_algs_list += "ECDSA+SHA512"; break;
                    case 0x0804: sig_algs_list += "RSA+SHA256"; break; // RSA-PSS + SHA256
                    case 0x0805: sig_algs_list += "RSA+SHA384"; break; // RSA-PSS + SHA384
                    case 0x0806: sig_algs_list += "RSA+SHA512"; break; // RSA-PSS + SHA512
                    default: 
                        // Unknown algorithm, use a common one
                        sig_algs_list += "RSA+SHA256"; 
                        break;
                }
            }
            
            if (!sig_algs_list.empty()) {
                SSL_set1_sigalgs_list(ssl, sig_algs_list.c_str());
            }
        }
    }
    
    // Configure supported groups (curves) based on browser fingerprint
    void configure_supported_groups(SSL* ssl) {
        std::vector<uint16_t> groups = get_supported_groups();
        
        if (!groups.empty()) {
            // Convert to OpenSSL format
            std::string groups_list;
            for (uint16_t group : groups) {
                if (!groups_list.empty()) {
                    groups_list += ":";
                }
                
                // Convert uint16_t to OpenSSL group string
                // This is a simplified mapping
                switch (group) {
                    case 0x0017: groups_list += "P-256"; break;
                    case 0x0018: groups_list += "P-384"; break;
                    case 0x0019: groups_list += "P-521"; break;
                    case 0x001d: groups_list += "X25519"; break;
                    case 0x001e: groups_list += "X448"; break;
                    case 0x0100: groups_list += "ffdhe2048"; break;
                    case 0x0101: groups_list += "ffdhe3072"; break;
                    case 0x0102: groups_list += "ffdhe4096"; break;
                    case 0x0103: groups_list += "ffdhe6144"; break;
                    case 0x0104: groups_list += "ffdhe8192"; break;
                    default:
                        // Unknown group, use a common one
                        groups_list += "X25519";
                        break;
                }
            }
            
            if (!groups_list.empty()) {
                SSL_set1_groups_list(ssl, groups_list.c_str());
            }
        }
    }
    
    // Configure ALPN protocols based on browser fingerprint
    void configure_alpn(SSL* ssl) {
        std::vector<std::string> protocols = get_alpn_protocols();
        
        if (!protocols.empty()) {
            // ALPN expects length-prefixed protocol names
            std::vector<unsigned char> alpn_data;
            
            for (const auto& protocol : protocols) {
                if (protocol.size() > 255) continue; // Skip too long protocols
                
                alpn_data.push_back(static_cast<unsigned char>(protocol.size()));
                alpn_data.insert(alpn_data.end(), protocol.begin(), protocol.end());
            }
            
            if (!alpn_data.empty()) {
                SSL_set_alpn_protos(ssl, alpn_data.data(), alpn_data.size());
            }
        }
    }
    
    // Apply browser-specific modifications to the ClientHello message
    void apply_browser_specific_modifications(std::vector<uint8_t>& client_hello) {
        // This would apply specific tweaks to the raw ClientHello message
        // to better match the target browser fingerprint
        
        // In a real implementation, this would involve:
        // 1. Parsing the TLS message structure
        // 2. Modifying specific fields or extensions
        // 3. Updating length fields and checksums
        
        // For now, this is a placeholder for browser-specific modifications
        switch (browser_type_) {
            case BrowserType::CHROME:
            case BrowserType::CHROME_MOBILE:
                apply_chrome_modifications(client_hello);
                break;
                
            case BrowserType::FIREFOX:
            case BrowserType::FIREFOX_MOBILE:
                apply_firefox_modifications(client_hello);
                break;
                
            case BrowserType::SAFARI:
            case BrowserType::SAFARI_MOBILE:
                apply_safari_modifications(client_hello);
                break;
                
            case BrowserType::EDGE:
                apply_edge_modifications(client_hello);
                break;
                
            default:
                // No specific modifications
                break;
        }
    }
    
    // Apply Chrome-specific modifications
    void apply_chrome_modifications(std::vector<uint8_t>& client_hello) {
        // Chrome-specific quirks in ClientHello
        
        // Find and modify extensions
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        // Chrome puts SNI, ALPN, and status_request early in the extensions list
        reorder_extensions(client_hello, extensions_offset, {0x0000, 0x0010, 0x0005});
        
        // Chrome uses specific EC point formats
        replace_ec_point_formats(client_hello, {0x00, 0x01, 0x02});
        
        // Chrome includes session ticket extension even when empty
        ensure_extension_exists(client_hello, 0x0023);
    }
    
    // Apply Firefox-specific modifications
    void apply_firefox_modifications(std::vector<uint8_t>& client_hello) {
        // Firefox-specific quirks in ClientHello
        
        // Find and modify extensions
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        // Firefox puts supported_groups and ec_point_formats early
        reorder_extensions(client_hello, extensions_offset, {0x000a, 0x000b});
        
        // Firefox uses specific EC point formats
        replace_ec_point_formats(client_hello, {0x00, 0x01, 0x02});
        
        // Firefox includes renegotiation_info
        ensure_extension_exists(client_hello, 0xff01);
    }
    
    // Apply Safari-specific modifications
    void apply_safari_modifications(std::vector<uint8_t>& client_hello) {
        // Safari-specific quirks in ClientHello
        
        // Find and modify extensions
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        // Safari has a specific extension order
        reorder_extensions(client_hello, extensions_offset, {0x0000, 0x0017, 0x0023});
        
        // Safari uses specific EC point formats
        replace_ec_point_formats(client_hello, {0x00, 0x01});
    }
    
    // Apply Edge-specific modifications
    void apply_edge_modifications(std::vector<uint8_t>& client_hello) {
        // Edge-specific quirks in ClientHello (similar to Chrome but with differences)
        
        // Find and modify extensions
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        // Edge extension order
        reorder_extensions(client_hello, extensions_offset, {0x0000, 0x0010, 0x0005, 0x000b});
        
        // Edge uses specific EC point formats
        replace_ec_point_formats(client_hello, {0x00, 0x01, 0x02});
        
        // Edge includes session ticket extension
        ensure_extension_exists(client_hello, 0x0023);
    }
    
    // Helper to find extensions section in ClientHello
    size_t find_extensions_offset(const std::vector<uint8_t>& client_hello) {
        // This is a simplified approach - in a real implementation,
        // we would properly parse the TLS message structure
        
        // Look for the extensions length field (2 bytes)
        // It's typically near the end of the ClientHello
        for (size_t i = client_hello.size() - 50; i < client_hello.size() - 6; i++) {
            // Check for a reasonable extensions length
            uint16_t ext_len = (client_hello[i] << 8) | client_hello[i + 1];
            if (ext_len > 0 && ext_len < 500 && i + 2 + ext_len <= client_hello.size()) {
                // Verify this looks like extensions by checking for valid extension types
                bool looks_valid = true;
                for (size_t j = i + 2; j < i + 2 + ext_len - 4; j += 4) {
                    uint16_t ext_type = (client_hello[j] << 8) | client_hello[j + 1];
                    uint16_t ext_size = (client_hello[j + 2] << 8) | client_hello[j + 3];
                    
                    // Check if extension type and size seem reasonable
                    if (ext_type > 0x4000 || ext_size > 400 || j + 4 + ext_size > i + 2 + ext_len) {
                        looks_valid = false;
                        break;
                    }
                }
                
                if (looks_valid) {
                    return i + 2; // Return offset to first extension
                }
            }
        }
        
        return 0; // Not found
    }
    
    // Reorder extensions to match browser fingerprint
    void reorder_extensions(std::vector<uint8_t>& client_hello, size_t extensions_offset,
                          const std::vector<uint16_t>& priority_extensions) {
        // This is a placeholder - in a real implementation,
        // we would properly parse and reorder the extensions
        
        // For now, just make sure the specified extensions exist
        for (uint16_t ext_type : priority_extensions) {
            ensure_extension_exists(client_hello, ext_type);
        }
    }
    
    // Replace EC point formats extension
    void replace_ec_point_formats(std::vector<uint8_t>& client_hello, 
                                const std::vector<uint8_t>& formats) {
        // Find EC point formats extension
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        // Look for extension type 0x000b (EC point formats)
        for (size_t i = extensions_offset; i < client_hello.size() - 4; i += 4) {
            uint16_t ext_type = (client_hello[i] << 8) | client_hello[i + 1];
            uint16_t ext_size = (client_hello[i + 2] << 8) | client_hello[i + 3];
            
            if (ext_type == 0x000b && i + 4 + ext_size <= client_hello.size()) {
                // Found EC point formats extension
                if (ext_size >= 1) {
                    // Replace formats list
                    uint8_t num_formats = static_cast<uint8_t>(formats.size());
                    client_hello[i + 4] = num_formats;
                    
                    // Copy new formats
                    for (size_t j = 0; j < formats.size() && i + 5 + j < client_hello.size(); j++) {
                        client_hello[i + 5 + j] = formats[j];
                    }
                }
                
                break;
            }
            
            i += ext_size;
        }
    }
    
    // Ensure a specific extension exists
    void ensure_extension_exists(std::vector<uint8_t>& client_hello, uint16_t ext_type) {
        // This is a placeholder - in a real implementation,
        // we would properly add the extension if missing
        
        // For now, just check if the extension exists
        size_t extensions_offset = find_extensions_offset(client_hello);
        if (extensions_offset == 0) return;
        
        bool found = false;
        for (size_t i = extensions_offset; i < client_hello.size() - 4; i += 4) {
            uint16_t current_ext_type = (client_hello[i] << 8) | client_hello[i + 1];
            uint16_t ext_size = (client_hello[i + 2] << 8) | client_hello[i + 3];
            
            if (current_ext_type == ext_type) {
                found = true;
                break;
            }
            
            i += ext_size;
        }
        
        // If not found, we would add it in a real implementation
    }
};

// Initialize static variable
bool UTLSImplementation::openssl_initialized_ = false;

/**
 * Factory function to create a uTLS implementation for a specific browser
 */
std::shared_ptr<UTLSImplementation> create_utls_implementation(
    BrowserType browser_type, OperatingSystem os) {
    
    return std::make_shared<UTLSImplementation>(browser_type, os);
}

} // namespace quicfuscate::stealth

#ifndef FAKE_TLS_HPP
#define FAKE_TLS_HPP

#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <map>
#include <memory>
#include "browser_profiles/fingerprints/browser_fingerprints.hpp"

// TLS-Konstanten für die Kommunikation
// TLS 1.3 Cipher Suites (RFC 8446) - Ersetzt durch AEGIS/MORUS für echte Verschlüsselung
// Diese Konstanten werden nur für TLS-Fingerprinting verwendet, nicht für echte Kryptographie
static constexpr uint16_t TLS_AEGIS_128X_SHA256 = 0x1301;  // Fake TLS ID für AEGIS-128X
static constexpr uint16_t TLS_AEGIS_128L_SHA384 = 0x1302;  // Fake TLS ID für AEGIS-128L
static constexpr uint16_t TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
static constexpr uint16_t TLS_MORUS_1280_128_SHA256 = 0x1304;  // Fake TLS ID für MORUS-1280-128

// TLS 1.2 ECDHE Cipher Suites - Ersetzt durch AEGIS/MORUS
static constexpr uint16_t TLS_ECDHE_ECDSA_WITH_AEGIS_128X_SHA256 = 0xC02B;  // Fake für AEGIS-128X
static constexpr uint16_t TLS_ECDHE_RSA_WITH_AEGIS_128L_SHA256 = 0xC02F;    // Fake für AEGIS-128L
static constexpr uint16_t TLS_ECDHE_ECDSA_WITH_AEGIS_128L_SHA384 = 0xC02C;  // Fake für AEGIS-128L
static constexpr uint16_t TLS_ECDHE_RSA_WITH_MORUS_1280_128_SHA256 = 0xC030;    // Fake für MORUS-1280-128
static constexpr uint16_t TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9;
static constexpr uint16_t TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8;

// TLS Extensions
static constexpr uint16_t TLS_EXT_SERVER_NAME = 0x0000;
static constexpr uint16_t TLS_EXT_STATUS_REQUEST = 0x0005;
static constexpr uint16_t TLS_EXT_SUPPORTED_GROUPS = 0x000A;
static constexpr uint16_t TLS_EXT_EC_POINT_FORMATS = 0x000B;
static constexpr uint16_t TLS_EXT_SIGNATURE_ALGORITHMS = 0x000D;
static constexpr uint16_t TLS_EXT_ALPN = 0x0010;
static constexpr uint16_t TLS_EXT_SUPPORTED_VERSIONS = 0x002B;
static constexpr uint16_t TLS_EXT_PSK_KEY_EXCHANGE_MODES = 0x002D;
static constexpr uint16_t TLS_EXT_KEY_SHARE = 0x0033;
static constexpr uint16_t TLS_EXT_RECORD_SIZE_LIMIT = 0x001C;

// Elliptic Curve Typen
static constexpr uint16_t X25519 = 0x001D;
static constexpr uint16_t SECP256R1 = 0x0017;
static constexpr uint16_t SECP384R1 = 0x0018;
static constexpr uint16_t SECP521R1 = 0x0019;

// Signatur-Algorithmen
static constexpr uint16_t ECDSA_SECP256R1_SHA256 = 0x0403;
static constexpr uint16_t ECDSA_SECP384R1_SHA384 = 0x0503;
static constexpr uint16_t ECDSA_SECP521R1_SHA512 = 0x0603;
static constexpr uint16_t RSA_PSS_RSAE_SHA256 = 0x0804;
static constexpr uint16_t RSA_PSS_RSAE_SHA384 = 0x0805;
static constexpr uint16_t RSA_PSS_RSAE_SHA512 = 0x0806;
static constexpr uint16_t ED25519 = 0x0807;

// Legacy RSA PKCS1 Signaturalgorithmen
static constexpr uint16_t RSA_PKCS1_SHA256 = 0x0401;
static constexpr uint16_t RSA_PKCS1_SHA384 = 0x0501;
static constexpr uint16_t RSA_PKCS1_SHA512 = 0x0601;

namespace quicfuscate::stealth {

// Definiere BrowserProfile-Enum, das in fake_tls.cpp verwendet wird
enum class BrowserProfile {
    CHROME_WINDOWS,
    CHROME_MACOS,
    CHROME_LINUX,
    CHROME_MOBILE,
    FIREFOX_WINDOWS,
    FIREFOX_MACOS,
    FIREFOX_LINUX,
    FIREFOX_MOBILE,
    EDGE_WINDOWS,
    EDGE_MACOS,
    SAFARI_MACOS,
    SAFARI_MOBILE,
    DEFAULT = CHROME_WINDOWS
};

class FakeTLS {
public:
    // Konstruktoren
    FakeTLS();
    FakeTLS(BrowserProfile profile);
    
    // Keine Kopien erlauben
    FakeTLS(const FakeTLS&) = delete;
    FakeTLS& operator=(const FakeTLS&) = delete;
    
    // Handshake und TLS-Operationen
    void perform_fake_handshake();
    void initialize();
    std::vector<uint8_t> generate_client_hello();
    std::vector<uint8_t> generate_key_share();
    
    // Advanced browser emulation methods (consolidated from advanced_browser_emulation)
    std::vector<uint8_t> generate_tls_fingerprint() const;
    std::vector<HTTP3Setting> generate_http3_settings() const;
    std::map<std::string, std::string> generate_http_headers(const std::string& url) const;
    std::vector<ResourceType> get_resource_loading_order() const;
    TimingPattern get_timing_pattern(RequestType request_type) const;
    int64_t apply_timing_jitter(int64_t base_time_ms, RequestType request_type) const;
    bool uses_http2_push() const;
    bool supports_http3() const;
    uint32_t get_max_concurrent_connections() const;
    uint32_t get_max_concurrent_streams() const;
    
    // Konfigurations-Methoden
    void set_enabled(bool enabled);
    void set_browser_profile(BrowserProfile profile);
    BrowserProfile get_browser_profile() const;
    void set_browser_type(BrowserType browser);
    void set_operating_system(OperatingSystem os);
    
private:
    // Private Hilfsmethoden für browser-spezifische Einstellungen
    void setup_chrome_parameters();
    void setup_firefox_parameters();
    void setup_edge_parameters();
    void setup_safari_parameters();
    
    // Advanced emulation methods (consolidated)
    void initialize_request_patterns();
    void initialize_timing_patterns();
    void initialize_protocol_behaviors();
    BrowserType convert_profile_to_type(BrowserProfile profile) const;
    OperatingSystem extract_os_from_profile(BrowserProfile profile) const;
    
    // Interne Zustandsvariablen
    BrowserProfile browser_profile_;
    bool enabled_;
    
    // TLS-Parameter
    std::vector<uint16_t> cipher_suites_;
    std::vector<uint16_t> extensions_;
    std::vector<uint16_t> supported_groups_;
    std::vector<uint8_t> ec_point_formats_;
    std::vector<uint16_t> signature_algorithms_;
    std::vector<std::string> alpn_protocols_;
    
    // Advanced emulation state (consolidated)
    std::shared_ptr<BrowserFingerprint> fingerprint_;
    BrowserType browser_type_;
    OperatingSystem os_;
    RequestPatterns request_patterns_;
    std::map<RequestType, TimingPattern> timing_patterns_;
    ProtocolBehaviors protocol_behaviors_;
    mutable std::mt19937 random_engine_;
    
    // Zufallszahlengenerator
    std::mt19937 rng_;
};

} // namespace quicfuscate::stealth

#endif // FAKE_TLS_HPP
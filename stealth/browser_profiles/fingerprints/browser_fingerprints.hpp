#pragma once

#include <string>
#include <vector>
#include <map>
#include <array>

namespace quicfuscate::stealth {

/**
 * @brief Enum für verschiedene Betriebssysteme
 */
enum class OperatingSystem {
    WINDOWS_10,
    WINDOWS_11,
    MACOS,
    LINUX,
    IOS,
    ANDROID,
    UNKNOWN
};

/**
 * @brief Enum für verschiedene Browser
 */
enum class BrowserType {
    CHROME,
    FIREFOX,
    EDGE,
    SAFARI,
    OPERA,
    VIVALDI,
    SAMSUNG,
    CHROME_MOBILE,
    FIREFOX_MOBILE,
    SAFARI_MOBILE
};

/**
 * @brief Browser-Version mit Major/Minor-Nummern
 */
struct BrowserVersion {
    int major;
    int minor;
    int build;
    int patch;
    
    std::string to_string() const {
        return std::to_string(major) + "." + 
               std::to_string(minor) + "." + 
               std::to_string(build) + "." + 
               std::to_string(patch);
    }
    
    std::string to_short_string() const {
        return std::to_string(major) + "." + 
               std::to_string(minor);
    }
};

/**
 * @brief TLS-Fingerprint-Konfiguration
 */
struct TLSFingerprint {
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint8_t> supported_groups;
    std::vector<uint8_t> ec_point_formats;
    std::vector<uint8_t> signature_algorithms;
    std::string alpn;
    bool encrypt_sni;
};

/**
 * @brief HTTP/2-Spezifische Fingerprint-Einstellungen
 */
struct HTTP2Fingerprint {
    uint32_t initial_window_size;
    uint32_t max_concurrent_streams;
    bool enable_push;
    uint32_t max_frame_size;
    std::vector<uint8_t> settings_priorities;
    std::map<std::string, std::string> additional_settings;
};

/**
 * @brief HTTP/3-Spezifische Fingerprint-Einstellungen
 */
struct HTTP3Fingerprint {
    uint64_t max_field_section_size;
    uint64_t qpack_max_table_capacity;
    uint64_t qpack_blocked_streams;
    bool enable_connect_protocol;
    bool enable_webtransport;
    bool enable_datagram;
    std::vector<std::string> supported_versions;
    std::map<std::string, std::string> additional_settings;
};

/**
 * @brief QUIC-Transport-Parameter
 */
struct QUICTransportParameters {
    uint64_t max_idle_timeout;
    uint64_t max_udp_payload_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    bool disable_active_migration;
    std::vector<uint8_t> preferred_address;
    std::vector<uint8_t> original_destination_connection_id;
};

/**
 * @brief JavaScript-Fingerprint-Eigenschaften
 */
struct JavaScriptFingerprint {
    std::string user_agent;
    std::string language;
    std::vector<std::string> languages;
    std::string platform;
    int color_depth;
    std::array<int, 2> screen_resolution;
    std::array<int, 2> available_screen_size;
    int timezone_offset;
    bool has_touch_support;
    int device_memory;
    int hardware_concurrency;
    std::vector<std::string> mime_types;
    std::vector<std::string> plugins;
    bool webgl_vendor_masked;
    std::string webgl_vendor;
    std::string webgl_renderer;
    std::map<std::string, std::string> navigator_properties;
};

/**
 * @brief Vollständiger Browser-Fingerprint
 */
struct BrowserFingerprint {
    OperatingSystem os;
    BrowserType browser;
    BrowserVersion version;
    std::string user_agent;
    std::string accept_language;
    std::string accept_encoding;
    std::string accept;
    TLSFingerprint tls;
    HTTP2Fingerprint http2;
    HTTP3Fingerprint http3;
    QUICTransportParameters quic;
    JavaScriptFingerprint js;
    std::map<std::string, std::string> additional_headers;
    
    // Hilfsfunktion zur Generierung eines base64-Strings für QUIC-Parameter
    std::string generate_quic_transport_params_base64() const;
};

/**
 * @brief Browser-Fingerprint-Fabrik
 * 
 * Diese Klasse erstellt aktuelle, authentische Browser-Fingerprints für verschiedene
 * Betriebssysteme und Browser. Die Fingerprints werden regelmäßig aktualisiert,
 * um aktuelle Browser-Versionen abzubilden.
 */
class BrowserFingerprintFactory {
public:
    /**
     * @brief Erstellt einen Fingerprint für eine bestimmte Kombination aus OS und Browser
     * 
     * @param os Betriebssystem
     * @param browser Browser-Typ
     * @param randomize_minor_version Minor-Version zufällig anpassen
     * @return BrowserFingerprint Vollständiger Fingerprint
     */
    static BrowserFingerprint create(OperatingSystem os, BrowserType browser, bool randomize_minor_version = false);
    
    /**
     * @brief Erstellt einen zufälligen Fingerprint für ein bestimmtes OS
     * 
     * @param os Betriebssystem
     * @return BrowserFingerprint Zufälliger Fingerprint für das angegebene OS
     */
    static BrowserFingerprint create_random_for_os(OperatingSystem os);
    
    /**
     * @brief Erstellt einen zufälligen, aber plausiblen Fingerprint
     * 
     * @return BrowserFingerprint Zufälliger Fingerprint
     */
    static BrowserFingerprint create_random();
    
    /**
     * @brief Aktualisiert einen bestehenden Fingerprint auf die neueste Version
     * 
     * @param fingerprint Zu aktualisierender Fingerprint
     * @return BrowserFingerprint Aktualisierter Fingerprint
     */
    static BrowserFingerprint update_to_latest(const BrowserFingerprint& fingerprint);
    
    /**
     * @brief Konvertiert einen Fingerprint für die Verwendung mit einer anderen JA3-Signatur
     * 
     * @param fingerprint Basis-Fingerprint
     * @param ja3_signature Ziel-JA3-Signatur
     * @return BrowserFingerprint Angepasster Fingerprint
     */
    static BrowserFingerprint convert_to_ja3(const BrowserFingerprint& fingerprint, const std::string& ja3_signature);
    
private:
    // Hilfsfunktionen zur Erstellung von Fingerprints für spezifische Browser
    static BrowserFingerprint create_chrome_windows10();
    static BrowserFingerprint create_chrome_windows11();
    static BrowserFingerprint create_chrome_macos();
    static BrowserFingerprint create_chrome_linux();
    static BrowserFingerprint create_chrome_android();
    
    static BrowserFingerprint create_firefox_windows10();
    static BrowserFingerprint create_firefox_windows11();
    static BrowserFingerprint create_firefox_macos();
    static BrowserFingerprint create_firefox_linux();
    static BrowserFingerprint create_firefox_android();
    
    static BrowserFingerprint create_edge_windows10();
    static BrowserFingerprint create_edge_windows11();
    static BrowserFingerprint create_edge_macos();
    
    static BrowserFingerprint create_safari_macos();
    static BrowserFingerprint create_safari_ios();
    
    // Brave Browser wurde entfernt, da nicht in den Anforderungen
    
    // Hilfsfunktionen zur Erstellung von TLS-Fingerprints
    static TLSFingerprint create_chrome_tls(OperatingSystem os);
    static TLSFingerprint create_firefox_tls(OperatingSystem os);
    static TLSFingerprint create_edge_tls(OperatingSystem os);
    static TLSFingerprint create_safari_tls(OperatingSystem os);
    static TLSFingerprint create_brave_tls(OperatingSystem os);
    
    // Hilfsfunktionen zur Erstellung von HTTP/3-Fingerprints
    static HTTP3Fingerprint create_chrome_http3();
    static HTTP3Fingerprint create_firefox_http3();
    static HTTP3Fingerprint create_edge_http3();
    static HTTP3Fingerprint create_safari_http3();
    
    // Hilfsfunktionen zur Erstellung von QUIC-Parametern
    static QUICTransportParameters create_chrome_quic();
    static QUICTransportParameters create_firefox_quic();
    static QUICTransportParameters create_edge_quic();
    static QUICTransportParameters create_safari_quic();
};

/**
 * @brief JA3-Fingerprint-Generator
 * 
 * Diese Klasse erzeugt und verarbeitet JA3-Fingerprints für TLS-Clientverbindungen.
 * JA3 ist ein Fingerprinting-Mechanismus für TLS-Clients, der von Salesforce entwickelt wurde.
 */
class JA3FingerprintGenerator {
public:
    /**
     * @brief Generiert einen JA3-Fingerprint aus einem TLS-Fingerprint
     * 
     * @param tls_fingerprint TLS-Fingerprint
     * @return std::string JA3-Fingerprint-String
     */
    static std::string generate(const TLSFingerprint& tls_fingerprint);
    
    /**
     * @brief Generiert einen MD5-Hash des JA3-Fingerprints
     * 
     * @param ja3_string JA3-Fingerprint-String
     * @return std::string MD5-Hash des JA3-Fingerprints
     */
    static std::string generate_hash(const std::string& ja3_string);
    
    /**
     * @brief Generiert einen TLS-Fingerprint aus einem JA3-String
     * 
     * @param ja3_string JA3-Fingerprint-String
     * @return TLSFingerprint Rekonstruierter TLS-Fingerprint
     */
    static TLSFingerprint parse(const std::string& ja3_string);
    
    /**
     * @brief Generiert einen JA3-Fingerprint für einen bestimmten Browser
     * 
     * @param os Betriebssystem
     * @param browser Browser-Typ
     * @return std::string JA3-Fingerprint-String
     */
    static std::string get_browser_ja3(OperatingSystem os, BrowserType browser);
};

} // namespace quicfuscate::stealth
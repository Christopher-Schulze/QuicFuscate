#ifndef FAKE_HEADERS_HPP
#define FAKE_HEADERS_HPP

#include <vector>
#include <string>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <functional>
#include "../../qpack_compression.hpp"

namespace quicfuscate::stealth {

/**
 * @brief Enum für verschiedene HTTP-Methoden, die in den Fake-Headers verwendet werden können
 */
enum class HttpMethod {
    GET,
    POST,
    HEAD,
    PUT,
    DELETE,
    OPTIONS,
    CONNECT,
    PATCH
};

/**
 * @brief Enum für verschiedene Header-Profile, die als Vorlagen für die Generierung dienen
 */
enum class HeaderProfileType {
    CHROME_BROWSER,    ///< Chrome Browser Header
    FIREFOX_BROWSER,   ///< Firefox Browser Header
    SAFARI_BROWSER,    ///< Safari Browser Header
    EDGE_BROWSER,      ///< Edge Browser Header
    ANDROID_APP,       ///< Android App Header
    IOS_APP,           ///< iOS App Header
    CDN_CLIENT,        ///< CDN Client Header (z.B. CloudFront)
    HTTP3_CLIENT,      ///< HTTP/3 spezifische Client-Header
    QUIC_MASQUERADE,   ///< QUIC-optimierte Masquerade-Header
    TROJAN_GFW,        ///< Trojan-GFW spezifische Header
    TROJAN_GO,         ///< Trojan-Go spezifische Header
    SHADOWSOCKS,       ///< Shadowsocks spezifische Header
    RANDOM,            ///< Zufällige Mischung aus verschiedenen Headern
    CUSTOM             ///< Benutzerdefinierte Header
};

/**
 * @brief HTTP-Version für die Header-Generierung
 */
enum class HttpVersion {
    HTTP_1_1,  ///< HTTP/1.1 (traditionelles HTTP)
    HTTP_2,    ///< HTTP/2 mit binärem Format und HPACK
    HTTP_3     ///< HTTP/3 mit QUIC und QPACK
};

/**
 * @brief Konfigurationsstruktur für FakeHeaders
 */
struct FakeHeadersConfig {
    // Grundlegende Konfiguration
    HeaderProfileType profile_type = HeaderProfileType::HTTP3_CLIENT;
    std::string base_url = "https://example.com/";
    HttpMethod http_method = HttpMethod::GET;
    HttpVersion http_version = HttpVersion::HTTP_3; ///< Standard: HTTP/3 für QUIC
    bool include_http2_pseudoheaders = true; ///< HTTP/2 Pseudo-Header einschließen
    
    // Erweiterte Konfiguration
    bool randomize_header_order = true;      ///< Zufällige Reihenfolge der nicht-Standard-Header
    bool randomize_cache_headers = true;     ///< Zufällige Cache-Control Header
    bool add_random_values = true;           ///< Zufällige Werte für bestimmte Header
    bool optimize_for_quic = true;           ///< QUIC-spezifische Optimierungen aktivieren
    bool mimic_alt_svc_upgrade = true;       ///< Alt-Svc Header für HTTP/3-Upgrade simulieren
    bool include_quic_transport_params = true; ///< QUIC-Transportparameter einschließen
    
    // QPACK-Konfiguration für HTTP/3
    bool use_qpack_headers = true;           ///< QPACK anstelle von HPACK für HTTP/3
    size_t qpack_table_size = 4096;          ///< Größe der QPACK-Tabelle
    
    // Benutzerdefinierte Header
    std::map<std::string, std::string> custom_headers;
    
    // Größenbegrenzung (0 = keine Begrenzung)
    size_t max_header_size = 0;
};

/**
 * @brief Klasse zur Generierung und Injektion von gefälschten HTTP-Headern für Stealth-Zwecke
 * 
 * Diese Klasse implementiert verschiedene Techniken zur Tarnung des VPN-Verkehrs,
 * indem HTTP-Header generiert werden, die reale Browser oder andere Client-Anwendungen
 * nachahmen. Die generierten Header werden in die Datenpakete injiziert, um Deep Packet
 * Inspection (DPI) zu umgehen und den Verkehr wie normalen Web-Traffic erscheinen zu lassen.
 */
class FakeHeaders {
public:
    /**
     * @brief Konstruktor mit Konfiguration
     * @param config Die Konfiguration für die Header-Generierung
     */
    explicit FakeHeaders(const FakeHeadersConfig& config = FakeHeadersConfig());
    
    /**
     * @brief Destruktor
     */
    ~FakeHeaders();
    
    /**
     * @brief Move-Konstruktor
     */
    FakeHeaders(FakeHeaders&& other) noexcept;
    
    /**
     * @brief Move-Zuweisungsoperator
     */
    FakeHeaders& operator=(FakeHeaders&& other) noexcept;
    
    /**
     * @brief Kopier-Konstruktor (deaktiviert)
     */
    FakeHeaders(const FakeHeaders&) = delete;
    
    /**
     * @brief Kopier-Zuweisungsoperator (deaktiviert)
     */
    FakeHeaders& operator=(const FakeHeaders&) = delete;
    
    /**
     * @brief Generiert und injiziert Fake-Headers in ein Paket
     * @param packet Das ursprüngliche Datenpaket
     * @return Ein neues Paket mit injizierten Headern
     */
    std::vector<uint8_t> inject_fake_headers(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Entfernt Fake-Headers aus einem Paket
     * @param packet Das Paket mit Fake-Headers
     * @return Das ursprüngliche Paket ohne Header
     */
    std::vector<uint8_t> remove_fake_headers(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Generiert HTTP-Headers als String
     * @return Der generierte Header-String
     */
    std::string generate_headers_string() const;
    
    /**
     * @brief Generiert eine optimierte Header-Vorlage ohne Datenpakete
     * 
     * Diese Methode erstellt eine wiederverwendbare Header-Vorlage, die
     * mit minimalen Änderungen auf mehrere Datenpakete angewendet werden kann.
     * Unterstützt Zero-Copy-Operationen für hohen Durchsatz.
     * 
     * @return Vorgenerierte Header-Vorlage als Byte-Array
     */
    std::vector<uint8_t> generate_header_template() const;
    
    /**
     * @brief Generiert HTTP/3-QPACK-kodierte Header für authentische HTTP/3-Maskierung
     * 
     * Verwendet QPACK (HTTP/3-Header-Kompression) für maximale Authentizität
     * der HTTP/3-Maskierung. Folgt den RFC 9204 Spezifikationen.
     * 
     * @return QPACK-kodierte Header als Byte-Array
     */
    std::vector<uint8_t> generate_qpack_headers() const;
    
    /**
     * @brief Überprüft, ob ein Paket Fake-Headers enthält
     * @param packet Das zu überprüfende Paket
     * @return true, wenn das Paket Fake-Headers enthält
     */
    bool has_fake_headers(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Liest die Header-Größe aus einem Paket
     * @param packet Das Paket mit Fake-Headers
     * @return Die Größe der Header in Bytes (0 wenn keine Header)
     */
    size_t get_header_size(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Extrahiert die Header-Daten als String
     * @param packet Das Paket mit Fake-Headers
     * @return Die Header-Daten als String
     */
    std::string extract_headers(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Setzt den Header-Profiltyp
     * @param profile_type Der neue Profiltyp
     */
    void set_profile_type(HeaderProfileType profile_type);
    
    /**
     * @brief Setzt die Basis-URL
     * @param url Die neue Basis-URL
     */
    void set_base_url(const std::string& url);
    
    /**
     * @brief Setzt die HTTP-Methode
     * @param method Die neue HTTP-Methode
     */
    void set_http_method(HttpMethod method);
    
    /**
     * @brief Fügt einen benutzerdefinierten Header hinzu
     * @param name Der Header-Name
     * @param value Der Header-Wert
     */
    void add_custom_header(const std::string& name, const std::string& value);
    
    /**
     * @brief Entfernt einen benutzerdefinierten Header
     * @param name Der Header-Name
     */
    void remove_custom_header(const std::string& name);
    
    /**
     * @brief Gibt die aktuelle Konfiguration zurück
     * @return Die aktuelle Konfiguration
     */
    const FakeHeadersConfig& get_config() const;
    
    /**
     * @brief Setzt eine neue Konfiguration
     * @param config Die neue Konfiguration
     */
    void set_config(const FakeHeadersConfig& config);
    
private:
    // PIMPL-Idiom für verbesserte Kompilierungsgeschwindigkeit und ABI-Stabilität
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace quicfuscate::stealth

#endif // FAKE_HEADERS_HPP

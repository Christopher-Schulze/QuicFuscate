#ifndef DOMAIN_FRONTING_HPP
#define DOMAIN_FRONTING_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <optional>

namespace quicfuscate {
namespace stealth {

/**
 * @brief Aufzählung der SNI-Hiding-Techniken
 */
enum class SniTechnique {
    DOMAIN_FRONTING,        // Domain Fronting (unterschiedliche Host-Header und SNI)
    SNI_OMISSION,           // SNI komplett weglassen
    SNI_PADDING,            // SNI mit zusätzlichem Padding
    SNI_SPLIT,              // SNI auf mehrere Pakete aufteilen
    ECH,                    // Encrypted Client Hello (TLS 1.3 Extension)
    ESNI                    // Encrypted SNI (veraltet, durch ECH ersetzt)
};

/**
 * @brief Konfiguration für das SNI-Hiding
 */
struct SniConfig {
    bool enable_domain_fronting = true;   // Domain Fronting aktivieren
    bool enable_sni_omission = false;     // SNI-Omission aktivieren (kann Probleme verursachen)
    bool enable_sni_padding = true;       // SNI-Padding aktivieren
    bool enable_sni_split = false;        // SNI-Split aktivieren (experimentell)
    bool enable_ech = false;              // ECH aktivieren (falls unterstützt)
    bool enable_esni = false;             // ESNI aktivieren (veraltet)
    
    // Domain Fronting Konfiguration
    std::string front_domain = "www.google.com";   // Domain für SNI
    std::string real_domain = "example.com";       // Tatsächliche Domain im Host-Header
    
    // ECH/ESNI Konfiguration
    std::vector<uint8_t> ech_config_data;          // ECH-Konfigurationsdaten
    
    // Liste von vertrauenswürdigen Fronting-Domains
    std::vector<std::string> trusted_fronts = {
        "www.google.com",
        "www.microsoft.com",
        "www.apple.com",
        "www.cloudflare.com",
        "www.amazon.com",
        "www.akamai.com",
        "www.cdn.com"
    };
};

/**
 * @brief Klasse für die Implementierung von SNI-Hiding-Techniken
 */
class SniHiding {
public:
    /**
     * @brief Konstruktor mit Konfiguration
     * @param config Die SNI-Hiding-Konfiguration
     */
    explicit SniHiding(const SniConfig& config = SniConfig());
    
    /**
     * @brief Destruktor
     */
    ~SniHiding() = default;
    
    /**
     * @brief Aktiviert eine spezifische SNI-Hiding-Technik
     * @param technique Die zu aktivierende Technik
     */
    void enable_technique(SniTechnique technique);
    
    /**
     * @brief Deaktiviert eine spezifische SNI-Hiding-Technik
     * @param technique Die zu deaktivierende Technik
     */
    void disable_technique(SniTechnique technique);
    
    /**
     * @brief Überprüft, ob eine Technik aktiviert ist
     * @param technique Die zu überprüfende Technik
     * @return true, wenn die Technik aktiviert ist, sonst false
     */
    bool is_technique_enabled(SniTechnique technique) const;
    
    /**
     * @brief Wendet die SNI-Hiding-Techniken auf TLS Client Hello Pakete an
     * @param client_hello Das zu verändernde TLS Client Hello Paket
     * @return Das modifizierte Paket mit angewendeten SNI-Hiding-Techniken
     */
    std::vector<uint8_t> process_client_hello(const std::vector<uint8_t>& client_hello);
    
    /**
     * @brief Modifiziert den SNI-Wert in einem TLS Client Hello Paket
     * @param client_hello Das zu verändernde TLS Client Hello Paket
     * @param new_sni Der neue SNI-Wert
     * @return Das modifizierte Paket mit geändertem SNI
     */
    std::vector<uint8_t> modify_sni(const std::vector<uint8_t>& client_hello, const std::string& new_sni);
    
    /**
     * @brief Wendet Domain Fronting auf HTTP/1.1 oder HTTP/2 Headers an
     * @param http_headers Die zu ändernden HTTP-Headers
     * @return Die modifizierten HTTP-Headers
     */
    std::string apply_domain_fronting(const std::string& http_headers);
    
    /**
     * @brief Generiert eine ECH-Konfiguration (Encrypted Client Hello)
     * @param target_domain Die Ziel-Domain für ECH
     * @return ECH-Konfigurationsdaten oder nullopt bei Fehler
     */
    std::optional<std::vector<uint8_t>> generate_ech_config(const std::string& target_domain);
    
    /**
     * @brief Ruft die aktuelle ECH-Konfiguration ab
     * @return Die aktuelle ECH-Konfiguration
     */
    std::vector<uint8_t> get_ech_config() const;
    
    /**
     * @brief Setzt die Konfiguration für das SNI-Hiding
     * @param config Die neue Konfiguration
     */
    void set_config(const SniConfig& config);
    
    /**
     * @brief Gibt die aktuelle Konfiguration zurück
     * @return Die aktuelle Konfiguration
     */
    SniConfig get_config() const;
    
    /**
     * @brief Fügt eine vertrauenswürdige Fronting-Domain hinzu
     * @param domain Die hinzuzufügende Domain
     */
    void add_trusted_front(const std::string& domain);
    
    /**
     * @brief Entfernt eine vertrauenswürdige Fronting-Domain
     * @param domain Die zu entfernende Domain
     */
    void remove_trusted_front(const std::string& domain);
    
    /**
     * @brief Ruft alle vertrauenswürdigen Fronting-Domains ab
     * @return Liste aller vertrauenswürdigen Fronting-Domains
     */
    std::vector<std::string> get_trusted_fronts() const;
    
private:
    SniConfig config_;
    std::unordered_map<SniTechnique, bool> enabled_techniques_;
    
    // Interne Hilfsfunktionen
    std::vector<uint8_t> apply_sni_padding(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_sni_omission(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_sni_split(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_ech(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> apply_esni(const std::vector<uint8_t>& client_hello);
    
    // Initialisierungsfunktionen
    void init_enabled_techniques();
    
    // Funktionen für die TLS-Paketmanipulation
    bool find_sni_extension(const std::vector<uint8_t>& client_hello, size_t& extension_offset, size_t& extension_length);
};

} // namespace stealth
} // namespace quicfuscate

#endif // DOMAIN_FRONTING_HPP
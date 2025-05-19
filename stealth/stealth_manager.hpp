#ifndef STEALTH_MANAGER_HPP
#define STEALTH_MANAGER_HPP

#include "dpi_evasion.hpp"
#include "sni_hiding.hpp"
#include "spin_bit_randomizer.hpp"

#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace quicsand {
namespace stealth {

/**
 * @brief Konfiguration für den Stealth-Manager
 */
struct StealthConfig {
    DpiConfig dpi_config;               // Konfiguration für DPI-Evasion
    SniConfig sni_config;               // Konfiguration für SNI-Hiding
    SpinBitConfig spin_bit_config;      // Konfiguration für Spin Bit Randomizer
    
    bool enabled = true;                // Globale Aktivierung/Deaktivierung
    uint32_t stealth_level = 2;         // Stealth-Level (0-3): Je höher, desto mehr Stealth-Features
};

/**
 * @brief Zentrale Klasse zur Verwaltung aller Stealth-Funktionen
 */
class StealthManager {
public:
    /**
     * @brief Konstruktor mit Konfiguration
     * @param config Die Stealth-Konfiguration
     */
    explicit StealthManager(const StealthConfig& config = StealthConfig());
    
    /**
     * @brief Destruktor
     */
    ~StealthManager() = default;
    
    /**
     * @brief Aktiviert alle Stealth-Funktionen
     */
    void enable();
    
    /**
     * @brief Deaktiviert alle Stealth-Funktionen
     */
    void disable();
    
    /**
     * @brief Überprüft, ob Stealth aktiviert ist
     * @return true, wenn aktiviert, sonst false
     */
    bool is_enabled() const;
    
    /**
     * @brief Setzt das Stealth-Level
     * @param level Das Stealth-Level (0-3)
     */
    void set_stealth_level(uint32_t level);
    
    /**
     * @brief Gibt das aktuelle Stealth-Level zurück
     * @return Das aktuelle Stealth-Level
     */
    uint32_t get_stealth_level() const;
    
    /**
     * @brief Verarbeitet ausgehende QUIC-Pakete mit Stealth-Funktionen
     * @param packet Das zu verarbeitende Paket
     * @return Ein Vektor mit verarbeiteten Paketen (kann fragmentiert sein)
     */
    std::vector<std::vector<uint8_t>> process_outgoing_packet(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Verarbeitet eingehende QUIC-Pakete
     * @param packet Das zu verarbeitende Paket
     * @return Das verarbeitete Paket
     */
    std::vector<uint8_t> process_incoming_packet(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Verarbeitet TLS Client Hello Pakete
     * @param client_hello Das zu verarbeitende Client Hello Paket
     * @return Das verarbeitete Paket
     */
    std::vector<uint8_t> process_client_hello(const std::vector<uint8_t>& client_hello);
    
    /**
     * @brief Verarbeitet HTTP-Headers mit Domain Fronting
     * @param http_headers Die zu verarbeitenden HTTP-Headers
     * @return Die verarbeiteten HTTP-Headers
     */
    std::string process_http_headers(const std::string& http_headers);
    
    /**
     * @brief Gibt die aktuelle Konfiguration zurück
     * @return Die aktuelle Konfiguration
     */
    StealthConfig get_config() const;
    
    /**
     * @brief Setzt die Konfiguration
     * @param config Die neue Konfiguration
     */
    void set_config(const StealthConfig& config);
    
    /**
     * @brief Berechnet die Verzögerung für das nächste Paket (Timing Randomization)
     * @return Die Verzögerung in Millisekunden
     */
    uint32_t calculate_next_delay() const;
    
    /**
     * @brief Konfiguriere einen Stealth-Proxy für Domain Fronting
     * @param front_domain Die Front-Domain (für SNI)
     * @param real_domain Die tatsächliche Ziel-Domain (im Host-Header)
     */
    void configure_domain_fronting(const std::string& front_domain, const std::string& real_domain);
    
    /**
     * @brief Zugriff auf die DPI-Evasion-Komponente
     * @return Referenz auf die DPI-Evasion-Komponente
     */
    DpiEvasion& dpi_evasion();
    
    /**
     * @brief Zugriff auf die SNI-Hiding-Komponente
     * @return Referenz auf die SNI-Hiding-Komponente
     */
    SniHiding& sni_hiding();
    
    /**
     * @brief Zugriff auf die Spin Bit Randomizer-Komponente
     * @return Referenz auf die Spin Bit Randomizer-Komponente
     */
    SpinBitRandomizer& spin_bit_randomizer();
    
private:
    StealthConfig config_;
    std::unique_ptr<DpiEvasion> dpi_evasion_;
    std::unique_ptr<SniHiding> sni_hiding_;
    std::unique_ptr<SpinBitRandomizer> spin_bit_randomizer_;
    
    // Konfiguration für verschiedene Stealth-Level
    void configure_stealth_level();
    
    // Interne Hilfsfunktionen
    bool is_client_hello(const std::vector<uint8_t>& packet) const;
    bool is_http_request(const std::vector<uint8_t>& packet) const;
    bool is_quic_packet(const std::vector<uint8_t>& packet) const;
};

} // namespace stealth
} // namespace quicsand

#endif // STEALTH_MANAGER_HPP

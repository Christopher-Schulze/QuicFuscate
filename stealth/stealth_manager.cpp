#include "stealth_manager.hpp"
#include <iostream>
#include <algorithm>

namespace quicsand {
namespace stealth {

// Konstruktor mit Konfiguration
StealthManager::StealthManager(const StealthConfig& config)
    : config_(config) {
    
    // Initialisiere die Komponenten
    dpi_evasion_ = std::make_unique<DpiEvasion>(config.dpi_config);
    sni_hiding_ = std::make_unique<SniHiding>(config.sni_config);
    spin_bit_randomizer_ = std::make_unique<SpinBitRandomizer>(config.spin_bit_config);
    
    // Konfiguriere die Komponenten basierend auf dem Stealth-Level
    configure_stealth_level();
}

// Aktiviere alle Stealth-Funktionen
void StealthManager::enable() {
    config_.enabled = true;
}

// Deaktiviere alle Stealth-Funktionen
void StealthManager::disable() {
    config_.enabled = false;
}

// Überprüfe, ob Stealth aktiviert ist
bool StealthManager::is_enabled() const {
    return config_.enabled;
}

// Setze das Stealth-Level
void StealthManager::set_stealth_level(uint32_t level) {
    // Begrenze das Level auf 0-3
    config_.stealth_level = std::min(level, 3u);
    
    // Konfiguriere die Komponenten basierend auf dem neuen Level
    configure_stealth_level();
}

// Gib das aktuelle Stealth-Level zurück
uint32_t StealthManager::get_stealth_level() const {
    return config_.stealth_level;
}

// Verarbeite ausgehende QUIC-Pakete
std::vector<std::vector<uint8_t>> StealthManager::process_outgoing_packet(const std::vector<uint8_t>& packet) {
    if (!config_.enabled) {
        return {packet};
    }
    
    // Verarbeite je nach Pakettyp
    if (is_client_hello(packet)) {
        // TLS Client Hello Paket
        std::vector<uint8_t> processed_client_hello = process_client_hello(packet);
        
        // Wende DPI-Evasion auf das verarbeitete Client Hello an
        return dpi_evasion_->process_packet(processed_client_hello);
    }
    else if (is_quic_packet(packet)) {
        // QUIC-Paket
        std::vector<uint8_t> processed_packet = packet;
        
        // Wende Spin Bit Randomisierung an
        bool original_bit = (packet[0] & 0x20) != 0; // 3. Bit im Header
        spin_bit_randomizer_->set_spin_bit(processed_packet, original_bit);
        
        // Wende DPI-Evasion an
        return dpi_evasion_->process_packet(processed_packet);
    }
    else {
        // Andere Pakete
        return dpi_evasion_->process_packet(packet);
    }
}

// Verarbeite eingehende QUIC-Pakete
std::vector<uint8_t> StealthManager::process_incoming_packet(const std::vector<uint8_t>& packet) {
    if (!config_.enabled) {
        return packet;
    }
    
    // Für eingehende Pakete machen wir in der Regel weniger
    // Keine Fragmentierung, keine Timing-Randomisierung
    
    return packet;
}

// Verarbeite TLS Client Hello Pakete
std::vector<uint8_t> StealthManager::process_client_hello(const std::vector<uint8_t>& client_hello) {
    if (!config_.enabled) {
        return client_hello;
    }
    
    // Wende SNI-Hiding an
    return sni_hiding_->process_client_hello(client_hello);
}

// Verarbeite HTTP-Headers mit Domain Fronting
std::string StealthManager::process_http_headers(const std::string& http_headers) {
    if (!config_.enabled || !sni_hiding_->is_technique_enabled(SniTechnique::DOMAIN_FRONTING)) {
        return http_headers;
    }
    
    // Wende Domain Fronting auf HTTP-Headers an
    return sni_hiding_->apply_domain_fronting(http_headers);
}

// Gib die aktuelle Konfiguration zurück
StealthConfig StealthManager::get_config() const {
    return config_;
}

// Setze die Konfiguration
void StealthManager::set_config(const StealthConfig& config) {
    config_ = config;
    
    // Aktualisiere die Komponenten
    dpi_evasion_->set_config(config.dpi_config);
    sni_hiding_->set_config(config.sni_config);
    spin_bit_randomizer_->set_config(config.spin_bit_config);
    
    // Konfiguriere die Komponenten basierend auf dem Stealth-Level
    configure_stealth_level();
}

// Berechne die Verzögerung für das nächste Paket
uint32_t StealthManager::calculate_next_delay() const {
    if (!config_.enabled) {
        return 0;
    }
    
    return dpi_evasion_->calculate_next_delay();
}

// Konfiguriere Domain Fronting
void StealthManager::configure_domain_fronting(const std::string& front_domain, const std::string& real_domain) {
    SniConfig sni_config = sni_hiding_->get_config();
    sni_config.front_domain = front_domain;
    sni_config.real_domain = real_domain;
    sni_hiding_->set_config(sni_config);
    
    // Aktiviere Domain Fronting
    sni_hiding_->enable_technique(SniTechnique::DOMAIN_FRONTING);
}

// Zugriff auf die DPI-Evasion-Komponente
DpiEvasion& StealthManager::dpi_evasion() {
    return *dpi_evasion_;
}

// Zugriff auf die SNI-Hiding-Komponente
SniHiding& StealthManager::sni_hiding() {
    return *sni_hiding_;
}

// Zugriff auf die Spin Bit Randomizer-Komponente
SpinBitRandomizer& StealthManager::spin_bit_randomizer() {
    return *spin_bit_randomizer_;
}

// --- Private Methoden ---

// Definition von Stealth-Level-Konfigurationen als Tabellen
using DpiTechniqueMap = std::unordered_map<DpiTechnique, bool>;
using SniTechniqueMap = std::unordered_map<SniTechnique, bool>;
using SpinBitConfigMap = std::pair<bool, SpinBitStrategy>;

// Stealth-Konfigurationen für die verschiedenen Level
static const std::unordered_map<uint32_t, std::tuple<DpiTechniqueMap, SniTechniqueMap, SpinBitConfigMap>> STEALTH_PROFILES = {
    // Level 0: Minimale Stealth
    {0, {
        // DPI-Evasion: Alles deaktiviert
        {
            {DpiTechnique::PACKET_FRAGMENTATION, false},
            {DpiTechnique::TIMING_RANDOMIZATION, false},
            {DpiTechnique::PAYLOAD_RANDOMIZATION, false},
            {DpiTechnique::HTTP_MIMICRY, false},
            {DpiTechnique::TLS_CHARACTERISTICS, false},
            {DpiTechnique::PADDING_VARIATION, false},
            {DpiTechnique::PROTOCOL_OBFUSCATION, false}
        },
        // SNI-Hiding: Alles deaktiviert
        {
            {SniTechnique::DOMAIN_FRONTING, false},
            {SniTechnique::SNI_OMISSION, false},
            {SniTechnique::SNI_PADDING, false},
            {SniTechnique::SNI_SPLIT, false},
            {SniTechnique::ECH, false},
            {SniTechnique::ESNI, false}
        },
        // Spin Bit: Deaktiviert
        {false, SpinBitStrategy::RANDOM}
    }},
    
    // Level 1: Mittlere Stealth
    {1, {
        // DPI-Evasion: Grundlegende Verschleierung
        {
            {DpiTechnique::PACKET_FRAGMENTATION, false},
            {DpiTechnique::TIMING_RANDOMIZATION, false},
            {DpiTechnique::PAYLOAD_RANDOMIZATION, true},
            {DpiTechnique::HTTP_MIMICRY, false},
            {DpiTechnique::TLS_CHARACTERISTICS, true},
            {DpiTechnique::PADDING_VARIATION, true},
            {DpiTechnique::PROTOCOL_OBFUSCATION, false}
        },
        // SNI-Hiding: Nur SNI-Padding
        {
            {SniTechnique::DOMAIN_FRONTING, false},
            {SniTechnique::SNI_OMISSION, false},
            {SniTechnique::SNI_PADDING, true},
            {SniTechnique::SNI_SPLIT, false},
            {SniTechnique::ECH, false},
            {SniTechnique::ESNI, false}
        },
        // Spin Bit: Random
        {true, SpinBitStrategy::RANDOM}
    }},
    
    // Level 2: Hohe Stealth
    {2, {
        // DPI-Evasion: Fortgeschrittene Verschleierung
        {
            {DpiTechnique::PACKET_FRAGMENTATION, true},
            {DpiTechnique::TIMING_RANDOMIZATION, true},
            {DpiTechnique::PAYLOAD_RANDOMIZATION, true},
            {DpiTechnique::HTTP_MIMICRY, false},
            {DpiTechnique::TLS_CHARACTERISTICS, true},
            {DpiTechnique::PADDING_VARIATION, true},
            {DpiTechnique::PROTOCOL_OBFUSCATION, true}
        },
        // SNI-Hiding: Fortgeschrittene Verschleierung
        {
            {SniTechnique::DOMAIN_FRONTING, true},
            {SniTechnique::SNI_OMISSION, false},
            {SniTechnique::SNI_PADDING, true},
            {SniTechnique::SNI_SPLIT, false},
            {SniTechnique::ECH, true},
            {SniTechnique::ESNI, false}
        },
        // Spin Bit: Timing-basiert
        {true, SpinBitStrategy::TIMING_BASED}
    }},
    
    // Level 3: Maximale Stealth
    {3, {
        // DPI-Evasion: Alle Techniken aktiviert
        {
            {DpiTechnique::PACKET_FRAGMENTATION, true},
            {DpiTechnique::TIMING_RANDOMIZATION, true},
            {DpiTechnique::PAYLOAD_RANDOMIZATION, true},
            {DpiTechnique::HTTP_MIMICRY, true},
            {DpiTechnique::TLS_CHARACTERISTICS, true},
            {DpiTechnique::PADDING_VARIATION, true},
            {DpiTechnique::PROTOCOL_OBFUSCATION, true}
        },
        // SNI-Hiding: Maximale Verschleierung
        {
            {SniTechnique::DOMAIN_FRONTING, true},
            {SniTechnique::SNI_OMISSION, false},  // Kann Probleme verursachen
            {SniTechnique::SNI_PADDING, true},
            {SniTechnique::SNI_SPLIT, true},      // Jetzt vollständig implementiert
            {SniTechnique::ECH, true},
            {SniTechnique::ESNI, false}           // Veraltet
        },
        // Spin Bit: Random
        {true, SpinBitStrategy::RANDOM}
    }}
};

// Konfiguriere die Komponenten basierend auf dem Stealth-Level
void StealthManager::configure_stealth_level() {
    // Suche das entsprechende Stealth-Profil
    auto profile_it = STEALTH_PROFILES.find(config_.stealth_level);
    if (profile_it == STEALTH_PROFILES.end()) {
        // Fallback auf Standardprofil (Level 2)
        profile_it = STEALTH_PROFILES.find(2);
    }
    
    // Extrahiere die Konfigurationstabellen
    const auto& [dpi_config, sni_config, spin_bit_config] = profile_it->second;
    
    // 1. Konfiguriere DPI-Evasion
    for (const auto& [technique, enabled] : dpi_config) {
        if (enabled) {
            dpi_evasion_->enable_technique(technique);
        } else {
            dpi_evasion_->disable_technique(technique);
        }
    }
    
    // 2. Konfiguriere SNI-Hiding
    for (const auto& [technique, enabled] : sni_config) {
        if (enabled) {
            sni_hiding_->enable_technique(technique);
        } else {
            sni_hiding_->disable_technique(technique);
        }
    }
    
    // 3. Konfiguriere Spin Bit Randomizer
    const auto& [spin_enabled, spin_strategy] = spin_bit_config;
    if (spin_enabled) {
        spin_bit_randomizer_->enable();
        spin_bit_randomizer_->set_strategy(spin_strategy);
    } else {
        spin_bit_randomizer_->disable();
    }
}

// Überprüfe, ob ein Paket ein TLS Client Hello ist
bool StealthManager::is_client_hello(const std::vector<uint8_t>& packet) const {
    // Vereinfachte Erkennung eines TLS Client Hello
    if (packet.size() >= 6 && 
        packet[0] == 0x16 &&   // Handshake
        packet[5] == 0x01) {   // Client Hello
        return true;
    }
    return false;
}

// Überprüfe, ob ein Paket ein HTTP-Request ist
bool StealthManager::is_http_request(const std::vector<uint8_t>& packet) const {
    // Überprüfe die ersten Bytes des Pakets auf typische HTTP-Methoden
    if (packet.size() >= 4) {
        if ((packet[0] == 'G' && packet[1] == 'E' && packet[2] == 'T' && packet[3] == ' ') ||
            (packet[0] == 'P' && packet[1] == 'O' && packet[2] == 'S' && packet[3] == 'T') ||
            (packet[0] == 'H' && packet[1] == 'E' && packet[2] == 'A' && packet[3] == 'D') ||
            (packet[0] == 'P' && packet[1] == 'U' && packet[2] == 'T' && packet[3] == ' ') ||
            (packet[0] == 'D' && packet[1] == 'E' && packet[2] == 'L' && packet[3] == 'E')) {
            return true;
        }
    }
    return false;
}

// Überprüfe, ob ein Paket ein QUIC-Paket ist
bool StealthManager::is_quic_packet(const std::vector<uint8_t>& packet) const {
    // QUIC-Pakete beginnen mit unterschiedlichen Headern abhängig vom Typ
    if (packet.size() >= 1) {
        // Long Header: Erstes Bit ist 1
        if ((packet[0] & 0x80) != 0) {
            return true;
        }
        
        // Short Header: Erstes Bit ist 0, zweites Bit ist 1
        if ((packet[0] & 0xC0) == 0x40) {
            return true;
        }
    }
    return false;
}

} // namespace stealth
} // namespace quicsand

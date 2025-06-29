#include "stealth_gov.hpp"
#include "browser_profiles/headers/FakeHeaders.hpp"
#include "XOR_Obfuscation.hpp"
#include "QuicFuscate_Stealth.hpp"
#include "DomainFronting.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace quicfuscate {
namespace stealth {

// Konstruktor mit Konfiguration
StealthManager::StealthManager(const StealthConfig& config)
    : config_(config) {
    
    // Initialisiere die Komponenten
    dpi_evasion_ = std::make_unique<DpiEvasion>(config.dpi_evasion_config);
    sni_hiding_ = std::make_unique<SniHiding>(config.sni_hiding_config);
    
    // Erstelle SpinBitRandomizer aus der QUIC-Integration-Konfiguration
    SpinBitConfig spin_config;
    spin_config.enabled = config.quic_integration_config.randomize_spin_bit;
    spin_config.probability = config.quic_integration_config.spin_bit_randomization_probability;
    spin_bit_randomizer_ = std::make_unique<SpinBitRandomizer>(spin_config);
    
    fake_headers_ = std::make_unique<FakeHeaders>(config.fake_headers_config);
    xor_obfuscator_ = std::make_unique<XORObfuscator>(config.xor_config);
    
    // Initialisiere QUIC Path Migration wenn aktiviert
    if (config.enable_path_migration) {
        path_migration_ = std::make_unique<QuicPathMigration>(config.path_migration_config);
    }
    
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
void StealthManager::set_stealth_level(StealthLevel level) {
    // Setze das neue Stealth-Level
    config_.stealth_level = level;
    
    // Konfiguriere die Komponenten basierend auf dem neuen Level
    configure_stealth_level();
}

// Gib das aktuelle Stealth-Level zurück
StealthLevel StealthManager::get_stealth_level() const {
    return config_.stealth_level;
}

// Verarbeite ausgehende QUIC-Pakete
std::vector<std::vector<uint8_t>> StealthManager::process_outgoing_packet(const std::vector<uint8_t>& packet) {
    // Wenn Stealth deaktiviert ist, Originalpaket ohne Verarbeitung zurückgeben
    if (!config_.enabled) {
        return {packet};
    }
    
    std::vector<std::vector<uint8_t>> processed_packets;
    
    // TLS Client Hello speziell verarbeiten
    if (is_client_hello(packet)) {
        auto processed = process_client_hello(packet);
        processed_packets.push_back(processed);
        return processed_packets;
    }
    
    // HTTP-Request mit HTTP/3-Maskierung speziell verarbeiten
    if (is_http_request(packet)) {
        // Wenn HTTP/3-Maskierung aktiviert ist, Fake-Headers verwenden
        if (config_.enable_quic_masquerading) {
            auto processed = process_http_traffic(packet);
            processed_packets.push_back(processed);
            return processed_packets;
        } else {
            // Traditionelle HTTP-Header-Verarbeitung (Domain Fronting)
            std::string headers(packet.begin(), packet.end());
            std::string processed_headers = process_http_headers(headers);
            processed_packets.push_back(std::vector<uint8_t>(processed_headers.begin(), processed_headers.end()));
            return processed_packets;
        }
    }
    
    // Allgemeine QUIC-Paketverarbeitung
    if (is_quic_packet(packet)) {
        // Wenn HTTP/3-Maskierung für QUIC aktiviert ist
        if (config_.enable_quic_masquerading) {
            // HTTP/3-Maskierung für QUIC-Pakete anwenden
            auto with_fake_headers = process_http_traffic(packet);
            
            // DPI-Evasion für besonders wichtige Pakete noch zusätzlich anwenden
            if (config_.stealth_level >= StealthLevel::ENHANCED) {
                auto fragmented = dpi_evasion_->fragment_packet(with_fake_headers);
                
                // Spin Bit Randomization anwenden
                for (auto& fragment : fragmented) {
                    fragment = spin_bit_randomizer_->randomize_spin_bit(fragment);
                    processed_packets.push_back(fragment);
                }
                
                return processed_packets;
            } else {
                // Bei niedrigerem Stealth-Level keine Fragmentierung
                processed_packets.push_back(with_fake_headers);
                return processed_packets;
            }
        } else {
            // Traditionelle DPI-Evasion anwenden
            auto fragmented = dpi_evasion_->fragment_packet(packet);
            
            // Spin Bit Randomization anwenden
            for (auto& fragment : fragmented) {
                fragment = spin_bit_randomizer_->randomize_spin_bit(fragment);
                processed_packets.push_back(fragment);
            }
            
            return processed_packets;
        }
    }
    
    // Fallback: Paket unverändert zurückgeben
    processed_packets.push_back(packet);
    return processed_packets;
}

// Verarbeite eingehende QUIC-Pakete
std::vector<uint8_t> StealthManager::process_incoming_packet(const std::vector<uint8_t>& packet) {
    // Wenn Stealth deaktiviert ist, Originalpaket ohne Verarbeitung zurückgeben
    if (!config_.enabled) {
        return packet;
    }
    
    // Prüfen, ob Paket Fake-Headers enthält und diese entfernen
    if (has_fake_headers(packet)) {
        return remove_fake_headers(packet);
    }
    
    // Eingehende Pakete verarbeiten
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
    
    if (config_.enable_xor_obfuscation) {
        xor_obfuscator_->set_config(config.xor_config);
    }
    
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
static const std::unordered_map<StealthLevel, std::tuple<DpiTechniqueMap, SniTechniqueMap, SpinBitConfigMap>> STEALTH_PROFILES = {
    // Level MINIMAL: Minimale Stealth
    {StealthLevel::MINIMAL, {
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
    
    // Level STANDARD: Mittlere Stealth
    {StealthLevel::STANDARD, {
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
    
    // Level ENHANCED: Hohe Stealth
    {StealthLevel::ENHANCED, {
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
    
    // Level MAXIMUM: Maximale Stealth
    {StealthLevel::MAXIMUM, {
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
        // Fallback auf Standardprofil (Level ENHANCED)
        profile_it = STEALTH_PROFILES.find(StealthLevel::ENHANCED);
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

// Verarbeitet HTTP-Traffic mit Fake-Headers (HTTP/3-Maskierung)
std::vector<uint8_t> StealthManager::process_http_traffic(const std::vector<uint8_t>& data) {
    // Wenn Stealth oder HTTP/3-Maskierung deaktiviert ist, Originalpaket zurückgeben
    if (!config_.enabled || !config_.use_http3_masquerading) {
        return data;
    }
    
    // Fake-Headers anwenden
    return fake_headers_->inject_fake_headers(data);
}

// Entfernt Fake-Headers aus HTTP-Traffic
std::vector<uint8_t> StealthManager::remove_fake_headers(const std::vector<uint8_t>& data) {
    // Sicherheitsprüfung: Hat das Paket Fake-Headers?
    if (!has_fake_headers(data)) {
        return data;
    }
    
    return fake_headers_->remove_fake_headers(data);
}

// Prüft, ob ein Paket Fake-Headers enthält
bool StealthManager::has_fake_headers(const std::vector<uint8_t>& data) const {
    // Delegate to the fake_headers component
    return fake_headers_->has_fake_headers(data);
}

// Zugriff auf die Fake-Headers-Komponente
FakeHeaders& StealthManager::fake_headers() {
    return *fake_headers_;
}

// XOR-Obfuskationsmethoden
std::vector<uint8_t> StealthManager::obfuscate_payload(const std::vector<uint8_t>& payload, uint64_t context_id) {
    if (!config_.enabled || !config_.enable_xor_obfuscation) {
        return payload;
    }
    return xor_obfuscator_->obfuscate(payload, XORPattern::SIMPLE, context_id);
}

std::vector<uint8_t> StealthManager::deobfuscate_payload(const std::vector<uint8_t>& obfuscated_payload, uint64_t context_id) {
    if (!config_.enabled || !config_.enable_xor_obfuscation) {
        return obfuscated_payload;
    }
    return xor_obfuscator_->deobfuscate(obfuscated_payload, XORPattern::SIMPLE, context_id);
}

std::vector<uint8_t> StealthManager::obfuscate_fec_metadata(const std::vector<uint8_t>& fec_data, uint64_t stream_id) {
    if (!config_.enabled || !config_.enable_xor_obfuscation) {
        return fec_data;
    }
    return xor_obfuscator_->obfuscate_fec_metadata(fec_data, stream_id);
}

std::string StealthManager::obfuscate_header_value(const std::string& header_value, const std::string& header_name) {
    if (!config_.enabled || !config_.enable_xor_obfuscation) {
        return header_value;
    }
    return xor_obfuscator_->obfuscate_header_value(header_value, header_name);
}

std::string StealthManager::deobfuscate_header_value(const std::string& obfuscated_value, const std::string& header_name) {
    if (!config_.enabled || !config_.enable_xor_obfuscation) {
        return obfuscated_value;
    }
    return xor_obfuscator_->deobfuscate_header_value(obfuscated_value, header_name);
}

// Zugriff auf die XOR-Obfuskation-Komponente
XORObfuscator& StealthManager::xor_obfuscator() {
    return *xor_obfuscator_;
}

// QUIC Path Migration Methoden
QuicPathMigration* StealthManager::path_migration() {
    return path_migration_.get();
}

bool StealthManager::add_quic_path(const QuicPath& path) {
    if (!config_.enable_path_migration || !path_migration_) {
        return false;
    }
    return path_migration_->add_path(path);
}

bool StealthManager::remove_quic_path(const std::string& path_id) {
    if (!config_.enable_path_migration || !path_migration_) {
        return false;
    }
    return path_migration_->remove_path(path_id);
}

bool StealthManager::migrate_to_path(const std::string& path_id) {
    if (!config_.enable_path_migration || !path_migration_) {
        return false;
    }
    return path_migration_->migrate_to_path(path_id);
}

std::optional<QuicPath> StealthManager::get_active_path() const {
    if (!config_.enable_path_migration || !path_migration_) {
        return std::nullopt;
    }
    return path_migration_->get_active_path();
}

void StealthManager::update_path_metrics(const std::string& path_id, uint32_t rtt_ms, uint32_t data_sent) {
    if (!config_.enable_path_migration || !path_migration_) {
        return;
    }
    path_migration_->update_path_metrics(path_id, rtt_ms, data_sent);
}

bool StealthManager::should_migrate() const {
    if (!config_.enable_path_migration || !path_migration_) {
        return false;
    }
    return path_migration_->should_migrate();
}

std::optional<QuicPath> StealthManager::select_best_path() const {
    if (!config_.enable_path_migration || !path_migration_) {
        return std::nullopt;
    }
    return path_migration_->select_best_path();
}

// =============================================================================
// QuicPathMigration Implementation
// =============================================================================

QuicPathMigration::QuicPathMigration() 
    : strategy_(PathMigrationStrategy::NONE),
      active_path_id_(0),
      max_rtt_threshold_ms_(200),
      max_loss_rate_threshold_(0.05),
      min_bandwidth_threshold_kbps_(1000),
      rng_(std::chrono::steady_clock::now().time_since_epoch().count()) {
}

bool QuicPathMigration::initialize(PathMigrationStrategy strategy) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    strategy_ = strategy;
    return true;
}

bool QuicPathMigration::add_path(const QuicPath& path) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    available_paths_[path.path_id] = path;
    
    // If this is the first path, make it active
    if (available_paths_.size() == 1) {
        active_path_id_ = path.path_id;
    }
    
    return true;
}

bool QuicPathMigration::remove_path(uint32_t path_id) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    auto it = available_paths_.find(path_id);
    if (it == available_paths_.end()) {
        return false;
    }
    
    // If removing the active path, switch to another one
    if (path_id == active_path_id_ && available_paths_.size() > 1) {
        for (const auto& [id, path] : available_paths_) {
            if (id != path_id && path.is_validated) {
                active_path_id_ = id;
                break;
            }
        }
    }
    
    available_paths_.erase(it);
    return true;
}

bool QuicPathMigration::migrate_to_path(uint32_t path_id) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    auto it = available_paths_.find(path_id);
    if (it == available_paths_.end() || !it->second.is_validated) {
        return false;
    }
    
    active_path_id_ = path_id;
    available_paths_[path_id].last_used = std::chrono::steady_clock::now();
    
    return true;
}

const QuicPath* QuicPathMigration::get_active_path() const {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    auto it = available_paths_.find(active_path_id_);
    if (it != available_paths_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

void QuicPathMigration::update_path_metrics(uint32_t path_id, uint32_t rtt_ms, double loss_rate, uint32_t bandwidth_kbps) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    auto it = available_paths_.find(path_id);
    if (it != available_paths_.end()) {
        it->second.rtt_ms = rtt_ms;
        it->second.packet_loss_rate = loss_rate;
        it->second.bandwidth_kbps = bandwidth_kbps;
        it->second.last_used = std::chrono::steady_clock::now();
    }
}

bool QuicPathMigration::should_migrate_path() const {
    if (strategy_ == PathMigrationStrategy::NONE) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    auto active_it = available_paths_.find(active_path_id_);
    if (active_it == available_paths_.end()) {
        return false;
    }
    
    const QuicPath& active_path = active_it->second;
    
    // Check if current path performance is degraded
    if (active_path.rtt_ms > max_rtt_threshold_ms_ ||
        active_path.packet_loss_rate > max_loss_rate_threshold_ ||
        active_path.bandwidth_kbps < min_bandwidth_threshold_kbps_) {
        
        // Check if there's a better path available
        for (const auto& [id, path] : available_paths_) {
            if (id != active_path_id_ && path.is_validated &&
                path.rtt_ms < active_path.rtt_ms &&
                path.packet_loss_rate < active_path.packet_loss_rate &&
                path.bandwidth_kbps > active_path.bandwidth_kbps) {
                return true;
            }
        }
    }
    
    return false;
}

uint32_t QuicPathMigration::select_best_path() const {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    switch (strategy_) {
        case PathMigrationStrategy::RANDOM:
            return select_random_path();
        case PathMigrationStrategy::BANDWIDTH_OPTIMIZED:
            return select_bandwidth_optimized_path();
        case PathMigrationStrategy::LATENCY_OPTIMIZED:
            return select_latency_optimized_path();
        case PathMigrationStrategy::LOAD_BALANCED:
            return select_load_balanced_path();
        default:
            return active_path_id_;
    }
}

uint32_t QuicPathMigration::select_random_path() const {
    std::vector<uint32_t> valid_paths;
    
    for (const auto& [id, path] : available_paths_) {
        if (path.is_validated) {
            valid_paths.push_back(id);
        }
    }
    
    if (valid_paths.empty()) {
        return active_path_id_;
    }
    
    std::uniform_int_distribution<size_t> dist(0, valid_paths.size() - 1);
    return valid_paths[dist(rng_)];
}

uint32_t QuicPathMigration::select_bandwidth_optimized_path() const {
    uint32_t best_path_id = active_path_id_;
    uint32_t best_bandwidth = 0;
    
    for (const auto& [id, path] : available_paths_) {
        if (path.is_validated && path.bandwidth_kbps > best_bandwidth) {
            best_bandwidth = path.bandwidth_kbps;
            best_path_id = id;
        }
    }
    
    return best_path_id;
}

uint32_t QuicPathMigration::select_latency_optimized_path() const {
    uint32_t best_path_id = active_path_id_;
    uint32_t best_rtt = UINT32_MAX;
    
    for (const auto& [id, path] : available_paths_) {
        if (path.is_validated && path.rtt_ms < best_rtt) {
            best_rtt = path.rtt_ms;
            best_path_id = id;
        }
    }
    
    return best_path_id;
}

uint32_t QuicPathMigration::select_load_balanced_path() const {
    uint32_t best_path_id = active_path_id_;
    uint64_t min_load = UINT64_MAX;
    
    for (const auto& [id, path] : available_paths_) {
        if (path.is_validated) {
            uint64_t load = path.bytes_sent + path.bytes_received;
            if (load < min_load) {
                min_load = load;
                best_path_id = id;
            }
        }
    }
    
    return best_path_id;
}

} // namespace stealth
} // namespace quicfuscate

#ifndef STEALTH_GOV_HPP
#define STEALTH_GOV_HPP

#include "anti_fingerprinting.hpp"
#include "HTTP3_Masquerading.hpp"
#include "DomainFronting.hpp"
#include "FakeTLS.hpp"
#include "XOR_Obfuscation.hpp"
#include "QuicFuscate_Stealth.hpp"
#include "browser_profiles/tls_profiles/uTLS_fingerprints.hpp"
#include "browser_profiles/headers/FakeHeaders.hpp"
#include "DoH.hpp"
// QUIC Path Migration definitions are now included directly in this file

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <thread>

namespace quicfuscate {
namespace stealth {

// Forward declarations
class XORObfuscator;
class FakeHeaders;
class DpiEvasion;
class SniHiding;
class QUICIntegration;
class SpinBitRandomizer;
class QuicPathMigration;

/**
 * @brief Stealth-Level Definitionen
 */
enum class StealthLevel : int {
    MINIMAL = 0,     // Nur grundlegende Verschleierung
    STANDARD = 1,    // Ausgewogene Performance/Sicherheit
    ENHANCED = 2,    // Starke Verschleierung
    MAXIMUM = 3      // Alle Techniken aktiviert
};

/**
 * @brief QUIC Path Migration Strategien
 */
enum class PathMigrationStrategy {
    NONE,                // Keine Pfadmigration
    RANDOM,              // Zufällige Pfadauswahl
    LATENCY_OPTIMIZED,   // Latenz-optimierte Auswahl
    LOAD_BALANCED        // Load-balancierte Auswahl
};

/**
 * @brief QUIC Path Struktur
 */
struct QuicPath {
    uint32_t path_id = 0;
    std::string local_address;
    uint16_t local_port = 0;
    std::string remote_address;
    uint16_t remote_port = 0;
    bool is_validated = false;
    uint32_t rtt_ms = 0;
    double packet_loss_rate = 0.0;
    uint32_t bandwidth_kbps = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    std::chrono::steady_clock::time_point last_used;
};

/**
 * @brief XOR-Obfuskations-Pattern
 */
enum class XORPattern {
    SIMPLE,           // Einfache XOR-Operation
    LAYERED,          // Mehrschichtige Obfuskation
    POSITION_BASED,   // Positionsabhängige Schlüssel
    CRYPTO_SECURE,    // Kryptografisch sichere Obfuskation
    FEC_OPTIMIZED,    // Optimiert für FEC-Metadaten
    HEADER_SPECIFIC   // Speziell für Header-Obfuskation
};

/**
 * @brief Browser-Typen für Header-Generierung
 */
enum class BrowserType {
    CHROME,
    FIREFOX,
    SAFARI,
    EDGE,
    OPERA,
    CUSTOM
};

/**
 * @brief DPI-Umgehungs-Techniken
 */
enum class DPITechnique {
    PACKET_FRAGMENTATION,
    TIMING_RANDOMIZATION,
    PAYLOAD_RANDOMIZATION,
    HTTP_MIMICRY,
    TLS_FEATURES,
    PADDING_VARIATION,
    PROTOCOL_OBFUSCATION
};

/**
 * @brief Konfiguration für XOR-Obfuskation
 */
struct XORConfig {
    XORPattern pattern = XORPattern::LAYERED;
    size_t key_size = 32;
    size_t layers = 3;
    size_t position_shift = 7;
    bool enable_simd = true;
    bool enable_key_rotation = true;
    bool use_hardware_rng = true;
    std::chrono::seconds rotation_interval{30};
    
    // Erweiterte Optionen
    bool enable_adaptive_pattern = false;
    double entropy_threshold = 0.8;
    size_t max_key_cache_size = 1024;
    bool enable_key_derivation = true;
    std::string key_derivation_salt = "QuicFuscateStealth2024";
    size_t pbkdf2_iterations = 10000;
    
    // Performance-Tuning
    size_t simd_chunk_size = 64;
    bool enable_parallel_processing = true;
    size_t thread_pool_size = 4;
    
    // Sicherheitsoptionen
    bool secure_key_deletion = true;
    bool constant_time_operations = true;
    bool side_channel_protection = true;
};

/**
 * @brief Header-Profil für Fake Headers
 */
struct HeaderProfile {
    std::vector<std::string> user_agent_patterns;
    std::vector<std::string> accept_language_variants;
    std::vector<std::string> accept_encoding_variants;
    std::vector<std::string> cache_control_variants;
    std::vector<std::string> connection_variants;
    std::unordered_map<std::string, std::vector<std::string>> custom_headers;
    
    // Wahrscheinlichkeiten für Header-Injection
    double injection_probability = 0.7;
    size_t min_fake_headers = 2;
    size_t max_fake_headers = 8;
    
    // Header-Ordering
    bool randomize_header_order = true;
    std::vector<std::string> preferred_header_order;
    
    // Werte-Generierung
    bool use_realistic_values = true;
    bool enable_value_obfuscation = true;
    size_t max_header_value_length = 256;
};

/**
 * @brief Konfiguration für Fake Headers
 */
struct FakeHeadersConfig {
    bool enabled = true;
    BrowserType default_browser = BrowserType::CHROME;
    std::unordered_map<std::string, HeaderProfile> profiles;
    
    // QPACK-Integration
    bool enable_qpack_optimization = true;
    bool use_static_table = true;
    bool enable_dynamic_table = true;
    size_t dynamic_table_size = 4096;
    
    // Header-Cache
    bool enable_header_cache = true;
    size_t cache_size = 1024;
    std::chrono::minutes cache_ttl{30};
    
    // Injection-Strategien
    bool inject_at_random_positions = true;
    bool preserve_critical_headers = true;
    std::vector<std::string> critical_header_names = {
        ":method", ":path", ":scheme", ":authority",
        "host", "content-length", "content-type"
    };
    
    // Anti-Detection
    bool enable_header_fingerprint_randomization = true;
    bool avoid_suspicious_patterns = true;
    double header_consistency_threshold = 0.9;
};

/**
 * @brief Konfiguration für DPI-Umgehung
 */
struct DPIEvasionConfig {
    bool enabled = true;
    std::vector<DPITechnique> enabled_techniques = {
        DPITechnique::PACKET_FRAGMENTATION,
        DPITechnique::TIMING_RANDOMIZATION,
        DPITechnique::PAYLOAD_RANDOMIZATION
    };
    
    // Paketfragmentierung
    size_t min_fragment_size = 64;
    size_t max_fragment_size = 1200;
    double fragmentation_probability = 0.3;
    
    // Timing-Randomisierung
    std::chrono::microseconds min_delay{100};
    std::chrono::microseconds max_delay{5000};
    double timing_randomization_probability = 0.5;
    
    // Payload-Randomisierung
    size_t min_padding_size = 0;
    size_t max_padding_size = 64;
    double padding_probability = 0.4;
    
    // HTTP-Mimikry
    bool enable_http_mimicry = true;
    std::vector<std::string> mimicry_patterns = {
        "GET /", "POST /api/", "PUT /upload/"
    };
    
    // TLS-Features
    bool randomize_tls_extensions = true;
    bool use_fake_cipher_suites = true;
    std::vector<uint16_t> fake_cipher_suites;
    
    // Protokoll-Obfuskation
    bool enable_protocol_obfuscation = true;
    uint8_t obfuscation_key = 0xAA;
    bool rotate_obfuscation_key = true;
};

/**
 * @brief Konfiguration für SNI-Hiding
 */
struct SNIHidingConfig {
    bool enabled = true;
    
    // Domain Fronting
    bool enable_domain_fronting = true;
    std::vector<std::string> fronting_domains = {
        "cloudflare.com", "amazonaws.com", "googleapis.com"
    };
    
    // SNI-Verschleierung
    bool obfuscate_sni = true;
    bool use_fake_sni = true;
    std::vector<std::string> fake_sni_patterns = {
        "www.google.com", "www.microsoft.com", "www.apple.com"
    };
    
    // ESNI/ECH Support
    bool enable_esni = true;
    bool enable_ech = true;
    
    // DNS-over-HTTPS
    bool use_doh = true;
    std::vector<std::string> doh_servers = {
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query"
    };
};

/**
 * @brief Konfiguration für QUIC-Integration
 */
struct QUICIntegrationConfig {
    bool enabled = true;
    
    // Spin Bit Randomization
    bool randomize_spin_bit = true;
    double spin_bit_randomization_probability = 0.5;
    
    // Connection ID Obfuscation
    bool obfuscate_connection_id = true;
    size_t connection_id_length = 8;
    
    // Packet Number Obfuscation
    bool obfuscate_packet_numbers = true;
    
    // Version Negotiation
    bool use_fake_versions = true;
    std::vector<uint32_t> fake_quic_versions = {
        0x00000001, 0x51303530, 0x51303433
    };
    
    // Flow Control
    bool randomize_flow_control = true;
    size_t min_initial_window = 32768;
    size_t max_initial_window = 1048576;
    
    // Congestion Control
    bool obfuscate_congestion_signals = true;
    bool randomize_ack_delays = true;
};

/**
 * @brief Konfiguration für QUIC Path Migration
 */
struct PathMigrationConfig {
    bool enabled = false;
    PathMigrationStrategy strategy = PathMigrationStrategy::NONE;
    
    // Quality Thresholds
    uint32_t max_rtt_threshold_ms = 200;
    double max_loss_rate_threshold = 0.05;
    uint32_t min_bandwidth_threshold_kbps = 1000;
    
    // Migration Behavior
    bool auto_migrate = true;
    std::chrono::seconds migration_check_interval{10};
    size_t max_concurrent_paths = 4;
    
    // Path Validation
    bool validate_paths = true;
    std::chrono::seconds path_validation_timeout{5};
    size_t max_validation_attempts = 3;
    
    // Stealth Features
    bool randomize_migration_timing = true;
    std::chrono::milliseconds min_migration_delay{100};
    std::chrono::milliseconds max_migration_delay{2000};
    bool obfuscate_path_probes = true;
};

/**
 * @brief Memory Pool Konfiguration
 */
struct MemoryPoolConfig {
    bool enabled = true;
    size_t initial_pool_size = 1024 * 1024; // 1MB
    size_t max_pool_size = 64 * 1024 * 1024; // 64MB
    size_t chunk_size = 4096;
    bool enable_zero_copy = true;
    bool thread_safe = true;
    bool enable_statistics = true;
    double growth_factor = 1.5;
    size_t max_free_chunks = 256;
};

/**
 * @brief SIMD-Optimierungs-Konfiguration
 */
struct SIMDConfig {
    bool enabled = true;
    bool auto_detect = true;
    
    // x86-64 Optionen
    bool enable_sse2 = true;
    bool enable_sse4_1 = true;
    bool enable_avx2 = true;
    bool enable_avx512 = false; // Standardmäßig deaktiviert
    
    // ARM Optionen
    bool enable_neon = true;
    bool enable_sve = false;
    
    // Performance-Tuning
    size_t simd_threshold = 64; // Mindestgröße für SIMD
    bool enable_prefetching = true;
    size_t prefetch_distance = 64;
};

/**
 * @brief Haupt-Stealth-Konfiguration
 */
struct StealthConfig {
    // Globale Einstellungen
    bool enabled = true;
    StealthLevel stealth_level = StealthLevel::STANDARD;
    
    // Feature-Flags
    bool enable_xor_obfuscation = true;
    bool enable_fake_headers = true;
    bool enable_dpi_evasion = true;
    bool enable_quic_masquerading = false;
    bool enable_sni_hiding = false;
    bool enable_stealth_mode = false;
    bool enable_path_migration = false;
    
    // Komponenten-Konfigurationen
    XORConfig xor_config;
    FakeHeadersConfig fake_headers_config;
    DPIEvasionConfig dpi_evasion_config;
    SNIHidingConfig sni_hiding_config;
    QUICIntegrationConfig quic_integration_config;
    PathMigrationConfig path_migration_config;
    MemoryPoolConfig memory_pool_config;
    SIMDConfig simd_config;
    
    // Performance-Einstellungen
    bool enable_parallel_processing = true;
    size_t worker_thread_count = 4;
    size_t processing_queue_size = 1024;
    
    // Logging und Debugging
    bool enable_logging = false;
    bool enable_statistics = true;
    bool enable_performance_monitoring = false;
    std::string log_level = "INFO";
    
    // Sicherheitseinstellungen
    bool enable_secure_memory = true;
    bool enable_constant_time_ops = true;
    bool enable_side_channel_protection = true;
    
    // Adaptive Konfiguration
    bool enable_adaptive_configuration = false;
    std::chrono::seconds adaptation_interval{60};
    double performance_threshold = 0.8;
    double security_threshold = 0.9;
};

/**
 * @brief Vordefinierte Stealth-Profile
 */
class StealthProfiles {
public:
    static StealthConfig minimal() {
        StealthConfig config;
        config.stealth_level = StealthLevel::MINIMAL;
        config.enable_xor_obfuscation = true;
        config.enable_fake_headers = false;
        config.enable_dpi_evasion = false;
        config.enable_quic_masquerading = false;
        config.enable_sni_hiding = false;
        config.enable_stealth_mode = false;
        return config;
    }
    
    static StealthConfig standard() {
        StealthConfig config;
        config.stealth_level = StealthLevel::STANDARD;
        config.enable_xor_obfuscation = true;
        config.enable_fake_headers = true;
        config.enable_dpi_evasion = true;
        config.enable_quic_masquerading = false;
        config.enable_sni_hiding = false;
        config.enable_stealth_mode = false;
        return config;
    }
    
    static StealthConfig enhanced() {
        StealthConfig config;
        config.stealth_level = StealthLevel::ENHANCED;
        config.enable_xor_obfuscation = true;
        config.enable_fake_headers = true;
        config.enable_dpi_evasion = true;
        config.enable_quic_masquerading = true;
        config.enable_sni_hiding = true;
        config.enable_path_migration = true;
        config.enable_stealth_mode = false;
        return config;
    }
    
    static StealthConfig maximum() {
        StealthConfig config;
        config.stealth_level = StealthLevel::MAXIMUM;
        config.enable_xor_obfuscation = true;
        config.enable_fake_headers = true;
        config.enable_dpi_evasion = true;
        config.enable_quic_masquerading = true;
        config.enable_sni_hiding = true;
        config.enable_stealth_mode = true;
        config.enable_path_migration = true;
        
        // Maximale Sicherheitseinstellungen
        config.xor_config.layers = 5;
        config.xor_config.key_size = 64;
        config.xor_config.enable_adaptive_pattern = true;
        
        config.fake_headers_config.max_fake_headers = 12;
        config.fake_headers_config.enable_header_fingerprint_randomization = true;
        
        config.dpi_evasion_config.enabled_techniques = {
            DPITechnique::PACKET_FRAGMENTATION,
            DPITechnique::TIMING_RANDOMIZATION,
            DPITechnique::PAYLOAD_RANDOMIZATION,
            DPITechnique::HTTP_MIMICRY,
            DPITechnique::TLS_FEATURES,
            DPITechnique::PADDING_VARIATION,
            DPITechnique::PROTOCOL_OBFUSCATION
        };
        
        // Path Migration für maximale Stealth
        config.path_migration_config.enabled = true;
        config.path_migration_config.strategy = PathMigrationStrategy::RANDOM;
        config.path_migration_config.randomize_migration_timing = true;
        config.path_migration_config.obfuscate_path_probes = true;
        
        return config;
    }
    
    static StealthConfig performance_optimized() {
        StealthConfig config = standard();
        
        // Performance-Optimierungen
        config.enable_parallel_processing = true;
        config.worker_thread_count = std::thread::hardware_concurrency();
        config.simd_config.enabled = true;
        config.simd_config.auto_detect = true;
        config.memory_pool_config.enabled = true;
        config.memory_pool_config.enable_zero_copy = true;
        
        // Reduzierte Sicherheit für bessere Performance
        config.xor_config.layers = 2;
        config.fake_headers_config.max_fake_headers = 4;
        config.dpi_evasion_config.fragmentation_probability = 0.2;
        
        // Path Migration für Performance
        config.enable_path_migration = true;
        config.path_migration_config.enabled = true;
        config.path_migration_config.strategy = PathMigrationStrategy::LATENCY_OPTIMIZED;
        config.path_migration_config.auto_migrate = true;
        
        return config;
    }
    
    static StealthConfig security_focused() {
        StealthConfig config = maximum();
        
        // Maximale Sicherheitseinstellungen
        config.enable_secure_memory = true;
        config.enable_constant_time_ops = true;
        config.enable_side_channel_protection = true;
        
        config.xor_config.use_hardware_rng = true;
        config.xor_config.secure_key_deletion = true;
        config.xor_config.constant_time_operations = true;
        config.xor_config.side_channel_protection = true;
        
        config.fake_headers_config.avoid_suspicious_patterns = true;
        config.fake_headers_config.header_consistency_threshold = 0.95;
        
        return config;
    }
};

/**
 * @brief Konfiguration-Validator
 */
class ConfigValidator {
public:
    static bool validate(const StealthConfig& config, std::string& error_message) {
        // XOR-Konfiguration validieren
        if (config.xor_config.key_size < 16 || config.xor_config.key_size > 256) {
            error_message = "XOR key size must be between 16 and 256 bytes";
            return false;
        }
        
        if (config.xor_config.layers < 1 || config.xor_config.layers > 10) {
            error_message = "XOR layers must be between 1 and 10";
            return false;
        }
        
        // Fake Headers Konfiguration validieren
        if (config.fake_headers_config.max_fake_headers > 50) {
            error_message = "Maximum fake headers cannot exceed 50";
            return false;
        }
        
        // Memory Pool Konfiguration validieren
        if (config.memory_pool_config.initial_pool_size > config.memory_pool_config.max_pool_size) {
            error_message = "Initial pool size cannot exceed maximum pool size";
            return false;
        }
        
        // Thread-Konfiguration validieren
        if (config.worker_thread_count > 64) {
            error_message = "Worker thread count cannot exceed 64";
            return false;
        }
        
        return true;
    }
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
     * @param level Das Stealth-Level
     */
    void set_stealth_level(StealthLevel level);
    
    /**
     * @brief Gibt das aktuelle Stealth-Level zurück
     * @return Das aktuelle Stealth-Level
     */
    StealthLevel get_stealth_level() const;
    
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
     * @brief Verarbeitet HTTP-Traffic mit Fake-Headers (HTTP/3-Maskierung)
     * @param data Die zu verarbeitenden Daten
     * @return Die verarbeiteten Daten mit Fake-Headers
     */
    std::vector<uint8_t> process_http_traffic(const std::vector<uint8_t>& data);
    
    /**
     * @brief Entfernt Fake-Headers aus HTTP-Traffic
     * @param data Die zu verarbeitenden Daten mit Fake-Headers
     * @return Die originalen Daten ohne Fake-Headers
     */
    std::vector<uint8_t> remove_fake_headers(const std::vector<uint8_t>& data);
    
    /**
     * @brief Prüft, ob ein Paket Fake-Headers enthält
     * @param data Die zu prüfenden Daten
     * @return true wenn Fake-Headers vorhanden sind
     */
    bool has_fake_headers(const std::vector<uint8_t>& data) const;
    
    /**
     * @brief Zugriff auf die Fake-Headers-Komponente
     * @return Referenz auf die Fake-Headers-Komponente
     */
    FakeHeaders& fake_headers();
    
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
    
    /**
     * @brief Obfuskiert Payload-Daten mit XOR
     * @param payload Die zu obfuskierenden Daten
     * @param context_id Kontext-ID für die Obfuskation
     * @return Die obfuskierten Daten
     */
    std::vector<uint8_t> obfuscate_payload(const std::vector<uint8_t>& payload, uint64_t context_id);
    
    /**
     * @brief Deobfuskiert Payload-Daten
     * @param obfuscated_payload Die obfuskierten Daten
     * @param context_id Kontext-ID für die Deobfuskation
     * @return Die ursprünglichen Daten
     */
    std::vector<uint8_t> deobfuscate_payload(const std::vector<uint8_t>& obfuscated_payload, uint64_t context_id);
    
    /**
     * @brief Obfuskiert FEC-Metadaten
     * @param fec_data Die FEC-Daten
     * @param stream_id Stream-ID
     * @return Die obfuskierten FEC-Daten
     */
    std::vector<uint8_t> obfuscate_fec_metadata(const std::vector<uint8_t>& fec_data, uint64_t stream_id);
    
    /**
     * @brief Obfuskiert Header-Werte
     * @param header_value Der Header-Wert
     * @param header_name Der Header-Name
     * @return Der obfuskierte Header-Wert
     */
    std::string obfuscate_header_value(const std::string& header_value, const std::string& header_name);
    
    /**
     * @brief Deobfuskiert Header-Werte
     * @param obfuscated_value Der obfuskierte Header-Wert
     * @param header_name Der Header-Name
     * @return Der ursprüngliche Header-Wert
     */
    std::string deobfuscate_header_value(const std::string& obfuscated_value, const std::string& header_name);
    
    /**
     * @brief Zugriff auf die XOR-Obfuskation-Komponente
     * @return Referenz auf die XOR-Obfuskation-Komponente
     */
    XORObfuscator& xor_obfuscator();
    
    /**
     * @brief Zugriff auf die Path Migration-Komponente
     * @return Referenz auf die Path Migration-Komponente
     */
    QuicPathMigration& path_migration();
    
    /**
     * @brief Fügt einen neuen QUIC-Pfad hinzu
     * @param path Der hinzuzufügende Pfad
     * @return true bei Erfolg
     */
    bool add_quic_path(const QuicPath& path);
    
    /**
     * @brief Entfernt einen QUIC-Pfad
     * @param path_id Die ID des zu entfernenden Pfads
     * @return true bei Erfolg
     */
    bool remove_quic_path(uint32_t path_id);
    
    /**
     * @brief Migriert zu einem bestimmten Pfad
     * @param path_id Die ID des Zielpfads
     * @return true bei Erfolg
     */
    bool migrate_to_path(uint32_t path_id);
    
    /**
     * @brief Gibt den aktiven Pfad zurück
     * @return Zeiger auf den aktiven Pfad oder nullptr
     */
    const QuicPath* get_active_path() const;
    
    /**
     * @brief Aktualisiert Pfad-Metriken
     * @param path_id Pfad-ID
     * @param rtt_ms RTT in Millisekunden
     * @param loss_rate Paketverlustrate
     * @param bandwidth_kbps Bandbreite in kbps
     */
    void update_path_metrics(uint32_t path_id, uint32_t rtt_ms, double loss_rate, uint32_t bandwidth_kbps);
    
    /**
     * @brief Prüft, ob eine Pfadmigration empfohlen wird
     * @return true wenn Migration empfohlen wird
     */
    bool should_migrate_path() const;
    
    /**
     * @brief Wählt den besten verfügbaren Pfad aus
     * @return Pfad-ID des besten Pfads
     */
    uint32_t select_best_path() const;
    
private:
    StealthConfig config_;               // Konfiguration
    
    std::unique_ptr<DpiEvasion> dpi_evasion_;             // DPI-Evasion-Komponente
    std::unique_ptr<SniHiding> sni_hiding_;               // SNI-Hiding-Komponente
    std::unique_ptr<SpinBitRandomizer> spin_bit_randomizer_;  // Spin Bit Randomizer
    std::unique_ptr<FakeHeaders> fake_headers_;           // Fake-Headers-Komponente für HTTP/3-Maskierung
    std::unique_ptr<XORObfuscator> xor_obfuscator_;       // XOR-Obfuskation-Komponente
    std::unique_ptr<QuicPathMigration> path_migration_;   // QUIC Path Migration-Komponente
    
    // Konfiguration für verschiedene Stealth-Level
    void configure_stealth_level();
    
    // Interne Hilfsfunktionen
    bool is_client_hello(const std::vector<uint8_t>& packet) const;
    bool is_http_request(const std::vector<uint8_t>& packet) const;
    bool is_quic_packet(const std::vector<uint8_t>& packet) const;
};

} // namespace stealth
} // namespace quicfuscate

#endif // STEALTH_GOV_HPP

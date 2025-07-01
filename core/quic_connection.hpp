#ifndef QUIC_CONNECTION_HPP
#define QUIC_CONNECTION_HPP

#include "quic_core_types.hpp"
#include "quic_constants.hpp"
#include "../optimize/unified_optimizations.hpp"    // Für alle Optimierungen (inkl. ZeroRttConfig)
#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>  // für UDP-Socket
#include <boost/enable_shared_from_this.hpp>
#include <functional>
#include <memory>
#include <array>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <quiche.h>
#include <openssl/ssl.h>
#include <chrono>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <algorithm>

// Network interface headers for Connection Migration
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <net/if.h>      // For IF_NAMESIZE, if_indextoname
#include <ifaddrs.h>     // For getifaddrs
#include <sys/socket.h>  // For socket options
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>      // For strerror
#include <errno.h>       // For errno
#endif

#include "../stealth/uTLS.hpp" // Für die uTLS-Integration
#include "../fec/FEC_Modul.hpp"  // Consolidated FEC module implementation
#include "../crypto/aegis128x.hpp"  // Für die SIMD-optimierte AEGIS-128X
#include "../crypto/aegis128l.hpp"  // Für die SIMD-optimierte AEGIS-128L
#include "../crypto/morus.hpp"      // Für die MORUS-1280-128 Fallback-Implementierung
// Alle Optimierungen sind jetzt in unified_optimizations.hpp konsolidiert

namespace quicfuscate {

/**
 * Erweiterter Congestion-Control-Algorithmus-Typ
 * Unterstützt klassische Algorithmen sowie moderne wie BBRv2
 */
enum class CongestionAlgorithm {
    RENO,       // Klassisches TCP Reno
    CUBIC,      // CUBIC (Standard in vielen Betriebssystemen)
    BBR,        // Google's BBR (Bottleneck Bandwidth and RTT)
    BBRv2,      // Verbesserte Version von BBR
};

/**
 * Statistiken für XDP Zero-Copy-Operationen
 */
struct XdpStats {
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    double throughput_mbps = 0.0;
    uint64_t batch_operations = 0;
    uint64_t fallback_operations = 0;
};

/**
 * Erweiterte Statistiken für die Netzwerkverbindung
 */
struct ConnectionStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    
    // RTT-Statistiken
    uint64_t min_rtt_us = 0;
    uint64_t smoothed_rtt_us = 0;
    uint64_t latest_rtt_us = 0;
    uint64_t rtt_variance_us = 0;
    
    // Congestion Control
    uint64_t congestion_window = 0;
    uint64_t bytes_in_flight = 0;
    bool congestion_recovery = false;
    double pacing_rate = 0.0;            // In Bytes pro Sekunde
    double bottleneck_bw = 0.0;          // In Bits pro Sekunde
    double loss_rate = 0.0;              // Packet Loss Rate
    
    // Burst-Statistiken
    uint64_t bursts_sent = 0;
    double avg_burst_size = 0.0;
    double avg_burst_interval_ms = 0.0;
    
    // XDP-spezifische Statistiken
    uint64_t xdp_packets_sent = 0;
    uint64_t xdp_packets_received = 0;
    double xdp_throughput_mbps = 0.0;
    
    // BBRv2-spezifische Metriken
    double pacing_gain = 0.0;
    double cwnd_gain = 0.0;
    uint64_t inflight_hi = 0;
    uint64_t inflight_lo = 0;
    
    // Zero-RTT-Statistiken
    uint64_t zero_rtt_attempts = 0;
    uint64_t zero_rtt_successes = 0;
    
    // FEC-Statistiken
    uint64_t fec_blocks_sent = 0;
    uint64_t fec_blocks_received = 0;
    uint64_t fec_recoveries = 0;
};

class QuicConnection : public boost::enable_shared_from_this<QuicConnection> {
public:
    // Konstruktor mit Standardkonfiguration
    QuicConnection(boost::asio::io_context& io_context, const QuicConfig& config);
    
    // Erweiterter Konstruktor mit explizitem Fingerprint
    QuicConnection(boost::asio::io_context& io_context, const QuicConfig& config, 
                   BrowserFingerprint fingerprint);
    
    // Destruktor
    ~QuicConnection();
    
    // Verbindungs- und Datenübertragungsmethoden
    void async_connect(const std::string& host, uint16_t port, std::function<void(std::error_code)> callback);
    void disconnect(std::error_code ec);
    std::shared_ptr<QuicStream> create_stream(); // Verwende konsistent std::shared_ptr
    
    // Optimierte Datenübertragungsmethoden mit Zero-Copy
    void send_datagram(const uint8_t* data, size_t size);
    void send_datagram_zero_copy(ZeroCopyBuffer& buffer);
    void send_datagram_burst(const uint8_t* data, size_t size, bool urgent = false);
    
    // Empfangen von Daten mit Zero-Copy
    void receive_datagram_zero_copy(ZeroCopyReceiver& receiver);
    
    // Fehlerbehandlung
    void handle_error(std::error_code ec);
    
    // uTLS-spezifische Methoden
    bool set_browser_fingerprint(BrowserFingerprint fingerprint);
    BrowserFingerprint get_browser_fingerprint() const;
    bool is_using_utls() const { return utls_client_configurator_ != nullptr; }
    
    // Paketverarbeitung
    void handle_packet(const uint8_t* packet, size_t size);
    
    // Callbacks - mit std::shared_ptr für Konsistenz
    std::function<void(std::shared_ptr<QuicConnection>, std::error_code)> connection_callback;
    std::function<void(std::shared_ptr<QuicStream>)> stream_callback;
    std::function<void(std::error_code)> error_callback;
    
    // FEC-spezifische Methoden
    bool enable_fec(bool enable = true);
    bool is_fec_enabled() const { return fec_enabled_; }
    void set_fec_redundancy_rate(double rate);
    double get_fec_redundancy_rate() const;
    void update_fec_redundancy_rate(double observed_loss_rate);
    
    // Methoden für SIMD-optimierte FEC
    bool enable_optimized_fec(bool enable = true);
    bool is_optimized_fec_enabled() const { return fec_enabled_; }
    
    // Allgemeine SIMD-Feature-Detection
    bool has_simd_support() const;
    uint32_t get_supported_simd_features() const;
    std::string get_simd_features_string() const;
    
    // SIMD-optimierte Kryptografie
    bool enable_optimized_crypto(bool enable = true);
    bool is_optimized_crypto_enabled() const;
    
    // Packet-Statistik für FEC
    size_t get_packet_loss_count() const { return packet_loss_count_; }
    size_t get_total_packets() const { return total_packets_; }
    size_t get_recovered_packets() const { return recovered_packets_; }
    double get_current_loss_rate() const;
    
    // Zero-Copy-spezifische Methoden
    bool enable_zero_copy(bool enable = true);
    bool is_zero_copy_enabled() const;
    
    // Burst-Buffering-spezifische Methoden
    bool enable_burst_buffering(bool enable = true);
    bool is_burst_buffering_enabled() const;
    void set_burst_config(const BurstConfig& config);
    BurstConfig get_burst_config() const;
    void flush_burst_buffer();
    
    // Memory-Pool-Methoden
    void init_memory_pool(size_t block_size = DEFAULT_MEMORY_BLOCK_SIZE,
                          size_t initial_blocks = 16);
    void* allocate_from_pool();
    void deallocate_to_pool(void* block);
    
    // Congestion-Control-Methoden
    void set_congestion_algorithm(CongestionAlgorithm algorithm);
    CongestionAlgorithm get_congestion_algorithm() const;
    void update_congestion_state(uint64_t rtt_us, double loss_rate, double bandwidth_estimate);
    
    // Zero-RTT-Methoden
    bool enable_zero_rtt(bool enable = true);
    bool is_zero_rtt_enabled() const;
    void set_zero_rtt_config(const ZeroRttConfig& config);
    ZeroRttConfig get_zero_rtt_config() const;
    
    // Connection Migration Methods
    /**
     * @brief Enable connection migration capability
     * 
     * When enabled, the connection will attempt to preserve the connection
     * when the local network changes (e.g., switching from WiFi to cellular).
     * 
     * @param enable True to enable migration, false to disable
     * @return bool True if the operation succeeded
     */
    bool enable_migration(bool enable = true);
    
    /**
     * @brief Check if connection migration is enabled
     * 
     * @return bool True if migration is enabled
     */
    bool is_migration_enabled() const;
    
    /**
     * @brief Manually initiate connection migration
     * 
     * This can be called when a network change is detected to proactively
     * migrate the connection instead of waiting for automatic detection.
     * 
     * @return bool True if migration was initiated successfully
     */
    bool initiate_migration();
    
    /**
     * @brief Set the preferred network interface for migration
     * 
     * @param interface_name Name of the network interface to use
     * @return bool True if the interface was set successfully
     */
    bool set_preferred_interface(const std::string& interface_name);
    
    /**
     * @brief Add a callback to be notified when migration occurs
     * 
     * @param callback Function to call when migration occurs
     */
    void set_migration_callback(std::function<void(bool success, const std::string& from_network, const std::string& to_network)> callback);
    
    /**
     * @brief Enable MTU discovery to find optimal packet size
     * 
     * When enabled, the connection will probe different packet sizes
     * to find the maximum MTU that works without fragmentation.
     * 
     * @param enable True to enable MTU discovery, false to disable
     * @return bool True if the operation succeeded
     */
    bool enable_mtu_discovery(bool enable = true);
    
    /**
     * @brief Check if MTU discovery is enabled
     * 
     * @return bool True if MTU discovery is enabled
     */
    bool is_mtu_discovery_enabled() const;
    
    /**
     * @brief Manually set the MTU size
     * 
     * This can be called to skip the discovery process and directly set
     * a known MTU size. Note that if MTU discovery is enabled, this value
     * might still be adjusted based on network conditions.
     * 
     * @param mtu_size The MTU size in bytes
     * @return bool True if the MTU size was set successfully
     */
    bool set_mtu_size(uint16_t mtu_size);
    
    /**
     * @brief Get the current MTU size
     * 
     * @return uint16_t The current MTU size in bytes
     */
    uint16_t get_mtu_size() const;
    
    /**
     * @brief Set MTU discovery parameters
     * 
     * @param min_mtu Minimum MTU size to consider (default: 1200)
     * @param max_mtu Maximum MTU size to try (default: 1500)
     * @param step_size Step size for MTU probing (default: 10)
     */
    void set_mtu_discovery_params(uint16_t min_mtu, uint16_t max_mtu, uint16_t step_size);
    
    /**
     * @brief Enable BBRv2 congestion control
     * 
     * This enables the BBRv2 (Bottleneck Bandwidth and RTT version 2) congestion
     * control algorithm which is optimized for high throughput and low latency.
     * 
     * @param enable True to enable BBRv2, false to use default congestion control
     * @return bool True if the operation succeeded
     */
    bool enable_bbr_congestion_control(bool enable = true);
    
    /**
     * @brief Get the current congestion control algorithm
     * 
     * @return CongestionAlgorithm The current congestion control algorithm
     */
    CongestionAlgorithm get_congestion_algorithm() const;
    
    /**
     * @brief Set the congestion control algorithm
     * 
     * @param algorithm The congestion control algorithm to use
     */
    void set_congestion_algorithm(CongestionAlgorithm algorithm);
    
    /**
     * @brief Set BBRv2 parameters
     * 
     * @param params The BBRv2 parameters
     */
    void set_bbr_params(const BBRParams& params);
    
    /**
     * @brief Get the current BBRv2 parameters
     * 
     * @return BBRParams The current BBRv2 parameters
     */
    BBRParams get_bbr_params() const;
    
    /**
     * @brief Force congestion feedback for testing
     * 
     * This is used for testing to simulate specific network conditions.
     * 
     * @param bandwidth_kbps Bandwidth in kilobits per second
     * @param rtt_ms Round-trip time in milliseconds
     */
    void force_congestion_feedback(uint64_t bandwidth_kbps, uint64_t rtt_ms);
    
    /**
     * @brief Aktiviert eBPF/XDP Zero-Copy für optimale Netzwerkleistung
     * 
     * Aktiviert XDP (eXpress Data Path) für echtes Zero-Copy zwischen NIC und Userspace,
     * was die Latenz dramatisch reduziert und den Durchsatz erhöht.
     * 
     * @param interface Name des Netzwerk-Interfaces (z.B. "eth0")
     * @return true wenn XDP erfolgreich aktiviert wurde, sonst false
     */
    bool enable_xdp_zero_copy(const std::string& interface);
    
    /**
     * @brief Deaktiviert eBPF/XDP Zero-Copy
     * 
     * @return true wenn XDP erfolgreich deaktiviert wurde, sonst false
     */
    bool disable_xdp_zero_copy();
    
    /**
     * @brief Prüft, ob eBPF/XDP Zero-Copy aktiviert ist
     * 
     * @return true wenn XDP aktiviert ist, sonst false
     */
    bool is_xdp_zero_copy_enabled() const;
    
    /**
     * @brief Sendet ein Datagramm mit XDP Zero-Copy
     * 
     * @param data Zeiger auf die zu sendenden Daten
     * @param len Länge der zu sendenden Daten in Bytes
     */
    void send_datagram_xdp(const uint8_t* data, size_t len);
    
    /**
     * @brief Sendet mehrere Datagramme in einem Batch mit XDP Zero-Copy
     * 
     * @param datagrams Vector von Datagrammen (Daten-Zeiger und Länge)
     */
    void send_datagram_batch_xdp(const std::vector<std::pair<const uint8_t*, size_t>>& datagrams);
    
    /**
     * @brief Optimiert die Verarbeitung für einen bestimmten CPU-Kern
     * 
     * Pinnt den XDP-Socket und die QUIC-Verarbeitung auf einen bestimmten CPU-Kern
     * für optimale Leistung und Lokalität.
     * 
     * @param core_id ID des CPU-Kerns (0-basiert)
     * @return true wenn die Optimierung erfolgreich war, sonst false
     */
    bool optimize_for_core(int core_id);
    
    /**
     * @brief Optimiert die Speichernutzung für NUMA-Architekturen
     * 
     * @return true wenn die NUMA-Optimierung erfolgreich war, sonst false
     */
    bool optimize_numa();
    
    /**
     * @brief Setzt die Batch-Größe für XDP-Übertragungen
     * 
     * @param size Anzahl der Pakete pro Batch
     */
    void set_xdp_batch_size(uint32_t size);
    
    /**
     * @brief Liefert detaillierte XDP-Statistiken
     * 
     * @return XdpStats-Struktur mit Statistiken
     */
    XdpStats get_xdp_stats() const;
    
    // Statistik-Methoden
    ConnectionStats get_stats() const;
    void reset_stats();
    
private:
    boost::asio::io_context& io_context_;
    QuicConfig config_;
    boost::asio::ip::udp::socket socket_;       // UDP-Socket für QUIC-Verkehr
    boost::asio::ip::udp::endpoint remote_endpoint_; // Ziel-Endpunkt (Server)
    quiche_config* quiche_config_{nullptr};     // quiche Konfiguration
    quiche_conn* quiche_conn_{nullptr};         // quiche Verbindung
    std::unique_ptr<UTLSClientConfigurator> utls_client_configurator_{nullptr}; // uTLS-Konfiguration
    SSL_CTX* utls_ssl_ctx_{nullptr};            // Für alte uTLS-Integration (wird durch utls_client_configurator_ ersetzt)
    bool using_external_quiche_config_{false};   // Für uTLS-Integration
    bool utls_enabled_{false};                  // Flag, ob uTLS aktiviert ist
    BrowserFingerprint browser_fingerprint_{BrowserFingerprint::CHROME_LATEST}; // Aktueller Browser-Fingerprint
    
    // Puffer und Datenübertragung
    std::array<uint8_t, DEFAULT_MAX_MTU> recv_buffer_; // Puffer für eingehende UDP-Pakete
    std::array<uint8_t, 2048> send_buf_;        // Puffer für ausgehende QUIC-Pakete
    mutable std::mutex socket_mutex_;           // Mutex für Thread-sichere Socket-Operationen
    
    // Consolidated FEC Support
    std::unique_ptr<stealth::FECModule> fec_;           // Konsolidierte FEC-Implementierung
    bool fec_enabled_{false};                        // Flag, ob FEC aktiviert ist
    double target_redundancy_rate_{0.3};             // Ziel-Redundanzrate
    size_t packet_loss_count_{0};                    // Anzahl der verlorenen Pakete
    size_t total_packets_{0};                        // Gesamtzahl der Pakete
    size_t recovered_packets_{0};                    // Anzahl der wiederhergestellten Pakete
    std::vector<std::vector<uint8_t>> fec_buffer_;   // Puffer für FEC-Pakete
    
    // Zero-Copy Support
    bool zero_copy_enabled_{false};                  // Flag, ob Zero-Copy aktiviert ist
    std::unique_ptr<ZeroCopyBuffer> send_buffer_;    // Zero-Copy-Sendepuffer
    std::unique_ptr<ZeroCopyReceiver> recv_zero_copy_; // Zero-Copy-Empfänger
    std::unique_ptr<MemoryPool> memory_pool_;        // Memory-Pool für effiziente Speicherverwaltung
    
    // Cryptography
    std::unique_ptr<SSL_CTX> ssl_ctx_;
    std::unique_ptr<SSL> ssl_;
    std::unique_ptr<EVP_CIPHER_CTX> encrypt_ctx_;
    std::unique_ptr<EVP_CIPHER_CTX> decrypt_ctx_;
    std::unique_ptr<crypto::AEGIS128X> aegis128x_optimized_;  // SIMD-optimierte AEGIS-128X-Implementierung
    std::unique_ptr<crypto::AEGIS128L> aegis128l_optimized_;  // SIMD-optimierte AEGIS-128L-Implementierung
    std::unique_ptr<crypto::MORUS> morus_fallback_;           // MORUS-1280-128 Fallback-Implementierung
    
    // eBPF/XDP Zero-Copy Unterstützung
    bool xdp_enabled_{false};                       // Flag, ob XDP Zero-Copy aktiviert ist
    std::shared_ptr<XdpSocket> xdp_socket_;         // XDP-Socket für optimierte Datenübertragung
    mutable std::mutex xdp_mutex_;                   // Mutex für Thread-sichere XDP-Operationen
    std::chrono::steady_clock::time_point xdp_start_time_{std::chrono::steady_clock::now()}; // Startzeit für Durchsatzberechnung
    int cpu_core_id_{-1};                            // CPU-Kern für optimierte Verarbeitung
    
    // Burst-Buffering Support
    bool burst_buffering_enabled_{false};            // Flag, ob Burst-Buffering aktiviert ist
    std::unique_ptr<BurstBuffer> burst_buffer_;      // Burst-Buffer für optimierte Datenübertragung
    BurstConfig burst_config_;                       // Konfiguration für den Burst-Buffer
    mutable std::mutex burst_mutex_;                 // Mutex für Thread-sichere Burst-Operationen
    
    // BBRv2 Congestion Control
    CongestionAlgorithm congestion_algorithm_{CongestionAlgorithm::BBRv2}; // Aktueller Congestion-Control-Algorithmus
    mutable std::mutex cc_mutex_;                    // Mutex für Thread-sichere Congestion-Control-Operationen
    std::unique_ptr<BBRv2> bbr_;                     // BBRv2-Instanz für erweiterte Congestion Control
    
    // BBRv2-spezifische Variablen
    double pacing_gain_{1.0};                        // BBRv2 Pacing-Faktor
    double cwnd_gain_{2.0};                         // BBRv2 Congestion-Window-Faktor
    uint64_t min_rtt_us_{UINT64_MAX};                // Minimale gemessene RTT
    uint64_t inflight_hi_{16 * 1024};               // Obere Grenze für Daten im Flug
    uint64_t inflight_lo_{4 * 1024};                // Untere Grenze für Daten im Flug
    bool probe_bw_state_{false};                     // BBRv2-Zustand: Bandwidth-Probing
    bool probe_rtt_state_{false};                    // BBRv2-Zustand: RTT-Probing
    
    // Zero-RTT Support
    ZeroRttConfig zero_rtt_config_;                  // Konfiguration für Zero-RTT
    bool zero_rtt_attempted_{false};                 // Flag, ob Zero-RTT versucht wurde
    bool zero_rtt_succeeded_{false};                 // Flag, ob Zero-RTT erfolgreich war
    std::vector<uint8_t> token_key_;                 // Schlüssel für Token-Generierung
    
    // Statistiken
    mutable std::mutex stats_mutex_;                 // Mutex für Thread-sichere Statistikoperationen
    ConnectionStats stats_;                          // Verbindungsstatistiken
    
    // Zähler für Stream-IDs bei der Erstellung neuer Streams
    uint64_t quiche_stream_id_counter_{0};
    
    // Private Hilfsmethoden
    bool initialize_utls(const std::string& hostname);
    void log_error(const std::string& message, bool print_ssl_errors = false);
    void start_receive(std::function<void(std::error_code)> callback);
    
    // FEC-bezogene private Methoden
    std::vector<uint8_t> apply_fec_encoding(const uint8_t* data, size_t size);
    std::vector<uint8_t> apply_fec_decoding(const uint8_t* data, size_t size);
    void update_packet_statistics(bool packet_lost, bool packet_recovered);
    
    // Zero-Copy-bezogene private Methoden
    void setup_zero_copy();
    void cleanup_zero_copy();
    
    // Burst-Buffering-bezogene private Methoden
    void setup_burst_buffer();
    void handle_burst_data(const std::vector<uint8_t>& data);
    
    // BBRv2-Congestion-Control-bezogene private Methoden
    void update_bbr_state(uint64_t rtt_us, double loss_rate, double bandwidth_estimate);
    void enter_probe_bw_state();
    void enter_probe_rtt_state();
    void exit_probe_rtt_state();
    void update_congestion_window();
    
    // Zero-RTT-bezogene private Methoden
    bool generate_token(std::vector<uint8_t>& token, const std::string& hostname);
    bool validate_token(const std::vector<uint8_t>& token, const std::string& hostname);
    void setup_zero_rtt();
    bool attempt_zero_rtt_handshake(const std::string& hostname);
    
    // Statistik-bezogene private Methoden
    void update_stats(const std::vector<uint8_t>& data, bool is_send);
    void update_rtt_stats(uint64_t rtt_us);
    
    // Connection Migration bezogene private Variablen und Methoden
    bool migration_enabled_{false};                     // Flag, ob Connection Migration aktiviert ist
    std::string preferred_interface_;                   // Bevorzugte Netzwerkschnittstelle für Migration
    std::vector<std::string> available_interfaces_;     // Liste verfügbarer Netzwerkschnittstellen
    std::vector<boost::asio::ip::udp::endpoint> previous_endpoints_; // Liste früherer Endpunkte für Migration
    boost::asio::ip::udp::endpoint original_endpoint_;  // Ursprünglicher Endpunkt (für Zurückwechseln)
    uint64_t path_challenge_timeout_ms_{DEFAULT_PATH_CHALLENGE_TIMEOUT_MS}; // Timeout für Path Challenge in Millisekunden
    uint64_t max_migration_attempts_{DEFAULT_MAX_MIGRATION_ATTEMPTS}; // Maximale Anzahl von Migrationsversuchen
    uint64_t migration_cooldown_ms_{DEFAULT_MIGRATION_COOLDOWN_MS}; // Abkühlungszeit zwischen Migrationsversuchen
    std::function<void(bool, const std::string&, const std::string&)> migration_callback_; // Benachrichtigungsfunktion
    
    // Private Migration-Methoden
    bool detect_network_change();                        // Erkennt Netzwerkänderungen automatisch
    bool send_path_challenge(const boost::asio::ip::udp::endpoint& endpoint); // Sendet Path Challenge für Migration
    bool validate_path_response(const uint8_t* data, size_t size); // Validiert Path Response
    std::vector<std::string> enumerate_network_interfaces(); // Listet verfügbare Netzwerkschnittstellen auf
    bool setup_migration_socket(const std::string& interface_name); // Richtet Socket für neues Interface ein
    void handle_migration_failure();                   // Behandelt Fehler bei der Migration
    void update_connection_id();                       // Aktualisiert Connection-ID nach Migration
    std::string get_current_interface_name() const;    // Gibt aktuelles Interface zurück
    
    // MTU Discovery bezogene private Variablen und Methoden
    bool mtu_discovery_enabled_{false};                // Flag, ob MTU Discovery aktiviert ist
    uint16_t current_mtu_{DEFAULT_INITIAL_MTU};        // Aktuelle MTU-Größe
    uint16_t min_mtu_{DEFAULT_MIN_MTU};                // Minimale MTU (RFC 8899 empfiehlt 1200 als Minimum)
    uint16_t max_mtu_{DEFAULT_MAX_MTU};                // Maximale MTU (typische Ethernet MTU)
    uint16_t mtu_step_size_{DEFAULT_MTU_STEP_SIZE};    // Schrittgröße für MTU-Probing
    uint16_t target_mtu_{DEFAULT_MAX_MTU};             // Ziel-MTU
    uint16_t last_successful_mtu_{DEFAULT_INITIAL_MTU}; // Zuletzt erfolgreich verwendete MTU
    uint16_t current_probe_mtu_{0};                    // Aktuell getestete MTU
    std::chrono::steady_clock::time_point last_probe_time_; // Zeitpunkt des letzten MTU-Probes
    uint32_t probe_timeout_ms_{DEFAULT_MTU_PROBE_TIMEOUT_MS}; // Timeout für MTU-Probes in Millisekunden
    uint16_t blackhole_detection_threshold_{DEFAULT_BLACKHOLE_DETECTION_THRESHOLD}; // Schwellenwert für Blackhole-Erkennung
    uint16_t consecutive_failures_{0};                 // Zähler für aufeinanderfolgende Fehlschläge
    bool in_search_phase_{false};                      // Flag, ob aktuell im Suchprozess
    bool mtu_validated_{false};                        // Flag, ob aktuelle MTU validiert ist
    uint16_t plpmtu_{0};                               // Packetization Layer Path MTU (PLPMTU)
    
    // Private MTU Discovery Methoden
    void start_mtu_discovery();                        // Startet den MTU-Discovery-Prozess
    void send_mtu_probe(uint16_t probe_size);           // Sendet ein MTU-Probe-Paket
    void handle_mtu_probe_response(bool success);       // Behandelt die Antwort auf ein MTU-Probe
    void update_mtu(uint16_t new_mtu);                 // Aktualisiert die MTU-Einstellung
    void reset_mtu_discovery();                        // Setzt den MTU-Discovery-Prozess zurück
    bool is_blackhole_detected();                      // Prüft, ob ein Blackhole erkannt wurde
    void schedule_next_probe();                        // Plant den nächsten MTU-Probe
};

} // namespace quicfuscate

#endif // QUIC_CONNECTION_HPP

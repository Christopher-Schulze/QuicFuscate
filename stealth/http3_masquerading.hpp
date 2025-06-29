/**
 * http3_masquerading.hpp
 * 
 * Implementierung des HTTP/3-Masquerading für QuicFuscate.
 * Diese Klasse ermöglicht es der VPN-Verbindung, sich als legitimer HTTP/3-Traffic
 * zu tarnen, indem sie HTTP/3-Header und Frame-Strukturen emuliert.
 */

#ifndef HTTP3_MASQUERADING_HPP
#define HTTP3_MASQUERADING_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>
#include <chrono>
#include <functional>
#include "../core/quic_packet.hpp"
#include "../core/quic_stream.hpp"
#include "QuicFuscate_Stealth.hpp"
#include "browser_profiles/fingerprints/browser_fingerprints.hpp"

namespace quicfuscate {

/**
 * HTTP/3 Frame-Typen gemäß RFC 9114 Abschnitt 7.2
 * https://datatracker.ietf.org/doc/html/rfc9114#section-7.2
 */
enum class Http3FrameType : uint64_t {
    DATA = 0x00,               // Enthält Request- oder Response-Payload
    HEADERS = 0x01,            // Enthält QPACK-kodierte Header
    RESERVED_1 = 0x02,         // Reserviert (für Cancel-Push in frühen Entwürfen)
    CANCEL_PUSH = 0x03,        // Request zum Abbrechen eines Server-Push
    SETTINGS = 0x04,           // Einstellungen für die Verbindung
    PUSH_PROMISE = 0x05,       // Ankündigung eines Server-Push
    RESERVED_2 = 0x06,         // Reserviert (für frühere Definition von Push)
    GOAWAY = 0x07,             // Signalisierung zum Verbindungsabbau
    RESERVED_3 = 0x08,         // Reserviert für zukünftige Erweiterungen
    RESERVED_4 = 0x09,         // Reserviert für zukünftige Erweiterungen
    MAX_PUSH_ID = 0x0D,        // Max Push ID, die vom Server verwendet werden darf
    UNKNOWN = 0xFF             // Unbekannter Frame-Typ (für interne Verwendung)
};

/**
 * HTTP/3 Setting-Bezeichner gemäß RFC 9114 Abschnitt 7.2.4.1
 * https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1
 */
enum class Http3SettingId : uint64_t {
    RESERVED = 0x00,                 // Reserviert, darf nicht verwendet werden
    QPACK_MAX_TABLE_CAPACITY = 0x01, // QPACK max dynamische Tabellengröße
    RESERVED_2 = 0x02,               // Reserviert (für frühere Entwürfe)
    QPACK_BLOCKED_STREAMS = 0x07,    // Max blockierte Streams für QPACK
    RESERVED_3 = 0x08,               // Reserviert (für frühere Entwürfe)
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08, // Extended CONNECT
    SETTINGS_H3_DATAGRAM = 0x0276,   // HTTP/3 Datagramm-Unterstützung (RFC 9297)
    SETTINGS_ENABLE_WEBTRANSPORT = 0x2B71, // WebTransport über HTTP/3
    UNKNOWN = 0xFFFFFFFFFFFFFFFF      // Unbekannter Setting-Typ
};

/**
 * HTTP/3 Stream-Typen gemäß RFC 9114 Abschnitt 6.2
 * https://datatracker.ietf.org/doc/html/rfc9114#section-6.2
 */
enum class Http3StreamType {
    CONTROL,        // Stream 0, für Steuerframes
    PUSH,           // Server-initiierte Uni Streams (0x01)
    QPACK_ENCODER,  // QPACK Encoder Stream (0x02)
    QPACK_DECODER,  // QPACK Decoder Stream (0x03)
    RESERVED,       // Reservierter Stream-Typ
    REQUEST,        // Request/Response Streams (bi-directional)
    WEBTRANSPORT,   // WebTransport Stream
    UNKNOWN         // Unbekannter Stream-Typ
};

/**
 * Basisklasse für alle HTTP/3-Frame-Typen
 */
class Http3Frame {
public:
    virtual ~Http3Frame() = default;
    
    /**
     * Serialisiert den Frame in eine Bytefolge gemäß HTTP/3-Spezifikation
     */
    virtual std::vector<uint8_t> serialize() const = 0;
    
    /**
     * Gibt den Frame-Typ zurück
     */
    virtual Http3FrameType get_type() const = 0;
    
    /**
     * Factory-Methode zum Deserialisieren eines Frames aus einer Bytefolge
     */
    static std::unique_ptr<Http3Frame> deserialize(const std::vector<uint8_t>& data);
    static std::unique_ptr<Http3Frame> deserialize(const uint8_t* data, size_t length);
    
protected:
    // Hilfsmethode zum Kodieren eines Variable-Length Integers gemäß HTTP/3
    static std::vector<uint8_t> encode_varint(uint64_t value);
    
    // Hilfsmethode zum Dekodieren eines Variable-Length Integers gemäß HTTP/3
    static uint64_t decode_varint(const uint8_t* data, size_t length, size_t& bytes_read);
};

/**
 * DATA Frame (Type = 0x00)
 * Enthält Request oder Response Body Daten
 */
class Http3DataFrame : public Http3Frame {
public:
    Http3DataFrame() = default;
    explicit Http3DataFrame(const std::vector<uint8_t>& payload);
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::DATA; }
    
    const std::vector<uint8_t>& get_payload() const { return payload_; }
    void set_payload(const std::vector<uint8_t>& payload) { payload_ = payload; }
    
private:
    std::vector<uint8_t> payload_;
};

/**
 * HEADERS Frame (Type = 0x01)
 * Enthält QPACK-kodierte Header
 */
class Http3HeadersFrame : public Http3Frame {
public:
    Http3HeadersFrame() = default;
    explicit Http3HeadersFrame(const std::vector<uint8_t>& header_block);
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::HEADERS; }
    
    const std::vector<uint8_t>& get_header_block() const { return header_block_; }
    void set_header_block(const std::vector<uint8_t>& header_block) { header_block_ = header_block; }
    
private:
    std::vector<uint8_t> header_block_;
};

/**
 * SETTINGS Frame (Type = 0x04)
 * Enthält HTTP/3-Verbindungseinstellungen
 */
class Http3SettingsFrame : public Http3Frame {
public:
    Http3SettingsFrame() = default;
    explicit Http3SettingsFrame(const std::map<Http3SettingId, uint64_t>& settings);
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::SETTINGS; }
    
    const std::map<Http3SettingId, uint64_t>& get_settings() const { return settings_; }
    void set_setting(Http3SettingId id, uint64_t value) { settings_[id] = value; }
    
private:
    std::map<Http3SettingId, uint64_t> settings_;
};

/**
 * HTTP/3-Status (Zustand einer HTTP/3-Verbindung oder eines Streams)
 */
enum class Http3Status {
    IDLE,               // Initialer Zustand
    OPEN,               // Stream / Verbindung ist offen
    LOCAL_CLOSED,       // Lokal geschlossen
    REMOTE_CLOSED,      // Remote geschlossen
    CLOSED,             // Vollständig geschlossen
    ERROR               // Fehlerzustand
};

/**
 * @brief Priorität eines HTTP/3-Streams (consolidated from HTTP3_Flow_Control)
 */
enum class StreamPriority {
    HIGHEST,   ///< Höchste Priorität (z.B. HTML-Dokument)
    HIGH,      ///< Hohe Priorität (z.B. CSS, JavaScript)
    MEDIUM,    ///< Mittlere Priorität (z.B. Fonts)
    LOW,       ///< Niedrige Priorität (z.B. Bilder)
    LOWEST     ///< Niedrigste Priorität (z.B. Analytics)
};

/**
 * @brief Ressourcentyp für die Content-Type-basierte Priorisierung
 */
enum class ResourceType {
    HTML,          ///< HTML-Dokument
    CSS,           ///< CSS-Stylesheet
    JAVASCRIPT,    ///< JavaScript
    FONT,          ///< Schriftart
    IMAGE,         ///< Bild
    VIDEO,         ///< Video
    AUDIO,         ///< Audio
    JSON,          ///< JSON-Daten
    XML,           ///< XML-Daten
    UNKNOWN        ///< Unbekannter Typ
};

/**
 * @brief Stream-Abhängigkeit für HTTP/2-Prioritätsmodell
 */
struct StreamDependency {
    uint32_t stream_id;         ///< ID des Streams, von dem dieser Stream abhängt
    bool exclusive;             ///< Exklusiv-Flag
    uint8_t weight;             ///< Gewichtung (1-256)
};

/**
 * @brief Flow-Control-Parameter für HTTP/3-Streams
 */
struct FlowControlParameters {
    uint32_t initial_window_size;         ///< Initiale Fenstergröße (bytes)
    uint32_t max_concurrent_streams;      ///< Maximale Anzahl gleichzeitiger Streams
    uint32_t max_header_list_size;        ///< Maximale Größe der Header-Liste (bytes)
    uint32_t stream_buffer_size;          ///< Puffergröße pro Stream (bytes)
    uint32_t connection_buffer_size;      ///< Puffergröße für die Verbindung (bytes)
    uint32_t max_stream_flow_control;     ///< Maximale Flow-Control pro Stream
    uint32_t min_stream_window_update;    ///< Minimale Größe für Window-Updates
    double window_update_threshold;       ///< Schwellenwert für Window-Updates (0.0-1.0)
};

/**
 * @brief Konfiguration für den Flow-Control-Emulator
 */
struct FlowControlConfig {
    // Browser-Emulation
    BrowserType browser_type;                 ///< Zu emulierender Browser
    OperatingSystem os;                       ///< Zu emulierendes Betriebssystem
    
    // Grundlegende Flow-Control-Parameter
    FlowControlParameters parameters;         ///< Flow-Control-Parameter
    
    // Prioritätsmodell
    bool use_http2_priority_model;           ///< HTTP/2-Prioritätsmodell verwenden
    bool use_http3_priority_model;           ///< HTTP/3-Prioritätsmodell verwenden
    
    // Content-Type-basierte Priorisierung
    std::unordered_map<ResourceType, StreamPriority> content_priorities;
    
    // Timing-Optimierungen
    std::chrono::milliseconds dynamic_update_interval{50}; ///< Intervall für dynamische Updates
    bool adaptive_window_sizing;              ///< Adaptive Fenstergrößen
    
    // Zero-Copy-Optimierungen
    bool enable_zero_copy;                    ///< Zero-Copy-Operationen aktivieren
    bool stream_coalescing;                   ///< Stream-Zusammenführung aktivieren
    
    // Erweiterte Optimierungen
    bool preemptive_window_updates;           ///< Präemptive Window-Updates
    bool congestion_aware_flow_control;       ///< Überlastungsbewusstes Flow-Control
    bool prioritize_header_frames;            ///< Header-Frames priorisieren
};

/**
 * @brief Callback-Typ für Stream-Priorisierungsereignisse
 */
using StreamPriorityChangedCallback = std::function<void(uint32_t stream_id, StreamPriority new_priority)>;

/**
 * @brief Statistiken für einen HTTP/3-Stream
 */
struct StreamStatistics {
    uint64_t bytes_sent;                    ///< Gesendete Bytes
    uint64_t bytes_received;                ///< Empfangene Bytes
    uint64_t frames_sent;                   ///< Gesendete Frames
    uint64_t frames_received;               ///< Empfangene Frames
    uint64_t window_updates_sent;           ///< Gesendete Window-Updates
    uint64_t window_updates_received;       ///< Empfangene Window-Updates
    std::chrono::steady_clock::time_point created_at;   ///< Erstellungszeit
    std::chrono::steady_clock::time_point last_active;  ///< Letzte Aktivität
};

/**
 * @brief Informationen über einen HTTP/3-Stream
 */
struct StreamInfo {
    uint32_t stream_id;                     ///< Stream-ID
    ResourceType resource_type;             ///< Ressourcentyp
    StreamPriority priority;                ///< Stream-Priorität
    uint32_t available_window;              ///< Verfügbares Flow-Control-Fenster
    uint32_t remote_window;                 ///< Remote-Flow-Control-Fenster
    bool is_closed;                         ///< Stream geschlossen
    StreamStatistics stats;                 ///< Stream-Statistiken
    StreamDependency dependency;            ///< Stream-Abhängigkeit (HTTP/2-Modell)
    std::string url;                        ///< URL der Ressource (falls bekannt)
};

/**
 * Datenstruktur für HTTP/3-Header-Felder
 */
using Http3HeaderField = quicfuscate::Http3HeaderField;

/**
 * Hauptklasse für HTTP/3-Masquerading
 */
class Http3Masquerading : public QuicStream {
public:
    Http3Masquerading(std::shared_ptr<QuicConnection> conn, int id, StreamType type);
    ~Http3Masquerading();
    
    // Initialisierung mit Konfigurationsoptionen
    void initialize(const std::map<std::string, std::string>& config);
    
    // Advanced HTTP/3 masquerading methods (from HTTP3Masquerader)
    /**
     * @brief Create a new HTTP3Masquerader instance
     * @param config Initial masquerading configuration
     * @return std::unique_ptr to HTTP3Masquerader instance
     */
    static std::unique_ptr<Http3Masquerading> create(const HTTP3MasqueradingConfig& config = {});
    
    /**
     * @brief Masquerade HTTP/3 frame to mimic browser behavior
     * @param frame Original HTTP/3 frame
     * @param browser_profile Target browser profile
     * @return Masqueraded frame
     */
    HTTP3Frame masquerade_frame(const HTTP3Frame& frame, BrowserType browser_profile);
    
    /**
     * @brief Generate browser-specific HTTP/3 SETTINGS frame
     * @param browser_profile Target browser profile
     * @return SETTINGS frame with browser-specific values
     */
    HTTP3Frame generate_settings_frame(BrowserType browser_profile);
    
    /**
     * @brief Modify HEADERS frame to include browser-specific headers
     * @param frame Original HEADERS frame
     * @param browser_profile Target browser profile
     * @return Modified HEADERS frame
     */
    HTTP3Frame modify_headers_frame(const HTTP3Frame& frame, BrowserType browser_profile);
    
    /**
     * @brief Generate browser-specific priority frame
     * @param stream_id Stream ID for priority
     * @param browser_profile Target browser profile
     * @return PRIORITY frame
     */
    HTTP3Frame generate_priority_frame(uint64_t stream_id, BrowserType browser_profile);
    
    /**
     * @brief Get browser-specific HTTP/3 profile
     * @param browser_type Browser type
     * @return Browser HTTP/3 profile
     */
    BrowserHTTP3Profile get_browser_profile(BrowserType browser_type);
    
    /**
     * @brief Update masquerading configuration
     * @param config New configuration
     */
    void update_config(const HTTP3MasqueradingConfig& config);
    
    /**
     * @brief Get current masquerading configuration
     * @return Current configuration
     */
    HTTP3MasqueradingConfig get_config() const;
    
    /**
     * @brief Process incoming HTTP/3 stream
     * @param stream_data Raw stream data
     * @param browser_profile Target browser profile
     * @return Processed stream data
     */
    std::vector<uint8_t> process_stream(const std::vector<uint8_t>& stream_data, 
                                       BrowserType browser_profile);
    
    /**
     * @brief Generate browser-specific connection preface
     * @param browser_profile Target browser profile
     * @return Connection preface data
     */
    std::vector<uint8_t> generate_connection_preface(BrowserType browser_profile);
    
    /**
     * @brief Randomize frame order to mimic browser behavior
     * @param frames Vector of frames to randomize
     * @param browser_profile Target browser profile
     */
    void randomize_frame_order(std::vector<HTTP3Frame>& frames, BrowserType browser_profile);
    
    /**
     * @brief Add browser-specific timing delays
     * @param frame_type Type of frame being sent
     * @param browser_profile Target browser profile
     * @return Delay in milliseconds
     */
    uint32_t get_frame_timing_delay(HTTP3FrameType frame_type, BrowserType browser_profile);
    
    /**
     * @brief Get masquerading statistics
     * @return Current statistics
     */
    HTTP3MasqueradingStats get_statistics() const;
    
    /**
     * @brief Reset statistics counters
     */
    void reset_statistics();
    
    /**
     * @brief Enable or disable masquerading
     * @param enabled true to enable, false to disable
     */
    void set_enabled(bool enabled);
    
    /**
     * @brief Check if masquerading is enabled
     * @return true if enabled
     */
    bool is_enabled() const;
    
    /**
     * @brief Validate HTTP/3 frame structure
     * @param frame Frame to validate
     * @return true if frame is valid
     */
    bool validate_frame(const HTTP3Frame& frame);
    
    /**
     * @brief Get supported HTTP/3 extensions for browser
     * @param browser_profile Target browser profile
     * @return List of supported extensions
     */
    std::vector<std::string> get_supported_extensions(BrowserType browser_profile);
    
    // Verarbeitet ausgehende Pakete und verschleiert sie als HTTP/3-Traffic
    bool process_outgoing_packet(std::shared_ptr<QuicPacket> packet);
    
    // Verarbeitet eingehende Pakete und entfernt die HTTP/3-Maskierung
    bool process_incoming_packet(std::shared_ptr<QuicPacket> packet);
    
    // Stream-Verwaltung (HTTP/3 specific)
    void register_stream(uint64_t stream_id, Http3StreamType type);
    std::optional<Http3StreamType> get_stream_type(uint64_t stream_id) const;
    
    // HTTP/3-Frame-Verarbeitung
    std::vector<uint8_t> create_frame(Http3FrameType type, const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_headers_frame(const std::vector<Http3HeaderField>& headers);
    bool extract_frames(const std::vector<uint8_t>& data, std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>>& frames);
    std::vector<std::shared_ptr<Http3Frame>> parse_frames(
        const std::vector<uint8_t>& data, size_t& bytes_consumed);
    std::vector<uint8_t> serialize_frames(
        const std::vector<std::shared_ptr<Http3Frame>>& frames);
    
    // Hilfsmethoden für Variablen-Längen-Integer
    std::vector<uint8_t> encode_varint(uint64_t value);
    uint64_t decode_varint(const uint8_t* data, size_t len, size_t& bytes_read);
    
    // HTTP/3-Request/Response-Helfer
    std::vector<uint8_t> create_http3_request(
        const std::string& host, 
        const std::string& path);
    
    std::vector<uint8_t> create_http3_response(
        int status_code, 
        const std::map<std::string, std::string>& headers = {}, 
        const std::vector<uint8_t>& payload = {});
    
    // Stream-Prioritäten
    void set_stream_priority(uint64_t stream_id, const PriorityParameters& priority);
    std::optional<PriorityParameters> get_stream_priority(uint64_t stream_id) const;
    
    // Browser-Profil-Verwaltung
    void set_browser_profile(const std::string& profile);
    std::string get_browser_profile() const;
    
    // Flow Control methods (consolidated from HTTP3_Flow_Control)
    static FlowControlConfig create_browser_config(BrowserType browser, OperatingSystem os);
    bool create_stream(uint32_t stream_id, ResourceType resource_type, const std::string& url = "");
    bool close_stream(uint32_t stream_id);
    uint32_t process_incoming_data(uint32_t stream_id, const std::vector<uint8_t>& data, bool is_fin = false);
    uint32_t process_outgoing_data(uint32_t stream_id, const std::vector<uint8_t>& data, bool is_fin = false);
    bool update_stream_priority(uint32_t stream_id, StreamPriority priority);
    bool update_stream_dependency(uint32_t stream_id, const StreamDependency& dependency);
    bool update_resource_type(uint32_t stream_id, ResourceType resource_type);
    uint32_t increase_stream_window(uint32_t stream_id, uint32_t increment);
    uint32_t increase_connection_window(uint32_t increment);
    std::vector<uint8_t> create_window_update_frame(uint32_t stream_id, uint32_t increment);
    std::vector<uint8_t> create_priority_frame(uint32_t stream_id, const StreamDependency& dependency);
    std::vector<uint8_t> create_priority_update_frame(uint32_t stream_id, StreamPriority priority);
    void set_priority_changed_callback(StreamPriorityChangedCallback callback);
    std::optional<StreamInfo> get_stream_info(uint32_t stream_id) const;
    std::vector<uint32_t> get_active_streams() const;
    const FlowControlConfig& get_config() const;
    void set_config(const FlowControlConfig& config);
    static ResourceType mime_type_to_resource_type(const std::string& mime_type);
    
    // Realistische Browserverhalten
    void simulate_realistic_timing(uint64_t& delay_ms);
    std::vector<Http3HeaderField> generate_realistic_headers(
        const std::string& host, 
        const std::string& path);
        

private:
    // QPACK-Codec
    std::unique_ptr<QpackCodec> qpack_codec_;
    
    // Prioritäts-Scheduler
    std::unique_ptr<PriorityScheduler> priority_scheduler_;
    
    // HTTP/3 specific stream types
    std::unordered_map<uint64_t, Http3StreamType> stream_types_;
    
    // Browser-Profil für konsistente HTTP-Header
    std::string browser_profile_;
    
    // Mapping zwischen Browser-Profilen und User-Agent-Strings
    static const std::unordered_map<std::string, std::string> browser_user_agents_;
    
    // Typische HTTP/3-Headerlisten für verschiedene Browser-Profile
    static const std::unordered_map<std::string, std::vector<std::string>> browser_typical_headers_;
    
    // Konfigurationsoptionen
    std::map<std::string, std::string> config_;
    
    // Hilfsmethoden
    bool is_control_stream(uint64_t stream_id) const;
    bool is_request_stream(uint64_t stream_id) const;
    bool is_unidirectional_stream(uint64_t stream_id) const;
    uint8_t detect_stream_type_from_first_byte(uint8_t first_byte) const;
};

/**
 * @brief QPACK integration for HTTP/3 masquerading
 */
class QPACKMasquerader {
public:
    /**
     * @brief Create a new QPACKMasquerader instance
     * @param config QPACK configuration
     * @return std::unique_ptr to QPACKMasquerader instance
     */
    static std::unique_ptr<QPACKMasquerader> create(const QPACKConfig& config = {});
    
    /**
     * @brief Virtual destructor
     */
    virtual ~QPACKMasquerader() = default;
    
    /**
     * @brief Encode headers using QPACK with browser-specific patterns
     * @param headers Headers to encode
     * @param browser_profile Target browser profile
     * @return Encoded header block
     */
    virtual std::vector<uint8_t> encode_headers(const std::vector<HTTPHeader>& headers,
                                               BrowserType browser_profile) = 0;
    
    /**
     * @brief Decode QPACK-encoded headers
     * @param encoded_data Encoded header block
     * @return Decoded headers
     */
    virtual std::vector<HTTPHeader> decode_headers(const std::vector<uint8_t>& encoded_data) = 0;
    
    /**
     * @brief Update QPACK dynamic table with browser-specific entries
     * @param browser_profile Target browser profile
     */
    virtual void update_dynamic_table(BrowserType browser_profile) = 0;
    
    /**
     * @brief Get QPACK encoder stream data
     * @return Encoder stream data
     */
    virtual std::vector<uint8_t> get_encoder_stream_data() = 0;
    
    /**
     * @brief Process QPACK decoder stream data
     * @param data Decoder stream data
     */
    virtual void process_decoder_stream_data(const std::vector<uint8_t>& data) = 0;
    
    /**
     * @brief Set maximum dynamic table capacity
     * @param capacity Maximum capacity in bytes
     */
    virtual void set_max_table_capacity(uint32_t capacity) = 0;
    
    /**
     * @brief Set maximum blocked streams
     * @param max_blocked Maximum number of blocked streams
     */
    virtual void set_max_blocked_streams(uint32_t max_blocked) = 0;
    
    /**
     * @brief Get current dynamic table size
     * @return Current table size in bytes
     */
    virtual uint32_t get_dynamic_table_size() const = 0;
    
    /**
     * @brief Get number of blocked streams
     * @return Number of currently blocked streams
     */
    virtual uint32_t get_blocked_streams_count() const = 0;
};

} // namespace quicfuscate

#endif // HTTP3_MASQUERADING_HPP

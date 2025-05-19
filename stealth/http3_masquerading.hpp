/**
 * http3_masquerading.hpp
 * 
 * Implementierung des HTTP/3-Masquerading für QuicSand.
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
#include "../core/quic_packet.hpp"
#include "../core/quic_stream.hpp"
#include "qpack.hpp"
#include "http3_frame.hpp"
#include "http3_priority.hpp"

namespace quicsand {

/**
 * HTTP/3 Stream-Typen gemäß RFC 9114 Abschnitt 6.2
 * https://datatracker.ietf.org/doc/html/rfc9114#section-6.2
 */
enum class Http3StreamType {
    CONTROL = 0,        // Stream 0, für Steuerframes
    PUSH = 1,           // Server-initiierte Uni Streams (0x01)
    QPACK_ENCODER = 2,  // QPACK Encoder Stream (0x02)
    QPACK_DECODER = 3,  // QPACK Decoder Stream (0x03)
    RESERVED = 4,       // Reservierter Stream-Typ
    REQUEST = 5,        // Request/Response Streams (bi-directional)
    WEBTRANSPORT = 6,   // WebTransport Stream
    UNKNOWN = 7         // Unbekannter Stream-Typ
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
 * Datenstruktur für HTTP/3-Header-Felder
 */
using Http3HeaderField = quicsand::Http3HeaderField;

/**
 * Hauptklasse für HTTP/3-Masquerading
 */
class Http3Masquerading {
public:
    Http3Masquerading();
    ~Http3Masquerading();
    
    // Initialisierung mit Konfigurationsoptionen
    void initialize(const std::map<std::string, std::string>& config);
    
    // Verarbeitet ausgehende Pakete und verschleiert sie als HTTP/3-Traffic
    bool process_outgoing_packet(std::shared_ptr<QuicPacket> packet);
    
    // Verarbeitet eingehende Pakete und entfernt die HTTP/3-Maskierung
    bool process_incoming_packet(std::shared_ptr<QuicPacket> packet);
    
    // Stream-Verwaltung
    void register_stream(uint64_t stream_id, Http3StreamType type);
    void update_stream_state(uint64_t stream_id, Http3Status state);
    std::optional<Http3StreamType> get_stream_type(uint64_t stream_id) const;
    std::optional<Http3Status> get_stream_state(uint64_t stream_id) const;
    
    // HTTP/3-Frame-Verarbeitung
    std::shared_ptr<Http3Frame> create_data_frame(const std::vector<uint8_t>& payload);
    std::shared_ptr<Http3Frame> create_headers_frame(const std::vector<Http3HeaderField>& headers);
    std::shared_ptr<Http3Frame> create_settings_frame(
        const std::map<Http3SettingId, uint64_t>& settings);
    std::vector<std::shared_ptr<Http3Frame>> parse_frames(
        const std::vector<uint8_t>& data, size_t& bytes_consumed);
    std::vector<uint8_t> serialize_frames(
        const std::vector<std::shared_ptr<Http3Frame>>& frames);
    
    // HTTP/3-Request/Response-Helfer
    std::vector<uint8_t> create_http3_request(
        const std::string& host, 
        const std::string& path, 
        const std::string& method = "GET", 
        const std::map<std::string, std::string>& additional_headers = {});
    
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
    
    // Realistische Browserverhalten
    void simulate_realistic_timing(uint64_t& delay_ms);
    std::vector<Http3HeaderField> generate_realistic_headers(
        const std::string& host, 
        const std::string& path, 
        const std::string& method = "GET");

private:
    // QPACK-Codec
    std::unique_ptr<QpackCodec> qpack_codec_;
    
    // Prioritäts-Scheduler
    std::unique_ptr<PriorityScheduler> priority_scheduler_;
    
    // Stream-Verwaltung
    std::unordered_map<uint64_t, Http3StreamType> stream_types_;
    std::unordered_map<uint64_t, Http3Status> stream_states_;
    
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

} // namespace quicsand

#endif // HTTP3_MASQUERADING_HPP

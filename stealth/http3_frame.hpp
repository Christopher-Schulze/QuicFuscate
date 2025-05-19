#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <variant>
#include <optional>

namespace quicsand {

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
 * CANCEL_PUSH Frame (Type = 0x03)
 * Wird vom Client gesendet, um einen Server-Push abzubrechen
 */
class Http3CancelPushFrame : public Http3Frame {
public:
    Http3CancelPushFrame() : push_id_(0) {}
    explicit Http3CancelPushFrame(uint64_t push_id) : push_id_(push_id) {}
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::CANCEL_PUSH; }
    
    uint64_t get_push_id() const { return push_id_; }
    void set_push_id(uint64_t push_id) { push_id_ = push_id; }
    
private:
    uint64_t push_id_;
};

/**
 * SETTINGS Frame (Type = 0x04)
 * Enthält Konfigurationsparameter für die HTTP/3-Verbindung
 */
class Http3SettingsFrame : public Http3Frame {
public:
    Http3SettingsFrame() = default;
    
    // Fügt eine neue Einstellung hinzu oder aktualisiert eine vorhandene
    void add_setting(Http3SettingId id, uint64_t value);
    
    // Prüft, ob eine bestimmte Einstellung vorhanden ist
    bool has_setting(Http3SettingId id) const;
    
    // Gibt den Wert einer Einstellung zurück
    std::optional<uint64_t> get_setting(Http3SettingId id) const;
    
    // Gibt alle Einstellungen zurück
    const std::map<Http3SettingId, uint64_t>& get_settings() const { return settings_; }
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::SETTINGS; }
    
private:
    std::map<Http3SettingId, uint64_t> settings_;
};

/**
 * PUSH_PROMISE Frame (Type = 0x05)
 * Kündigt einen Server-Push an
 */
class Http3PushPromiseFrame : public Http3Frame {
public:
    Http3PushPromiseFrame() : push_id_(0) {}
    Http3PushPromiseFrame(uint64_t push_id, const std::vector<uint8_t>& header_block)
        : push_id_(push_id), header_block_(header_block) {}
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::PUSH_PROMISE; }
    
    uint64_t get_push_id() const { return push_id_; }
    void set_push_id(uint64_t push_id) { push_id_ = push_id; }
    
    const std::vector<uint8_t>& get_header_block() const { return header_block_; }
    void set_header_block(const std::vector<uint8_t>& header_block) { header_block_ = header_block; }
    
private:
    uint64_t push_id_;
    std::vector<uint8_t> header_block_;
};

/**
 * GOAWAY Frame (Type = 0x07)
 * Signalisiert, dass die Verbindung beendet werden soll
 */
class Http3GoAwayFrame : public Http3Frame {
public:
    Http3GoAwayFrame() : stream_id_(0) {}
    explicit Http3GoAwayFrame(uint64_t stream_id) : stream_id_(stream_id) {}
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::GOAWAY; }
    
    uint64_t get_stream_id() const { return stream_id_; }
    void set_stream_id(uint64_t stream_id) { stream_id_ = stream_id; }
    
private:
    uint64_t stream_id_;
};

/**
 * MAX_PUSH_ID Frame (Type = 0x0D)
 * Gibt die maximale Push-ID an, die vom Server verwendet werden darf
 */
class Http3MaxPushIdFrame : public Http3Frame {
public:
    Http3MaxPushIdFrame() : push_id_(0) {}
    explicit Http3MaxPushIdFrame(uint64_t push_id) : push_id_(push_id) {}
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::MAX_PUSH_ID; }
    
    uint64_t get_push_id() const { return push_id_; }
    void set_push_id(uint64_t push_id) { push_id_ = push_id; }
    
private:
    uint64_t push_id_;
};

/**
 * Unbekannter Frame-Typ
 * Repräsentiert einen Frame-Typ, der nicht in der Spezifikation definiert ist
 */
class Http3UnknownFrame : public Http3Frame {
public:
    Http3UnknownFrame() : type_(0) {}
    Http3UnknownFrame(uint64_t type, const std::vector<uint8_t>& payload)
        : type_(type), payload_(payload) {}
    
    std::vector<uint8_t> serialize() const override;
    Http3FrameType get_type() const override { return Http3FrameType::UNKNOWN; }
    
    uint64_t get_raw_type() const { return type_; }
    const std::vector<uint8_t>& get_payload() const { return payload_; }
    
private:
    uint64_t type_;
    std::vector<uint8_t> payload_;
};

} // namespace quicsand

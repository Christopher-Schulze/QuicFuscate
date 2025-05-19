#include "http3_masquerading.hpp"
#include <random>
#include <algorithm>
#include <iostream>

namespace quicsand {

Http3Masquerading::Http3Masquerading() 
    : qpack_codec_(std::make_unique<QpackCodec>()),
      priority_scheduler_(std::make_unique<PriorityScheduler>()),
      browser_profile_("Chrome_Latest") {
}

Http3Masquerading::~Http3Masquerading() = default;

void Http3Masquerading::initialize(const std::map<std::string, std::string>& config) {
    config_ = config;
    
    // Browser-Profil aus Konfiguration auslesen
    if (config.find("browser_profile") != config.end()) {
        set_browser_profile(config.at("browser_profile"));
    }
    
    // QPACK-Einstellungen initialisieren
    qpack_codec_->set_max_table_capacity(4096); // Standardwert
    qpack_codec_->set_max_blocked_streams(100); // Standardwert
    
    if (config.find("qpack_max_table_capacity") != config.end()) {
        try {
            qpack_codec_->set_max_table_capacity(std::stoi(config.at("qpack_max_table_capacity")));
        } catch (const std::exception&) {
            // Ungültiger Wert, behalte Standard bei
        }
    }
    
    if (config.find("qpack_max_blocked_streams") != config.end()) {
        try {
            qpack_codec_->set_max_blocked_streams(std::stoi(config.at("qpack_max_blocked_streams")));
        } catch (const std::exception&) {
            // Ungültiger Wert, behalte Standard bei
        }
    }
}

bool Http3Masquerading::process_outgoing_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    // Extrahiere Stream-ID und Daten aus dem Paket
    uint64_t stream_id = packet->get_stream_id();
    auto payload = packet->get_payload();
    
    // Überprüfe, ob dieser Stream bereits registriert ist
    auto stream_type = get_stream_type(stream_id);
    if (!stream_type.has_value()) {
        // Neuen Stream erkennen und registrieren
        if (stream_id == 0) {
            // Stream 0 ist immer der Control Stream
            register_stream(stream_id, Http3StreamType::CONTROL);
        } else if (is_unidirectional_stream(stream_id)) {
            // Unidirektionale Streams werden anhand des ersten Bytes identifiziert
            if (!payload.empty()) {
                uint8_t stream_type_byte = payload[0];
                auto detected_type = detect_stream_type_from_first_byte(stream_type_byte);
                if (detected_type != static_cast<uint8_t>(Http3StreamType::UNKNOWN)) {
                    register_stream(stream_id, static_cast<Http3StreamType>(detected_type));
                } else {
                    // Unbekannter Stream-Typ
                    register_stream(stream_id, Http3StreamType::UNKNOWN);
                }
            } else {
                // Leeres Payload, kann noch nicht klassifiziert werden
                register_stream(stream_id, Http3StreamType::UNKNOWN);
            }
        } else {
            // Bidirektionale Streams sind in der Regel Request-Streams
            register_stream(stream_id, Http3StreamType::REQUEST);
        }
        
        // Stream als offen markieren
        update_stream_state(stream_id, Http3Status::OPEN);
    }
    
    // Aktuellen Stream-Typ abrufen
    stream_type = get_stream_type(stream_id);
    
    // Verarbeitung basierend auf Stream-Typ
    if (stream_type.value() == Http3StreamType::CONTROL) {
        // Control Stream: SETTINGS und andere Kontrollframes
        if (payload.empty()) {
            // Leerer Control-Stream, nichts zu tun
            return true;
        }
        
        // Control Stream muss mit dem Stream-Typ beginnen, falls es das erste Byte ist
        if (packet->is_stream_start()) {
            std::vector<uint8_t> new_payload = {0x00}; // Control Stream Type = 0
            new_payload.insert(new_payload.end(), payload.begin(), payload.end());
            packet->set_payload(new_payload);
        }
        
        // Falls es keine Frames gibt, SETTINGS-Frame hinzufügen
        size_t bytes_consumed = 0;
        auto frames = parse_frames(payload, bytes_consumed);
        
        if (frames.empty() && packet->is_stream_start()) {
            // Erstelle und füge ein SETTINGS-Frame hinzu
            std::map<Http3SettingId, uint64_t> settings = {
                {Http3SettingId::QPACK_MAX_TABLE_CAPACITY, qpack_codec_->get_max_table_capacity()},
                {Http3SettingId::QPACK_BLOCKED_STREAMS, qpack_codec_->get_max_blocked_streams()},
                {Http3SettingId::MAX_FIELD_SECTION_SIZE, 16384} // 16KB Header-Sektion
            };
            
            auto settings_frame = create_settings_frame(settings);
            std::vector<std::shared_ptr<Http3Frame>> new_frames = {settings_frame};
            
            // Serialisiere Frames
            auto serialized = serialize_frames(new_frames);
            
            // Aktualisiere Payload
            std::vector<uint8_t> new_payload;
            if (packet->is_stream_start()) {
                new_payload.push_back(0x00); // Control Stream Type
            }
            new_payload.insert(new_payload.end(), serialized.begin(), serialized.end());
            
            packet->set_payload(new_payload);
        }
    } else if (stream_type.value() == Http3StreamType::REQUEST) {
        // Request-Stream: HEADERS und DATA Frames
        
        // Wenn der Stream gerade gestartet wird, füge HEADERS-Frame hinzu
        if (packet->is_stream_start()) {
            // Erstelle realistische Headers
            std::string host = "example.com"; // Sollte aus Konfiguration oder Paket abgeleitet werden
            std::string path = "/"; // Standardpfad
            
            auto headers = generate_realistic_headers(host, path);
            auto headers_frame = create_headers_frame(headers);
            
            // Erstelle DATA-Frame mit den eigentlichen Daten
            auto data_frame = create_data_frame(payload);
            
            // Serialisiere Frames
            std::vector<std::shared_ptr<Http3Frame>> frames = {headers_frame, data_frame};
            auto serialized = serialize_frames(frames);
            
            // Setze neue Payload
            packet->set_payload(serialized);
        } else {
            // Für fortlaufende Stream-Pakete, verpacke Daten in DATA-Frames
            auto data_frame = create_data_frame(payload);
            std::vector<std::shared_ptr<Http3Frame>> frames = {data_frame};
            auto serialized = serialize_frames(frames);
            
            // Setze neue Payload
            packet->set_payload(serialized);
        }
    } else if (stream_type.value() == Http3StreamType::QPACK_ENCODER) {
        // QPACK-Encoder-Stream: keine weitere Verarbeitung erforderlich,
        // da die QPACK-Implementierung bereits korrekte Encoder-Anweisungen generiert
        if (packet->is_stream_start()) {
            // Stream-Typ am Anfang hinzufügen
            std::vector<uint8_t> new_payload = {0x02}; // QPACK Encoder Stream Type = 2
            new_payload.insert(new_payload.end(), payload.begin(), payload.end());
            packet->set_payload(new_payload);
        }
    } else if (stream_type.value() == Http3StreamType::QPACK_DECODER) {
        // QPACK-Decoder-Stream: keine weitere Verarbeitung erforderlich
        if (packet->is_stream_start()) {
            // Stream-Typ am Anfang hinzufügen
            std::vector<uint8_t> new_payload = {0x03}; // QPACK Decoder Stream Type = 3
            new_payload.insert(new_payload.end(), payload.begin(), payload.end());
            packet->set_payload(new_payload);
        }
    }
    
    return true;
}

bool Http3Masquerading::process_incoming_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    uint64_t stream_id = packet->get_stream_id();
    auto payload = packet->get_payload();
    
    // Überprüfe, ob dieser Stream bereits registriert ist
    auto stream_type = get_stream_type(stream_id);
    if (!stream_type.has_value()) {
        // Neuer eingehender Stream
        if (stream_id == 0) {
            register_stream(stream_id, Http3StreamType::CONTROL);
        } else if (is_unidirectional_stream(stream_id)) {
            if (!payload.empty()) {
                uint8_t stream_type_byte = payload[0];
                auto detected_type = detect_stream_type_from_first_byte(stream_type_byte);
                register_stream(stream_id, static_cast<Http3StreamType>(detected_type));
                
                // Entferne Stream-Typ-Byte von der Payload
                payload.erase(payload.begin());
                packet->set_payload(payload);
            } else {
                register_stream(stream_id, Http3StreamType::UNKNOWN);
            }
        } else {
            register_stream(stream_id, Http3StreamType::REQUEST);
        }
        
        update_stream_state(stream_id, Http3Status::OPEN);
    }
    
    // Aktuellen Stream-Typ abrufen
    stream_type = get_stream_type(stream_id);
    
    if (stream_type.value() == Http3StreamType::CONTROL || 
        stream_type.value() == Http3StreamType::REQUEST) {
        // Parse HTTP/3 Frames
        size_t bytes_consumed = 0;
        auto frames = parse_frames(payload, bytes_consumed);
        
        // Extrahiere die eigentlichen Daten aus den Frames
        std::vector<uint8_t> actual_data;
        
        for (const auto& frame : frames) {
            if (frame->get_type() == Http3FrameType::DATA) {
                auto data_frame = std::dynamic_pointer_cast<Http3DataFrame>(frame);
                if (data_frame) {
                    const auto& frame_data = data_frame->get_data();
                    actual_data.insert(actual_data.end(), frame_data.begin(), frame_data.end());
                }
            } else if (frame->get_type() == Http3FrameType::HEADERS) {
                // Headers verarbeiten, falls notwendig
                auto headers_frame = std::dynamic_pointer_cast<Http3HeadersFrame>(frame);
                if (headers_frame && stream_type.value() == Http3StreamType::REQUEST) {
                    // In einem realen System würden wir hier Header-Informationen extrahieren
                    // und verarbeiten, z.B. Prioritäten
                }
            }
        }
        
        // Wenn Daten extrahiert wurden, setze sie als neue Payload
        if (!actual_data.empty()) {
            packet->set_payload(actual_data);
        } else if (bytes_consumed > 0) {
            // Es wurden Frames verarbeitet, aber keine Daten extrahiert
            // Setze leere Payload
            packet->set_payload({});
        }
    } else if (stream_type.value() == Http3StreamType::QPACK_ENCODER || 
               stream_type.value() == Http3StreamType::QPACK_DECODER) {
        // Leite Daten direkt an den QPACK-Codec weiter
        // In einer vollständigen Implementierung würde dies QPACK-Anweisungen verarbeiten
    }
    
    return true;
}

// Stream-Verwaltungsmethoden

void Http3Masquerading::register_stream(uint64_t stream_id, Http3StreamType type) {
    stream_types_[stream_id] = type;
    stream_states_[stream_id] = Http3Status::IDLE;
}

void Http3Masquerading::update_stream_state(uint64_t stream_id, Http3Status state) {
    stream_states_[stream_id] = state;
}

std::optional<Http3StreamType> Http3Masquerading::get_stream_type(uint64_t stream_id) const {
    auto it = stream_types_.find(stream_id);
    if (it != stream_types_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<Http3Status> Http3Masquerading::get_stream_state(uint64_t stream_id) const {
    auto it = stream_states_.find(stream_id);
    if (it != stream_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// Hilfsmethoden

bool Http3Masquerading::is_control_stream(uint64_t stream_id) const {
    return stream_id == 0;
}

bool Http3Masquerading::is_request_stream(uint64_t stream_id) const {
    // In QUIC sind bidirektionale Streams immer gerade Zahlen
    return (stream_id & 0x01) == 0 && stream_id != 0;
}

bool Http3Masquerading::is_unidirectional_stream(uint64_t stream_id) const {
    // In QUIC sind unidirektionale Streams immer ungerade Zahlen
    return (stream_id & 0x01) == 1;
}

uint8_t Http3Masquerading::detect_stream_type_from_first_byte(uint8_t first_byte) const {
    switch (first_byte) {
        case 0x00:
            return static_cast<uint8_t>(Http3StreamType::CONTROL);
        case 0x01:
            return static_cast<uint8_t>(Http3StreamType::PUSH);
        case 0x02:
            return static_cast<uint8_t>(Http3StreamType::QPACK_ENCODER);
        case 0x03:
            return static_cast<uint8_t>(Http3StreamType::QPACK_DECODER);
        default:
            if (first_byte >= 0x21 && first_byte <= 0x3F) {
                return static_cast<uint8_t>(Http3StreamType::RESERVED);
            }
            return static_cast<uint8_t>(Http3StreamType::UNKNOWN);
    }
}

// Prioritätsmethoden

void Http3Masquerading::set_stream_priority(uint64_t stream_id, const PriorityParameters& priority) {
    priority_scheduler_->update_stream_priority(stream_id, priority);
}

std::optional<PriorityParameters> Http3Masquerading::get_stream_priority(uint64_t stream_id) const {
    return priority_scheduler_->get_stream_priority(stream_id);
}

} // namespace quicsand

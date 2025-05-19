#include "http3_masquerading.hpp"
#include <iostream>
#include <stdexcept>

namespace quicsand {

// HTTP/3 Frame-Erstellungsmethoden
std::shared_ptr<Http3Frame> Http3Masquerading::create_data_frame(const std::vector<uint8_t>& payload) {
    auto frame = std::make_shared<Http3DataFrame>();
    frame->set_data(payload);
    return frame;
}

std::shared_ptr<Http3Frame> Http3Masquerading::create_headers_frame(const std::vector<Http3HeaderField>& headers) {
    auto frame = std::make_shared<Http3HeadersFrame>();
    
    // Komprimiere Headers mit QPACK
    std::vector<uint8_t> encoded_headers = qpack_codec_->encode_header_fields(headers);
    frame->set_header_block(encoded_headers);
    
    return frame;
}

std::shared_ptr<Http3Frame> Http3Masquerading::create_settings_frame(
    const std::map<Http3SettingId, uint64_t>& settings) {
    
    auto frame = std::make_shared<Http3SettingsFrame>();
    for (const auto& [id, value] : settings) {
        frame->add_setting(id, value);
    }
    
    return frame;
}

// Frame-Parsing und -Serialisierung
std::vector<std::shared_ptr<Http3Frame>> Http3Masquerading::parse_frames(
    const std::vector<uint8_t>& data, size_t& bytes_consumed) {
    
    std::vector<std::shared_ptr<Http3Frame>> frames;
    bytes_consumed = 0;
    
    while (bytes_consumed < data.size()) {
        try {
            // Frame-Typ und -Länge aus dem Datenstrom lesen
            uint64_t frame_type_value = 0;
            size_t frame_type_bytes = 0;
            if (!Http3VariableInt::decode(&data[bytes_consumed], data.size() - bytes_consumed, frame_type_value, frame_type_bytes)) {
                // Nicht genügend Daten für den Frame-Typ
                break;
            }
            
            if (frame_type_bytes > data.size() - bytes_consumed) {
                // Überprüfe auf ungültige Dekodierung (sollte nie passieren)
                break;
            }
            
            bytes_consumed += frame_type_bytes;
            
            // Frame-Länge dekodieren
            uint64_t frame_length = 0;
            size_t frame_length_bytes = 0;
            if (!Http3VariableInt::decode(&data[bytes_consumed], data.size() - bytes_consumed, frame_length, frame_length_bytes)) {
                // Nicht genügend Daten für die Frame-Länge
                bytes_consumed -= frame_type_bytes; // Rücksetzen
                break;
            }
            
            bytes_consumed += frame_length_bytes;
            
            // Überprüfe, ob genügend Daten für den Frame-Inhalt vorhanden sind
            if (frame_length > data.size() - bytes_consumed) {
                // Nicht genügend Daten, setze zurück und warte auf mehr
                bytes_consumed -= (frame_type_bytes + frame_length_bytes);
                break;
            }
            
            // Erstelle das entsprechende Frame basierend auf dem Typ
            Http3FrameType frame_type = static_cast<Http3FrameType>(frame_type_value);
            std::shared_ptr<Http3Frame> frame;
            
            switch (frame_type) {
                case Http3FrameType::DATA: {
                    auto data_frame = std::make_shared<Http3DataFrame>();
                    std::vector<uint8_t> payload(data.begin() + bytes_consumed, data.begin() + bytes_consumed + frame_length);
                    data_frame->set_data(payload);
                    frame = data_frame;
                    break;
                }
                case Http3FrameType::HEADERS: {
                    auto headers_frame = std::make_shared<Http3HeadersFrame>();
                    std::vector<uint8_t> header_block(data.begin() + bytes_consumed, data.begin() + bytes_consumed + frame_length);
                    headers_frame->set_header_block(header_block);
                    frame = headers_frame;
                    break;
                }
                case Http3FrameType::SETTINGS: {
                    auto settings_frame = std::make_shared<Http3SettingsFrame>();
                    size_t settings_offset = 0;
                    
                    // Parse settings pairs
                    while (settings_offset < frame_length) {
                        // Decode setting identifier
                        uint64_t identifier = 0;
                        size_t id_bytes = 0;
                        if (!Http3VariableInt::decode(&data[bytes_consumed + settings_offset], 
                                                     frame_length - settings_offset, 
                                                     identifier, id_bytes)) {
                            break;
                        }
                        settings_offset += id_bytes;
                        
                        // Decode setting value
                        uint64_t value = 0;
                        size_t value_bytes = 0;
                        if (!Http3VariableInt::decode(&data[bytes_consumed + settings_offset], 
                                                     frame_length - settings_offset, 
                                                     value, value_bytes)) {
                            break;
                        }
                        settings_offset += value_bytes;
                        
                        // Add setting to frame
                        settings_frame->add_setting(static_cast<Http3SettingId>(identifier), value);
                    }
                    
                    frame = settings_frame;
                    break;
                }
                case Http3FrameType::GOAWAY: {
                    auto goaway_frame = std::make_shared<Http3GoAwayFrame>();
                    
                    if (frame_length > 0) {
                        // Decode Stream ID
                        uint64_t stream_id = 0;
                        size_t stream_id_bytes = 0;
                        if (Http3VariableInt::decode(&data[bytes_consumed], frame_length, stream_id, stream_id_bytes)) {
                            goaway_frame->set_stream_id(stream_id);
                        }
                    }
                    
                    frame = goaway_frame;
                    break;
                }
                case Http3FrameType::CANCEL_PUSH: {
                    auto cancel_push_frame = std::make_shared<Http3CancelPushFrame>();
                    
                    if (frame_length > 0) {
                        // Decode Push ID
                        uint64_t push_id = 0;
                        size_t push_id_bytes = 0;
                        if (Http3VariableInt::decode(&data[bytes_consumed], frame_length, push_id, push_id_bytes)) {
                            cancel_push_frame->set_push_id(push_id);
                        }
                    }
                    
                    frame = cancel_push_frame;
                    break;
                }
                case Http3FrameType::PUSH_PROMISE: {
                    auto push_promise_frame = std::make_shared<Http3PushPromiseFrame>();
                    
                    if (frame_length > 0) {
                        // Decode Push ID
                        uint64_t push_id = 0;
                        size_t push_id_bytes = 0;
                        if (Http3VariableInt::decode(&data[bytes_consumed], frame_length, push_id, push_id_bytes)) {
                            push_promise_frame->set_push_id(push_id);
                            
                            // Get header block
                            if (push_id_bytes < frame_length) {
                                std::vector<uint8_t> header_block(
                                    data.begin() + bytes_consumed + push_id_bytes,
                                    data.begin() + bytes_consumed + frame_length);
                                push_promise_frame->set_header_block(header_block);
                            }
                        }
                    }
                    
                    frame = push_promise_frame;
                    break;
                }
                case Http3FrameType::MAX_PUSH_ID: {
                    auto max_push_id_frame = std::make_shared<Http3MaxPushIdFrame>();
                    
                    if (frame_length > 0) {
                        // Decode Push ID
                        uint64_t push_id = 0;
                        size_t push_id_bytes = 0;
                        if (Http3VariableInt::decode(&data[bytes_consumed], frame_length, push_id, push_id_bytes)) {
                            max_push_id_frame->set_push_id(push_id);
                        }
                    }
                    
                    frame = max_push_id_frame;
                    break;
                }
                default: {
                    // Unbekannter Frame-Typ, erstelle ein generisches Frame
                    auto unknown_frame = std::make_shared<Http3UnknownFrame>(frame_type);
                    std::vector<uint8_t> payload(data.begin() + bytes_consumed, data.begin() + bytes_consumed + frame_length);
                    unknown_frame->set_payload(payload);
                    frame = unknown_frame;
                    break;
                }
            }
            
            // Füge das Frame zur Liste hinzu
            frames.push_back(frame);
            
            // Aktualisiere die verarbeiteten Bytes
            bytes_consumed += frame_length;
        } catch (const std::exception& e) {
            // Bei Ausnahmen während der Frame-Verarbeitung
            std::cerr << "Error parsing HTTP/3 frame: " << e.what() << std::endl;
            break;
        }
    }
    
    return frames;
}

std::vector<uint8_t> Http3Masquerading::serialize_frames(
    const std::vector<std::shared_ptr<Http3Frame>>& frames) {
    
    std::vector<uint8_t> serialized;
    
    for (const auto& frame : frames) {
        try {
            // Serialisiere jedes Frame
            auto frame_data = frame->serialize();
            
            // Füge die serialisierten Daten zum Ergebnis hinzu
            serialized.insert(serialized.end(), frame_data.begin(), frame_data.end());
        } catch (const std::exception& e) {
            // Fehlerbehandlung bei der Serialisierung
            std::cerr << "Error serializing HTTP/3 frame: " << e.what() << std::endl;
        }
    }
    
    return serialized;
}

// Request/Response-Erstellungsmethoden
std::vector<uint8_t> Http3Masquerading::create_http3_request(
    const std::string& host, 
    const std::string& path, 
    const std::string& method,
    const std::map<std::string, std::string>& additional_headers) {
    
    // Erzeuge Headers für die HTTP-Anfrage
    auto headers = generate_realistic_headers(host, path, method);
    
    // Füge zusätzliche Header hinzu
    for (const auto& [name, value] : additional_headers) {
        // Überprüfe, ob dieser Header bereits existiert
        auto it = std::find_if(headers.begin(), headers.end(), 
                             [&name](const Http3HeaderField& field) {
                                 return field.name == name;
                             });
        
        if (it != headers.end()) {
            // Ersetze vorhandenen Header
            it->value = value;
        } else {
            // Füge neuen Header hinzu
            headers.push_back({name, value});
        }
    }
    
    // Prioritätsinformationen hinzufügen
    PriorityParameters priority;
    priority.urgency = UrgencyLevel::NORMAL; // Standard-Dringlichkeit für Anfragen
    priority.incremental = false;
    
    std::string priority_value = PriorityManager::generate_priority_header(priority);
    headers.push_back({"priority", priority_value});
    
    // Erstelle HEADERS-Frame
    auto headers_frame = create_headers_frame(headers);
    
    // Serialisiere das Frame
    std::vector<std::shared_ptr<Http3Frame>> frames = {headers_frame};
    return serialize_frames(frames);
}

std::vector<uint8_t> Http3Masquerading::create_http3_response(
    int status_code, 
    const std::map<std::string, std::string>& headers,
    const std::vector<uint8_t>& payload) {
    
    // Erstelle Response-Headers
    std::vector<Http3HeaderField> response_headers;
    
    // Pseudo-Header für Status
    response_headers.push_back({":status", std::to_string(status_code)});
    
    // Standardheader für HTTP/3-Antworten
    response_headers.push_back({"content-type", "application/octet-stream"});
    response_headers.push_back({"date", "Wed, 01 Jan 2023 00:00:00 GMT"}); // Sollte eigentlich aktuelles Datum sein
    response_headers.push_back({"server", "quicsand-http3-server"});
    
    // Benutzerdefinierte Header hinzufügen
    for (const auto& [name, value] : headers) {
        // Überprüfe, ob dieser Header bereits existiert
        auto it = std::find_if(response_headers.begin(), response_headers.end(), 
                             [&name](const Http3HeaderField& field) {
                                 return field.name == name;
                             });
        
        if (it != response_headers.end()) {
            // Ersetze vorhandenen Header
            it->value = value;
        } else {
            // Füge neuen Header hinzu
            response_headers.push_back({name, value});
        }
    }
    
    // Erstelle Frames
    std::vector<std::shared_ptr<Http3Frame>> frames;
    
    // HEADERS-Frame für Response-Header
    auto headers_frame = create_headers_frame(response_headers);
    frames.push_back(headers_frame);
    
    // DATA-Frame für Payload, falls vorhanden
    if (!payload.empty()) {
        auto data_frame = create_data_frame(payload);
        frames.push_back(data_frame);
    }
    
    // Serialisiere Frames
    return serialize_frames(frames);
}

} // namespace quicsand

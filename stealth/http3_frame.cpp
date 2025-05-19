#include "http3_frame.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace quicsand {

// Frame-Serialisierungs- und Deserialisierungsfunktionen

// DATA Frame
Http3DataFrame::Http3DataFrame(const std::vector<uint8_t>& payload)
    : payload_(payload) {
}

std::vector<uint8_t> Http3DataFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (DATA = 0x00)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::DATA));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Frame-Länge
    auto length_bytes = encode_varint(payload_.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Payload
    result.insert(result.end(), payload_.begin(), payload_.end());
    
    return result;
}

// HEADERS Frame
Http3HeadersFrame::Http3HeadersFrame(const std::vector<uint8_t>& header_block)
    : header_block_(header_block) {
}

std::vector<uint8_t> Http3HeadersFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (HEADERS = 0x01)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::HEADERS));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Frame-Länge
    auto length_bytes = encode_varint(header_block_.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // QPACK-kodierter Header-Block
    result.insert(result.end(), header_block_.begin(), header_block_.end());
    
    return result;
}

// CANCEL_PUSH Frame
std::vector<uint8_t> Http3CancelPushFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (CANCEL_PUSH = 0x03)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::CANCEL_PUSH));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Push-ID kodieren
    auto push_id_bytes = encode_varint(push_id_);
    
    // Frame-Länge
    auto length_bytes = encode_varint(push_id_bytes.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Push-ID
    result.insert(result.end(), push_id_bytes.begin(), push_id_bytes.end());
    
    return result;
}

// SETTINGS Frame
void Http3SettingsFrame::add_setting(Http3SettingId id, uint64_t value) {
    settings_[id] = value;
}

bool Http3SettingsFrame::has_setting(Http3SettingId id) const {
    return settings_.find(id) != settings_.end();
}

std::optional<uint64_t> Http3SettingsFrame::get_setting(Http3SettingId id) const {
    auto it = settings_.find(id);
    if (it != settings_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<uint8_t> Http3SettingsFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (SETTINGS = 0x04)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::SETTINGS));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Payload zusammenstellen (Identifier-Value-Paare)
    std::vector<uint8_t> payload;
    for (const auto& setting : settings_) {
        auto id_bytes = encode_varint(static_cast<uint64_t>(setting.first));
        auto value_bytes = encode_varint(setting.second);
        
        payload.insert(payload.end(), id_bytes.begin(), id_bytes.end());
        payload.insert(payload.end(), value_bytes.begin(), value_bytes.end());
    }
    
    // Frame-Länge
    auto length_bytes = encode_varint(payload.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

// PUSH_PROMISE Frame
std::vector<uint8_t> Http3PushPromiseFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (PUSH_PROMISE = 0x05)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::PUSH_PROMISE));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Push-ID kodieren
    auto push_id_bytes = encode_varint(push_id_);
    
    // Gesamtlänge = Push-ID + Header-Block
    auto length_bytes = encode_varint(push_id_bytes.size() + header_block_.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Push-ID
    result.insert(result.end(), push_id_bytes.begin(), push_id_bytes.end());
    
    // QPACK-kodierter Header-Block
    result.insert(result.end(), header_block_.begin(), header_block_.end());
    
    return result;
}

// GOAWAY Frame
std::vector<uint8_t> Http3GoAwayFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (GOAWAY = 0x07)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::GOAWAY));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Stream-ID kodieren
    auto stream_id_bytes = encode_varint(stream_id_);
    
    // Frame-Länge
    auto length_bytes = encode_varint(stream_id_bytes.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Stream-ID
    result.insert(result.end(), stream_id_bytes.begin(), stream_id_bytes.end());
    
    return result;
}

// MAX_PUSH_ID Frame
std::vector<uint8_t> Http3MaxPushIdFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Frame-Typ (MAX_PUSH_ID = 0x0D)
    auto type_bytes = encode_varint(static_cast<uint64_t>(Http3FrameType::MAX_PUSH_ID));
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Push-ID kodieren
    auto push_id_bytes = encode_varint(push_id_);
    
    // Frame-Länge
    auto length_bytes = encode_varint(push_id_bytes.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Push-ID
    result.insert(result.end(), push_id_bytes.begin(), push_id_bytes.end());
    
    return result;
}

// UNKNOWN Frame
std::vector<uint8_t> Http3UnknownFrame::serialize() const {
    std::vector<uint8_t> result;
    
    // Raw Frame-Typ
    auto type_bytes = encode_varint(type_);
    result.insert(result.end(), type_bytes.begin(), type_bytes.end());
    
    // Frame-Länge
    auto length_bytes = encode_varint(payload_.size());
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
    
    // Payload
    result.insert(result.end(), payload_.begin(), payload_.end());
    
    return result;
}

// Deserialisierungsmethode für HTTP/3-Frames
std::unique_ptr<Http3Frame> Http3Frame::deserialize(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return nullptr;
    }
    
    return deserialize(data.data(), data.size());
}

std::unique_ptr<Http3Frame> Http3Frame::deserialize(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return nullptr;
    }
    
    size_t pos = 0;
    
    // Frame-Typ dekodieren
    uint64_t type_val = decode_varint(data, length, pos);
    Http3FrameType type = static_cast<Http3FrameType>(type_val);
    
    // Frame-Länge dekodieren
    uint64_t frame_length = decode_varint(data, length, pos);
    
    // Prüfen, ob genügend Daten vorhanden sind
    if (pos + frame_length > length) {
        return nullptr;
    }
    
    // Frame-spezifische Deserialisierung
    switch (type) {
        case Http3FrameType::DATA: {
            std::vector<uint8_t> payload(data + pos, data + pos + frame_length);
            return std::make_unique<Http3DataFrame>(payload);
        }
        
        case Http3FrameType::HEADERS: {
            std::vector<uint8_t> header_block(data + pos, data + pos + frame_length);
            return std::make_unique<Http3HeadersFrame>(header_block);
        }
        
        case Http3FrameType::CANCEL_PUSH: {
            if (frame_length == 0) {
                return nullptr;
            }
            
            size_t end_pos = pos;
            uint64_t push_id = decode_varint(data + pos, frame_length, end_pos);
            return std::make_unique<Http3CancelPushFrame>(push_id);
        }
        
        case Http3FrameType::SETTINGS: {
            auto settings_frame = std::make_unique<Http3SettingsFrame>();
            size_t end_pos = 0;
            
            // Alle Settings-Paare dekodieren
            while (end_pos < frame_length) {
                uint64_t id = decode_varint(data + pos + end_pos, frame_length - end_pos, end_pos);
                if (end_pos >= frame_length) {
                    break;
                }
                
                uint64_t value = decode_varint(data + pos + end_pos, frame_length - end_pos, end_pos);
                settings_frame->add_setting(static_cast<Http3SettingId>(id), value);
            }
            
            return settings_frame;
        }
        
        case Http3FrameType::PUSH_PROMISE: {
            if (frame_length == 0) {
                return nullptr;
            }
            
            size_t end_pos = 0;
            uint64_t push_id = decode_varint(data + pos, frame_length, end_pos);
            
            // Header-Block extrahieren
            std::vector<uint8_t> header_block;
            if (end_pos < frame_length) {
                header_block.assign(data + pos + end_pos, data + pos + frame_length);
            }
            
            return std::make_unique<Http3PushPromiseFrame>(push_id, header_block);
        }
        
        case Http3FrameType::GOAWAY: {
            if (frame_length == 0) {
                return nullptr;
            }
            
            size_t end_pos = 0;
            uint64_t stream_id = decode_varint(data + pos, frame_length, end_pos);
            return std::make_unique<Http3GoAwayFrame>(stream_id);
        }
        
        case Http3FrameType::MAX_PUSH_ID: {
            if (frame_length == 0) {
                return nullptr;
            }
            
            size_t end_pos = 0;
            uint64_t push_id = decode_varint(data + pos, frame_length, end_pos);
            return std::make_unique<Http3MaxPushIdFrame>(push_id);
        }
        
        default: {
            // Unbekannter Frame-Typ
            std::vector<uint8_t> payload(data + pos, data + pos + frame_length);
            return std::make_unique<Http3UnknownFrame>(type_val, payload);
        }
    }
}

// Variable-Length Integer Kodierung gemäß QUIC-Spezifikation
std::vector<uint8_t> Http3Frame::encode_varint(uint64_t value) {
    std::vector<uint8_t> result;
    
    // 1-Byte Darstellung (0xxxxxxx)
    if (value < 64) {
        result.push_back(static_cast<uint8_t>(value));
    }
    // 2-Byte Darstellung (10xxxxxx + 1 Byte)
    else if (value < 16384) {
        result.push_back(static_cast<uint8_t>((value >> 8) | 0x40));
        result.push_back(static_cast<uint8_t>(value));
    }
    // 4-Byte Darstellung (11xxxxxx + 3 Bytes)
    else if (value < 1073741824) {
        result.push_back(static_cast<uint8_t>((value >> 24) | 0x80));
        result.push_back(static_cast<uint8_t>(value >> 16));
        result.push_back(static_cast<uint8_t>(value >> 8));
        result.push_back(static_cast<uint8_t>(value));
    }
    // 8-Byte Darstellung (11xxxxxx + 7 Bytes)
    else {
        result.push_back(static_cast<uint8_t>((value >> 56) | 0xC0));
        result.push_back(static_cast<uint8_t>(value >> 48));
        result.push_back(static_cast<uint8_t>(value >> 40));
        result.push_back(static_cast<uint8_t>(value >> 32));
        result.push_back(static_cast<uint8_t>(value >> 24));
        result.push_back(static_cast<uint8_t>(value >> 16));
        result.push_back(static_cast<uint8_t>(value >> 8));
        result.push_back(static_cast<uint8_t>(value));
    }
    
    return result;
}

// Variable-Length Integer Dekodierung gemäß QUIC-Spezifikation
uint64_t Http3Frame::decode_varint(const uint8_t* data, size_t length, size_t& bytes_read) {
    if (length == 0) {
        bytes_read = 0;
        return 0;
    }
    
    uint8_t first_byte = data[0];
    uint8_t prefix = first_byte & 0xC0;  // Erste 2 Bits
    
    // Bestimme die Anzahl der Bytes basierend auf dem Präfix
    size_t num_bytes = 1;
    if (prefix == 0x00) {
        num_bytes = 1;       // 0b00xxxxxx: 1 Byte
    } else if (prefix == 0x40) {
        num_bytes = 2;       // 0b01xxxxxx: 2 Bytes
    } else if (prefix == 0x80) {
        num_bytes = 4;       // 0b10xxxxxx: 4 Bytes
    } else if (prefix == 0xC0) {
        num_bytes = 8;       // 0b11xxxxxx: 8 Bytes
    }
    
    // Prüfe, ob genug Bytes vorhanden sind
    if (length < num_bytes) {
        bytes_read = 0;
        return 0;
    }
    
    // Dekodieren des Werts
    uint64_t value = 0;
    if (num_bytes == 1) {
        value = first_byte & 0x3F;  // Maske für 6 Bits
    } else if (num_bytes == 2) {
        value = ((uint64_t)(first_byte & 0x3F) << 8) | data[1];
    } else if (num_bytes == 4) {
        value = ((uint64_t)(first_byte & 0x3F) << 24) |
                ((uint64_t)data[1] << 16) |
                ((uint64_t)data[2] << 8) |
                data[3];
    } else if (num_bytes == 8) {
        value = ((uint64_t)(first_byte & 0x3F) << 56) |
                ((uint64_t)data[1] << 48) |
                ((uint64_t)data[2] << 40) |
                ((uint64_t)data[3] << 32) |
                ((uint64_t)data[4] << 24) |
                ((uint64_t)data[5] << 16) |
                ((uint64_t)data[6] << 8) |
                data[7];
    }
    
    // Aktualisieren der gelesenen Bytes
    bytes_read += num_bytes;
    
    return value;
}

} // namespace quicsand

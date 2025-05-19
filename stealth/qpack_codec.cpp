#include "qpack.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace quicsand {

// Konstruktor
QpackCodec::QpackCodec(size_t maxTableCapacity)
    : dynamic_table_capacity_(maxTableCapacity),
      dynamic_table_size_(0),
      insert_count_(0),
      known_received_count_(0),
      required_insert_count_(0),
      base_index_(0) {
}

// Kodiert eine Liste von Header-Fields
std::vector<uint8_t> QpackCodec::encode_header_block(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    
    std::vector<uint8_t> result;
    
    // Präfix: Required Insert Count und Base Index kodieren (RFC 9204, 4.5.1)
    if (insert_count_ > 0) {
        // Kodiere Required Insert Count (maximal insert_count_)
        uint64_t required_insert_count = insert_count_;
        result.push_back(required_insert_count & 0x7F); // 0xxxxxxx, nur 7 Bits
        
        // Base Index auf insert_count_ - 1 setzen (wie in RFC empfohlen)
        uint64_t base = insert_count_ - 1;
        result.push_back(base & 0x7F); // 0xxxxxxx, nur 7 Bits
    } else {
        // Keine Einträge in der dynamischen Tabelle
        result.push_back(0);
        result.push_back(0);
    }
    
    // Header-Felder kodieren
    for (const auto& header : headers) {
        const std::string& name = header.first;
        const std::string& value = header.second;
        
        // Zuerst in der statischen Tabelle suchen
        int static_idx = find_in_static_table(name, value);
        
        if (static_idx > 0 && !static_table_[static_idx].second.empty()) {
            // Exakter Treffer in der statischen Tabelle (Name und Wert)
            // INDEXED_FIELD_LINE (RFC 9204, 4.5.2)
            uint8_t prefix = static_cast<uint8_t>(QpackFieldLineInstruction::INDEXED_FIELD_LINE);
            result.push_back(prefix | 0x40); // Bei statischer Tabelle Bit 6 setzen
            result.push_back(static_idx & 0x7F); // 0xxxxxxx, nur 7 Bits
        } else if (static_idx > 0) {
            // Name in der statischen Tabelle, aber Wert muss literal sein
            // LITERAL_FIELD_LINE_WITH_NAME_REFERENCE (RFC 9204, 4.5.4)
            uint8_t prefix = static_cast<uint8_t>(QpackFieldLineInstruction::LITERAL_FIELD_LINE_WITH_NAME_REFERENCE);
            result.push_back(prefix | 0x10); // Bei statischer Tabelle Bit 4 setzen
            result.push_back(static_idx & 0x7F); // 0xxxxxxx, nur 7 Bits
            
            // Wert literal kodieren
            auto encoded_value = encode_string(value);
            result.insert(result.end(), encoded_value.begin(), encoded_value.end());
        } else {
            // Kein Eintrag in statischer Tabelle, in dynamischer Tabelle suchen
            int dynamic_idx = find_in_dynamic_table(name, value);
            
            if (dynamic_idx >= 0 && dynamic_table_[dynamic_idx].value == value) {
                // Exakter Treffer in der dynamischen Tabelle
                // INDEXED_FIELD_LINE (RFC 9204, 4.5.2)
                uint8_t prefix = static_cast<uint8_t>(QpackFieldLineInstruction::INDEXED_FIELD_LINE);
                result.push_back(prefix);
                result.push_back(dynamic_idx & 0x7F); // 0xxxxxxx, nur 7 Bits
            } else if (dynamic_idx >= 0) {
                // Name in der dynamischen Tabelle, aber Wert muss literal sein
                // LITERAL_FIELD_LINE_WITH_NAME_REFERENCE (RFC 9204, 4.5.4)
                uint8_t prefix = static_cast<uint8_t>(QpackFieldLineInstruction::LITERAL_FIELD_LINE_WITH_NAME_REFERENCE);
                result.push_back(prefix);
                result.push_back(dynamic_idx & 0x7F); // 0xxxxxxx, nur 7 Bits
                
                // Wert literal kodieren
                auto encoded_value = encode_string(value);
                result.insert(result.end(), encoded_value.begin(), encoded_value.end());
            } else {
                // Weder in statischer noch in dynamischer Tabelle
                // LITERAL_FIELD_LINE_WITH_LITERAL_NAME (RFC 9204, 4.5.5)
                uint8_t prefix = static_cast<uint8_t>(QpackFieldLineInstruction::LITERAL_FIELD_LINE_WITH_LITERAL_NAME);
                result.push_back(prefix);
                
                // Name und Wert literal kodieren
                auto encoded_name = encode_string(name);
                auto encoded_value = encode_string(value);
                
                result.insert(result.end(), encoded_name.begin(), encoded_name.end());
                result.insert(result.end(), encoded_value.begin(), encoded_value.end());
            }
        }
    }
    
    return result;
}

// Dekodiert einen Header-Block zu einer Liste von Header-Fields
std::vector<std::pair<std::string, std::string>> QpackCodec::decode_header_block(
    const std::vector<uint8_t>& encoded_header_block) {
    
    std::vector<std::pair<std::string, std::string>> headers;
    
    if (encoded_header_block.empty()) {
        return headers;
    }
    
    // Parse Required Insert Count und Base Index
    size_t pos = 0;
    uint64_t required_insert_count = decode_integer(encoded_header_block.data(), 
                                                    encoded_header_block.size(), 
                                                    pos, 7);
    
    uint64_t base = decode_integer(encoded_header_block.data(), 
                                encoded_header_block.size(), 
                                pos, 7);
    
    // Der tatsächliche Base-Index gemäß RFC 9204, 4.5.1
    int64_t base_index = base;
    
    // Header-Felder dekodieren
    while (pos < encoded_header_block.size()) {
        uint8_t first_byte = encoded_header_block[pos++];
        
        if (first_byte & 0x80) {
            // INDEXED_FIELD_LINE (RFC 9204, 4.5.2)
            bool static_entry = (first_byte & 0x40) != 0;
            uint64_t index = decode_integer(encoded_header_block.data(), 
                                         encoded_header_block.size(), 
                                         pos, 6);
            
            if (static_entry) {
                // Eintrag aus der statischen Tabelle
                if (index < static_table_.size()) {
                    headers.push_back(static_table_[index]);
                }
            } else {
                // Eintrag aus der dynamischen Tabelle
                // Index relativ zum Base-Index berechnen (RFC 9204, 3.2.4)
                index = base_index - index;
                
                if (index < dynamic_table_.size()) {
                    const auto& entry = dynamic_table_[index];
                    headers.push_back({entry.name, entry.value});
                }
            }
        } else if ((first_byte & 0xC0) == 0x40) {
            // LITERAL_FIELD_LINE_WITH_NAME_REFERENCE (RFC 9204, 4.5.4)
            bool static_entry = (first_byte & 0x10) != 0;
            uint64_t name_index = decode_integer(encoded_header_block.data(), 
                                              encoded_header_block.size(), 
                                              pos, 4);
            
            std::string name;
            if (static_entry) {
                // Name aus der statischen Tabelle
                if (name_index < static_table_.size()) {
                    name = static_table_[name_index].first;
                }
            } else {
                // Name aus der dynamischen Tabelle
                // Index relativ zum Base-Index berechnen (RFC 9204, 3.2.4)
                name_index = base_index - name_index;
                
                if (name_index < dynamic_table_.size()) {
                    name = dynamic_table_[name_index].name;
                }
            }
            
            // Wert dekodieren
            std::string value = decode_string(encoded_header_block.data(), 
                                            encoded_header_block.size(), 
                                            pos);
            
            headers.push_back({name, value});
        } else {
            // LITERAL_FIELD_LINE_WITH_LITERAL_NAME (RFC 9204, 4.5.5)
            // Name und Wert dekodieren
            std::string name = decode_string(encoded_header_block.data(), 
                                           encoded_header_block.size(), 
                                           pos);
            
            std::string value = decode_string(encoded_header_block.data(), 
                                            encoded_header_block.size(), 
                                            pos);
            
            headers.push_back({name, value});
        }
    }
    
    return headers;
}

// Verarbeitet Anweisungen vom Encoder-Stream
void QpackCodec::process_encoder_stream(const std::vector<uint8_t>& data) {
    size_t pos = 0;
    while (pos < data.size()) {
        uint8_t first_byte = data[pos];
        
        if ((first_byte & 0xE0) == static_cast<uint8_t>(QpackEncoderStreamInstruction::SET_DYNAMIC_TABLE_CAPACITY)) {
            // SET_DYNAMIC_TABLE_CAPACITY (RFC 9204, 5.2.1)
            pos++;
            uint64_t capacity = decode_integer(data.data(), data.size(), pos, 5);
            update_dynamic_table_capacity(capacity);
        } else if ((first_byte & 0xC0) == static_cast<uint8_t>(QpackEncoderStreamInstruction::INSERT_WITH_NAME_REFERENCE)) {
            // INSERT_WITH_NAME_REFERENCE (RFC 9204, 5.2.2)
            bool static_entry = (first_byte & 0x20) != 0;
            pos++;
            uint64_t name_index = decode_integer(data.data(), data.size(), pos, 6);
            std::string value = decode_string(data.data(), data.size(), pos);
            
            std::string name;
            if (static_entry) {
                // Name aus der statischen Tabelle
                if (name_index < static_table_.size()) {
                    name = static_table_[name_index].first;
                }
            } else {
                // Name aus der dynamischen Tabelle
                if (name_index < dynamic_table_.size()) {
                    name = dynamic_table_[name_index].name;
                }
            }
            
            if (!name.empty()) {
                add_to_dynamic_table(name, value);
            }
        } else if ((first_byte & 0xE0) == static_cast<uint8_t>(QpackEncoderStreamInstruction::INSERT_WITH_LITERAL_NAME)) {
            // INSERT_WITH_LITERAL_NAME (RFC 9204, 5.2.3)
            pos++;
            std::string name = decode_string(data.data(), data.size(), pos);
            std::string value = decode_string(data.data(), data.size(), pos);
            
            add_to_dynamic_table(name, value);
        } else if ((first_byte & 0xC0) == static_cast<uint8_t>(QpackEncoderStreamInstruction::DUPLICATE)) {
            // DUPLICATE (RFC 9204, 5.2.4)
            pos++;
            uint64_t index = decode_integer(data.data(), data.size(), pos, 6);
            
            if (index < dynamic_table_.size()) {
                const auto& entry = dynamic_table_[index];
                add_to_dynamic_table(entry.name, entry.value);
            }
        } else {
            // Unbekannte Anweisung, weiter zur nächsten Anweisung
            pos++;
        }
    }
}

// Verarbeitet Anweisungen vom Decoder-Stream
void QpackCodec::process_decoder_stream(const std::vector<uint8_t>& data) {
    size_t pos = 0;
    while (pos < data.size()) {
        uint8_t first_byte = data[pos];
        
        if (first_byte & 0x80) {
            // SECTION_ACKNOWLEDGEMENT (RFC 9204, 5.3.1)
            pos++;
            uint64_t stream_id = decode_integer(data.data(), data.size(), pos, 7);
            // Aktualisiere den Zustand basierend auf der Bestätigung
            // (Implementierung abhängig von der Anwendung)
        } else if ((first_byte & 0xC0) == 0x40) {
            // STREAM_CANCELLATION (RFC 9204, 5.3.2)
            pos++;
            uint64_t stream_id = decode_integer(data.data(), data.size(), pos, 6);
            // Behandle die Stream-Abbruch-Anweisung
            // (Implementierung abhängig von der Anwendung)
        } else if ((first_byte & 0xC0) == 0x00) {
            // INSERT_COUNT_INCREMENT (RFC 9204, 5.3.3)
            pos++;
            uint64_t increment = decode_integer(data.data(), data.size(), pos, 6);
            
            // Aktualisiere known_received_count_
            known_received_count_ += increment;
        } else {
            // Unbekannte Anweisung, weiter zur nächsten Anweisung
            pos++;
        }
    }
}

// Erstellung von Encoder-Stream-Anweisungen
std::vector<uint8_t> QpackCodec::set_dynamic_table_capacity(uint64_t capacity) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackEncoderStreamInstruction::SET_DYNAMIC_TABLE_CAPACITY);
    
    auto encoded = encode_integer(capacity, 5, prefix);
    result.insert(result.end(), encoded.begin(), encoded.end());
    
    return result;
}

std::vector<uint8_t> QpackCodec::insert_with_name_reference(uint64_t name_index, 
                                                         const std::string& value, 
                                                         bool is_static) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackEncoderStreamInstruction::INSERT_WITH_NAME_REFERENCE);
    
    if (is_static) {
        prefix |= 0x20; // Bit 5 setzen für statische Tabelle
    }
    
    auto encoded_index = encode_integer(name_index, 6, prefix);
    auto encoded_value = encode_string(value);
    
    result.insert(result.end(), encoded_index.begin(), encoded_index.end());
    result.insert(result.end(), encoded_value.begin(), encoded_value.end());
    
    return result;
}

std::vector<uint8_t> QpackCodec::insert_with_literal_name(const std::string& name, 
                                                       const std::string& value) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackEncoderStreamInstruction::INSERT_WITH_LITERAL_NAME);
    
    auto encoded_name = encode_string(name);
    auto encoded_value = encode_string(value);
    
    result.push_back(prefix);
    result.insert(result.end(), encoded_name.begin(), encoded_name.end());
    result.insert(result.end(), encoded_value.begin(), encoded_value.end());
    
    return result;
}

std::vector<uint8_t> QpackCodec::duplicate(uint64_t index) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackEncoderStreamInstruction::DUPLICATE);
    
    auto encoded = encode_integer(index, 6, prefix);
    result.insert(result.end(), encoded.begin(), encoded.end());
    
    return result;
}

// Erstellung von Decoder-Stream-Anweisungen
std::vector<uint8_t> QpackCodec::section_acknowledgement(uint64_t stream_id) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackDecoderStreamInstruction::SECTION_ACKNOWLEDGEMENT);
    
    auto encoded = encode_integer(stream_id, 7, prefix);
    result.insert(result.end(), encoded.begin(), encoded.end());
    
    return result;
}

std::vector<uint8_t> QpackCodec::stream_cancellation(uint64_t stream_id) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackDecoderStreamInstruction::STREAM_CANCELLATION);
    
    auto encoded = encode_integer(stream_id, 6, prefix);
    result.insert(result.end(), encoded.begin(), encoded.end());
    
    return result;
}

std::vector<uint8_t> QpackCodec::insert_count_increment(uint64_t increment) {
    std::vector<uint8_t> result;
    uint8_t prefix = static_cast<uint8_t>(QpackDecoderStreamInstruction::INSERT_COUNT_INCREMENT);
    
    auto encoded = encode_integer(increment, 6, prefix);
    result.insert(result.end(), encoded.begin(), encoded.end());
    
    return result;
}

// Hilfsmethoden zur Suche in der statischen und dynamischen Tabelle
int QpackCodec::find_in_static_table(const std::string& name, const std::string& value) {
    for (size_t i = 1; i < static_table_.size(); i++) {
        if (static_table_[i].first == name) {
            if (value.empty() || static_table_[i].second == value) {
                return i;
            }
        }
    }
    
    return -1;
}

int QpackCodec::find_in_dynamic_table(const std::string& name, const std::string& value) {
    auto name_it = dynamic_name_index_.find(name);
    if (name_it != dynamic_name_index_.end()) {
        if (value.empty()) {
            // Nur nach dem Namen suchen
            return name_it->second.front();
        } else {
            // Nach Name und Wert suchen
            auto value_it = dynamic_entry_index_.find(name);
            if (value_it != dynamic_entry_index_.end()) {
                auto entry_it = value_it->second.find(value);
                if (entry_it != value_it->second.end()) {
                    return entry_it->second;
                }
            }
        }
    }
    
    return -1;
}

// Kodiert eine ganze Zahl mit dem angegebenen Präfix gemäß RFC 9204, 4.1.1
std::vector<uint8_t> QpackCodec::encode_integer(uint64_t value, uint8_t prefix_bits, uint8_t prefix) {
    std::vector<uint8_t> result;
    
    // Berechne die maximale Anzahl an Bits für das Präfix
    uint64_t max_prefix_value = (1ULL << prefix_bits) - 1;
    
    if (value < max_prefix_value) {
        // Wert passt in das Präfix
        result.push_back(prefix | static_cast<uint8_t>(value));
    } else {
        // Wert ist größer als das Präfix
        result.push_back(prefix | static_cast<uint8_t>(max_prefix_value));
        value -= max_prefix_value;
        
        // Kodiere den Rest als 7-Bit-Chunks mit Fortsetzungsbit
        while (value >= 128) {
            result.push_back(static_cast<uint8_t>(value % 128 + 128));
            value /= 128;
        }
        
        // Letzter Chunk ohne Fortsetzungsbit
        result.push_back(static_cast<uint8_t>(value));
    }
    
    return result;
}

// Dekodiert eine ganze Zahl gemäß RFC 9204, 4.1.1
uint64_t QpackCodec::decode_integer(const uint8_t* buf, size_t len, size_t& pos, uint8_t prefix_bits) {
    if (pos >= len) {
        return 0;
    }
    
    // Berechne die maximale Anzahl an Bits für das Präfix
    uint64_t max_prefix_value = (1ULL << prefix_bits) - 1;
    uint64_t value = buf[pos] & ((1 << prefix_bits) - 1);
    pos++;
    
    if (value < max_prefix_value) {
        // Wert passt in das Präfix
        return value;
    }
    
    // Wert ist größer als das Präfix
    uint64_t multiplier = 1;
    
    // Dekodiere den Rest als 7-Bit-Chunks mit Fortsetzungsbit
    while (pos < len) {
        uint8_t byte = buf[pos++];
        value += (byte & 127) * multiplier;
        multiplier <<= 7;
        
        if (!(byte & 128)) {
            // Letzter Chunk ohne Fortsetzungsbit
            break;
        }
    }
    
    return value;
}

// Kodiert einen String mit optionaler Huffman-Kodierung gemäß RFC 9204, 4.1.2
std::vector<uint8_t> QpackCodec::encode_string(const std::string& str, bool huffman) {
    std::vector<uint8_t> result;
    
    std::vector<uint8_t> string_data;
    if (huffman) {
        // String mit Huffman kodieren
        string_data = huffman_encode(str);
        
        // Länge mit gesetztem H-Bit (RFC 9204, 4.1.2)
        auto encoded_length = encode_integer(string_data.size(), 7, 0x80);
        result.insert(result.end(), encoded_length.begin(), encoded_length.end());
    } else {
        // String ohne Huffman kodieren
        string_data.assign(str.begin(), str.end());
        
        // Länge ohne H-Bit (RFC 9204, 4.1.2)
        auto encoded_length = encode_integer(string_data.size(), 7, 0);
        result.insert(result.end(), encoded_length.begin(), encoded_length.end());
    }
    
    // String-Daten hinzufügen
    result.insert(result.end(), string_data.begin(), string_data.end());
    
    return result;
}

// Dekodiert einen String gemäß RFC 9204, 4.1.2
std::string QpackCodec::decode_string(const uint8_t* buf, size_t len, size_t& pos) {
    if (pos >= len) {
        return "";
    }
    
    // Überprüfe das H-Bit (Huffman-Kodierung)
    bool huffman_encoded = (buf[pos] & 0x80) != 0;
    
    // Dekodiere die Länge
    uint64_t length = decode_integer(buf, len, pos, 7);
    
    if (pos + length > len) {
        // Ungültige Länge
        return "";
    }
    
    if (huffman_encoded) {
        // String mit Huffman dekodieren
        std::vector<uint8_t> encoded_data(buf + pos, buf + pos + length);
        pos += length;
        return huffman_decode(encoded_data);
    } else {
        // String ohne Huffman dekodieren
        std::string result(reinterpret_cast<const char*>(buf + pos), length);
        pos += length;
        return result;
    }
}

// Verwaltung der dynamischen Tabelle
void QpackCodec::add_to_dynamic_table(const std::string& name, const std::string& value) {
    // Erstelle einen neuen Eintrag
    QpackTableEntry entry(name, value);
    
    // Überprüfe, ob genug Platz in der dynamischen Tabelle ist
    while (dynamic_table_size_ + entry.size > dynamic_table_capacity_ && !dynamic_table_.empty()) {
        evict_from_dynamic_table();
    }
    
    // Wenn der Eintrag immer noch zu groß ist, nicht hinzufügen
    if (entry.size > dynamic_table_capacity_) {
        return;
    }
    
    // Füge den Eintrag zur dynamischen Tabelle hinzu
    dynamic_table_.push_front(entry);
    dynamic_table_size_ += entry.size;
    
    // Aktualisiere die Indizes
    size_t index = 0;
    dynamic_name_index_[name].push_back(index);
    
    if (dynamic_entry_index_.find(name) == dynamic_entry_index_.end()) {
        dynamic_entry_index_[name] = std::unordered_map<std::string, size_t>();
    }
    dynamic_entry_index_[name][value] = index;
    
    // Erhöhe den insert_count
    insert_count_++;
}

void QpackCodec::evict_from_dynamic_table() {
    if (dynamic_table_.empty()) {
        return;
    }
    
    // Entferne den ältesten Eintrag (von hinten)
    const auto& entry = dynamic_table_.back();
    dynamic_table_size_ -= entry.size;
    
    // Aktualisiere die Indizes
    auto& indices = dynamic_name_index_[entry.name];
    indices.pop_back();
    if (indices.empty()) {
        dynamic_name_index_.erase(entry.name);
    }
    
    dynamic_entry_index_[entry.name].erase(entry.value);
    if (dynamic_entry_index_[entry.name].empty()) {
        dynamic_entry_index_.erase(entry.name);
    }
    
    dynamic_table_.pop_back();
}

void QpackCodec::clear_dynamic_table() {
    dynamic_table_.clear();
    dynamic_name_index_.clear();
    dynamic_entry_index_.clear();
    dynamic_table_size_ = 0;
}

void QpackCodec::update_dynamic_table_capacity(size_t capacity) {
    // Begrenze die Kapazität auf den konfigurierten Maximalwert
    capacity = std::min(capacity, dynamic_table_capacity_);
    
    // Wenn die neue Kapazität kleiner ist, entferne Einträge, bis die Größe passt
    while (dynamic_table_size_ > capacity && !dynamic_table_.empty()) {
        evict_from_dynamic_table();
    }
    
    // Aktualisiere die Kapazität
    dynamic_table_capacity_ = capacity;
}

} // namespace quicsand

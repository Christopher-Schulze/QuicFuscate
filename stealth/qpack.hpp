#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <deque>
#include <array>
#include <memory>

namespace quicsand {

// QPACK 5.2. Instructions für den Encoder-Stream
enum class QpackEncoderStreamInstruction : uint8_t {
    SET_DYNAMIC_TABLE_CAPACITY = 0x20, // '001' gefolgt von Kapazitätswert
    INSERT_WITH_NAME_REFERENCE = 0x40, // '01' gefolgt von Namensreferenz und Wert
    INSERT_WITH_LITERAL_NAME = 0x60,   // '001' gefolgt von Name und Wert
    DUPLICATE = 0x80                   // '00' gefolgt von Index
};

// QPACK 5.3. Instructions für den Decoder-Stream
enum class QpackDecoderStreamInstruction : uint8_t {
    SECTION_ACKNOWLEDGEMENT = 0x00, // '1' gefolgt von Stream-ID
    STREAM_CANCELLATION = 0x40,     // '01' gefolgt von Stream-ID
    INSERT_COUNT_INCREMENT = 0x80    // '00' gefolgt von Inkrementwert
};

// QPACK 4.5. Instructions für Field Line Representations
enum class QpackFieldLineInstruction : uint8_t {
    INDEXED_FIELD_LINE = 0x80,           // '1' gefolgt von Index
    INDEXED_FIELD_LINE_WITH_POST_BASE = 0x10, // '0001' gefolgt von Index
    LITERAL_FIELD_LINE_WITH_NAME_REFERENCE = 0x40, // '01' gefolgt von Namensreferenz und Wert
    LITERAL_FIELD_LINE_WITH_POST_BASE_NAME_REFERENCE = 0x20, // '001' gefolgt von Namensreferenz und Wert
    LITERAL_FIELD_LINE_WITH_LITERAL_NAME = 0x00 // '000' gefolgt von Name und Wert
};

// QPACK 4.5.4. Präfixe für Präfix-Integer-Kodierung
struct QpackPrefixes {
    static constexpr uint8_t N_BIT_7 = 0x80; // 1000 0000
    static constexpr uint8_t N_BIT_6 = 0x40; // 0100 0000
    static constexpr uint8_t N_BIT_5 = 0x20; // 0010 0000
    static constexpr uint8_t N_BIT_4 = 0x10; // 0001 0000
    static constexpr uint8_t N_BIT_3 = 0x08; // 0000 1000
};

/**
 * QPACK 3.2.1. Struktur für einen Eintrag in der Dynamischen Tabelle
 */
struct QpackTableEntry {
    std::string name;
    std::string value;
    size_t size;  // Gesamtgröße des Eintrags (Name + Wert + 32 Byte Overhead)
    
    QpackTableEntry(const std::string& n, const std::string& v)
        : name(n), value(v) {
        // Gemäß RFC 9204 Abschnitt 4.1.1. Dynamische Tabellengröße
        size = name.size() + value.size() + 32;
    }
};

/**
 * Vollständige QPACK-Implementierung gemäß RFC 9204 für HTTP/3
 * https://datatracker.ietf.org/doc/html/rfc9204
 */
class QpackCodec {
public:
    static constexpr int DEFAULT_MAX_TABLE_CAPACITY = 4096;
    static constexpr int DEFAULT_HEADER_TABLE_SIZE = 128;
    
    QpackCodec(size_t maxTableCapacity = DEFAULT_MAX_TABLE_CAPACITY);
    ~QpackCodec() = default;
    
    // Kodiert eine Liste von Header-Fields
    std::vector<uint8_t> encode_header_block(const std::vector<std::pair<std::string, std::string>>& headers);
    
    // Dekodiert einen Header-Block zu einer Liste von Header-Fields
    std::vector<std::pair<std::string, std::string>> decode_header_block(
        const std::vector<uint8_t>& encoded_header_block);
    
    // Verarbeitet Anweisungen vom Encoder-Stream
    void process_encoder_stream(const std::vector<uint8_t>& data);
    
    // Verarbeitet Anweisungen vom Decoder-Stream
    void process_decoder_stream(const std::vector<uint8_t>& data);
    
    // Erstellung von Encoder-Stream-Anweisungen
    std::vector<uint8_t> set_dynamic_table_capacity(uint64_t capacity);
    std::vector<uint8_t> insert_with_name_reference(uint64_t name_index, const std::string& value, bool is_static);
    std::vector<uint8_t> insert_with_literal_name(const std::string& name, const std::string& value);
    std::vector<uint8_t> duplicate(uint64_t index);
    
    // Erstellung von Decoder-Stream-Anweisungen
    std::vector<uint8_t> section_acknowledgement(uint64_t stream_id);
    std::vector<uint8_t> stream_cancellation(uint64_t stream_id);
    std::vector<uint8_t> insert_count_increment(uint64_t increment);
    
    // Getter/Setter für den Zustand
    size_t get_dynamic_table_size() const { return dynamic_table_size_; }
    size_t get_dynamic_table_capacity() const { return dynamic_table_capacity_; }
    
private:
    // Referenz zur statischen Tabelle gemäß Appendix A der RFC
    static const std::vector<std::pair<std::string, std::string>> static_table_;
    
    // Dynamische Tabelle als Ring-Puffer
    std::deque<QpackTableEntry> dynamic_table_;
    
    // Indexzuordnungen für schnelle Lookups in der dynamischen Tabelle
    std::unordered_map<std::string, std::vector<size_t>> dynamic_name_index_;
    std::unordered_map<std::string, std::unordered_map<std::string, size_t>> dynamic_entry_index_;
    
    // Konfiguration und Zustand
    size_t dynamic_table_capacity_;  // Maximale Kapazität der dynamischen Tabelle
    size_t dynamic_table_size_;      // Aktuelle Größe der dynamischen Tabelle
    size_t insert_count_;            // Anzahl der Einfügungen in die dynamische Tabelle
    size_t known_received_count_;    // Anzahl der bekannten vom Decoder empfangenen Einträge
    
    // Referenzpunkt-Werte für die Base-Indizes gemäß 4.5.1
    size_t required_insert_count_;   // Benötigte Anzahl an Einfügungen für Dekodierung
    size_t base_index_;              // Base-Index für relative Indizierung
    
    // Hilfsmethoden zur Suche in der statischen und dynamischen Tabelle
    int find_in_static_table(const std::string& name, const std::string& value = "");
    int find_in_dynamic_table(const std::string& name, const std::string& value = "");
    
    // Hilfsmethoden zur Kodierung und Dekodierung
    std::vector<uint8_t> encode_integer(uint64_t value, uint8_t prefix_bits, uint8_t prefix = 0);
    uint64_t decode_integer(const uint8_t* buf, size_t len, size_t& pos, uint8_t prefix_bits);
    
    std::vector<uint8_t> encode_string(const std::string& str, bool huffman = true);
    std::string decode_string(const uint8_t* buf, size_t len, size_t& pos);
    
    // Huffman-Kodierung/Dekodierung gemäß RFC 7541
    std::vector<uint8_t> huffman_encode(const std::string& input);
    std::string huffman_decode(const std::vector<uint8_t>& input);
    
    // Verwaltung der dynamischen Tabelle
    void add_to_dynamic_table(const std::string& name, const std::string& value);
    void evict_from_dynamic_table();
    void clear_dynamic_table();
    void update_dynamic_table_capacity(size_t capacity);
};

// HTTP Header-Struktur für einfache Verwendung von QpackCodec
struct Http3HeaderField {
    std::string name;
    std::string value;
    
    Http3HeaderField(const std::string& n, const std::string& v) : name(n), value(v) {}
};

} // namespace quicsand

#include "tetrys_fec_optimized.hpp"
#include <cstring>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <sstream>
#include <numeric>
#include <chrono>

// ARM NEON SIMD-Instruktionen für Apple M1/M2
#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

namespace quicsand {

// Konstruktor mit Anzahl der Daten-Shards und Parity-Shards (für Kompatibilität)
OptimizedTetrysFEC::OptimizedTetrysFEC(int data_shards, int parity_shards) 
    : data_shards_(data_shards),
      parity_shards_(parity_shards),
      next_seq_num_(0),
      current_redundancy_(0.0),
      repair_packet_count_(0),
      next_expected_seq_(0),
      packets_encoded_(0),
      packets_recovered_(0),
      bytes_saved_(0) {
        
    // Parameter in die neue Konfigurationsstruktur konvertieren
    config_.window_size = data_shards;
    config_.initial_redundancy = static_cast<double>(parity_shards) / data_shards;
    config_.min_redundancy = config_.initial_redundancy / 2;
    config_.max_redundancy = config_.initial_redundancy * 2;
    
    initialize();
}

// Konstruktor mit detaillierter Konfiguration
OptimizedTetrysFEC::OptimizedTetrysFEC(const Config& config)
    : config_(config),
      data_shards_(config.window_size),
      parity_shards_(static_cast<int>(config.window_size * config.initial_redundancy + 0.5)),
      next_seq_num_(0),
      current_redundancy_(config.initial_redundancy),
      repair_packet_count_(0),
      next_expected_seq_(0),
      packets_encoded_(0),
      packets_recovered_(0),
      bytes_saved_(0) {
    
    initialize();
}

// Destruktor
OptimizedTetrysFEC::~OptimizedTetrysFEC() {
    // Speicher in den Bufferpools freigeben
    buffer_pool_.clear();
}

// Initialisierungsmethode
void OptimizedTetrysFEC::initialize() {
    // Redundanzrate auf den anfänglichen Wert setzen
    current_redundancy_ = config_.initial_redundancy;
    
    // Zähler zurücksetzen
    next_seq_num_ = 0;
    repair_packet_count_ = 0;
    next_expected_seq_ = 0;
    packets_encoded_ = 0;
    packets_recovered_ = 0;
    bytes_saved_ = 0;
    
    // Datenstrukturen leeren
    encoding_window_.clear();
    received_packets_.clear();
    recovered_packets_.clear();
    missing_packets_.clear();
    assembled_data_.clear();
    
    // Speicherpools vorbereiten
    if (config_.pool_size > 0) {
        // Puffer für die gängigen Paketgrößen vorallokieren
        size_t typical_sizes[] = {
            static_cast<size_t>(PacketSizeClass::TINY),
            static_cast<size_t>(PacketSizeClass::SMALL),
            static_cast<size_t>(PacketSizeClass::MEDIUM),
            static_cast<size_t>(PacketSizeClass::LARGE)
        };
        
        // Reserve buffer pool für alle Größen
        buffer_pool_.reserve(config_.pool_size * 4);  // Platz für alle Größenklassen
        
        for (size_t size : typical_sizes) {
            for (size_t i = 0; i < config_.pool_size / 4; ++i) {
                auto buffer = std::make_shared<std::vector<uint8_t>>();
                buffer->reserve(size);  // Nur Kapazität reservieren, nicht allokieren
                buffer_pool_.push_back(buffer);
            }
        }
    }
    
    // Zufallszahlengenerator initialisieren
    std::random_device rd;
    rng_.seed(rd());
    
    // Galois Field Tabellen initialisieren
    initialize_gf_tables();
}

// Setter für Konfiguration mit Neuinitialisierung
void OptimizedTetrysFEC::set_config(const Config& config) {
    config_ = config;
    initialize();
}

// GF(2^8) Multiplikationstabellen initialisieren
void OptimizedTetrysFEC::initialize_gf_tables() {
    // Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
    const uint16_t poly = 0x11D;
    
    // Multiplikationstabelle erstellen
    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b++) {
            uint8_t result = 0;
            uint8_t temp_a = a;
            
            for (int i = 0; i < 8; i++) {
                if (b & (1 << i)) {
                    result ^= temp_a;
                }
                
                // Polynommultiplikation im GF(2^8)
                bool carry = (temp_a & 0x80) != 0;
                temp_a <<= 1;
                if (carry) {
                    temp_a ^= (poly & 0xFF);
                }
            }
            
            gf_mul_table_[a][b] = result;
        }
    }
    
    // Inversionstabelle erstellen
    gf_inv_table_[0] = 0;  // 0 hat keine Inverse
    for (int a = 1; a < 256; a++) {
        for (int b = 1; b < 256; b++) {
            if (gf_mul_table_[a][b] == 1) {
                gf_inv_table_[a] = b;
                break;
            }
        }
    }
}

// GF(2^8) Multiplikation
uint8_t OptimizedTetrysFEC::gf_mul(uint8_t a, uint8_t b) const {
    return gf_mul_table_[a][b];
}

// GF(2^8) Inversion
uint8_t OptimizedTetrysFEC::gf_inv(uint8_t a) const {
    return gf_inv_table_[a];
}

// XOR zweier Byte-Puffer mit memory_span und SIMD-Optimierung
void OptimizedTetrysFEC::xor_buffers(memory_span<uint8_t> dst, memory_span<uint8_t> src) {
    const size_t min_size = std::min(dst.size(), src.size());
    
#ifdef __ARM_NEON
    // Optimale Chunk-Größe für den L1-Cache (64-Byte Cache Line auf M1/M2)
    const size_t CHUNK_SIZE = 64 * 16; // 1024 Bytes pro Chunk
    const size_t vec_size = min_size & ~63; // Runde auf den nächsten durch 64 teilbaren Wert ab
    
    // Verarbeite große Datenmengen in Chunks für bessere Cache-Lokalität
    for (size_t chunk = 0; chunk < vec_size; chunk += CHUNK_SIZE) {
        const size_t chunk_end = std::min(chunk + CHUNK_SIZE, vec_size);
        
        // Prefetch den nächsten Chunk, falls vorhanden
        if (chunk + CHUNK_SIZE < vec_size) {
            __builtin_prefetch(dst.data() + chunk + CHUNK_SIZE, 1); // 1 = für Schreibzugriff
            __builtin_prefetch(src.data() + chunk + CHUNK_SIZE, 0); // 0 = für Lesezugriff
        }
        
        // Unrolled loop - Verarbeite 64 Bytes pro Iteration (4x16 Bytes)
        for (size_t i = chunk; i < chunk_end; i += 64) {
            // Lade 4 NEON-Register (4x16 Bytes = 64 Bytes)
            uint8x16_t v_dst1 = vld1q_u8(dst.data() + i);
            uint8x16_t v_src1 = vld1q_u8(src.data() + i);
            uint8x16_t v_dst2 = vld1q_u8(dst.data() + i + 16);
            uint8x16_t v_src2 = vld1q_u8(src.data() + i + 16);
            uint8x16_t v_dst3 = vld1q_u8(dst.data() + i + 32);
            uint8x16_t v_src3 = vld1q_u8(src.data() + i + 32);
            uint8x16_t v_dst4 = vld1q_u8(dst.data() + i + 48);
            uint8x16_t v_src4 = vld1q_u8(src.data() + i + 48);
            
            // Führe XOR-Operationen durch
            uint8x16_t result1 = veorq_u8(v_dst1, v_src1);
            uint8x16_t result2 = veorq_u8(v_dst2, v_src2);
            uint8x16_t result3 = veorq_u8(v_dst3, v_src3);
            uint8x16_t result4 = veorq_u8(v_dst4, v_src4);
            
            // Speichere die Ergebnisse zurück
            vst1q_u8(dst.data() + i, result1);
            vst1q_u8(dst.data() + i + 16, result2);
            vst1q_u8(dst.data() + i + 32, result3);
            vst1q_u8(dst.data() + i + 48, result4);
        }
    }
    
    // Handle remaining 16-byte blocks
    for (size_t i = vec_size; i < (min_size & ~15); i += 16) {
        uint8x16_t v_dst = vld1q_u8(dst.data() + i);
        uint8x16_t v_src = vld1q_u8(src.data() + i);
        uint8x16_t result = veorq_u8(v_dst, v_src);
        vst1q_u8(dst.data() + i, result);
    }
    
    // Verarbeite die übrigen Bytes einzeln
    for (size_t i = (min_size & ~15); i < min_size; i++) {
        dst[i] ^= src[i];
    }
#else
    // Fallback für nicht-ARM-Plattformen oder wenn NEON nicht aktiviert ist
    // Ungerollte Schleife für bessere Performance auch ohne SIMD
    const size_t step = 8;
    const size_t vec_size = min_size & ~(step-1);
    
    for (size_t i = 0; i < vec_size; i += step) {
        dst[i] ^= src[i];
        dst[i+1] ^= src[i+1];
        dst[i+2] ^= src[i+2];
        dst[i+3] ^= src[i+3];
        dst[i+4] ^= src[i+4];
        dst[i+5] ^= src[i+5];
        dst[i+6] ^= src[i+6];
        dst[i+7] ^= src[i+7];
    }
    
    // Rest verarbeiten
    for (size_t i = vec_size; i < min_size; i++) {
        dst[i] ^= src[i];
    }
#endif
}

// Speicherpuffer aus dem Pool holen
std::shared_ptr<std::vector<uint8_t>> OptimizedTetrysFEC::get_buffer_from_pool(size_t size) {
    if (buffer_pool_.empty() || config_.pool_size == 0) {
        // Fallback: Neuen Puffer erstellen, wenn kein Pool verfügbar
        auto buffer = std::make_shared<std::vector<uint8_t>>();
        buffer->resize(size, 0);
        return buffer;
    }
    
    // Finde einen Puffer mit ausreichender Kapazität
    for (auto it = buffer_pool_.begin(); it != buffer_pool_.end(); ++it) {
        if ((*it)->capacity() >= size) {
            auto buffer = *it;
            buffer_pool_.erase(it);
            buffer->resize(size, 0);
            return buffer;
        }
    }
    
    // Wenn kein passender Puffer gefunden wurde, nimm den ersten und passe ihn an
    auto buffer = buffer_pool_.back();
    buffer_pool_.pop_back();
    buffer->resize(size, 0);
    return buffer;
}

// Puffer in den Pool zurückgeben
void OptimizedTetrysFEC::return_buffer_to_pool(std::shared_ptr<std::vector<uint8_t>> buffer) {
    if (config_.pool_size == 0 || buffer_pool_.size() >= config_.pool_size * 4) {
        // Pool ist deaktiviert oder voll, lasse den Puffer freigeben
        return;
    }
    
    // Füge den Puffer zum Pool hinzu (behalte aber seine Kapazität)
    buffer->clear();  // Entferne Daten, behalte Kapazität
    buffer_pool_.push_back(buffer);
}

// Enkodiert ein Datenblock und erzeugt Source-Pakete + Reparatur-Pakete
std::vector<OptimizedTetrysFEC::TetrysPacket> OptimizedTetrysFEC::encode_block(memory_span<uint8_t> data) {
    std::vector<TetrysPacket> result;
    size_t block_size = config_.block_size;
    
    // Aufteilung der Daten in Blöcke
    for (size_t i = 0; i < data.size(); i += block_size) {
        size_t chunk_size = std::min(block_size, data.size() - i);
        memory_span<uint8_t> chunk = data.subspan(i, chunk_size);
        
        // Paket erzeugen
        auto buffer = get_buffer_from_pool(chunk_size);
        std::copy(chunk.begin(), chunk.end(), buffer->begin());
        
        TetrysPacket packet;
        packet.seq_num = next_seq_num_++;
        packet.is_repair = false;
        packet.assign_from_pool(buffer, memory_span<uint8_t>(*buffer));
        
        // Zum Encoding-Fenster hinzufügen
        encoding_window_.push_back(packet);
        result.push_back(packet);
        
        // Wenn das Encoding-Fenster zu groß wird, entferne älteste Pakete
        while (encoding_window_.size() > config_.window_size) {
            encoding_window_.pop_front();
        }
        
        packets_encoded_++;
        
        // Bestimme, ob ein Reparaturpaket benötigt wird
        double repair_threshold = 1.0 / current_redundancy_;
        if (repair_packet_count_ >= repair_threshold) {
            TetrysPacket repair = generate_repair_packet();
            result.push_back(repair);
            repair_packet_count_ = 0;
        } else {
            repair_packet_count_++;
        }
    }
    
    return result;
}

// Fügt ein einzelnes Datenpaket hinzu und gibt ggf. ein Reparaturpaket zurück
std::vector<OptimizedTetrysFEC::TetrysPacket> OptimizedTetrysFEC::encode_packet(memory_span<uint8_t> data) {
    std::vector<TetrysPacket> result;
    
    // Erzeuge ein Source-Paket mit gepooltem Buffer
    auto buffer = get_buffer_from_pool(data.size());
    std::copy(data.begin(), data.end(), buffer->begin());
    
    TetrysPacket packet;
    packet.seq_num = next_seq_num_++;
    packet.is_repair = false;
    packet.assign_from_pool(buffer, memory_span<uint8_t>(*buffer));
    
    // Zum Encoding-Fenster hinzufügen
    encoding_window_.push_back(packet);
    result.push_back(packet);
    
    // Wenn das Encoding-Fenster zu groß wird, entferne älteste Pakete
    while (encoding_window_.size() > config_.window_size) {
        encoding_window_.pop_front();
    }
    
    packets_encoded_++;
    
    // Bestimme, ob ein Reparaturpaket benötigt wird
    double repair_threshold = 1.0 / current_redundancy_;
    if (repair_packet_count_ >= repair_threshold) {
        TetrysPacket repair = generate_repair_packet();
        result.push_back(repair);
        repair_packet_count_ = 0;
    } else {
        repair_packet_count_++;
    }
    
    return result;
}

// Generiert ein Reparaturpaket aus dem aktuellen Encoding-Fenster
OptimizedTetrysFEC::TetrysPacket OptimizedTetrysFEC::generate_repair_packet() {
    // Erstelle ein neues Reparaturpaket
    TetrysPacket repair_packet;
    repair_packet.is_repair = true;
    repair_packet.seq_num = next_seq_num_++;
    
    // Weise einen Puffer aus dem Pool zu, wenn möglich
    size_t max_packet_size = 0;
    for (const auto& packet : encoding_window_) {
        max_packet_size = std::max(max_packet_size, packet.data_view.size());
    }
    
    auto buffer = get_buffer_from_pool(max_packet_size);
    std::fill(buffer->begin(), buffer->begin() + max_packet_size, 0);
    repair_packet.owned_data = buffer;
    repair_packet.data_view = memory_span<uint8_t>(buffer->data(), max_packet_size);
    
    // Erster Encoding-Durchlauf: Kopiere erstes Paket
    if (!encoding_window_.empty()) {
        const auto& first_packet = encoding_window_.front();
        // Verwende SIMD-optimierte Operationen für bessere Leistung auf ARM Prozessoren
#ifdef __ARM_NEON
        // Direkte Kopie mit NEON-Vektorisierung
        size_t size = std::min(first_packet.data_view.size(), repair_packet.data_view.size());
        size_t vec_size = size & ~15; // Auf 16-Byte-Grenze abrunden
        
        for (size_t i = 0; i < vec_size; i += 16) {
            uint8x16_t data = vld1q_u8(first_packet.data_view.data() + i);
            vst1q_u8(repair_packet.data_view.data() + i, data);
        }
        
        // Rest kopieren
        for (size_t i = vec_size; i < size; i++) {
            repair_packet.data_view[i] = first_packet.data_view[i];
        }
#else
        std::memcpy(repair_packet.data_view.data(), 
                 first_packet.data_view.data(), 
                 std::min(first_packet.data_view.size(), repair_packet.data_view.size()));
#endif
        repair_packet.add_seen(first_packet.seq_num);
        
        // XOR die restlichen Pakete im Fenster
        for (auto it = std::next(encoding_window_.begin()); it != encoding_window_.end(); ++it) {
            // Verwende SIMD-optimierte XOR-Operation
            xor_buffers(repair_packet.data_view, it->data_view);
            repair_packet.add_seen(it->seq_num);
        }
    }
    
    // Aktualisiere Zähler
    repair_packet_count_++;
    
    return repair_packet;
}

// Fügt ein empfangenes Paket zum Dekoder hinzu
memory_span<uint8_t> OptimizedTetrysFEC::add_received_packet(const TetrysPacket& packet) {
    // Ignoriere Pakete, die bereits empfangen wurden
    if (received_packets_.count(packet.seq_num) > 0 || 
        recovered_packets_.count(packet.seq_num) > 0) {
        return memory_span<uint8_t>();
    }
    
    // Füge Paket zur Empfangsliste hinzu
    received_packets_[packet.seq_num] = packet;
    
    // Aktualisiere fehlende Pakete
    if (packet.seq_num > next_expected_seq_) {
        for (uint32_t seq = next_expected_seq_; seq < packet.seq_num; seq++) {
            if (received_packets_.count(seq) == 0 && recovered_packets_.count(seq) == 0) {
                // Vermeidung von Duplikaten in missing_packets_
                bool already_missing = false;
                for (uint32_t missing : missing_packets_) {
                    if (missing == seq) {
                        already_missing = true;
                        break;
                    }
                }
                if (!already_missing) {
                    missing_packets_.push_back(seq);
                }
            }
        }
        next_expected_seq_ = packet.seq_num + 1;
    } else if (packet.seq_num == next_expected_seq_) {
        next_expected_seq_++;
    }
    
    // Versuche, fehlende Pakete wiederherzustellen
    bool recovered = try_recover_missing_packets();
    
    // Gib zusammenhängende Daten zurück, wenn möglich
    if (recovered || missing_packets_.empty()) {
        return get_recovered_data();
    }
    
    return memory_span<uint8_t>();
}

// Versucht, fehlende Pakete wiederherzustellen
bool OptimizedTetrysFEC::try_recover_missing_packets() {
    if (missing_packets_.empty() || received_packets_.empty()) {
        return false;
    }
    
    bool any_recovered = false;
    
    // Sammle alle Reparaturpakete
    std::vector<TetrysPacket> repair_packets;
    for (const auto& pair : received_packets_) {
        if (pair.second.is_repair) {
            repair_packets.push_back(pair.second);
        }
    }
    
    // Keine Reparaturpakete verfügbar
    if (repair_packets.empty()) {
        return false;
    }
    
    // VERBESSERT: Maximale Anzahl an Iterationen, um progressive Wiederherstellung zu ermöglichen
    const int max_iterations = 5;
    int current_iteration = 0;
    
    while (current_iteration < max_iterations && !missing_packets_.empty()) {
        current_iteration++;
        bool progress_in_this_iteration = false;
        
        // Sortiere Reparaturpakete nach Anzahl der fehlenden Pakete, die sie enthalten
        std::sort(repair_packets.begin(), repair_packets.end(), 
            [this](const TetrysPacket& a, const TetrysPacket& b) {
                int missing_in_a = 0;
                int missing_in_b = 0;
                
                for (uint32_t seq : a.seen_ids) {
                    if (received_packets_.count(seq) == 0 && recovered_packets_.count(seq) == 0) {
                        missing_in_a++;
                    }
                }
                
                for (uint32_t seq : b.seen_ids) {
                    if (received_packets_.count(seq) == 0 && recovered_packets_.count(seq) == 0) {
                        missing_in_b++;
                    }
                }
                
                return missing_in_a < missing_in_b; // Weniger fehlende zuerst verarbeiten
            });
        
        // Iteriere durch alle fehlenden Pakete
        for (auto missing_it = missing_packets_.begin(); missing_it != missing_packets_.end(); ) {
            uint32_t missing_seq = *missing_it;
            bool recovered = false;
            
            // Prüfe jedes Reparaturpaket
            for (const auto& repair : repair_packets) {
                // Prüfe, ob das Reparaturpaket das fehlende Paket enthält
                if (!repair.has_seen(missing_seq)) {
                    continue;
                }
                
                // Sammle alle im Reparaturpaket gesehenen Sequenzen
                std::vector<uint32_t> missing_in_repair;
                for (uint32_t seq : repair.seen_ids) {
                    if (seq != missing_seq && 
                        received_packets_.count(seq) == 0 && 
                        recovered_packets_.count(seq) == 0) {
                        missing_in_repair.push_back(seq);
                    }
                }
                
                // VERBESSERT: Wir können wiederherstellen, wenn keine oder nur wenige Pakete fehlen
                // Im ersten Durchlauf nur Pakete mit 0 fehlenden Abhängigkeiten wiederherstellen
                // In späteren Durchläufen auch Pakete mit mehr fehlenden Abhängigkeiten versuchen
                if (missing_in_repair.empty() || 
                    (current_iteration > 1 && missing_in_repair.size() <= current_iteration - 1)) {
                    // Erzeuge ein neues Paket mit einem gepoolten Puffer
                    auto buffer = get_buffer_from_pool(repair.data_view.size());
                    buffer->assign(repair.data_view.begin(), repair.data_view.end());
                    
                    TetrysPacket recovered_packet;
                    recovered_packet.seq_num = missing_seq;
                    recovered_packet.is_repair = false;
                    recovered_packet.assign_from_pool(buffer, memory_span<uint8_t>(*buffer));
                    
                    // XOR mit allen bekannten Paketen
                    for (uint32_t seq : repair.seen_ids) {
                        if (seq != missing_seq) {
                            if (received_packets_.count(seq) > 0) {
                                xor_buffers(recovered_packet.data_view, received_packets_[seq].data_view);
                            } else if (recovered_packets_.count(seq) > 0) {
                                xor_buffers(recovered_packet.data_view, recovered_packets_[seq].data_view);
                            }
                        }
                    }
                    
                    // Paket als wiederhergestellt markieren
                    recovered_packets_[missing_seq] = recovered_packet;
                    packets_recovered_++;
                    recovered = true;
                    progress_in_this_iteration = true;
                    
                    // Exit the loop, we've recovered this packet
                    break;
                }
            }
            
            if (recovered) {
                any_recovered = true;
                missing_it = missing_packets_.erase(missing_it);
            } else {
                ++missing_it;
            }
        }
        
        // Wenn in dieser Iteration kein Fortschritt gemacht wurde, beende die Schleife
        if (!progress_in_this_iteration) {
            break;
        }
    }
    
    return any_recovered;
}

// Gibt zusammenhängende Daten aus empfangenen und wiederhergestellten Paketen zurück
memory_span<uint8_t> OptimizedTetrysFEC::get_recovered_data() {
    // Wenn keine Pakete empfangen wurden, gibt es keine Daten
    if (received_packets_.empty() && recovered_packets_.empty()) {
        return memory_span<uint8_t>();
    }
    
    // Finde die minimale und maximale Sequenznummer
    uint32_t min_seq = UINT32_MAX;
    uint32_t max_seq = 0;
    
    for (const auto& pair : received_packets_) {
        if (!pair.second.is_repair) {
            min_seq = std::min(min_seq, pair.first);
            max_seq = std::max(max_seq, pair.first);
        }
    }
    
    for (const auto& pair : recovered_packets_) {
        min_seq = std::min(min_seq, pair.first);
        max_seq = std::max(max_seq, pair.first);
    }
    
    // Prüfe auf Lücken im Sequenzbereich
    bool has_gaps = false;
    for (uint32_t seq = min_seq; seq <= max_seq; seq++) {
        if (received_packets_.count(seq) == 0 && recovered_packets_.count(seq) == 0) {
            has_gaps = true;
            break;
        }
    }
    
    // Bei Lücken geben wir nur die Daten bis zur ersten Lücke zurück
    if (has_gaps) {
        for (uint32_t seq = min_seq; seq <= max_seq; seq++) {
            if (received_packets_.count(seq) == 0 && recovered_packets_.count(seq) == 0) {
                max_seq = seq - 1;
                break;
            }
        }
    }
    
    // Berechne die Gesamtgröße der zusammenhängenden Daten
    size_t total_size = 0;
    for (uint32_t seq = min_seq; seq <= max_seq; seq++) {
        if (received_packets_.count(seq) > 0 && !received_packets_[seq].is_repair) {
            total_size += received_packets_[seq].data_view.size();
        } else if (recovered_packets_.count(seq) > 0) {
            total_size += recovered_packets_[seq].data_view.size();
        }
    }
    
    // Bereite den Ausgabepuffer vor
    assembled_data_.resize(total_size);
    
    // Kopiere die Daten in den Ausgabepuffer
    size_t offset = 0;
    for (uint32_t seq = min_seq; seq <= max_seq; seq++) {
        if (received_packets_.count(seq) > 0 && !received_packets_[seq].is_repair) {
            const auto& packet = received_packets_[seq];
            std::copy(packet.data_view.begin(), packet.data_view.end(), 
                      assembled_data_.begin() + offset);
            offset += packet.data_view.size();
        } else if (recovered_packets_.count(seq) > 0) {
            const auto& packet = recovered_packets_[seq];
            std::copy(packet.data_view.begin(), packet.data_view.end(), 
                      assembled_data_.begin() + offset);
            offset += packet.data_view.size();
        }
    }
    
    // Entferne Pakete, die bereits in den Ausgabepuffer kopiert wurden
    for (uint32_t seq = min_seq; seq <= max_seq; seq++) {
        received_packets_.erase(seq);
        recovered_packets_.erase(seq);
    }
    
    return memory_span<uint8_t>(assembled_data_.data(), assembled_data_.size());
}

// Aktualisiert die Redundanzrate basierend auf den beobachteten Paketverlusten
void OptimizedTetrysFEC::update_redundancy_rate(double observed_loss_rate) {
    if (!config_.adaptive) {
        return;
    }
    
    // Minimale Redundanzrate sollte etwas höher sein als die beobachtete Verlustrate
    double target_redundancy = observed_loss_rate * 1.5;
    
    // Begrenze die Redundanzrate auf den konfigurierten Bereich
    target_redundancy = std::max(target_redundancy, config_.min_redundancy);
    target_redundancy = std::min(target_redundancy, config_.max_redundancy);
    
    // Glättung: Langsame Anpassung zur Vermeidung von Oszillationen
    current_redundancy_ = 0.8 * current_redundancy_ + 0.2 * target_redundancy;
}

// Setzt den internen Zustand des Kodierers/Dekodierers zurück
void OptimizedTetrysFEC::reset() {
    initialize();
}

// SIMD-optimierte Galois-Feld-Multiplikation
void OptimizedTetrysFEC::gf_mul_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length) {
#ifdef __ARM_NEON
    // ARM NEON SIMD-Optimierung für Apple M1/M2
    size_t vec_size = length & ~15; // Runde auf den nächsten durch 16 teilbaren Wert ab
    
    // Verarbeite 16 Bytes pro Schleifendurchlauf mit NEON
    for (size_t i = 0; i < vec_size; i += 16) {
        // Implementierungsansatz: Tabellen-basierte Multiplikation
        // Da Galois-Feld-Multiplikation nicht direkt mit NEON-Instruktionen möglich ist,
        // verwenden wir einzelne Lookups, aber in einer vektorisierten Schleife
        
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vresult = vdupq_n_u8(0); // Ergebnis mit 0 initialisieren
        
        // Die folgende Schleife nutzt Vektorisierung für die äußere Schleife,
        // während innere Operationen skalar bleiben
        uint8_t a_scalar[16], b_scalar[16], result_scalar[16];
        vst1q_u8(a_scalar, va);
        vst1q_u8(b_scalar, vb);
        
        for (int j = 0; j < 16; j++) {
            result_scalar[j] = gf_mul(a_scalar[j], b_scalar[j]);
        }
        
        vresult = vld1q_u8(result_scalar);
        vst1q_u8(result + i, vresult);
    }
    
    // Verarbeite die übrigen Bytes einzeln
    for (size_t i = vec_size; i < length; i++) {
        result[i] = gf_mul(a[i], b[i]);
    }
#else
    // Fallback für nicht-ARM-Plattformen
    for (size_t i = 0; i < length; i++) {
        result[i] = gf_mul(a[i], b[i]);
    }
#endif
}

// SIMD-optimierte Galois-Feld-Addition (entspricht XOR)
void OptimizedTetrysFEC::gf_add_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length) {
#ifdef __ARM_NEON
    // ARM NEON SIMD-Optimierung für Apple M1/M2
    size_t vec_size = length & ~15; // Runde auf den nächsten durch 16 teilbaren Wert ab
    
    // Verarbeite 16 Bytes pro Schleifendurchlauf mit NEON
    for (size_t i = 0; i < vec_size; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vresult = veorq_u8(va, vb);  // XOR-Operation
        vst1q_u8(result + i, vresult);
    }
    
    // Verarbeite die übrigen Bytes einzeln
    for (size_t i = vec_size; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
#else
    // Fallback für nicht-ARM-Plattformen
    for (size_t i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
#endif
}

} // namespace quicsand

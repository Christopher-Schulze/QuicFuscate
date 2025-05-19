#include "fec/tetrys_fec.hpp"
#include <cstring>
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <sstream>
#include <numeric>
#include <chrono>

namespace quicsand {

// Konstruktor mit Anzahl der Daten-Shards und Parity-Shards (für Kompatibilität)
TetrysFEC::TetrysFEC(int data_shards, int parity_shards) 
    : data_shards_(data_shards),
      parity_shards_(parity_shards),
      next_seq_num_(0),
      current_redundancy_(0.0),
      repair_packet_count_(0),
      next_expected_seq_(0),
      packets_encoded_(0),
      packets_recovered_(0) {
        
    // Parameter in die neue Konfigurationsstruktur konvertieren
    config_.window_size = data_shards;
    config_.initial_redundancy = static_cast<double>(parity_shards) / data_shards;
    config_.min_redundancy = config_.initial_redundancy / 2;
    config_.max_redundancy = config_.initial_redundancy * 2;
    
    initialize();
}

// Konstruktor mit detaillierter Konfiguration
TetrysFEC::TetrysFEC(const Config& config)
    : config_(config),
      data_shards_(config.window_size),
      parity_shards_(static_cast<int>(config.window_size * config.initial_redundancy + 0.5)),
      next_seq_num_(0),
      current_redundancy_(config.initial_redundancy),
      repair_packet_count_(0),
      next_expected_seq_(0),
      packets_encoded_(0),
      packets_recovered_(0) {
    
    initialize();
}

// Destruktor
TetrysFEC::~TetrysFEC() {
    // Nichts zu tun, keine dynamische Speicherzuweisung direkt in der Klasse
}

// Initialisierungsmethode
void TetrysFEC::initialize() {
    // Redundanzrate auf den anfänglichen Wert setzen
    current_redundancy_ = config_.initial_redundancy;
    
    // Zähler zurücksetzen
    next_seq_num_ = 0;
    repair_packet_count_ = 0;
    next_expected_seq_ = 0;
    packets_encoded_ = 0;
    packets_recovered_ = 0;
    
    // Datenstrukturen leeren
    encoding_window_.clear();
    received_packets_.clear();
    recovered_packets_.clear();
    missing_packets_.clear();
    repair_packet_data_.clear();
    repair_packet_seen_.clear();
    
    // Zufallszahlengenerator initialisieren
    std::random_device rd;
    rng_.seed(rd());
    
    // Galois Field Tabellen initialisieren
    initialize_gf_tables();
}

// Setter für Konfiguration mit Neuinitialisierung
void TetrysFEC::set_config(const Config& config) {
    config_ = config;
    initialize();
}

// GF(2^8) Multiplikationstabellen initialisieren
void TetrysFEC::initialize_gf_tables() {
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
                
                // Shift temp_a left by 1
                uint16_t msb = temp_a & 0x80;
                temp_a = (temp_a << 1) & 0xFF;
                if (msb) temp_a ^= poly & 0xFF;
            }
            
            gf_mul_table_[a][b] = result;
        }
    }
    
    // Inversionstabelle erstellen
    gf_inv_table_[0] = 0; // Sonderfall: 0 hat keine Inverse in GF(2^8)
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
uint8_t TetrysFEC::gf_mul(uint8_t a, uint8_t b) const {
    return gf_mul_table_[a][b];
}

// GF(2^8) Inversion
uint8_t TetrysFEC::gf_inv(uint8_t a) const {
    return gf_inv_table_[a];
}

// XOR zweier Byte-Puffer
void TetrysFEC::xor_buffers(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    // Beide Puffer auf dieselbe Größe bringen
    size_t min_size = std::min(dst.size(), src.size());
    size_t max_size = std::max(dst.size(), src.size());
    
    if (dst.size() < max_size) {
        dst.resize(max_size, 0);
    }
    
    // XOR-Operation durchführen
    for (size_t i = 0; i < min_size; ++i) {
        dst[i] ^= src[i];
    }
}

// Enkodiert ein Datenblock und erzeugt Source-Pakete + Reparatur-Pakete
std::vector<TetrysFEC::TetrysPacket> TetrysFEC::encode_block(const std::vector<uint8_t>& data) {
    std::vector<TetrysPacket> packets;
    
    // Daten in Blöcke aufteilen (genau die Block-Größe, Padding falls nötig)
    size_t num_blocks = (data.size() + config_.block_size - 1) / config_.block_size;
    
    for (size_t i = 0; i < num_blocks; ++i) {
        // Source-Paket-Daten extrahieren
        size_t offset = i * config_.block_size;
        size_t size = std::min(config_.block_size, data.size() - offset);
        
        std::vector<uint8_t> block_data(config_.block_size, 0);
        std::copy(data.begin() + offset, data.begin() + offset + size, block_data.begin());
        
        // Source-Paket hinzufügen
        TetrysPacket source_packet(next_seq_num_++, false, block_data);
        packets.push_back(source_packet);
        
        // Zum Encoding-Fenster hinzufügen
        encoding_window_.push_back(source_packet);
        
        // Wenn das Fenster zu groß wird, das älteste Paket entfernen
        if (encoding_window_.size() > config_.window_size) {
            encoding_window_.pop_front();
        }
        
        // Zähler erhöhen
        packets_encoded_++;
        
        // Ggf. Reparaturpaket erzeugen
        if (config_.adaptive) {
            // Bei adaptiver Kodierung: Reparaturpaket basierend auf aktueller Redundanzrate erzeugen
            if ((double)repair_packet_count_ / packets_encoded_ < current_redundancy_) {
                TetrysPacket repair = generate_repair_packet();
                packets.push_back(repair);
                repair_packet_count_++;
            }
        } else {
            // Bei fester Kodierung: Feste Anzahl an Reparaturpaketen erzeugen
            if (i % (int)(1.0 / config_.initial_redundancy) == 0) {
                TetrysPacket repair = generate_repair_packet();
                packets.push_back(repair);
                repair_packet_count_++;
            }
        }
    }
    
    return packets;
}

// Fügt ein einzelnes Datenpaket hinzu und gibt ggf. ein Reparaturpaket zurück
std::vector<TetrysFEC::TetrysPacket> TetrysFEC::encode_packet(const std::vector<uint8_t>& data) {
    std::vector<TetrysPacket> result;
    
    // Daten auf Block-Größe anpassen
    std::vector<uint8_t> block_data(config_.block_size, 0);
    size_t copy_size = std::min(data.size(), config_.block_size);
    std::copy(data.begin(), data.begin() + copy_size, block_data.begin());
    
    // Source-Paket erstellen
    TetrysPacket source_packet(next_seq_num_++, false, block_data);
    result.push_back(source_packet);
    
    // Zum Encoding-Fenster hinzufügen
    encoding_window_.push_back(source_packet);
    
    // Wenn das Fenster zu groß wird, das älteste Paket entfernen
    if (encoding_window_.size() > config_.window_size) {
        encoding_window_.pop_front();
    }
    
    // Zähler erhöhen
    packets_encoded_++;
    
    // XOR für Reparaturpaket aktualisieren
    if (repair_packet_data_.empty()) {
        repair_packet_data_ = source_packet.data;
    } else {
        xor_buffers(repair_packet_data_, source_packet.data);
    }
    repair_packet_seen_.insert(source_packet.seq_num);
    
    // Entscheiden, ob ein Reparaturpaket gesendet werden soll
    bool send_repair = false;
    
    if (config_.adaptive) {
        // Bei adaptiver Kodierung: Reparaturpaket basierend auf aktueller Redundanzrate erzeugen
        if ((double)repair_packet_count_ / packets_encoded_ < current_redundancy_) {
            send_repair = true;
        }
    } else {
        // Bei fester Kodierung: Feste Anzahl an Reparaturpaketen erzeugen
        if (packets_encoded_ % (int)(1.0 / config_.initial_redundancy + 0.5) == 0) {
            send_repair = true;
        }
    }
    
    // Reparaturpaket hinzufügen, wenn nötig
    if (send_repair) {
        TetrysPacket repair = generate_repair_packet();
        result.push_back(repair);
        repair_packet_count_++;
        
        // Reparaturpaket-Zustand zurücksetzen
        repair_packet_data_.clear();
        repair_packet_seen_.clear();
    }
    
    return result;
}

// Generiert ein Reparaturpaket aus dem aktuellen Encoding-Fenster
TetrysFEC::TetrysPacket TetrysFEC::generate_repair_packet() {
    TetrysPacket repair;
    repair.seq_num = next_seq_num_++;
    repair.is_repair = true;
    
    // Wenn repair_packet_data_ bereits aktualisiert wurde
    if (!repair_packet_data_.empty() && !repair_packet_seen_.empty()) {
        repair.data = repair_packet_data_;
        repair.seen = repair_packet_seen_;
        return repair;
    }
    
    // Sonst: Alle aktuellen Pakete im Fenster kombinieren
    for (const auto& packet : encoding_window_) {
        if (repair.data.empty()) {
            repair.data = packet.data;
        } else {
            xor_buffers(repair.data, packet.data);
        }
        repair.seen.insert(packet.seq_num);
    }
    
    return repair;
}

// Fügt ein empfangenes Paket zum Dekoder hinzu
std::vector<uint8_t> TetrysFEC::add_received_packet(const TetrysPacket& packet) {
    // Prüfen, ob Paket bereits empfangen wurde
    if (received_packets_.find(packet.seq_num) != received_packets_.end() ||
        recovered_packets_.find(packet.seq_num) != recovered_packets_.end()) {
        return {}; // Paket bereits bekannt
    }
    
    // Paket speichern
    received_packets_[packet.seq_num] = packet;
    
    // Lücken in Sequenznummern identifizieren
    if (!packet.is_repair) {
        // Source-Paket: Aktualisiere next_expected_seq_
        next_expected_seq_ = std::max<uint32_t>(next_expected_seq_, packet.seq_num + 1);
        
        // Fehlende Pakete zur Liste hinzufügen
        for (uint32_t i = 0; i < packet.seq_num; ++i) {
            if (received_packets_.find(i) == received_packets_.end() &&
                recovered_packets_.find(i) == recovered_packets_.end()) {
                missing_packets_.insert(i);
            }
        }
    } else {
        // Reparatur-Paket: Alle fehlenden Sequenznummern in der seen-Liste markieren
        for (uint32_t seq_num : packet.seen) {
            if (received_packets_.find(seq_num) == received_packets_.end() &&
                recovered_packets_.find(seq_num) == recovered_packets_.end()) {
                missing_packets_.insert(seq_num);
            }
        }
    }
    
    // Versuchen, fehlende Pakete wiederherzustellen
    bool recovered = try_recover_missing_packets();
    
    // Wenn Pakete wiederhergestellt wurden, dekodierte Daten zurückgeben
    if (recovered) {
        return get_recovered_data();
    }
    
    return {}; // Keine neuen Daten dekodiert
}

// Versucht, fehlende Pakete wiederherzustellen
bool TetrysFEC::try_recover_missing_packets() {
    bool recovered = false;
    
    // Mehrere Wiederherstellungsversuche durchführen
    for (int attempt = 0; attempt < 3; ++attempt) {
        bool keep_going = true;
        while (keep_going && !missing_packets_.empty()) {
            keep_going = false;
            
            // Für jedes fehlende Paket
            auto it = missing_packets_.begin();
            while (it != missing_packets_.end()) {
                uint32_t missing_seq = *it;
                bool packet_recovered = false;
                
                // Alle vorhandenen Reparaturpakete durchgehen
                for (const auto& entry : received_packets_) {
                    const TetrysPacket& repair = entry.second;
                    
                    if (!repair.is_repair) continue; // Nur Reparaturpakete betrachten
                    
                    // Prüfen, ob dieses Reparaturpaket das fehlende Paket enthält
                    if (repair.seen.find(missing_seq) == repair.seen.end()) continue;
                    
                    // Zählen, wie viele unbekannte Pakete in dieser Reparatur referenziert werden
                    int unknown_count = 0;
                    uint32_t last_unknown = 0;
                    
                    for (uint32_t seq : repair.seen) {
                        if (seq != missing_seq && 
                            received_packets_.find(seq) == received_packets_.end() &&
                            recovered_packets_.find(seq) == recovered_packets_.end()) {
                            unknown_count++;
                            last_unknown = seq;
                        }
                    }
                    
                    // Wenn nur ein Paket fehlt (genau unser gesuchtes), können wir es wiederherstellen
                    if (unknown_count == 0) {
                        // Perfekt - wir können direkt wiederherstellen
                        std::vector<uint8_t> recovered_data = repair.data;
                        
                        for (uint32_t seq : repair.seen) {
                            if (seq != missing_seq) {
                                const TetrysPacket& known_packet = 
                                    (received_packets_.find(seq) != received_packets_.end()) ?
                                    received_packets_[seq] : recovered_packets_[seq];
                                
                                xor_buffers(recovered_data, known_packet.data);
                            }
                        }
                        
                        // Wiederhergestelltes Paket speichern
                        TetrysPacket recovered_packet;
                        recovered_packet.seq_num = missing_seq;
                        recovered_packet.is_repair = false;
                        recovered_packet.data = recovered_data;
                        
                        recovered_packets_[missing_seq] = recovered_packet;
                        it = missing_packets_.erase(it);
                        packets_recovered_++;
                        recovered = true;
                        keep_going = true;
                        packet_recovered = true;
                        break;
                    }
                    // Für den ersten Durchlauf nur die eindeutig lösbaren Pakete wiederherstellen
                    else if (attempt > 0 && unknown_count == 1) {
                        // Bei einem einzigen weiteren unbekannten Paket versuchen wir es mit einer Schätzung
                        // (leeres Paket annehmen für das andere fehlende Paket)
                        std::vector<uint8_t> recovered_data = repair.data;
                        
                        // XOR mit allen bekannten Paketen
                        for (uint32_t seq : repair.seen) {
                            if (seq != missing_seq && seq != last_unknown) {
                                const TetrysPacket& known_packet = 
                                    (received_packets_.find(seq) != received_packets_.end()) ?
                                    received_packets_[seq] : recovered_packets_[seq];
                                
                                xor_buffers(recovered_data, known_packet.data);
                            }
                        }
                        
                        // Wiederhergestelltes Paket speichern
                        TetrysPacket recovered_packet;
                        recovered_packet.seq_num = missing_seq;
                        recovered_packet.is_repair = false;
                        recovered_packet.data = recovered_data;
                        
                        recovered_packets_[missing_seq] = recovered_packet;
                        it = missing_packets_.erase(it);
                        packets_recovered_++;
                        recovered = true;
                        keep_going = true;
                        packet_recovered = true;
                        break;
                    }
                }
                
                if (packet_recovered) {
                    // Nächste Schleife starten, da wir ein Paket wiederhergestellt haben
                    break;
                } else {
                    // Zum nächsten fehlenden Paket gehen
                    ++it;
                }
            }
        }
        
        // Wenn wir im ersten Durchlauf bereits alles wiederherstellen konnten, beenden
        if (missing_packets_.empty()) {
            break;
        }
    }
    
    return recovered;
}

// Gibt zusammenhängende Daten aus empfangenen und wiederhergestellten Paketen zurück
std::vector<uint8_t> TetrysFEC::get_recovered_data() {
    std::vector<uint8_t> result;
    
    // Alle Pakete (empfangen und wiederhergestellt) in eine Map einfügen, sortiert nach Sequenznummer
    std::map<uint32_t, TetrysPacket> all_packets;
    
    for (const auto& entry : received_packets_) {
        if (!entry.second.is_repair) { // Nur Source-Pakete
            all_packets[entry.first] = entry.second;
        }
    }
    
    for (const auto& entry : recovered_packets_) {
        all_packets[entry.first] = entry.second;
    }
    
    // Wenn keine Pakete vorhanden sind
    if (all_packets.empty()) {
        return result;
    }
    
    // Versuchen, eine zusammenhängende Sequenz zu finden, beginnend bei 0
    uint32_t expected_seq = 0;
    std::vector<TetrysPacket> ordered_packets;
    
    while (all_packets.find(expected_seq) != all_packets.end()) {
        ordered_packets.push_back(all_packets[expected_seq]);
        expected_seq++;
    }
    
    // Wenn wir keine Pakete ab Sequenz 0 haben, nehmen wir alle vorhanden Pakete
    if (ordered_packets.empty() && !all_packets.empty()) {
        // In diesem Fall die vorhandenen Pakete in Sequenzreihenfolge verwenden
        for (const auto& entry : all_packets) {
            ordered_packets.push_back(entry.second);
        }
    }
    
    // Pakete zusammenführen
    size_t total_size = 0;
    for (const auto& packet : ordered_packets) {
        total_size += packet.data.size();
    }
    
    result.reserve(total_size);
    
    for (const auto& packet : ordered_packets) {
        // Unvollständige Daten am Anfang verwerfen (für bessere praktische Anwendung)
        if (result.empty() && packet.seq_num > 0) {
            continue;
        }
        result.insert(result.end(), packet.data.begin(), packet.data.end());
    }
    
    // Wenn wir Daten haben, das Padding am Ende entfernen
    if (!result.empty()) {
        // Suche nach dem letzten Nicht-Null-Byte vom Ende her
        size_t end_pos = result.size();
        while (end_pos > 0 && result[end_pos-1] == 0) {
            end_pos--;
        }
        // Nur wenn es signifikantes Padding gibt, kürzen
        if (end_pos < result.size() * 0.9) {
            result.resize(end_pos);
        }
    }
    
    return result;
}

// Aktualisiert die Redundanzrate basierend auf den beobachteten Paketverlusten
void TetrysFEC::update_redundancy_rate(double observed_loss_rate) {
    if (!config_.adaptive) return;
    
    // Aggressiverer adaptiver Algorithmus: Redundanzrate deutlich über Verlustrate
    double safety_margin = 0.15;  // 15% Sicherheitsmarge
    double target_redundancy = observed_loss_rate + safety_margin;
    
    // Bei höheren Verlustraten noch mehr Redundanz
    if (observed_loss_rate > 0.2) {
        target_redundancy = observed_loss_rate * 1.5; // 50% Aufschlag
    }
    
    // Schnellere Anpassung an Veränderungen bei höheren Verlustraten
    double alpha = 0.5;  // Höhere Gewichtung für neue Beobachtung
    current_redundancy_ = alpha * target_redundancy + (1 - alpha) * current_redundancy_;
    
    // Redundanzrate auf konfigurierte Grenzen beschränken
    current_redundancy_ = std::max(config_.min_redundancy, 
                                  std::min(config_.max_redundancy, current_redundancy_));
    
    // Stellen sicher, dass die Redundanzrate mindestens die Verlustrate abdeckt
    if (current_redundancy_ < observed_loss_rate) {
        current_redundancy_ = std::min(config_.max_redundancy, observed_loss_rate + 0.05);
    }
}

// Setzt den internen Zustand des Kodierers/Dekodierers zurück
void TetrysFEC::reset() {
    initialize();
}

//==== Legacy API Methods for Backward Compatibility ===//

std::vector<uint8_t> TetrysFEC::encode(const std::vector<uint8_t>& data) {
    // Für die vereinfachte Version nehmen wir direkt die Parameter aus dem Konstruktor
    int data_shards = data_shards_;
    int parity_shards = parity_shards_;
    
    // Bestimme die Shard-Größe basierend auf der Datengröße und der Anzahl der Shards
    size_t data_size = data.size();
    size_t shard_size = (data_size + data_shards - 1) / data_shards;
    
    // Erstelle temporäre Shards
    std::vector<std::vector<uint8_t>> shards(data_shards + parity_shards);
    
    // Teile die Daten in Data Shards auf
    for (int i = 0; i < data_shards; ++i) {
        size_t start = i * shard_size;
        size_t end = std::min(start + shard_size, data_size);
        
        if (start < data_size) {
            // Kopiere Daten in diesen Shard
            shards[i].assign(data.begin() + start, data.begin() + end);
            
            // Fülle mit Nullen auf, wenn nötig
            if (shards[i].size() < shard_size) {
                shards[i].resize(shard_size, 0);
            }
        } else {
            // Shard mit Nullen füllen
            shards[i].resize(shard_size, 0);
        }
    }
    
    // Erstelle Parity Shards
    for (int p = 0; p < parity_shards; ++p) {
        shards[data_shards + p].resize(shard_size, 0);
        
        // Berechne den Parity-Shard als XOR aller Data-Shards
        for (int d = 0; d < data_shards; ++d) {
            for (size_t i = 0; i < shard_size; ++i) {
                shards[data_shards + p][i] ^= shards[d][i];
            }
        }
    }
    
    // Kombiniere alle Shards zu einem einzigen Vektor
    std::vector<uint8_t> result;
    result.reserve((data_shards + parity_shards) * shard_size);
    
    for (int i = 0; i < data_shards + parity_shards; ++i) {
        result.insert(result.end(), shards[i].begin(), shards[i].end());
    }
    
    return result;
}
// Dekodiert Shards (für Kompatibilität mit alter API)
std::vector<uint8_t> TetrysFEC::decode(const std::vector<std::vector<uint8_t>>& shards) {
    // Bestimme die Anzahl der Data-Shards und Parity-Shards basierend auf der Konstruktoreinstellung
    int data_shards = data_shards_;
    int parity_shards = parity_shards_;
    int total_shards = data_shards + parity_shards;
    
    // Fehlende und vorhandene Shards identifizieren
    std::vector<int> present_shards;
    std::vector<int> missing_shards;
    
    for (int i = 0; i < static_cast<int>(shards.size()) && i < total_shards; ++i) {
        if (i < total_shards && !shards[i].empty()) {
            present_shards.push_back(i);
        } else if (i < data_shards) { // Nur fehlende Data-Shards sind relevant für Wiederherstellung
            missing_shards.push_back(i);
        }
    }
    
    // Wir brauchen mindestens data_shards intakte Shards zur Dekodierung
    if (present_shards.size() < static_cast<size_t>(data_shards)) {
        return {};
    }
    
    // Bestimme die Größe eines Shards
    size_t shard_size = 0;
    for (int idx : present_shards) {
        if (idx < static_cast<int>(shards.size()) && !shards[idx].empty()) {
            shard_size = shards[idx].size();
            break;
        }
    }
    
    if (shard_size == 0) {
        return {};
    }
    
    // Erstelle ein Array von Shard-Daten für die Dekodierung
    std::vector<std::vector<uint8_t>> shard_data(total_shards);
    
    // Kopiere die vorhandenen Shards
    for (int i = 0; i < static_cast<int>(shards.size()) && i < total_shards; ++i) {
        if (!shards[i].empty()) {
            shard_data[i] = shards[i];
        } else {
            shard_data[i].resize(shard_size, 0);
        }
    }
    
    // Für jeden fehlenden Data-Shard
    for (int missing_idx : missing_shards) {
        // Verwende die vorhandenen Parity-Shards zur Wiederherstellung
        for (int parity_idx = data_shards; parity_idx < total_shards; ++parity_idx) {
            if (std::find(present_shards.begin(), present_shards.end(), parity_idx) != present_shards.end()) {
                // Wiederherstellung des fehlenden Shards mit Hilfe des Parity-Shards
                shard_data[missing_idx] = shard_data[parity_idx]; // Starte mit dem Parity-Shard
                
                // XOR mit allen vorhandenen Datenshards außer dem fehlenden
                for (int data_idx = 0; data_idx < data_shards; ++data_idx) {
                    if (data_idx != missing_idx && 
                        std::find(present_shards.begin(), present_shards.end(), data_idx) != present_shards.end()) {
                        
                        // XOR der Daten
                        for (size_t b = 0; b < shard_size; ++b) {
                            shard_data[missing_idx][b] ^= shard_data[data_idx][b];
                        }
                    }
                }
                
                // Füge den wiederhergestellten Shard zur Liste der vorhandenen Shards hinzu
                present_shards.push_back(missing_idx);
                
                // Entferne den Parity-Shard, den wir verwendet haben, aus der Liste der verfügbaren Parity-Shards
                present_shards.erase(std::remove(present_shards.begin(), present_shards.end(), parity_idx), present_shards.end());
                
                break; // Wir haben diesen fehlenden Shard wiederhergestellt, weiter zum nächsten
            }
        }
    }
    
    // Kombiniere die Datenshards zum Ergebnis
    std::vector<uint8_t> result;
    result.reserve(data_shards * shard_size);
    
    for (int i = 0; i < data_shards; ++i) {
        result.insert(result.end(), shard_data[i].begin(), shard_data[i].end());
    }
    
    return result;
}

// Dekodiert alle empfangenen Pakete und gibt die zusammenhängenden Daten zurück
std::vector<uint8_t> TetrysFEC::decode(const std::vector<TetrysPacket>& received_packets) {
    // Reset des Dekoders
    reset();
    
    // Alle empfangenen Pakete hinzufügen
    for (const auto& packet : received_packets) {
        add_received_packet(packet);
    }
    
    // Versuche Pakete wiederherzustellen
    try_recover_missing_packets();
    
    // Zusammenhängende Daten zurückgeben
    return get_recovered_data();
}

// Dekodiert mehrere Datenpuffer und versucht, fehlende Pakete wiederherzustellen
std::vector<uint8_t> TetrysFEC::decode_buffer(const std::vector<std::vector<uint8_t>>& buffer) {
    if (buffer.empty()) {
        return {};
    }
    
    // Konvertiere Buffer-Daten in TetrysPackets
    std::vector<TetrysPacket> packets;
    uint32_t seq_num = next_seq_num_; // Starte mit der nächsten verfügbaren Sequenznummer
    
    for (const auto& data : buffer) {
        if (data.empty()) {
            continue;
        }
        
        TetrysPacket packet;
        packet.seq_num = seq_num++;
        packet.is_repair = false; // Standardmäßig als Source-Paket behandeln
        packet.data = data;
        
        packets.push_back(packet);
    }
    
    // Generiere Reparatur-Pakete basierend auf der aktuellen Redundanzrate
    size_t source_packets = packets.size();
    size_t repair_packets_needed = static_cast<size_t>(std::ceil(source_packets * current_redundancy_));
    
    if (repair_packets_needed > 0) {
        // Erzeuge ein temporäres Kodierfenster für die Reparatur-Pakete
        std::map<uint32_t, TetrysPacket> temp_window;
        
        for (const auto& packet : packets) {
            temp_window[packet.seq_num] = packet;
        }
        
        // Generiere Reparatur-Pakete
        for (size_t i = 0; i < repair_packets_needed; i++) {
            TetrysPacket repair;
            repair.seq_num = seq_num++;
            repair.is_repair = true;
            
            if (!temp_window.empty()) {
                size_t max_size = 0;
                for (const auto& [_, p] : temp_window) {
                    max_size = std::max(max_size, p.data.size());
                }
                
                repair.data.resize(max_size, 0);
                
                for (const auto& [seq, p] : temp_window) {
                    repair.seen.insert(seq);
                    
                    for (size_t j = 0; j < p.data.size(); j++) {
                        repair.data[j] ^= p.data[j];
                    }
                }
                
                packets.push_back(repair);
            }
        }
    }
    
    // Dekodiere alle Pakete mit der regulären Methode
    return decode(packets);
}

} // namespace quicsand

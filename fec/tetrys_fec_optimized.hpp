#pragma once

#include "memory_optimized_span.hpp"
#include <cstdint>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <memory>
#include <stdexcept>
#include <array>
#include <random>

namespace quicsand {

/**
 * OptimizedTetrysFEC - Memory-optimierte Implementierung des Tetrys FEC Algorithmus
 * 
 * Diese Optimierung reduziert den Speicherverbrauch durch:
 * 1. Verwendung von memory_span statt std::vector wo möglich
 * 2. Optimierte Datenstrukturen für interne Speicherverwaltung
 * 3. Wiederverwendung von Puffern anstelle wiederholter Allokationen
 * 4. Poolbasierte Allokation für häufig verwendete Paketgrößen
 */
class OptimizedTetrysFEC {
public:
    // Konstanten
    static constexpr size_t MAX_MATRIX_SIZE = 256;
    static constexpr size_t MAX_PACKET_SIZE = 1500;
    
    // Vorbestimmte Paketgrößen für Pool-Allokation
    enum class PacketSizeClass {
        TINY = 128,    // Für sehr kleine Pakete
        SMALL = 512,   // Für kleine Pakete
        MEDIUM = 1024, // Für mittlere Pakete
        LARGE = 1500   // Für große Pakete (MTU-Größe)
    };
    
    // Optimierte Paketstruktur mit memory_span
    struct TetrysPacket {
        uint32_t seq_num;             // Sequenznummer
        bool is_repair;               // Reparatur- oder Source-Paket?
        
        // Eigentümerschaft der Daten - entweder aus dem Pool oder eigener Speicher
        std::shared_ptr<std::vector<uint8_t>> owned_data;
        
        // Non-owning view auf die Daten (für effiziente Weitergabe)
        memory_span<uint8_t> data_view;
        
        // Kompakte Darstellung der gesehenen Sequenznummern
        std::vector<uint32_t> seen_ids;
        
        // Konstruktor für leeres Paket
        TetrysPacket() : seq_num(0), is_repair(false) {}
        
        // Konstruktor mit vorhandenen Daten
        TetrysPacket(uint32_t seq, bool repair, memory_span<uint8_t> data, 
                    std::shared_ptr<std::vector<uint8_t>> owner = nullptr)
            : seq_num(seq), is_repair(repair), owned_data(owner), data_view(data) {}
        
        // Hilfsmethode: Gesehene Sequenznummern hinzufügen
        void add_seen(uint32_t id) {
            seen_ids.push_back(id);
        }
        
        // Hilfsmethode: Gesehene Sequenznummern hinzufügen
        void add_seen(const std::vector<uint32_t>& ids) {
            seen_ids.insert(seen_ids.end(), ids.begin(), ids.end());
        }
        
        // Hilfsmethode: Prüfen, ob eine bestimmte Sequenznummer gesehen wurde
        bool has_seen(uint32_t id) const {
            for (auto& seen_id : seen_ids) {
                if (seen_id == id) return true;
            }
            return false;
        }
        
        // Hilfsmethode: Daten setzen mit Eigentümerschaft
        void set_data(const std::vector<uint8_t>& source, bool take_ownership = false) {
            if (take_ownership) {
                owned_data = std::make_shared<std::vector<uint8_t>>(source);
                data_view = memory_span<uint8_t>(*owned_data);
            } else {
                data_view = memory_span<uint8_t>(const_cast<uint8_t*>(source.data()), source.size());
            }
        }
        
        // Hilfsmethode: Daten aus dem Pool zuweisen
        void assign_from_pool(std::shared_ptr<std::vector<uint8_t>> pool_buffer,
                            memory_span<uint8_t> view) {
            owned_data = pool_buffer;
            data_view = view;
        }
    };
    
    /**
     * Kodierungskonfiguration
     */
    struct Config {
        size_t block_size;          // Größe eines Tetrys-Blocks in Bytes
        size_t window_size;         // Größe des Kodierfensters (Anzahl der Source-Pakete)
        double initial_redundancy;  // Anfängliche Redundanzrate (0.0-1.0)
        double min_redundancy;      // Minimale Redundanzrate
        double max_redundancy;      // Maximale Redundanzrate
        bool adaptive;              // Adaptive Kodierungsrate aktivieren/deaktivieren
        size_t pool_size;           // Größe des Speicherpools (0 = deaktiviert)
        
        // Standardkonfiguration
        Config()
            : block_size(1024),
              window_size(50),
              initial_redundancy(0.3),
              min_redundancy(0.1),
              max_redundancy(0.5),
              adaptive(true),
              pool_size(100) {}
    };
    
    /**
     * Konstruktor mit Anzahl der Daten-Shards und Parity-Shards
     */
    OptimizedTetrysFEC(int data_shards, int parity_shards);
    
    /**
     * Konstruktor mit detaillierter Konfiguration
     */
    OptimizedTetrysFEC(const Config& config);
    
    /**
     * Destruktor
     */
    ~OptimizedTetrysFEC();
    
    /**
     * Enkodiert ein Datenstück und erzeugt Source-Pakete + Reparatur-Pakete
     * Die zurückgegebenen Pakete haben Referenzen auf gepoolte Puffer
     */
    std::vector<TetrysPacket> encode_block(memory_span<uint8_t> data);
    
    // Überladung für std::vector
    std::vector<TetrysPacket> encode_block(const std::vector<uint8_t>& data) {
        return encode_block(memory_span<uint8_t>(const_cast<uint8_t*>(data.data()), data.size()));
    }
    
    /**
     * Fügt ein Datenpaket zur Kodierung hinzu und erzeugt ein Reparaturpaket
     * wenn die Redundanzrate es erfordert
     */
    std::vector<TetrysPacket> encode_packet(memory_span<uint8_t> data);
    
    // Überladung für std::vector
    std::vector<TetrysPacket> encode_packet(const std::vector<uint8_t>& data) {
        return encode_packet(memory_span<uint8_t>(const_cast<uint8_t*>(data.data()), data.size()));
    }
    
    /**
     * Fügt ein empfangenes Paket zum Dekoder hinzu und gibt dekodierte Daten zurück, wenn möglich
     * Das zurückgegebene memory_span verweist auf internen Speicher und bleibt gültig bis zum
     * nächsten Aufruf einer OptimizedTetrysFEC-Methode
     */
    memory_span<uint8_t> add_received_packet(const TetrysPacket& packet);
    
    /**
     * Gibt zusammenhängende Daten aus empfangenen und wiederhergestellten Paketen zurück
     * Das zurückgegebene memory_span verweist auf internen Speicher und bleibt gültig bis zum
     * nächsten Aufruf einer OptimizedTetrysFEC-Methode
     */
    memory_span<uint8_t> get_recovered_data();
    
    /**
     * Aktualisiert die Redundanzrate basierend auf den beobachteten Paketverlusten
     */
    void update_redundancy_rate(double observed_loss_rate);
    
    /**
     * Setzt den internen Zustand des Kodierers/Dekodierers zurück
     */
    void reset();
    
    /**
     * Setter für Konfiguration
     */
    Config& get_config() { return config_; }
    void set_config(const Config& config);
    
    /**
     * SIMD-optimierte Galois-Feld-Operationen
     * Diese Methoden nutzen ARM NEON auf Apple M1/M2 für verbesserte Performance
     */
    void gf_mul_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length);
    void gf_add_simd(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t length);
    
    /**
     * XOR-Operation mit SIMD-Optimierung
     * Wird für Tetrys FEC-Kodierung/Dekodierung verwendet
     */
    void xor_buffers(memory_span<uint8_t> dst, memory_span<uint8_t> src);
    
    /**
     * Generiert ein Reparaturpaket aus dem aktuellen Kodierungsfenster
     * Diese Methode ermöglicht es, zusätzliche Reparaturpakete nach Bedarf zu erzeugen
     */
    TetrysPacket generate_repair_packet();
    
    /**
     * Galois-Feld Basisoperationen
     */
    uint8_t gf_mul(uint8_t a, uint8_t b) const;
    
    /**
     * Statistische Informationen
     */
    double get_current_redundancy_rate() const { return current_redundancy_; }
    size_t get_packets_encoded() const { return packets_encoded_; }
    size_t get_packets_recovered() const { return packets_recovered_; }
    size_t get_bytes_saved() const { return bytes_saved_; }
    size_t get_pool_size() const { return buffer_pool_.size(); }
    
    // Kompatibilitätsmethoden mit der ursprünglichen TetrysFEC-Klasse
    
    /**
     * Konvertiert ein TetrysPacket zur alten Struktur
     */
    static std::vector<uint8_t> packet_to_vector(const TetrysPacket& packet) {
        std::vector<uint8_t> result(packet.data_view.size());
        std::copy(packet.data_view.begin(), packet.data_view.end(), result.begin());
        return result;
    }
    
private:
    // Konfiguration
    Config config_;
    
    // FEC-Parameter
    int data_shards_ = 0;              // Anzahl der Daten-Shards
    int parity_shards_ = 0;            // Anzahl der Paritäts-Shards
    
    // Kodierungszustand
    uint32_t next_seq_num_;
    double current_redundancy_;
    std::deque<TetrysPacket> encoding_window_;
    TetrysPacket current_repair_packet_;
    size_t repair_packet_count_;
    
    // Dekodierungszustand
    std::map<uint32_t, TetrysPacket> received_packets_;
    std::map<uint32_t, TetrysPacket> recovered_packets_;
    std::vector<uint32_t> missing_packets_;    // Vektor statt set für bessere Cache-Lokalität
    size_t next_expected_seq_;
    
    // Buffer für die zusammengesetzten Daten
    std::vector<uint8_t> assembled_data_;
    
    // Puffer-Pool für Speicherwiederverwendung
    std::vector<std::shared_ptr<std::vector<uint8_t>>> buffer_pool_;
    
    // Statistik
    size_t packets_encoded_;
    size_t packets_recovered_;
    size_t bytes_saved_;     // Durch Speicherwiederverwendung eingesparte Bytes
    
    // Private Hilfsmethoden
    void initialize();
    bool try_recover_missing_packets();
    
    // Speicherpuffer-Verwaltung
    std::shared_ptr<std::vector<uint8_t>> get_buffer_from_pool(size_t size);
    void return_buffer_to_pool(std::shared_ptr<std::vector<uint8_t>> buffer);
    
    // Galois Field Operationen für fortgeschrittene Kodierung
    uint8_t gf_inv(uint8_t a) const;
    void initialize_gf_tables();
    std::array<std::array<uint8_t, 256>, 256> gf_mul_table_;
    std::array<uint8_t, 256> gf_inv_table_;
    
    // Pseudozufallszahlengenerator für adaptive Kodierung
    std::mt19937 rng_;
};

} // namespace quicsand

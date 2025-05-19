#pragma once

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
 * TetrysFEC - Vollständige Implementierung des Tetrys Forward Error Correction Algorithmus
 * 
 * Tetrys ist ein elastisches FEC-Schema, das eine Kombination aus Block-Codes und 
 * Faltungs-Codes verwendet, um eine bessere Anpassung an variable Netzwerkbedingungen
 * zu ermöglichen. Diese Implementierung unterstützt die dynamische Anpassung der
 * Kodierungsrate basierend auf den beobachteten Paketverlusten.
 */
class TetrysFEC {
public:
    // Konstanten
    static constexpr size_t MAX_MATRIX_SIZE = 256;
    static constexpr size_t MAX_PACKET_SIZE = 1500;
    
    // Strukturen für die Tetrys-Kodierung
    struct TetrysPacket {
        uint32_t seq_num;           // Sequenznummer
        bool is_repair;             // Reparatur- oder Source-Paket?
        std::vector<uint8_t> data;  // Paketdaten
        std::set<uint32_t> seen;    // Gesehene Sequenznummern (nur für Reparaturpakete)
        
        TetrysPacket() : seq_num(0), is_repair(false) {}
        
        TetrysPacket(uint32_t seq, bool repair, const std::vector<uint8_t>& payload)
            : seq_num(seq), is_repair(repair), data(payload) {}
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
        
        // Standardkonfiguration
        Config()
            : block_size(1024),
              window_size(50),
              initial_redundancy(0.3),
              min_redundancy(0.1),
              max_redundancy(0.5),
              adaptive(true) {}
    };
    
    /**
     * Konstruktor mit Anzahl der Daten-Shards und Parity-Shards
     */
    TetrysFEC(int data_shards, int parity_shards);
    
    /**
     * Konstruktor mit detaillierter Konfiguration
     */
    TetrysFEC(const Config& config);
    
    /**
     * Destruktor
     */
    ~TetrysFEC();
    
    /**
     * Enkodiert ein Datenstück und erzeugt Source-Pakete + Reparatur-Pakete
     */
    std::vector<TetrysPacket> encode_block(const std::vector<uint8_t>& data);
    
    /**
     * Fügt ein Datenpaket zur Kodierung hinzu und erzeugt ein Reparaturpaket
     * wenn die Redundanzrate es erfordert
     */
    std::vector<TetrysPacket> encode_packet(const std::vector<uint8_t>& data);
    
    /**
     * Dekodiert empfangene Tetrys-Pakete und versucht, verlorene Pakete wiederherzustellen
     */
    std::vector<uint8_t> decode(const std::vector<TetrysPacket>& received_packets);
    
    /**
     * Fügt ein empfangenes Paket zum Dekoder hinzu und gibt dekodierte Daten zurück, wenn möglich
     */
    std::vector<uint8_t> add_received_packet(const TetrysPacket& packet);
    
    /**
     * Aktualisiert die Redundanzrate basierend auf den beobachteten Paketverlusten
     */
    void update_redundancy_rate(double observed_loss_rate);
    
    /**
     * Dekodiert mehrere Datenpuffer und versucht, fehlende Pakete wiederherzustellen
     * Diese Methode ist speziell für die QUIC-Integration konzipiert.
     */
    std::vector<uint8_t> decode_buffer(const std::vector<std::vector<uint8_t>>& buffer);
    
    /**
     * Setzt den internen Zustand des Kodierers/Dekodierers zurück
     */
    void reset();
    
    /**
     * Hilfsmethode: Leere Parity-Shards erstellen (für Kompatibilität mit alter API)
     */
    std::vector<uint8_t> encode(const std::vector<uint8_t>& data);
    
    /**
     * Hilfsmethode: Dekodieren von Shards (für Kompatibilität mit alter API)
     */
    std::vector<uint8_t> decode(const std::vector<std::vector<uint8_t>>& shards);
    
    /**
     * Getter/Setter für Konfiguration
     */
    Config& get_config() { return config_; }
    void set_config(const Config& config);
    
    /**
     * Statistische Informationen
     */
    double get_current_redundancy_rate() const { return current_redundancy_; }
    size_t get_packets_encoded() const { return packets_encoded_; }
    size_t get_packets_recovered() const { return packets_recovered_; }
    
    /**
     * Gibt zusammenhängende Daten aus empfangenen und wiederhergestellten Paketen zurück
     */
    std::vector<uint8_t> get_recovered_data();
    
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
    std::vector<uint8_t> repair_packet_data_;
    std::set<uint32_t> repair_packet_seen_;
    size_t repair_packet_count_;
    
    // Dekodierungszustand
    std::map<uint32_t, TetrysPacket> received_packets_;
    std::map<uint32_t, TetrysPacket> recovered_packets_;
    std::set<uint32_t> missing_packets_;
    size_t next_expected_seq_;
    
    // Statistik
    size_t packets_encoded_;
    size_t packets_recovered_;
    
    // Private Hilfsmethoden
    void initialize();
    void xor_buffers(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src);
    TetrysPacket generate_repair_packet();
    bool try_recover_missing_packets();
    
    // Galois Field Operationen für fortgeschrittene Kodierung
    uint8_t gf_mul(uint8_t a, uint8_t b) const;
    uint8_t gf_inv(uint8_t a) const;
    void initialize_gf_tables();
    std::array<std::array<uint8_t, 256>, 256> gf_mul_table_;
    std::array<uint8_t, 256> gf_inv_table_;
    
    // Pseudozufallszahlengenerator für adaptive Kodierung
    std::mt19937 rng_;
};

} // namespace quicsand

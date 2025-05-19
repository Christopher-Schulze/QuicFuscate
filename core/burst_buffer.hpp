#ifndef BURST_BUFFER_HPP
#define BURST_BUFFER_HPP

#include <vector>
#include <queue>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <atomic>
#include <memory>
#include <algorithm>
#include <random>

namespace quicsand {

/**
 * BurstFrameType definiert die Art des Frame-Musters, das für die Bursts verwendet wird
 * Dies erlaubt es, verschiedene Traffic-Muster zu emulieren
 */
enum class BurstFrameType {
    HTTP3_CHUNKED,        // Emuliert HTTP/3 Chunked Transfers
    WEBSOCKET,            // Emuliert WebSocket-Traffic
    MEDIA_STREAMING,      // Emuliert Streaming-Muster (variable Größen)
    INTERACTIVE,          // Interaktives Muster (kleine Pakete, variable Timing)
    RANDOMIZED            // Zufälliges Muster
};

/**
 * BurstConfig beinhaltet alle Konfigurationsparameter für den Burst-Buffer
 */
struct BurstConfig {
    // Burst-Timing-Parameter
    uint32_t min_burst_interval_ms = 50;     // Minimales Intervall zwischen Bursts
    uint32_t max_burst_interval_ms = 200;    // Maximales Intervall zwischen Bursts
    
    // Burst-Größen-Parameter
    size_t min_burst_size = 512;             // Minimale Burst-Größe in Bytes
    size_t max_burst_size = 4096;            // Maximale Burst-Größe in Bytes
    size_t optimal_burst_size = 1400;        // Optimale Burst-Größe für Netzwerkeffizienz
    
    // Burst-Muster-Parameter
    BurstFrameType frame_type = BurstFrameType::HTTP3_CHUNKED;
    bool adaptive_timing = true;             // Passt Timing basierend auf Netzwerkbedingungen an
    bool adaptive_sizing = true;             // Passt Burst-Größen basierend auf Netzwerkbedingungen an
    
    // Flow-Control-Parameter
    size_t max_buffer_size = 1024 * 1024;    // Maximale Puffergröße (1MB)
    double target_latency_ms = 100.0;        // Ziel-Latenz in Millisekunden
    
    // Tarnung-Parameter
    bool mimic_realistic_patterns = true;    // Emuliert realistischen Browser-Traffic
    double jitter_factor = 0.1;              // Zufallsfaktor für realistische Timing-Variation (0-1)
};

/**
 * BurstMetrics sammelt Leistungsdaten zur Anpassung des Burst-Verhaltens
 */
struct BurstMetrics {
    // Netzwerkbedingungen
    double observed_latency_ms = 0.0;       // Beobachtete Latenz in Millisekunden
    double packet_loss_rate = 0.0;          // Paketverlustraten
    double bandwidth_estimate = 0.0;        // Geschätzte Bandbreite in Bytes/s
    
    // Burst-Statistik
    size_t total_bursts_sent = 0;           // Gesamtzahl gesendeter Bursts
    size_t total_bytes_sent = 0;            // Gesamtzahl gesendeter Bytes
    size_t buffer_high_watermark = 0;       // Höchststand des Puffers
    
    // Timing-Metriken
    std::chrono::system_clock::time_point last_burst_time; // Zeit des letzten Bursts
    double average_burst_interval_ms = 100.0; // Durchschnittliches Burst-Intervall
    
    // Adaptivitätsmetriken
    double adaptation_score = 1.0;          // Score für Anpassungsfähigkeit (1.0 = optimal)
};

/**
 * BurstBuffer implementiert einen adaptiven Burst-basierten Puffer für QUIC-Datenübertragungen.
 * Sammelt Traffic und sendet ihn in kontrollierten Bursts, die wie legitimer HTTP/3-Verkehr aussehen.
 */
class BurstBuffer {
public:
    // Konstruktor mit Standardkonfiguration
    BurstBuffer();
    
    // Konstruktor mit benutzerdefinierter Konfiguration
    explicit BurstBuffer(const BurstConfig& config);
    
    // Destruktor
    ~BurstBuffer();
    
    // Hinzufügen von Daten zum Puffer
    bool add_data(const uint8_t* data, size_t size);
    
    // Konfiguration setzen/abrufen
    void set_config(const BurstConfig& config);
    BurstConfig get_config() const;
    
    // Metriken abrufen
    BurstMetrics get_metrics() const;
    
    // Handler für ausgehende Daten setzen
    using DataSendHandler = std::function<void(const std::vector<uint8_t>&)>;
    void set_data_handler(DataSendHandler handler);
    
    // Burst-Engine starten/stoppen
    bool start();
    bool stop();
    
    // Puffer sofort leeren (für zeitkritische Daten)
    void flush();
    
    // Netzwerkbedingungen aktualisieren
    void update_network_conditions(double latency_ms, double loss_rate, double bandwidth);
    
private:
    // Private Hilfsmethoden
    void burst_processor(); // Haupt-Thread-Funktion für Burst-Verarbeitung
    void adapt_to_network_conditions(); // Adaptionsmethode für Netzwerkbedingungen
    uint32_t calculate_burst_interval() const; // Berechnet das optimale Burst-Intervall
    size_t calculate_optimal_burst_size() const; // Berechnet die optimale Burst-Größe
    std::vector<uint8_t> create_burst(size_t target_size); // Erstellt einen Burst mit gegebener maximaler Größe
    
    // Frame-spezifische Methoden
    void apply_http3_chunked_framing(std::vector<uint8_t>& data);
    void apply_websocket_framing(std::vector<uint8_t>& data);
    void apply_media_streaming_framing(std::vector<uint8_t>& data);
    void apply_interactive_framing(std::vector<uint8_t>& data);
    void apply_random_framing(std::vector<uint8_t>& data);
    
    // Member-Variablen
    mutable std::mutex mutex_; // Mutex für Thread-Sicherheit
    std::condition_variable cv_;
    std::atomic<bool> running_{false};
    std::thread burst_thread_;
    std::queue<std::vector<uint8_t>> data_queue_;
    size_t current_buffer_size_{0};
    
    BurstConfig config_;
    BurstMetrics metrics_;
    DataSendHandler data_handler_;
    
    // Zufallsgenerator für variable Intervalle/Größen
    mutable std::mt19937 rng_; // Mutable, damit er in const-Methoden verwendet werden kann
};

} // namespace quicsand

#endif // BURST_BUFFER_HPP

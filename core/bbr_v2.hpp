#ifndef BBR_V2_HPP
#define BBR_V2_HPP

#include <cstdint>
#include <cmath>
#include <deque>
#include <vector>
#include <algorithm>
#include <chrono>
#include <mutex>

namespace quicsand {

/**
 * BBRv2 ist eine implementierung des Bottleneck Bandwidth and Round-trip propagation time
 * Version 2 Congestion-Control-Algorithmus von Google.
 * 
 * Diese Implementierung folgt dem BBRv2-Entwurf und integriert die neuesten Verbesserungen
 * für höhere Leistung, bessere Fairness und robustere Bandbreitenmessung.
 */

// Parameter für BBRv2
struct BBRParams {
    double startup_gain = 2.885;           // Pacing-Gain während STARTUP
    double drain_gain = 0.75;              // Pacing-Gain während DRAIN
    double probe_rtt_gain = 0.75;          // Pacing-Gain während PROBE_RTT
    double cwnd_gain = 2.0;                // Multiplikator für das Congestion Window
    double startup_cwnd_gain = 2.885;      // CWND-Gain während STARTUP
    
    uint64_t probe_rtt_interval_ms = 10000; // Minimales Intervall zwischen PROBE_RTT-Phasen
    uint64_t probe_rtt_duration_ms = 200;   // Dauer der PROBE_RTT-Phase
    
    uint64_t min_rtt_window_ms = 10000;     // Fenster für Min-RTT-Messungen
    
    uint64_t bw_window_length = 10;         // Anzahl der max. Bandbreitenmessungen für Filter
    double bw_probe_up_gain = 1.25;         // Pacing-Gain für Bandbreiten-Probing nach oben
    double bw_probe_down_gain = 0.75;       // Pacing-Gain für Bandbreiten-Probing nach unten
    uint64_t bw_probe_max_rounds = 63;      // Max. Anzahl von Runden in Probe_BW
    
    double inflight_headroom = 0.15;        // Headroom für Inflight-Daten
    uint64_t min_pipe_cwnd = 4 * 1024;      // Minimales Congestion Window (Bytes)
};

class BBRv2 {
public:
    /**
     * Status der BBRv2-Zustandsmaschine
     */
    enum class State {
        STARTUP,        // Anfangsphase (exponentielles Wachstum)
        DRAIN,          // Dränierungsphase (Rückgang auf optimalen Betriebspunkt)
        PROBE_BW,       // Bandbreiten-Sondierungsphase (zyklisches Gain-Muster)
        PROBE_RTT       // RTT-Sondierungsphase (minimale Inflight-Daten)
    };
    
    /**
     * Pacing-Gain-Zyklus für PROBE_BW-Zustand
     * Zyklus von Faktoren, die auf die Datenrate angewendet werden
     */
    static constexpr double kPacingGainCycle[8] = {
        1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
    };
    
    /**
     * Konstruktor
     * @param params Parameter für den BBRv2-Algorithmus
     */
    explicit BBRv2(const BBRParams& params = BBRParams());
    
    /**
     * Destruktor
     */
    ~BBRv2();
    
    /**
     * Aktualisiert den BBRv2-Zustand mit neuen Messungen
     * @param rtt_us Aktuelle RTT in Mikrosekunden
     * @param bandwidth_bps Geschätzte Bandbreite in Bits pro Sekunde
     * @param bytes_in_flight Aktuell im Flug befindliche Bytes
     * @param bytes_acked Anzahl der bestätigten Bytes seit letzter Aktualisierung
     * @param bytes_lost Anzahl der verlorenen Bytes seit letzter Aktualisierung
     * @param timestamp_us Aktueller Zeitstempel in Mikrosekunden
     */
    void update(uint64_t rtt_us, double bandwidth_bps, uint64_t bytes_in_flight,
                uint64_t bytes_acked, uint64_t bytes_lost, uint64_t timestamp_us);
    
    /**
     * Berechnet die optimale Senderate basierend auf dem aktuellen BBRv2-Zustand
     * @return Optimale Senderate in Bytes pro Sekunde
     */
    double get_pacing_rate() const;
    
    /**
     * Berechnet das optimale Congestion Window basierend auf dem aktuellen BBRv2-Zustand
     * @return Optimales Congestion Window in Bytes
     */
    uint64_t get_congestion_window() const;
    
    /**
     * Gibt den aktuellen BBRv2-Zustand zurück
     * @return Aktueller Zustand
     */
    State get_state() const;
    
    /**
     * Gibt die aktuelle geschätzte Bandbreite zurück
     * @return Geschätzte Bandbreite in Bits pro Sekunde
     */
    double get_bottleneck_bandwidth() const;
    
    /**
     * Gibt die aktuelle minimale RTT zurück
     * @return Minimale RTT in Mikrosekunden
     */
    uint64_t get_min_rtt() const;
    
    /**
     * Gibt die aktuelle zyklische Index-Position im PROBE_BW-Zustand zurück
     * @return Aktueller Index im Pacing-Gain-Zyklus
     */
    int get_pacing_gain_cycle_index() const;
    
    /**
     * Gibt zurück, ob sich der Algorithmus in der Bandbreiten-Probing-Phase befindet
     * @return true, wenn in Probing-Phase
     */
    bool is_probing_bandwidth() const;
    
    /**
     * Gibt zurück, ob eine sofortige PROBE_RTT-Phase notwendig ist
     * @return true, wenn PROBE_RTT benötigt wird
     */
    bool probe_rtt_due() const;
    
    /**
     * Setzt einen neuen Parameter-Satz für den BBRv2-Algorithmus
     * @param params Neue Parameter
     */
    void set_params(const BBRParams& params);
    
    /**
     * Gibt die aktuellen Parameter zurück
     * @return Aktuelle Parameter
     */
    quicsand::BBRParams get_params() const;
    
private:
    // Struktur für Bandbreitenmessungen
    struct BandwidthSample {
        double bandwidth;      // Gemessene Bandbreite in Bits pro Sekunde
        uint64_t timestamp_us; // Zeitstempel der Messung
    };
    
    // Struktur für RTT-Messungen
    struct RTTSample {
        uint64_t rtt_us;       // Gemessene RTT in Mikrosekunden
        uint64_t timestamp_us; // Zeitstempel der Messung
    };
    
    // Private Hilfsmethoden
    void enter_startup();
    void enter_drain();
    void enter_probe_bw(uint64_t timestamp_us);
    void enter_probe_rtt(uint64_t timestamp_us);
    
    void handle_startup_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us);
    void handle_drain_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us);
    void handle_probe_bw_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us);
    void handle_probe_rtt_mode(uint64_t bytes_in_flight, uint64_t timestamp_us);
    
    void update_bandwidth_filter(double bandwidth_bps, uint64_t timestamp_us);
    void update_rtt_filter(uint64_t rtt_us, uint64_t timestamp_us);
    
    void advance_cycle_phase(uint64_t timestamp_us);
    void update_model(uint64_t rtt_us, double bandwidth_bps, uint64_t timestamp_us);
    
    double calculate_pacing_rate() const;
    uint64_t calculate_congestion_window() const;
    uint64_t calculate_probe_rtt_cwnd() const;
    
    // Attribute
    mutable std::mutex mutex_;
    BBRParams params_;
    State state_;
    
    // Bandbreiten- und RTT-Messungen
    std::vector<BandwidthSample> bandwidth_samples_;
    std::vector<RTTSample> rtt_samples_;
    
    // Aktuelle Schätzungen
    double bottleneck_bandwidth_;  // Aktuelle Bandbreitenschätzung (Bits/s)
    uint64_t min_rtt_us_;          // Minimale beobachtete RTT (µs)
    uint64_t last_bandwidth_update_us_; // Letztes Bandbreiten-Update
    uint64_t last_rtt_update_us_;     // Letztes RTT-Update
    
    // Zustandsvariablen
    int cycle_index_;              // Aktueller Index im Pacing-Gain-Zyklus
    uint64_t cycle_start_time_us_; // Startzeit des aktuellen Zyklus
    uint64_t probe_rtt_done_time_us_; // Zeit, zu der PROBE_RTT abgeschlossen ist
    uint64_t probe_rtt_round_done_time_us_; // Zeit, zu der eine PROBE_RTT-Runde abgeschlossen ist
    uint64_t next_probe_rtt_time_us_; // Zeit für die nächste PROBE_RTT-Phase
    
    double pacing_gain_;           // Aktueller Pacing-Gain-Faktor
    double cwnd_gain_;             // Aktueller Congestion-Window-Gain-Faktor
    
    // BBRv2-spezifische Status-Flags
    bool filled_pipe_;             // Flag, ob die Leitung gefüllt ist
    bool probe_rtt_round_done_;    // Flag, ob eine PROBE_RTT-Runde abgeschlossen ist
    uint64_t probe_bw_rounds_;     // Anzahl der Runden in PROBE_BW
    bool exiting_probe_rtt_;       // Flag, ob PROBE_RTT gerade verlassen wird
};

} // namespace quicsand

#endif // BBR_V2_HPP

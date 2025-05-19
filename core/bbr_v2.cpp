#include "bbr_v2.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <limits>

namespace quicsand {

BBRv2::BBRv2(const BBRParams& params)
    : params_(params),
      state_(State::STARTUP),
      bottleneck_bandwidth_(0.0),
      min_rtt_us_(std::numeric_limits<uint64_t>::max()),
      last_bandwidth_update_us_(0),
      last_rtt_update_us_(0),
      cycle_index_(0),
      cycle_start_time_us_(0),
      probe_rtt_done_time_us_(0),
      probe_rtt_round_done_time_us_(0),
      next_probe_rtt_time_us_(0),
      pacing_gain_(params.startup_gain),
      cwnd_gain_(params.startup_cwnd_gain),
      filled_pipe_(false),
      probe_rtt_round_done_(false),
      probe_bw_rounds_(0),
      exiting_probe_rtt_(false) {
    // Initialisierung der Datenstrukturen
    bandwidth_samples_.reserve(params.bw_window_length);
    rtt_samples_.reserve(10);  // Spezifische Größe für RTT-Messungen
}

BBRv2::~BBRv2() {
    // Aufräumarbeiten, falls nötig
}

void BBRv2::update(uint64_t rtt_us, double bandwidth_bps, uint64_t bytes_in_flight,
                  uint64_t bytes_acked, uint64_t bytes_lost, uint64_t timestamp_us) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Aktualisiere die Bandbreiten- und RTT-Filter
    update_bandwidth_filter(bandwidth_bps, timestamp_us);
    update_rtt_filter(rtt_us, timestamp_us);
    
    // Aktualisiere das BBR-Modell mit den neuen Messungen
    update_model(rtt_us, bandwidth_bps, timestamp_us);
    
    // Handle-Methode je nach aktuellem Zustand aufrufen
    switch (state_) {
        case State::STARTUP:
            handle_startup_mode(bandwidth_bps, bytes_in_flight, timestamp_us);
            break;
        case State::DRAIN:
            handle_drain_mode(bandwidth_bps, bytes_in_flight, timestamp_us);
            break;
        case State::PROBE_BW:
            handle_probe_bw_mode(bandwidth_bps, bytes_in_flight, timestamp_us);
            break;
        case State::PROBE_RTT:
            handle_probe_rtt_mode(bytes_in_flight, timestamp_us);
            break;
    }
}

double BBRv2::get_pacing_rate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calculate_pacing_rate();
}

uint64_t BBRv2::get_congestion_window() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calculate_congestion_window();
}

BBRv2::State BBRv2::get_state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

double BBRv2::get_bottleneck_bandwidth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bottleneck_bandwidth_;
}

uint64_t BBRv2::get_min_rtt() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return min_rtt_us_;
}

int BBRv2::get_pacing_gain_cycle_index() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cycle_index_;
}

bool BBRv2::is_probing_bandwidth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::PROBE_BW && 
           (cycle_index_ == 0 || (pacing_gain_ > 1.0 && filled_pipe_));
}

bool BBRv2::probe_rtt_due() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t time_since_last_probe = last_rtt_update_us_ - next_probe_rtt_time_us_;
    return time_since_last_probe >= params_.probe_rtt_interval_ms * 1000;
}

void BBRv2::set_params(const BBRParams& params) {
    std::lock_guard<std::mutex> lock(mutex_);
    params_ = params;
}

quicsand::BBRParams BBRv2::get_params() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return params_;
}

// Private Hilfsmethoden
void BBRv2::enter_startup() {
    state_ = State::STARTUP;
    pacing_gain_ = params_.startup_gain;
    cwnd_gain_ = params_.startup_cwnd_gain;
}

void BBRv2::enter_drain() {
    state_ = State::DRAIN;
    pacing_gain_ = params_.drain_gain;
    cwnd_gain_ = params_.cwnd_gain;  // Standard CWND-Gain für DRAIN
}

void BBRv2::enter_probe_bw(uint64_t timestamp_us) {
    state_ = State::PROBE_BW;
    
    // Starte mit der Hochphase des Zyklus
    cycle_index_ = 0;
    cycle_start_time_us_ = timestamp_us;
    pacing_gain_ = kPacingGainCycle[0];
    cwnd_gain_ = params_.cwnd_gain;
    probe_bw_rounds_ = 0;
}

void BBRv2::enter_probe_rtt(uint64_t timestamp_us) {
    state_ = State::PROBE_RTT;
    pacing_gain_ = params_.probe_rtt_gain;
    cwnd_gain_ = params_.probe_rtt_gain;  // Reduziertes CWND während PROBE_RTT
    
    // Setze Timer für die minimale PROBE_RTT-Dauer
    probe_rtt_done_time_us_ = timestamp_us + params_.probe_rtt_duration_ms * 1000;
    probe_rtt_round_done_ = false;
    probe_rtt_round_done_time_us_ = 0;
}

void BBRv2::handle_startup_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // In STARTUP suchen wir nach exponentieller Steigerung der Bandbreite
    
    // Prüfe, ob wir die Leitung gefüllt haben (keine signifikante Bandbreitensteigerung mehr)
    if (!filled_pipe_ && bandwidth_samples_.size() >= 3) {
        // Berechne das Verhältnis der aktuellen zur vorherigen max. Bandbreite
        double latest_bw = bandwidth_samples_.back().bandwidth;
        double prev_max_bw = 0.0;
        
        for (size_t i = 0; i < bandwidth_samples_.size() - 1; ++i) {
            prev_max_bw = std::max(prev_max_bw, bandwidth_samples_[i].bandwidth);
        }
        
        // Wenn die Bandbreite nicht mehr signifikant zunimmt, haben wir die Pipe gefüllt
        if (prev_max_bw > 0.0 && latest_bw < prev_max_bw * 1.25) {
            filled_pipe_ = true;
            
            // Wechsle in den DRAIN-Modus, um überschüssige Queue zu entfernen
            enter_drain();
        }
    }
}

void BBRv2::handle_drain_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // In DRAIN reduzieren wir die Queue, die während STARTUP aufgebaut wurde
    
    // Schätze die optimale Datenmenge in der Leitung
    uint64_t bdp = static_cast<uint64_t>(bottleneck_bandwidth_ * (min_rtt_us_ / 1e6) / 8);
    
    // Wenn wir genug Daten entfernt haben, wechsle zu PROBE_BW
    if (bytes_in_flight <= bdp) {
        enter_probe_bw(timestamp_us);
    }
}

void BBRv2::handle_probe_bw_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // In PROBE_BW verwenden wir einen zyklischen Pacing-Gain, um die Bandbreite zu testen
    
    // Prüfe, ob es Zeit ist, in die PROBE_RTT-Phase zu wechseln
    if (probe_rtt_due() && !exiting_probe_rtt_) {
        enter_probe_rtt(timestamp_us);
        return;
    }
    
    // Überprüfe, ob es Zeit ist, die Zyklusphase zu ändern
    uint64_t cycle_duration_us = min_rtt_us_ * 2;  // Zyklusphasen dauern etwa 2 RTTs
    if (timestamp_us - cycle_start_time_us_ > cycle_duration_us) {
        advance_cycle_phase(timestamp_us);
    }
    
    // Inkrementiere die Anzahl der Runden, die wir in PROBE_BW verbracht haben
    probe_bw_rounds_++;
}

void BBRv2::handle_probe_rtt_mode(uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // In PROBE_RTT reduzieren wir die Daten im Flug auf ein Minimum,
    // um eine genaue RTT-Messung zu erhalten
    
    // Überprüfe, ob wir die Ausgangsvoraussetzungen erfüllt haben:
    // 1. Wir haben genug Zeit in PROBE_RTT verbracht
    // 2. Wir haben die Daten im Flug auf ein Minimum reduziert
    
    uint64_t target_cwnd = calculate_probe_rtt_cwnd();
    
    // Wir brauchen eine RTT-Runde mit reduziertem cwnd
    if (!probe_rtt_round_done_ && bytes_in_flight <= target_cwnd) {
        probe_rtt_round_done_ = true;
        probe_rtt_round_done_time_us_ = timestamp_us + min_rtt_us_;
    }
    
    // Prüfe, ob sowohl die Minimaldauer als auch eine RTT-Runde abgeschlossen sind
    if (probe_rtt_round_done_ && timestamp_us > probe_rtt_done_time_us_ &&
        timestamp_us > probe_rtt_round_done_time_us_) {
        // Setze den Zeitpunkt für die nächste PROBE_RTT-Phase
        next_probe_rtt_time_us_ = timestamp_us + params_.probe_rtt_interval_ms * 1000;
        
        // Zurück zu PROBE_BW
        exiting_probe_rtt_ = true;
        enter_probe_bw(timestamp_us);
void BBRv2::update_bandwidth_filter(double bandwidth_bps, uint64_t timestamp_us) {
    // Füge die neue Bandbreitenmessung zum Filter hinzu
    if (bandwidth_bps > 0) {
        // Erstelle eine neue Bandbreitenmessung
        BandwidthSample sample{bandwidth_bps, timestamp_us};
        
        // Füge die Messung zum Filter hinzu
        if (bandwidth_samples_.size() >= params_.bw_window_length) {
            bandwidth_samples_.erase(bandwidth_samples_.begin());
        }
        bandwidth_samples_.push_back(sample);
        
        // Hole alle Bandbreitenwerte für die Berechnung
        std::vector<double> bw_values;
        bw_values.reserve(bandwidth_samples_.size());
        for (const auto& s : bandwidth_samples_) {
            bw_values.push_back(s.bandwidth);
        }
        
        // Optimierte Bandbreitenschätzung mit Ausreißererkennung
        // Sortiere die Samples für eine effizientere Berechnung
        std::sort(bw_values.begin(), bw_values.end());
        
        // Verwende die oberen 80% der Samples für eine robuste Schätzung
        // und ignoriere potenzielle Ausreißer bei niedrigen Werten
        size_t start_idx = std::max(size_t(1), static_cast<size_t>(bw_values.size() * 0.2));
        double max_bandwidth = 0.0;
        double sum_bandwidth = 0.0;
        size_t count = 0;
        
        for (size_t i = start_idx; i < bw_values.size(); i++) {
            max_bandwidth = std::max(max_bandwidth, bw_values[i]);
            sum_bandwidth += bw_values[i];
            count++;
        }
        
        // Gewichteter Durchschnitt aus Maximum und Durchschnitt für bessere Stabilität
        double avg_bandwidth = count > 0 ? sum_bandwidth / count : 0.0;
        
        // Dynamische Gewichtung basierend auf Netzwerkeigenschaften
        // Instabilere Netzwerke profitieren von mehr Gewicht auf dem Durchschnitt
        // Wir erkennen Instabilität durch die Varianz der Messungen
        double variance = 0.0;
        if (count > 1) {
            double mean = avg_bandwidth;
            for (size_t i = start_idx; i < bw_values.size(); i++) {
                variance += (bw_values[i] - mean) * (bw_values[i] - mean);
            }
            variance /= count;
        }
        
        // Normalisierte Varianz für Gewichtung
        double norm_variance = std::min(1.0, variance / (avg_bandwidth * avg_bandwidth + 1e-10));
        double max_weight = std::max(0.5, 0.8 - norm_variance * 0.3); // Zwischen 0.5 und 0.8
        
        double weighted_bandwidth = max_bandwidth * max_weight + avg_bandwidth * (1.0 - max_weight);
        
        // Aktualisiere die Bottleneck-Bandbreite mit einer Hysterese
        // um unvorteilhafte Oszillationen zu vermeiden
        if (weighted_bandwidth > bottleneck_bandwidth_ * 1.05 || // 5% Schwelle für Erhöhung
            weighted_bandwidth < bottleneck_bandwidth_ * 0.75 || // 25% Schwelle für Senkung
            timestamp_us - last_bandwidth_update_us_ > params_.min_rtt_window_ms * 1000) {
            
            // Sanfter Übergang mit Gewichtung basierend auf Varianz
            double transition_weight = std::min(0.5, 0.1 + norm_variance * 0.4); // Zwischen 0.1 und 0.5
            
            if (bottleneck_bandwidth_ > 0) {
                bottleneck_bandwidth_ = bottleneck_bandwidth_ * (1.0 - transition_weight) + 
                                        weighted_bandwidth * transition_weight;
            } else {
                bottleneck_bandwidth_ = weighted_bandwidth;
            }
            last_bandwidth_update_us_ = timestamp_us;
        }
    }
}

void BBRv2::update_rtt_filter(uint64_t rtt_us, uint64_t timestamp_us) {
    // Plausibilitätsprüfung für RTT-Werte
    if (rtt_us < 500) { // Extrem niedrige RTT (unter 0.5ms) ist verdächtig
        std::cout << "Warning: Very low RTT detected: " << rtt_us << " us, setting minimum threshold" << std::endl;
        rtt_us = 500; // Setze ein Minimum, um keine unrealistischen Werte zu verwenden
    } else if (rtt_us > 15000000) { // RTT > 15s ist unwahrscheinlich
        std::cout << "Warning: Extremely high RTT detected: " << rtt_us << " us, ignoring sample" << std::endl;
        return; // Diese Messung ignorieren
    }
    
    // Erstelle eine neue RTT-Messung
    RTTSample sample{rtt_us, timestamp_us};
    
    // Füge die Messung zum Filter hinzu
    if (rtt_samples_.size() >= 10) { // Maximale Anzahl von RTT-Samples begrenzen
        rtt_samples_.erase(rtt_samples_.begin());
    }
    rtt_samples_.push_back(sample);
    
    // Verbesserte RTT-Filterung mit Ausreißerdetektion
    // Hole alle RTT-Werte aus dem Fenster
    std::vector<uint64_t> rtts;
    rtts.reserve(rtt_samples_.size());
    for (const auto& s : rtt_samples_) {
        rtts.push_back(s.rtt_us);
    }
    
    // Sortiere die RTTs für bessere Filterung
    std::sort(rtts.begin(), rtts.end());
    
    // Berechne min_rtt als das 10. Perzentil, um extrem niedrige Ausreißer zu vermeiden
    uint64_t min_rtt_filtered = rtts[0]; // Default zum niedrigsten Wert
    if (rtts.size() >= 5) {
        // Bei genügend Samples nehmen wir das 10. Perzentil
        min_rtt_filtered = rtts[rtts.size() / 10];
    }
    
    // Überprüfe, ob wir einen neuen Min-RTT-Wert haben
    if (min_rtt_filtered < min_rtt_us_) {
        // Neuer niedrigerer RTT-Wert gefunden
        min_rtt_us_ = min_rtt_filtered;
        last_rtt_update_us_ = timestamp_us;
    } else if (timestamp_us - last_rtt_update_us_ > params_.min_rtt_window_ms * 1000) {
        // Min-RTT-Fenster ist abgelaufen, aktualisiere den Wert
        
        // Berechne ein gewichtetes Minimum als den Mittelwert der unteren 20% aller Messungen
        // Dies ist robuster gegen veränderliche Netzwerkbedingungen
        uint64_t sum = 0;
        size_t count = 0;
        size_t max_lower_samples = std::max(size_t(1), rtts.size() / 5);
        
        for (size_t i = 0; i < std::min(max_lower_samples, rtts.size()); i++) {
            sum += rtts[i];
            count++;
        }
        
        uint64_t avg_min_rtt = count > 0 ? sum / count : min_rtt_us_;
        
        // Verwende einen Blend aus dem vorherigen Min-RTT und dem neuen Wert
        // für eine sanftere Übergangsphase und bessere Stabilität
        if (min_rtt_us_ > 0) {
            // Gewichteter Durchschnitt: 70% alter Wert, 30% neuer Wert
            min_rtt_us_ = (min_rtt_us_ * 7 + avg_min_rtt * 3) / 10;
        } else {
            min_rtt_us_ = avg_min_rtt;
        }
        
        last_rtt_update_us_ = timestamp_us;
    }
}

void BBRv2::advance_cycle_phase(uint64_t timestamp_us) {
    cycle_index_ = (cycle_index_ + 1) % (sizeof(kPacingGainCycle) / sizeof(kPacingGainCycle[0]));
    cycle_start_time_us_ = timestamp_us;
    pacing_gain_ = kPacingGainCycle[cycle_index_];
}

void BBRv2::update_model(uint64_t rtt_us, double bandwidth_bps, uint64_t timestamp_us) {
    // Aktualisiere das BW-Modell, falls nötig
    if (bandwidth_bps > 0) {
        update_bandwidth_filter(bandwidth_bps, timestamp_us);
    }
    
    // Aktualisiere das RTT-Modell, falls nötig
    if (rtt_us > 0) {
        update_rtt_filter(rtt_us, timestamp_us);
    }
}

double BBRv2::calculate_pacing_rate() const {
    // Die Pacing-Rate basiert auf der geschätzten Bandbreite und dem aktuellen Gain-Faktor
    double rate = bottleneck_bandwidth_ * pacing_gain_;
    
    // Stelle sicher, dass wir eine minimale Rate haben
    double min_rate = (params_.min_pipe_cwnd * 8) / (min_rtt_us_ / 1e6);
    return std::max(rate, min_rate);
}

uint64_t BBRv2::calculate_congestion_window() const {
    // Das Congestion Window basiert auf dem Bandbreite-Verzögerungs-Produkt (BDP)
    // und einem Gain-Faktor
    
    // Berechne das BDP: Bandbreite * RTT
    uint64_t bdp = static_cast<uint64_t>((bottleneck_bandwidth_ / 8.0) * (min_rtt_us_ / 1e6));
    
    // Wende den CWND-Gain-Faktor an
    uint64_t cwnd = static_cast<uint64_t>(bdp * cwnd_gain_);
    
    // Stelle sicher, dass wir ein Minimum-CWND haben
    return std::max(cwnd, params_.min_pipe_cwnd);
}

uint64_t BBRv2::calculate_probe_rtt_cwnd() const {
    // Während PROBE_RTT verwenden wir ein sehr kleines Congestion Window
    return std::max(params_.min_pipe_cwnd, 
                   static_cast<uint64_t>((bottleneck_bandwidth_ / 8.0) * (min_rtt_us_ / 1e6) * 0.5));
}

} // namespace quicsand

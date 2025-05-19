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
      next_probe_rtt_time_us_(0) {
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
    return state_ == State::PROBE_BW && kPacingGainCycle[cycle_index_] > 1.0;
}

bool BBRv2::probe_rtt_due() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return now >= next_probe_rtt_time_us_;
}

void BBRv2::set_params(const BBRParams& params) {
    std::lock_guard<std::mutex> lock(mutex_);
    params_ = params;
}

BBRParams BBRv2::get_params() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return params_;
}

// Private Hilfsmethoden
void BBRv2::enter_startup() {
    state_ = State::STARTUP;
    // Weitere Initialisierungen für STARTUP-Phase
}

void BBRv2::enter_drain() {
    state_ = State::DRAIN;
    // Weitere Initialisierungen für DRAIN-Phase
}

void BBRv2::enter_probe_bw(uint64_t timestamp_us) {
    state_ = State::PROBE_BW;
    cycle_index_ = 0;
    cycle_start_time_us_ = timestamp_us;
    
    // Setze den nächsten Zeitpunkt für PROBE_RTT
    next_probe_rtt_time_us_ = timestamp_us + params_.probe_rtt_interval_ms * 1000;
}

void BBRv2::enter_probe_rtt(uint64_t timestamp_us) {
    state_ = State::PROBE_RTT;
    
    // Setze den Zeitpunkt, wann PROBE_RTT beendet sein wird
    probe_rtt_done_time_us_ = timestamp_us + params_.probe_rtt_duration_ms * 1000;
    probe_rtt_round_done_time_us_ = 0;
}

void BBRv2::handle_startup_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // STARTUP: Exponentielles Wachstum, bis die Bandbreite nicht mehr zunimmt
    
    // Wenn wir feststellen, dass die Bandbreite nicht mehr zunimmt,
    // wechseln wir in den DRAIN-Zustand
    static double prev_bottleneck_bw = 0.0;
    
    if (bottleneck_bandwidth_ > 0 && 
        bottleneck_bandwidth_ < 1.25 * prev_bottleneck_bw) {
        // Bandbreite nimmt nicht mehr signifikant zu
        enter_drain();
    }
    
    prev_bottleneck_bw = bottleneck_bandwidth_;
}

void BBRv2::handle_drain_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // DRAIN: Reduziere das Congestion Window, um die Queue zu leeren
    
    // Wenn die Daten im Flug unter das berechnete optimale Niveau fallen,
    // wechseln wir in den PROBE_BW-Zustand
    uint64_t target_cwnd = static_cast<uint64_t>(bottleneck_bandwidth_ * min_rtt_us_ / 8000000.0);
    
    if (bytes_in_flight <= target_cwnd) {
        enter_probe_bw(timestamp_us);
    }
}

void BBRv2::handle_probe_bw_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // PROBE_BW: Zyklische Probing-Phasen
    
    // Überprüfe, ob es Zeit ist, in PROBE_RTT zu wechseln
    if (timestamp_us >= next_probe_rtt_time_us_) {
        enter_probe_rtt(timestamp_us);
        return;
    }
    
    // Überprüfe, ob es Zeit ist, die Zyklusphase voranzutreiben
    uint64_t cycle_duration_us = min_rtt_us_ * 2; // Ein Zyklus dauert 2 RTT
    
    if (timestamp_us - cycle_start_time_us_ > cycle_duration_us) {
        advance_cycle_phase(timestamp_us);
    }
}

void BBRv2::handle_probe_rtt_mode(uint64_t bytes_in_flight, uint64_t timestamp_us) {
    // In PROBE_RTT reduzieren wir die Daten im Flug auf ein Minimum,
    // um eine genaue RTT-Messung zu erhalten
    
    // Wenn die PROBE_RTT-Phase abgeschlossen ist, kehren wir zu PROBE_BW zurück
    if (timestamp_us > probe_rtt_done_time_us_) {
        // RTT-Messung abgeschlossen, zurück zu PROBE_BW
        enter_probe_bw(timestamp_us);
    }
}

void BBRv2::update_bandwidth_filter(double bandwidth_bps, uint64_t timestamp_us) {
    // Füge neue Bandbreitenmessung hinzu
    if (bandwidth_bps > 0) {
        BandwidthSample sample = {bandwidth_bps, timestamp_us};
        
        // Ältere Proben entfernen, wenn das Fenster voll ist
        if (bandwidth_samples_.size() >= params_.bw_window_length) {
            // Entferne die älteste Probe
            bandwidth_samples_.erase(bandwidth_samples_.begin());
        }
        
        // Neue Probe hinzufügen
        bandwidth_samples_.push_back(sample);
        
        // Aktualisiere die Bandbreitenschätzung als Maximum aller Proben im Fenster
        double max_bw = 0.0;
        for (const auto& sample : bandwidth_samples_) {
            max_bw = std::max(max_bw, sample.bandwidth);
        }
        
        // Aktualisiere die Bandbreitenschätzung nur, wenn sie sich erhöht hat
        // oder wenn eine bestimmte Zeit vergangen ist
        if (max_bw > bottleneck_bandwidth_ || 
            timestamp_us - last_bandwidth_update_us_ > 10000000) { // 10 Sekunden
            
            bottleneck_bandwidth_ = max_bw;
            last_bandwidth_update_us_ = timestamp_us;
        }
    }
}

void BBRv2::update_rtt_filter(uint64_t rtt_us, uint64_t timestamp_us) {
    // Füge neue RTT-Messung hinzu
    if (rtt_us > 0) {
        RTTSample sample = {rtt_us, timestamp_us};
        
        // Ältere Proben entfernen, wenn zu viele
        if (rtt_samples_.size() >= 10) {
            // Entferne die älteste Probe
            rtt_samples_.erase(rtt_samples_.begin());
        }
        
        // Neue Probe hinzufügen
        rtt_samples_.push_back(sample);
        
        // Aktualisiere min_rtt_us_ mit dem Minimum der letzten RTT-Messungen,
        // aber nur innerhalb des min_rtt_window_ms
        
        // Lösche veraltete RTT-Proben
        uint64_t min_timestamp = timestamp_us - params_.min_rtt_window_ms * 1000;
        rtt_samples_.erase(
            std::remove_if(rtt_samples_.begin(), rtt_samples_.end(),
                         [min_timestamp](const RTTSample& s) {
                             return s.timestamp_us < min_timestamp;
                         }),
            rtt_samples_.end());
        
        // Finde das Minimum der verbliebenen RTT-Messungen
        uint64_t min_rtt = std::numeric_limits<uint64_t>::max();
        for (const auto& sample : rtt_samples_) {
            min_rtt = std::min(min_rtt, sample.rtt_us);
        }
        
        // Aktualisiere die minimale RTT
        if (min_rtt < min_rtt_us_) {
            min_rtt_us_ = min_rtt;
        }
        
        last_rtt_update_us_ = timestamp_us;
    }
}

void BBRv2::advance_cycle_phase(uint64_t timestamp_us) {
    cycle_index_ = (cycle_index_ + 1) % 8;
    cycle_start_time_us_ = timestamp_us;
}

void BBRv2::update_model(uint64_t rtt_us, double bandwidth_bps, uint64_t timestamp_us) {
    // Aktualisiere das BBR-Modell basierend auf den neuen Messungen
    // Diese Methode wird von update() aufgerufen, bevor die zustandsspezifischen Handler aufgerufen werden
    
    // Hier könnte weitere Logik hinzugefügt werden, um das BBR-Modell zu aktualisieren
    // basierend auf den übergebenen Parametern
}

double BBRv2::calculate_pacing_rate() const {
    // Berechne die optimale Pacing-Rate basierend auf der Bandbreite und dem aktuellen Gain
    double pacing_gain = 1.0;
    
    if (state_ == State::STARTUP) pacing_gain = params_.startup_gain;
    else if (state_ == State::DRAIN) pacing_gain = params_.drain_gain;
    else if (state_ == State::PROBE_BW) pacing_gain = kPacingGainCycle[cycle_index_];
    else if (state_ == State::PROBE_RTT) pacing_gain = params_.probe_rtt_gain;
    
    return bottleneck_bandwidth_ * pacing_gain;
}

uint64_t BBRv2::calculate_congestion_window() const {
    // Berechne das optimale Congestion Window basierend auf BDP und cwnd_gain
    double cwnd_gain = params_.cwnd_gain;
    
    if (state_ == State::STARTUP) cwnd_gain = params_.startup_cwnd_gain;
    
    // BDP = Bottleneck Bandwidth (Bytes/s) * Min RTT (s)
    uint64_t bdp = static_cast<uint64_t>(bottleneck_bandwidth_ * min_rtt_us_ / 8000000.0);
    
    // Congestion Window = BDP * cwnd_gain
    uint64_t cwnd = static_cast<uint64_t>(bdp * cwnd_gain);
    
    // Stellt sicher, dass das Congestion Window mindestens min_pipe_cwnd groß ist
    return std::max(cwnd, params_.min_pipe_cwnd);
}

uint64_t BBRv2::calculate_probe_rtt_cwnd() const {
    // Während PROBE_RTT verwenden wir ein kleineres Congestion Window
    // typischerweise 4 Segmente
    return params_.min_pipe_cwnd;
}

} // namespace quicsand

#include "quic_connection.hpp"
#include "bbr_v2.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>

namespace quicsand {

// Congestion Control bezogene Methoden

bool QuicConnection::enable_bbr_congestion_control(bool enable) {
    if (quiche_conn_ == nullptr) {
        std::cerr << "Cannot enable congestion control without an active QUIC connection" << std::endl;
        return false;
    }
    
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // Wenn BBRv2 bereits im gewünschten Zustand ist, nichts tun
    if ((congestion_algorithm_ == CongestionAlgorithm::BBRv2) == enable) {
        return true;
    }
    
    if (enable) {
        std::cout << "Enabling BBRv2 congestion control" << std::endl;
        congestion_algorithm_ = CongestionAlgorithm::BBRv2;
        
        // BBRv2-Parameter initialisieren, falls noch nicht geschehen
        BBRParams bbr_params;
        bbr_params.startup_gain = 2.885;
        bbr_params.drain_gain = 0.75;
        bbr_params.probe_rtt_gain = 0.75;
        bbr_params.cwnd_gain = 2.0;
        bbr_params.startup_cwnd_gain = 2.885;
        
        // Erstelle eine BBRv2-Instanz, falls noch nicht vorhanden
        if (!bbr_) {
            bbr_ = std::make_unique<BBRv2>(bbr_params);
        } else {
            bbr_->set_params(bbr_params);
        }
        
        // Setze explizit BBRv2 in der QUIC-Verbindung
        // Quiche verwendet standardmäßig den in der Verbindung konfigurierten Algorithmus
        // oder versucht, den Namen des Algorithmus zu parsen
        const char* cc_name = "bbr2";
        quiche_conn_set_congestion_control_algorithm(quiche_conn_, cc_name, strlen(cc_name));
        
        // Setze anfängliche Congestion-Window-Größe
        uint64_t initial_cwnd = 32 * 1024; // 32 KB typische Startgröße
        quiche_conn_set_initial_congestion_window(quiche_conn_, initial_cwnd);
    } else {
        std::cout << "Switching to default congestion control (Cubic)" << std::endl;
        congestion_algorithm_ = CongestionAlgorithm::CUBIC;
        
        // Setze Cubic in der QUIC-Verbindung
        const char* cc_name = "cubic";
        quiche_conn_set_congestion_control_algorithm(quiche_conn_, cc_name, strlen(cc_name));
    }
    
    return true;
}

CongestionAlgorithm QuicConnection::get_congestion_algorithm() const {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    return congestion_algorithm_;
}

void QuicConnection::set_congestion_algorithm(CongestionAlgorithm algorithm) {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    if (algorithm == congestion_algorithm_) {
        return; // Nichts ändern, wenn bereits gesetzt
    }
    
    if (quiche_conn_ == nullptr) {
        // Speichern für spätere Verwendung
        congestion_algorithm_ = algorithm;
        return;
    }
    
    const char* cc_name = nullptr;
    
    switch (algorithm) {
        case CongestionAlgorithm::BBRv2:
            cc_name = "bbr2";
            
            // BBRv2-Parameter initialisieren, falls noch nicht geschehen
            if (!bbr_) {
                BBRParams bbr_params;
                bbr_ = std::make_unique<BBRv2>(bbr_params);
            }
            break;
            
        case CongestionAlgorithm::CUBIC:
            cc_name = "cubic";
            break;
            
        case CongestionAlgorithm::RENO:
            cc_name = "reno";
            break;
            
        default:
            std::cerr << "Unknown congestion control algorithm, using BBRv2" << std::endl;
            cc_name = "bbr2";
            algorithm = CongestionAlgorithm::BBRv2;
            
            if (!bbr_) {
                BBRParams bbr_params;
                bbr_ = std::make_unique<BBRv2>(bbr_params);
            }
            break;
    }
    
    if (cc_name != nullptr) {
        quiche_conn_set_congestion_control_algorithm(quiche_conn_, cc_name, strlen(cc_name));
        congestion_algorithm_ = algorithm;
        
        std::cout << "Congestion control algorithm set to " << cc_name << std::endl;
    }
}

void QuicConnection::set_bbr_params(const BBRParams& params) {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    if (congestion_algorithm_ != CongestionAlgorithm::BBRv2) {
        std::cerr << "Warning: Setting BBR parameters while not using BBRv2" << std::endl;
    }
    
    // Erstelle oder aktualisiere die BBRv2-Instanz
    if (!bbr_) {
        bbr_ = std::make_unique<BBRv2>(params);
    } else {
        bbr_->set_params(params);
    }
}

BBRParams QuicConnection::get_bbr_params() const {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    if (bbr_) {
        return bbr_->get_params();
    }
    
    // Rückgabe von Standardparametern, wenn keine BBRv2-Instanz existiert
    return BBRParams();
}

void QuicConnection::update_congestion_window() {
    if (!quiche_conn_ || congestion_algorithm_ != CongestionAlgorithm::BBRv2 || !bbr_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // Hole aktuelle Verbindungsdaten
    uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // Für Testumgebungen, wenn quiche_conn_stats null zurückgeben könnte
    uint64_t rtt_us = min_rtt_us_;
    double bandwidth_estimate = 10e6; // 10 Mbps Standardwert
    uint64_t bytes_in_flight = 0;
    uint64_t bytes_acked = 0;
    uint64_t bytes_lost = 0;
    
    // Wenn quiche_conn_ gültig ist, versuche die echten Statistiken zu bekommen
    if (quiche_conn_) {
        const quiche_stats* stats = quiche_conn_stats(quiche_conn_);
        if (stats) {
            rtt_us = stats->min_rtt;
            bandwidth_estimate = stats->est_bandwidth;
            bytes_in_flight = stats->bytes_in_flight;
            bytes_lost = stats->lost;
        }
    }
    
    // Aktualisiere BBRv2-Modell
    bbr_->update(rtt_us, bandwidth_estimate, bytes_in_flight, bytes_acked, bytes_lost, now_us);
    
    // Hole optimale Werte aus dem BBRv2-Modell
    uint64_t bbr_cwnd = bbr_->get_congestion_window();
    double bbr_pacing_rate = bbr_->get_pacing_rate();
    double bbr_bw = bbr_->get_bottleneck_bandwidth();
    
    // Setze Pacing-Gains basierend auf BBRv2-Modell
    pacing_gain_ = bbr_->is_probing_bandwidth() ? 1.25 : 1.0; // Vereinfachte Logik
    cwnd_gain_ = bbr_->get_state() == BBRv2::State::STARTUP ? 2.0 : 1.0;
    
    // Speichere min_rtt für andere Komponenten
    min_rtt_us_ = bbr_->get_min_rtt();
    
    // Update Statistiken
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.congestion_window = bbr_cwnd;
        stats_.pacing_rate = bbr_pacing_rate;
        stats_.bottleneck_bw = bbr_bw;
        stats_.min_rtt_us = min_rtt_us_;
    }
    
    // Logging für Debugging
    static int log_counter = 0;
    if (++log_counter % 10 == 0) { // Log nur gelegentlich für weniger Overhead
        std::cout << "BBRv2 state: " 
                  << static_cast<int>(bbr_->get_state()) 
                  << ", CWND: " << bbr_cwnd 
                  << ", Pacing rate: " << bbr_pacing_rate / 1000000.0 << " Mbps" 
                  << ", BW: " << bbr_bw / 1000000.0 << " Mbps"
                  << ", Min RTT: " << min_rtt_us_ / 1000.0 << " ms" 
                  << std::endl;
    }
}

// Testmethode für Performance-Tuning
void QuicConnection::force_congestion_feedback(uint64_t bandwidth_kbps, uint64_t rtt_ms) {
    if (!quiche_conn_ || congestion_algorithm_ != CongestionAlgorithm::BBRv2 || !bbr_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // Konvertiere Einheiten
    double bandwidth_bps = bandwidth_kbps * 1000.0;
    uint64_t rtt_us = rtt_ms * 1000;
    
    uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // Aktualisiere BBRv2-Modell mit den erzwungenen Werten
    uint64_t bytes_in_flight = quiche_conn_stats(quiche_conn_)->bytes_in_flight;
    bbr_->update(rtt_us, bandwidth_bps, bytes_in_flight, 0, 0, now_us);
    
    // Aktualisiere Congestion-Window und Pacing-Rate
    update_congestion_window();
    
    std::cout << "Forced congestion feedback: Bandwidth = " << bandwidth_kbps 
              << " kbps, RTT = " << rtt_ms << " ms" << std::endl;
}

} // namespace quicsand

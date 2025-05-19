#include "quic_connection.hpp"
#include <iostream>
#include <chrono>

namespace quicsand {

// Helfer-Funktion, um regelmäßig das BBRv2-Modell zu aktualisieren
void QuicConnection::update_state_periodic() {
    if (!quiche_conn_) {
        return;
    }
    
    // Aktualisiere Congestion Control, wenn BBRv2 aktiviert ist
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 && bbr_) {
        update_congestion_window();
    }
    
    // MTU Discovery aktualisieren, falls aktiviert
    if (mtu_discovery_enabled_ && !in_search_phase_ && 
        current_mtu_ < max_mtu_ && 
        probe_counter_ < max_probe_attempts_) {
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_mtu_update_).count();
        
        // Periodisch MTU-Probes senden, wenn Zeit seit letztem Update verstrichen ist
        if (elapsed >= mtu_probe_interval_s_) {
            probe_next_mtu();
        }
    }
    
    // Prüfe, ob Verbindung Migration notwendig ist
    if (migration_enabled_) {
        check_network_changes();
    }
    
    // Prüfe auf abgelaufene Tokens, falls Zero-RTT aktiviert ist
    if (zero_rtt_manager_) {
        zero_rtt_manager_->clean_expired_tokens();
    }
}

// Hauptverarbeitungsschleife für eingehende Pakete mit Congestion Control
void QuicConnection::process_packet(const uint8_t* data, size_t len, const boost::asio::ip::udp::endpoint& remote_endpoint) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    
    if (!quiche_conn_) {
        std::cerr << "Cannot process packet: connection not initialized" << std::endl;
        return;
    }
    
    // Paket verarbeiten
    ssize_t recv_len = quiche_conn_recv(quiche_conn_, data, len, socket_addr_helpers::to_quiche_sockaddr(remote_endpoint));
    
    if (recv_len < 0) {
        // Fehler beim Paketempfang
        log_error("Failed to process packet: " + std::to_string(recv_len));
        return;
    }
    
    // Aktualisiere Statistiken
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_received += recv_len;
        stats_.packets_received++;
    }
    
    // Verarbeitete Bytes für FEC-Integration
    if (fec_enabled_ && fec_) {
        // Hier würde die FEC-Integration erfolgen
    }
    
    // Aktualisiere BBRv2 Congestion Control
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 && bbr_) {
        // Wir aktualisieren BBRv2 nur alle N Pakete für Effizienz
        if (stats_.packets_received % 5 == 0) {
            update_congestion_window();
        }
    }
    
    // Prüfe auf MTU-Probe-Antworten
    check_mtu_probes();
    
    // Sende ausstehende Pakete
    flush_egress();
    
    // Prüfe auf Verbindungsstatus-Änderungen
    check_connection_status();
}

// Aktualisiert das BBRv2-Modell basierend auf QUIC-Metriken
void QuicConnection::update_bbr_model() {
    if (!quiche_conn_ || !bbr_) {
        return;
    }
    
    uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // QUIC Metriken extrahieren
    const quiche_stats* stats = quiche_conn_stats(quiche_conn_);
    if (!stats) {
        return;
    }
    
    uint64_t rtt_us = stats->min_rtt;
    double bandwidth_bps = stats->est_bandwidth;
    uint64_t bytes_in_flight = stats->bytes_in_flight;
    uint64_t bytes_acked = 0; // Aus QUIC-Stats nicht direkt verfügbar
    uint64_t bytes_lost = stats->lost;
    
    // BBRv2-Modell aktualisieren
    bbr_->update(rtt_us, bandwidth_bps, bytes_in_flight, bytes_acked, bytes_lost, now_us);
    
    // Statistiken aktualisieren
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.congestion_window = bbr_->get_congestion_window();
        stats_.pacing_rate = bbr_->get_pacing_rate();
        stats_.bottleneck_bw = bbr_->get_bottleneck_bandwidth();
        stats_.min_rtt_us = bbr_->get_min_rtt();
    }
    
    // Logging
    if (debug_log_enabled_ && stats_.packets_received % 100 == 0) {
        std::cout << "BBRv2 state: " << static_cast<int>(bbr_->get_state()) 
                  << ", BW: " << (bbr_->get_bottleneck_bandwidth() / 1000000.0) << " Mbps" 
                  << ", RTT: " << (bbr_->get_min_rtt() / 1000.0) << " ms" << std::endl;
    }
}

} // namespace quicsand

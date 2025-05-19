#include "quic_connection.hpp"
#include <chrono>
#include <iostream>
#include <algorithm>
#include <random>
#include <cassert>

namespace quicsand {

// MTU Discovery Methoden
bool QuicConnection::enable_mtu_discovery(bool enable) {
    if (!quiche_conn_) {
        std::cerr << "Cannot enable MTU discovery without an active QUIC connection" << std::endl;
        return false;
    }
    
    if (enable && !mtu_discovery_enabled_) {
        std::cout << "Enabling MTU discovery (min=" << min_mtu_ << ", max=" << max_mtu_ 
                  << ", step=" << mtu_step_size_ << ")" << std::endl;
        
        // Initialisiere den Prozess
        mtu_discovery_enabled_ = true;
        current_mtu_ = min_mtu_; // Starte mit der minimalen MTU
        last_successful_mtu_ = min_mtu_;
        mtu_validated_ = false;
        plpmtu_ = min_mtu_;
        
        // Setze die MTU in der quiche-Verbindung
        if (quiche_conn_) {
            quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
        }
        
        // Starte den Discovery-Prozess
        start_mtu_discovery();
    } else if (!enable && mtu_discovery_enabled_) {
        std::cout << "Disabling MTU discovery, final MTU = " << current_mtu_ << std::endl;
        mtu_discovery_enabled_ = false;
        
        // Setze die MTU auf den letzten erfolgreichen Wert
        if (quiche_conn_) {
            quiche_conn_set_max_send_udp_payload_size(quiche_conn_, last_successful_mtu_);
        }
    }
    
    return true;
}

bool QuicConnection::is_mtu_discovery_enabled() const {
    return mtu_discovery_enabled_;
}

bool QuicConnection::set_mtu_size(uint16_t mtu_size) {
    if (mtu_size < min_mtu_ || mtu_size > max_mtu_) {
        std::cerr << "Invalid MTU size: " << mtu_size << ", must be between " 
                  << min_mtu_ << " and " << max_mtu_ << std::endl;
        return false;
    }
    
    std::cout << "Manually setting MTU size to " << mtu_size << std::endl;
    current_mtu_ = mtu_size;
    last_successful_mtu_ = mtu_size;
    
    // Setze die MTU in der quiche-Verbindung
    if (quiche_conn_) {
        quiche_conn_set_max_send_udp_payload_size(quiche_conn_, mtu_size);
    }
    
    return true;
}

uint16_t QuicConnection::get_mtu_size() const {
    return current_mtu_;
}

void QuicConnection::set_mtu_discovery_params(uint16_t min_mtu, uint16_t max_mtu, uint16_t step_size) {
    // Validiere die Parameter
    if (min_mtu < 576) {
        std::cerr << "Warning: min_mtu less than 576 bytes, setting to 576" << std::endl;
        min_mtu = 576; // Absolute minimale MTU laut RFC 791
    }
    
    if (max_mtu > 9000) {
        std::cerr << "Warning: max_mtu greater than 9000 bytes (jumbo frames), setting to 9000" << std::endl;
        max_mtu = 9000; // Jumbo-Frame-Obergrenze
    }
    
    if (min_mtu >= max_mtu) {
        std::cerr << "Error: min_mtu must be less than max_mtu, using defaults" << std::endl;
        min_mtu = 1200;
        max_mtu = 1500;
    }
    
    if (step_size < 1) {
        std::cerr << "Warning: step_size must be at least 1, setting to 10" << std::endl;
        step_size = 10;
    }
    
    min_mtu_ = min_mtu;
    max_mtu_ = max_mtu;
    mtu_step_size_ = step_size;
    
    std::cout << "MTU discovery parameters updated: min=" << min_mtu_ 
              << ", max=" << max_mtu_ << ", step=" << mtu_step_size_ << std::endl;
    
    // Wenn MTU-Discovery bereits aktiviert ist, setze den Prozess zurück
    if (mtu_discovery_enabled_) {
        reset_mtu_discovery();
    }
}

// Private MTU Discovery Hilfsmethoden

void QuicConnection::start_mtu_discovery() {
    if (!mtu_discovery_enabled_ || !quiche_conn_) {
        return;
    }
    
    std::cout << "Starting MTU discovery process..." << std::endl;
    
    // Setze den Suchstatus zurück
    in_search_phase_ = true;
    consecutive_failures_ = 0;
    current_probe_mtu_ = current_mtu_ + mtu_step_size_;
    
    // Stelle sicher, dass die Probe-MTU nicht größer als die maximale MTU ist
    current_probe_mtu_ = std::min(current_probe_mtu_, max_mtu_);
    
    // Starte mit einem Probe-Paket
    schedule_next_probe();
}

void QuicConnection::send_mtu_probe(uint16_t probe_size) {
    if (!quiche_conn_ || !mtu_discovery_enabled_ || !in_search_phase_) {
        return;
    }
    
    std::cout << "Sending MTU probe packet with size " << probe_size << " bytes" << std::endl;
    
    // Erstelle ein spezielles MTU-Probe-Paket
    // In QUIC werden PING-Frames für diesen Zweck verwendet
    
    // Erstelle ein Ping-Frame mit speziellen Daten, um es als MTU-Probe zu identifizieren
    // QUIC PING Frame (Typ 0x01) + Padding bis zur gewünschten Größe
    
    std::vector<uint8_t> probe_data;
    
    // Ping-Frame-Typ
    probe_data.push_back(0x01);
    
    // Füge eine spezielle Kennung hinzu, damit wir das Paket als MTU-Probe erkennen können
    const char* probe_marker = "MTU_PROBE";
    probe_data.insert(probe_data.end(), probe_marker, probe_marker + strlen(probe_marker));
    
    // Füge Padding hinzu, um die gewünschte Größe zu erreichen
    size_t padding_needed = probe_size - probe_data.size();
    if (padding_needed > 0) {
        // QUIC PADDING Frame (Typ 0x00)
        probe_data.push_back(0x00);
        
        // Füge Nullen als Padding hinzu
        probe_data.insert(probe_data.end(), padding_needed - 1, 0);
    }
    
    // Sende das Paket über QUIC
    // Da wir direkten Zugriff auf den QUIC-Stack haben, verwenden wir die QUIC-API
    
    // Erstelle QUIC-Frames für das Ping und Padding
    uint8_t* out = send_buf_.data();
    size_t out_len = send_buf_.size();
    
    // Erstelle eine send_info-Struktur
    quiche_send_info send_info;
    memset(&send_info, 0, sizeof(send_info));
    
    // Verwende quiche_conn_send mit einem temporär erhöhten MTU-Wert
    uint16_t original_mtu = quiche_conn_get_max_send_udp_payload_size(quiche_conn_);
    quiche_conn_set_max_send_udp_payload_size(quiche_conn_, probe_size);
    
    // Schreibe einen PING-Frame
    if (quiche_conn_send_ping(quiche_conn_) != 0) {
        std::cerr << "Failed to send PING frame for MTU probe" << std::endl;
        quiche_conn_set_max_send_udp_payload_size(quiche_conn_, original_mtu);
        return;
    }
    
    // Sende das Paket
    ssize_t written = quiche_conn_send(quiche_conn_, out, out_len, &send_info);
    
    // Setze die MTU zurück
    quiche_conn_set_max_send_udp_payload_size(quiche_conn_, original_mtu);
    
    if (written > 0) {
        // Sende das Paket über den UDP-Socket
        try {
            boost::system::error_code ec;
            socket_.send_to(boost::asio::buffer(out, static_cast<size_t>(written)), 
                           remote_endpoint_, 0, ec);
            
            if (ec) {
                std::cerr << "Failed to send MTU probe: " << ec.message() << std::endl;
                handle_mtu_probe_response(false);
            } else {
                // Speichere den Zeitpunkt des Sendens
                last_probe_time_ = std::chrono::steady_clock::now();
                
                // Der Erfolg wird später in handle_packet() oder bei einem Timeout geprüft
            }
        } catch (const std::exception& e) {
            std::cerr << "Exception while sending MTU probe: " << e.what() << std::endl;
            handle_mtu_probe_response(false);
        }
    } else {
        std::cerr << "Failed to create MTU probe packet, error code: " << written << std::endl;
        handle_mtu_probe_response(false);
    }
}

void QuicConnection::handle_mtu_probe_response(bool success) {
    if (!mtu_discovery_enabled_ || !in_search_phase_) {
        return;
    }
    
    if (success) {
        std::cout << "MTU probe successful for size " << current_probe_mtu_ << " bytes" << std::endl;
        
        // Erfolgreiche Probe, aktualisiere die MTU
        last_successful_mtu_ = current_probe_mtu_;
        consecutive_failures_ = 0;
        
        // Wenn wir die Ziel-MTU erreicht haben, validieren wir sie
        if (current_probe_mtu_ >= target_mtu_ || current_probe_mtu_ >= max_mtu_) {
            std::cout << "Reached target MTU " << current_probe_mtu_ << ", validating..." << std::endl;
            mtu_validated_ = true;
            plpmtu_ = current_probe_mtu_;
            current_mtu_ = current_probe_mtu_;
            
            // Setze die validierte MTU in der QUIC-Verbindung
            if (quiche_conn_) {
                quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
            }
            
            // Beende die Suchphase
            in_search_phase_ = false;
        } else {
            // Versuche eine größere MTU
            current_probe_mtu_ += mtu_step_size_;
            current_probe_mtu_ = std::min(current_probe_mtu_, max_mtu_);
            
            // Plane den nächsten Probe-Versuch
            schedule_next_probe();
        }
    } else {
        std::cout << "MTU probe failed for size " << current_probe_mtu_ << " bytes" << std::endl;
        
        // Fehlgeschlagene Probe, erhöhe den Zähler für aufeinanderfolgende Fehlschläge
        consecutive_failures_++;
        
        // Prüfe auf Blackhole
        if (is_blackhole_detected()) {
            std::cerr << "MTU blackhole detected at " << current_probe_mtu_ << " bytes, "
                      << "reverting to last successful MTU: " << last_successful_mtu_ << std::endl;
            
            // Setze die MTU auf den letzten erfolgreichen Wert
            current_mtu_ = last_successful_mtu_;
            plpmtu_ = last_successful_mtu_;
            
            // Setze die MTU in der QUIC-Verbindung
            if (quiche_conn_) {
                quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
            }
            
            // Beende die Suchphase
            in_search_phase_ = false;
            mtu_validated_ = true;
        } else {
            // Versuche eine kleinere MTU zwischen der aktuellen und der letzten erfolgreichen
            uint16_t range = current_probe_mtu_ - last_successful_mtu_;
            
            if (range <= mtu_step_size_) {
                // Wenn der Bereich zu klein ist, nehmen wir den letzten erfolgreichen Wert
                current_probe_mtu_ = last_successful_mtu_;
                mtu_validated_ = true;
                plpmtu_ = last_successful_mtu_;
                current_mtu_ = last_successful_mtu_;
                
                // Setze die MTU in der QUIC-Verbindung
                if (quiche_conn_) {
                    quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
                }
                
                // Beende die Suchphase
                in_search_phase_ = false;
            } else {
                // Versuche einen Wert in der Mitte
                current_probe_mtu_ = last_successful_mtu_ + (range / 2);
                
                // Plane den nächsten Probe-Versuch
                schedule_next_probe();
            }
        }
    }
}

void QuicConnection::update_mtu(uint16_t new_mtu) {
    if (new_mtu < min_mtu_ || new_mtu > max_mtu_) {
        std::cerr << "Invalid MTU update: " << new_mtu << ", must be between " 
                  << min_mtu_ << " and " << max_mtu_ << std::endl;
        return;
    }
    
    std::cout << "Updating MTU from " << current_mtu_ << " to " << new_mtu << std::endl;
    current_mtu_ = new_mtu;
    
    // Setze die MTU in der QUIC-Verbindung
    if (quiche_conn_) {
        quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
    }
    
    // Aktualisiere Statistiken
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.current_mtu = current_mtu_;
}

void QuicConnection::reset_mtu_discovery() {
    std::cout << "Resetting MTU discovery process" << std::endl;
    
    // Setze den Prozess zurück
    in_search_phase_ = false;
    mtu_validated_ = false;
    consecutive_failures_ = 0;
    
    // Starte mit der minimalen MTU
    current_mtu_ = min_mtu_;
    last_successful_mtu_ = min_mtu_;
    plpmtu_ = min_mtu_;
    
    // Setze die MTU in der QUIC-Verbindung
    if (quiche_conn_) {
        quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
    }
    
    // Starte den Discovery-Prozess neu
    if (mtu_discovery_enabled_) {
        start_mtu_discovery();
    }
}

bool QuicConnection::is_blackhole_detected() {
    // Wenn mehrere aufeinanderfolgende Probes fehlschlagen, könnte ein Blackhole vorliegen
    // Ein Blackhole ist ein Netzwerkpfad, der Pakete ab einer bestimmten Größe verwirft
    return consecutive_failures_ >= blackhole_detection_threshold_;
}

void QuicConnection::schedule_next_probe() {
    // Diese Methode plant den nächsten MTU-Probe-Versuch
    // In einer asynchronen Implementierung könnten wir hier einen Timer verwenden
    
    // In dieser einfachen Implementierung senden wir den Probe direkt
    // In einer realen Implementierung sollten wir einen Timer verwenden
    
    if (!mtu_discovery_enabled_ || !in_search_phase_) {
        return;
    }
    
    // Sende den MTU-Probe
    send_mtu_probe(current_probe_mtu_);
}

} // namespace quicsand

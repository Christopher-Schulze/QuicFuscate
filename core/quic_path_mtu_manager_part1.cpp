#include "quic_path_mtu_manager.hpp"
#include "quic_connection.hpp"
#include <iostream>
#include <algorithm>
#include <random>
#include <cassert>

namespace quicsand {

// Konstruktor
PathMtuManager::PathMtuManager(QuicConnection& connection, 
                            uint16_t min_mtu, 
                            uint16_t max_mtu, 
                            uint16_t step_size,
                            uint8_t blackhole_threshold)
    : connection_(connection),
      bidirectional_enabled_(false),
      blackhole_detection_threshold_(blackhole_threshold),
      last_adaptive_check_(std::chrono::steady_clock::now()) {
    
    // Validiere MTU-Parameter
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
    
    // Initialisiere Zustände für beide Pfade
    outgoing_path_.current_mtu = min_mtu;
    outgoing_path_.last_successful_mtu = min_mtu;
    outgoing_path_.current_probe_mtu = min_mtu + step_size;
    outgoing_path_.min_mtu = min_mtu;
    outgoing_path_.max_mtu = max_mtu;
    outgoing_path_.step_size = step_size;
    outgoing_path_.in_search_phase = false;
    outgoing_path_.mtu_validated = false;
    outgoing_path_.consecutive_failures = 0;
    outgoing_path_.status = MtuStatus::UNKNOWN;
    outgoing_path_.last_probe_time = std::chrono::steady_clock::time_point::min();
    
    incoming_path_.current_mtu = min_mtu;
    incoming_path_.last_successful_mtu = min_mtu;
    incoming_path_.current_probe_mtu = min_mtu + step_size;
    incoming_path_.min_mtu = min_mtu;
    incoming_path_.max_mtu = max_mtu;
    incoming_path_.step_size = step_size;
    incoming_path_.in_search_phase = false;
    incoming_path_.mtu_validated = false;
    incoming_path_.consecutive_failures = 0;
    incoming_path_.status = MtuStatus::UNKNOWN;
    incoming_path_.last_probe_time = std::chrono::steady_clock::time_point::min();
}

PathMtuManager::~PathMtuManager() = default;

bool PathMtuManager::enable_bidirectional_discovery(bool enable) {
    // Aktiviere oder deaktiviere bidirektionale MTU Discovery
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (enable == bidirectional_enabled_) {
        // Keine Änderung notwendig
        return true;
    }
    
    bidirectional_enabled_ = enable;
    
    if (enable) {
        std::cout << "Enabling bidirectional MTU discovery" << std::endl;
        
        // Starte Discovery für beide Pfade
        outgoing_path_.current_mtu = outgoing_path_.min_mtu;
        outgoing_path_.last_successful_mtu = outgoing_path_.min_mtu;
        outgoing_path_.status = MtuStatus::UNKNOWN;
        outgoing_path_.in_search_phase = false;
        outgoing_path_.mtu_validated = false;
        
        incoming_path_.current_mtu = incoming_path_.min_mtu;
        incoming_path_.last_successful_mtu = incoming_path_.min_mtu;
        incoming_path_.status = MtuStatus::UNKNOWN;
        incoming_path_.in_search_phase = false;
        incoming_path_.mtu_validated = false;
        
        // Aktualisiere die QUIC-Verbindung
        connection_.set_mtu_size(outgoing_path_.current_mtu);
        
        // Starte mit ausgehender Discovery, eingehende startet nach erfolgreicher Validierung
        start_discovery(outgoing_path_, false);
    } else {
        std::cout << "Disabling bidirectional MTU discovery" << std::endl;
        
        // Stoppe Discovery für beide Pfade
        outgoing_path_.in_search_phase = false;
        incoming_path_.in_search_phase = false;
        
        // Setze MTU auf validierte Werte oder Minimum
        uint16_t outgoing_mtu = outgoing_path_.mtu_validated ? 
                              outgoing_path_.current_mtu : outgoing_path_.min_mtu;
        
        // Aktualisiere die QUIC-Verbindung
        connection_.set_mtu_size(outgoing_mtu);
        
        // Leere die ausstehenden Proben
        pending_outgoing_probes_.clear();
        pending_incoming_probes_.clear();
    }
    
    return true;
}

bool PathMtuManager::is_bidirectional_discovery_enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bidirectional_enabled_;
}

bool PathMtuManager::set_mtu_size(uint16_t mtu_size, bool apply_both) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validiere MTU-Größe
    if (mtu_size < outgoing_path_.min_mtu || mtu_size > outgoing_path_.max_mtu) {
        std::cerr << "Invalid MTU size: " << mtu_size << ", must be between " 
                << outgoing_path_.min_mtu << " and " << outgoing_path_.max_mtu << std::endl;
        return false;
    }
    
    std::cout << "Manually setting outgoing MTU size to " << mtu_size << std::endl;
    
    // Aktualisiere ausgehende MTU
    bool triggered_by_probe = false;
    handle_mtu_change(outgoing_path_, mtu_size, false, triggered_by_probe);
    
    // Aktualisiere eingehende MTU, falls gewünscht
    if (apply_both && bidirectional_enabled_) {
        std::cout << "Also setting incoming MTU size to " << mtu_size << std::endl;
        handle_mtu_change(incoming_path_, mtu_size, true, triggered_by_probe);
    }
    
    // Aktualisiere die QUIC-Verbindung
    connection_.set_mtu_size(outgoing_path_.current_mtu);
    
    return true;
}

uint16_t PathMtuManager::get_outgoing_mtu() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return outgoing_path_.current_mtu;
}

uint16_t PathMtuManager::get_incoming_mtu() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return incoming_path_.current_mtu;
}

void PathMtuManager::set_discovery_params(uint16_t min_mtu, uint16_t max_mtu, uint16_t step_size, bool apply_both) {
    std::lock_guard<std::mutex> lock(mutex_);
    
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
    
    std::cout << "Setting MTU discovery parameters: min=" << min_mtu 
              << ", max=" << max_mtu << ", step=" << step_size << std::endl;
    
    // Aktualisiere Parameter für ausgehenden Pfad
    outgoing_path_.min_mtu = min_mtu;
    outgoing_path_.max_mtu = max_mtu;
    outgoing_path_.step_size = step_size;
    
    // Aktualisiere auch Parameter für eingehenden Pfad, falls gewünscht
    if (apply_both) {
        incoming_path_.min_mtu = min_mtu;
        incoming_path_.max_mtu = max_mtu;
        incoming_path_.step_size = step_size;
    }
    
    // Wenn MTU Discovery bereits aktiviert ist, setze den Prozess zurück
    if (bidirectional_enabled_) {
        outgoing_path_.current_mtu = outgoing_path_.min_mtu;
        outgoing_path_.last_successful_mtu = outgoing_path_.min_mtu;
        outgoing_path_.status = MtuStatus::UNKNOWN;
        outgoing_path_.in_search_phase = false;
        outgoing_path_.mtu_validated = false;
        
        if (apply_both) {
            incoming_path_.current_mtu = incoming_path_.min_mtu;
            incoming_path_.last_successful_mtu = incoming_path_.min_mtu;
            incoming_path_.status = MtuStatus::UNKNOWN;
            incoming_path_.in_search_phase = false;
            incoming_path_.mtu_validated = false;
        }
        
        // Aktualisiere die QUIC-Verbindung
        connection_.set_mtu_size(outgoing_path_.current_mtu);
        
        // Starte mit ausgehender Discovery
        start_discovery(outgoing_path_, false);
    }
}

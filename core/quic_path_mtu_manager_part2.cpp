// Teil 2 der PathMtuManager Implementierung
// Adaptive MTU und Probe-Verarbeitung

void PathMtuManager::adapt_mtu_dynamically(float packet_loss_rate, uint32_t rtt_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_adaptive_check_);
    
    // Prüfe, ob es Zeit für eine Anpassung ist
    if (elapsed < adaptive_check_interval_) {
        return;
    }
    
    last_adaptive_check_ = now;
    
    // Wenn die MTU nicht validiert ist oder wir in einer Suchphase sind, überspringen
    if (!outgoing_path_.mtu_validated || outgoing_path_.in_search_phase) {
        return;
    }
    
    // Adaptive Strategie basierend auf Netzwerkbedingungen
    // Bei hohem Paketverlust oder hohem RTT reduzieren wir die MTU
    bool should_decrease = false;
    bool should_increase = false;
    
    if (packet_loss_rate > 0.05f) { // Über 5% Paketverlust
        // Reduziere MTU um einen Schritt, wenn die Verlustrate zu hoch ist
        should_decrease = true;
        std::cout << "High packet loss rate (" << packet_loss_rate * 100.0f 
                  << "%), considering MTU reduction" << std::endl;
    } else if (packet_loss_rate < 0.01f && rtt_ms < 100) { // Niedriger Verlust und RTT
        // Versuche die MTU zu erhöhen, wenn die Bedingungen gut sind
        should_increase = true;
        std::cout << "Good network conditions, considering MTU increase" << std::endl;
    }
    
    if (should_decrease && outgoing_path_.current_mtu > outgoing_path_.min_mtu) {
        // Reduziere die MTU um einen Schritt
        uint16_t new_mtu = std::max(outgoing_path_.current_mtu - outgoing_path_.step_size, 
                                   outgoing_path_.min_mtu);
        
        std::cout << "Dynamically decreasing MTU from " << outgoing_path_.current_mtu 
                  << " to " << new_mtu << " due to poor network conditions" << std::endl;
        
        handle_mtu_change(outgoing_path_, new_mtu, false, false);
        
        // Aktualisiere QUIC-Verbindung
        connection_.set_mtu_size(outgoing_path_.current_mtu);
    } else if (should_increase && outgoing_path_.current_mtu < outgoing_path_.max_mtu) {
        // Starte eine Probe für eine höhere MTU
        outgoing_path_.current_probe_mtu = outgoing_path_.current_mtu + outgoing_path_.step_size;
        outgoing_path_.current_probe_mtu = std::min(outgoing_path_.current_probe_mtu, outgoing_path_.max_mtu);
        
        std::cout << "Dynamically probing larger MTU " << outgoing_path_.current_probe_mtu 
                  << " due to good network conditions" << std::endl;
        
        // Sende eine Probe-Anfrage
        send_probe(outgoing_path_.current_probe_mtu, false);
    }
}

void PathMtuManager::handle_probe_response(uint32_t probe_id, bool success, bool is_incoming) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Je nachdem, ob es sich um eine eingehende oder ausgehende Probe handelt
    auto& probe_map = is_incoming ? pending_incoming_probes_ : pending_outgoing_probes_;
    auto& path_state = is_incoming ? incoming_path_ : outgoing_path_;
    
    // Probe in der Map suchen
    auto it = probe_map.find(probe_id);
    if (it == probe_map.end()) {
        // Unbekannte Probe, ignorieren
        std::cerr << "Received response for unknown probe ID: " << probe_id << std::endl;
        return;
    }
    
    uint16_t probe_size = it->second;
    probe_map.erase(it);
    
    std::cout << "Received " << (success ? "successful" : "failed") << " response for "
              << (is_incoming ? "incoming" : "outgoing") << " MTU probe "
              << probe_id << " (size: " << probe_size << ")" << std::endl;
    
    if (success) {
        // Erfolgreiche Probe
        if (probe_size > path_state.last_successful_mtu) {
            // Update zu größerer MTU
            path_state.last_successful_mtu = probe_size;
            
            // Bei ausgehender MTU aktualisieren wir die tatsächliche MTU sofort
            if (!is_incoming) {
                std::cout << "Updating outgoing MTU to " << probe_size << std::endl;
                handle_mtu_change(path_state, probe_size, is_incoming, true);
                
                // Aktualisiere QUIC-Verbindung
                connection_.set_mtu_size(path_state.current_mtu);
            }
        }
        
        // Erfolg zurücksetzen
        path_state.consecutive_failures = 0;
        
        // Wenn wir in der Suchphase sind, nächste Probe planen
        if (path_state.in_search_phase) {
            // Versuche eine größere MTU, falls nicht am Maximum
            if (probe_size < path_state.max_mtu) {
                path_state.current_probe_mtu = probe_size + path_state.step_size;
                path_state.current_probe_mtu = std::min(path_state.current_probe_mtu, path_state.max_mtu);
                
                std::cout << "Planning next " << (is_incoming ? "incoming" : "outgoing") 
                          << " probe with size " << path_state.current_probe_mtu << std::endl;
                
                // Sende nächste Probe
                send_probe(path_state.current_probe_mtu, is_incoming);
            } else {
                // Maximal unterstützte MTU erreicht
                std::cout << "Reached maximum " << (is_incoming ? "incoming" : "outgoing") 
                          << " MTU: " << probe_size << std::endl;
                
                path_state.mtu_validated = true;
                path_state.in_search_phase = false;
                path_state.status = MtuStatus::VALIDATED;
                
                // Wenn ausgehende MTU validiert und bidirektionale Discovery aktiviert,
                // starte die eingehende Discovery, falls noch nicht geschehen
                if (!is_incoming && bidirectional_enabled_ && !incoming_path_.in_search_phase) {
                    std::cout << "Starting incoming path MTU discovery" << std::endl;
                    start_discovery(incoming_path_, true);
                }
            }
        }
    } else {
        // Fehlgeschlagene Probe
        path_state.consecutive_failures++;
        
        // Prüfe auf Blackhole
        if (detect_blackhole(path_state)) {
            std::cout << "MTU blackhole detected for " << (is_incoming ? "incoming" : "outgoing") 
                      << " path at " << probe_size << " bytes. Reverting to last successful: " 
                      << path_state.last_successful_mtu << std::endl;
            
            // Setze Status auf BLACKHOLE
            path_state.status = MtuStatus::BLACKHOLE;
            path_state.in_search_phase = false;
            
            // Bei ausgehender MTU: setze auf letzten erfolgreichen Wert
            if (!is_incoming) {
                handle_mtu_change(path_state, path_state.last_successful_mtu, is_incoming, false);
                
                // Aktualisiere QUIC-Verbindung
                connection_.set_mtu_size(path_state.current_mtu);
            }
        } else if (path_state.in_search_phase) {
            // Versuche eine Probe zwischen aktuellem Wert und letzter erfolgreicher MTU
            uint16_t range = probe_size - path_state.last_successful_mtu;
            
            if (range <= path_state.step_size) {
                // Wenn der Bereich zu klein ist, stoppe die Suche und verwende den letzten erfolgreichen Wert
                std::cout << "No viable MTU found between " << path_state.last_successful_mtu 
                          << " and " << probe_size << ", using last successful: " 
                          << path_state.last_successful_mtu << std::endl;
                
                path_state.status = MtuStatus::VALIDATED;
                path_state.in_search_phase = false;
                path_state.mtu_validated = true;
                
                // Bei ausgehender MTU aktualisiere die tatsächliche MTU
                if (!is_incoming) {
                    handle_mtu_change(path_state, path_state.last_successful_mtu, is_incoming, false);
                    
                    // Aktualisiere QUIC-Verbindung
                    connection_.set_mtu_size(path_state.current_mtu);
                }
                
                // Wenn ausgehende MTU validiert und bidirektional aktiviert, starte eingehende Discovery
                if (!is_incoming && bidirectional_enabled_ && !incoming_path_.in_search_phase) {
                    std::cout << "Starting incoming path MTU discovery" << std::endl;
                    start_discovery(incoming_path_, true);
                }
            } else {
                // Versuche einen Wert in der Mitte
                uint16_t next_probe = path_state.last_successful_mtu + (range / 2);
                path_state.current_probe_mtu = next_probe;
                
                std::cout << "Trying intermediate " << (is_incoming ? "incoming" : "outgoing") 
                          << " probe size: " << next_probe << std::endl;
                
                // Sende nächste Probe
                send_probe(next_probe, is_incoming);
            }
        }
    }
}

void PathMtuManager::handle_incoming_probe(uint32_t probe_id, uint16_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "Received incoming MTU probe ID " << probe_id << " with size " << size << std::endl;
    
    // Prüfe, ob wir eine Probe dieser Größe verarbeiten können
    bool success = size <= incoming_path_.max_mtu;
    
    // Wenn erfolgreich, aktualisiere eingehende MTU
    if (success && size > incoming_path_.current_mtu) {
        std::cout << "Updating incoming MTU from " << incoming_path_.current_mtu << " to " << size << std::endl;
        handle_mtu_change(incoming_path_, size, true, true);
    }
    
    // Sende eine Antwort zum Client zurück
    // In einem echten System sollte dies über den QUIC-Stack erfolgen
    std::cout << "Sending probe response (success=" << (success ? "true" : "false") 
              << ") for probe ID " << probe_id << std::endl;
    
    // Hier würde die Antwort zurückgesendet werden
    // zum Beispiel über einen speziellen QUIC-Frame-Typ
}

// Teil 3 der PathMtuManager Implementierung
// Hilfsmethoden und Update-Funktionen

void PathMtuManager::update(const std::chrono::steady_clock::time_point& now) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!bidirectional_enabled_) {
        return;
    }
    
    // Prüfe auf Timeouts bei ausstehenden Proben
    check_probe_timeouts(now);
    
    // Periodische Probes bei validierter MTU
    if (outgoing_path_.mtu_validated && !outgoing_path_.in_search_phase) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - outgoing_path_.last_probe_time);
        
        if (elapsed > periodic_probe_interval_) {
            // Sende gelegentlich Proben, um Veränderungen zu erkennen
            std::cout << "Sending periodic outgoing MTU probe to check for path changes" << std::endl;
            
            // Sende Probe mit aktueller MTU, um zu validieren
            send_probe(outgoing_path_.current_mtu, false);
            
            // Wenn die aktuelle MTU nicht dem Maximum entspricht, probiere eine höhere
            if (outgoing_path_.current_mtu < outgoing_path_.max_mtu) {
                uint16_t next_probe = outgoing_path_.current_mtu + outgoing_path_.step_size;
                next_probe = std::min(next_probe, outgoing_path_.max_mtu);
                
                std::cout << "Also probing larger MTU: " << next_probe << std::endl;
                send_probe(next_probe, false);
            }
        }
    }
    
    // Ähnlich für eingehende MTU, wenn bidirektionale Discovery aktiviert ist
    if (bidirectional_enabled_ && incoming_path_.mtu_validated && !incoming_path_.in_search_phase) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - incoming_path_.last_probe_time);
        
        if (elapsed > periodic_probe_interval_) {
            std::cout << "Sending periodic incoming MTU probe to check for path changes" << std::endl;
            
            // Sende Probe mit aktueller MTU, um zu validieren
            send_probe(incoming_path_.current_mtu, true);
        }
    }
}

MtuStatus PathMtuManager::get_mtu_status(bool is_incoming) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const PathMtuState& path = is_incoming ? incoming_path_ : outgoing_path_;
    return path.status;
}

void PathMtuManager::set_mtu_change_callback(std::function<void(const MtuChange&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    mtu_change_callback_ = callback;
}

bool PathMtuManager::is_mtu_unstable() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Wir betrachten die MTU als instabil, wenn mehr als 3 Änderungen in den letzten 5 Minuten aufgetreten sind
    const auto& changes = outgoing_path_.recent_changes;
    if (changes.size() < 3) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    size_t recent_changes = 0;
    
    // Zähle Änderungen in den letzten 5 Minuten
    for (const auto& change : changes) {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - change.timestamp);
        if (elapsed.count() < 5) {
            recent_changes++;
        }
    }
    
    return recent_changes >= 3;
}

// Private Hilfsmethoden

void PathMtuManager::start_discovery(PathMtuState& state, bool is_incoming) {
    if (!bidirectional_enabled_ && is_incoming) {
        return; // Ignoriere eingehende Discovery, wenn nicht bidirektional
    }
    
    std::cout << "Starting " << (is_incoming ? "incoming" : "outgoing") 
              << " path MTU discovery (min=" << state.min_mtu << ", max=" << state.max_mtu
              << ", step=" << state.step_size << ")" << std::endl;
    
    // Setze den Discovery-Status zurück
    state.in_search_phase = true;
    state.mtu_validated = false;
    state.consecutive_failures = 0;
    state.status = MtuStatus::SEARCHING;
    
    // Beginne mit der Mindest-MTU
    state.current_mtu = state.min_mtu;
    state.last_successful_mtu = state.min_mtu;
    
    // Setze die erste Probe-MTU
    state.current_probe_mtu = state.min_mtu + state.step_size;
    state.current_probe_mtu = std::min(state.current_probe_mtu, state.max_mtu);
    
    // Bei ausgehender MTU, aktualisiere die QUIC-Verbindung
    if (!is_incoming) {
        connection_.set_mtu_size(state.current_mtu);
    }
    
    // Sende erste Probe
    send_probe(state.current_probe_mtu, is_incoming);
}

uint32_t PathMtuManager::send_probe(uint16_t size, bool is_incoming) {
    if (size < 576 || size > 9000) {
        std::cerr << "Invalid MTU probe size: " << size << std::endl;
        return 0;
    }
    
    uint32_t probe_id = generate_probe_id();
    
    std::cout << "Sending " << (is_incoming ? "incoming" : "outgoing") 
              << " MTU probe ID " << probe_id << " with size " << size << std::endl;
    
    // Speichere Probe in ausstehenden Proben
    auto& probe_map = is_incoming ? pending_incoming_probes_ : pending_outgoing_probes_;
    probe_map[probe_id] = size;
    
    // Aktualisiere Zeitpunkt der letzten Probe
    auto& path = is_incoming ? incoming_path_ : outgoing_path_;
    path.last_probe_time = std::chrono::steady_clock::now();
    
    // Erstelle Probe-Paket
    std::vector<uint8_t> probe = create_probe_packet(probe_id, size, true);
    
    if (probe.empty()) {
        std::cerr << "Failed to create probe packet" << std::endl;
        probe_map.erase(probe_id);
        return 0;
    }
    
    // In einer echten Implementierung würden wir hier das Paket senden
    // Über den QUIC-Stack mit einem speziellen Frame-Typ für MTU-Proben
    
    // Für diese Implementierung simulieren wir das Senden
    // und nehmen an, dass die andere Seite antworten wird
    
    return probe_id;
}

void PathMtuManager::handle_mtu_change(PathMtuState& state, uint16_t new_mtu, bool is_incoming, bool triggered_by_probe) {
    if (new_mtu == state.current_mtu) {
        return; // Keine Änderung
    }
    
    std::cout << "MTU change for " << (is_incoming ? "incoming" : "outgoing") 
              << " path: " << state.current_mtu << " -> " << new_mtu << std::endl;
    
    // Erstelle MTU-Änderungsereignis
    MtuChange change;
    change.old_mtu = state.current_mtu;
    change.new_mtu = new_mtu;
    change.timestamp = std::chrono::steady_clock::now();
    change.triggered_by_probe = triggered_by_probe;
    
    // Aktualisiere MTU
    state.current_mtu = new_mtu;
    
    // Aktualisiere MTU-Stabilität
    update_stability_tracking(state, new_mtu, triggered_by_probe);
    
    // Rufe Callback auf, falls registriert
    if (mtu_change_callback_) {
        mtu_change_callback_(change);
    }
}

bool PathMtuManager::detect_blackhole(const PathMtuState& state) const {
    // Blackhole erkannt, wenn mehrere aufeinanderfolgende Proben fehlschlagen
    return state.consecutive_failures >= blackhole_detection_threshold_;
}

uint32_t PathMtuManager::generate_probe_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dist(1, std::numeric_limits<uint32_t>::max());
    
    return dist(gen);
}

void PathMtuManager::update_stability_tracking(PathMtuState& state, uint16_t new_mtu, bool triggered_by_probe) {
    // Aktualisiere Liste der kürzlichen Änderungen
    MtuChange change;
    change.old_mtu = state.current_mtu;
    change.new_mtu = new_mtu;
    change.timestamp = std::chrono::steady_clock::now();
    change.triggered_by_probe = triggered_by_probe;
    
    state.recent_changes.push_back(change);
    
    // Begrenze die Anzahl der gespeicherten Änderungen
    const size_t max_changes = 10;
    if (state.recent_changes.size() > max_changes) {
        state.recent_changes.erase(state.recent_changes.begin());
    }
    
    // Prüfe auf Instabilität - häufige Änderungen in kurzer Zeit
    auto now = std::chrono::steady_clock::now();
    size_t changes_in_last_minute = 0;
    
    for (const auto& c : state.recent_changes) {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - c.timestamp);
        if (elapsed.count() < 1) {
            changes_in_last_minute++;
        }
    }
    
    // Wenn mehr als 3 Änderungen in der letzten Minute, markiere als instabil
    if (changes_in_last_minute >= 3) {
        std::cout << "MTU path appears unstable with " << changes_in_last_minute 
                  << " changes in the last minute" << std::endl;
        state.status = MtuStatus::UNSTABLE;
    }
}

void PathMtuManager::check_probe_timeouts(const std::chrono::steady_clock::time_point& now) {
    // Prüfe auf Timeouts bei ausgehenden Proben
    auto outgoing_it = pending_outgoing_probes_.begin();
    while (outgoing_it != pending_outgoing_probes_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - outgoing_path_.last_probe_time);
        
        if (elapsed > probe_timeout_) {
            // Timeout - behandle als Fehlschlag
            std::cout << "Timeout for outgoing probe ID " << outgoing_it->first 
                      << " (size: " << outgoing_it->second << ")" << std::endl;
            
            uint32_t probe_id = outgoing_it->first;
            outgoing_it = pending_outgoing_probes_.erase(outgoing_it);
            
            // Behandle Fehlschlag
            handle_probe_response(probe_id, false, false);
        } else {
            ++outgoing_it;
        }
    }
    
    // Prüfe auf Timeouts bei eingehenden Proben
    auto incoming_it = pending_incoming_probes_.begin();
    while (incoming_it != pending_incoming_probes_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - incoming_path_.last_probe_time);
        
        if (elapsed > probe_timeout_) {
            // Timeout - behandle als Fehlschlag
            std::cout << "Timeout for incoming probe ID " << incoming_it->first 
                      << " (size: " << incoming_it->second << ")" << std::endl;
            
            uint32_t probe_id = incoming_it->first;
            incoming_it = pending_incoming_probes_.erase(incoming_it);
            
            // Behandle Fehlschlag
            handle_probe_response(probe_id, false, true);
        } else {
            ++incoming_it;
        }
    }
}

std::vector<uint8_t> PathMtuManager::create_probe_packet(uint32_t probe_id, uint16_t size, bool is_request) {
    // In einer echten Implementierung würden wir hier ein spezielles MTU-Probe-Paket erstellen
    // Für diese Simulation erstellen wir einen einfachen Byte-Vektor
    
    std::vector<uint8_t> packet;
    
    // Mindestgröße für ein sinnvolles Paket
    const size_t min_header_size = 16;
    
    if (size < min_header_size) {
        return {}; // Zu klein für ein gültiges Paket
    }
    
    // Header-Typ: 0x77 für MTU Probe Request, 0x78 für MTU Probe Response
    packet.push_back(is_request ? 0x77 : 0x78);
    
    // Probe-ID (4 Bytes)
    packet.push_back(static_cast<uint8_t>((probe_id >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((probe_id >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((probe_id >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(probe_id & 0xFF));
    
    // Probe-Größe (2 Bytes)
    packet.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(size & 0xFF));
    
    // Zeitstempel (8 Bytes)
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    for (int i = 7; i >= 0; --i) {
        packet.push_back(static_cast<uint8_t>((now_ms >> (i * 8)) & 0xFF));
    }
    
    // Fülle mit 0x00 auf bis zur gewünschten Größe
    size_t padding_size = size - packet.size();
    packet.insert(packet.end(), padding_size, 0x00);
    
    return packet;
}

} // namespace quicsand

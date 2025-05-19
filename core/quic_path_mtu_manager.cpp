// Automatisch zusammengeführte Datei aus den Teil-Implementierungen
// Erstellt am Sun May 18 17:38:03 CEST 2025


// --- Beginn von core/quic_path_mtu_manager_part1.cpp ---

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

// --- Ende von core/quic_path_mtu_manager_part1.cpp ---


// --- Beginn von core/quic_path_mtu_manager_part2.cpp ---

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

// --- Ende von core/quic_path_mtu_manager_part2.cpp ---


// --- Beginn von core/quic_path_mtu_manager_part3.cpp ---

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

// --- Ende von core/quic_path_mtu_manager_part3.cpp ---


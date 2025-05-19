#include "quic_path_mtu_manager.hpp"
#include "quic_connection.hpp"
#include "error_handling.hpp"
#include <iostream>

namespace quicsand {

// Diese Datei enthält nur die aktualisierten Methoden, die das neue Error-Framework verwenden
// Sie würde in der Praxis in die quic_path_mtu_manager.cpp Datei integriert werden

// Aktualisierte Methode mit Result<void> Rückgabewert
Result<void> PathMtuManager::enable_bidirectional_discovery(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (enable == bidirectional_enabled_) {
        // Keine Änderung notwendig
        return success();
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
    
    return success();
}

// Aktualisierte Methode mit Result<void> Rückgabewert
Result<void> PathMtuManager::set_mtu_size(uint16_t mtu_size, bool apply_both) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validiere MTU-Größe
    if (mtu_size < outgoing_path_.min_mtu || mtu_size > outgoing_path_.max_mtu) {
        // Statt boolean false zurückgeben, geben wir einen aussagekräftigen Fehler zurück
        return MAKE_ERROR(
            ErrorCategory::NETWORK,
            ErrorCode::INVALID_ARGUMENT,
            "Ungültige MTU-Größe: " + std::to_string(mtu_size) + ", muss zwischen " +
            std::to_string(outgoing_path_.min_mtu) + " und " + 
            std::to_string(outgoing_path_.max_mtu) + " liegen"
        );
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
    try {
        connection_.set_mtu_size(outgoing_path_.current_mtu);
    } catch (const std::exception& e) {
        // Fange mögliche Ausnahmen der Connection-Methode ab
        return MAKE_ERROR(
            ErrorCategory::NETWORK,
            ErrorCode::OPERATION_FAILED,
            std::string("Fehler beim Setzen der MTU in der QUIC-Verbindung: ") + e.what()
        );
    }
    
    return success();
}

// Beispiel für eine neue Methode, die einen Result-Typ mit Wert zurückgibt
Result<std::pair<uint16_t, uint16_t>> PathMtuManager::get_optimal_mtu_pair() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Prüfe, ob MTU Discovery aktiviert und erfolgreich ist
    if (!bidirectional_enabled_) {
        return MAKE_ERROR(
            ErrorCategory::NETWORK,
            ErrorCode::INVALID_STATE,
            "Bidirektionale MTU Discovery ist nicht aktiviert"
        );
    }
    
    if (outgoing_path_.status != MtuStatus::VALIDATED || 
        incoming_path_.status != MtuStatus::VALIDATED) {
        return MAKE_ERROR(
            ErrorCategory::NETWORK,
            ErrorCode::INVALID_STATE,
            "MTU ist noch nicht für beide Richtungen validiert"
        );
    }
    
    // Berechne das optimale MTU-Paar basierend auf validierter MTU in beide Richtungen
    uint16_t optimal_outgoing = outgoing_path_.current_mtu;
    uint16_t optimal_incoming = incoming_path_.current_mtu;
    
    // Passe die Werte an, um ein symmetrisches Paar zu bilden, wenn gewünscht
    bool symmetric = false;  // Konfigurationsoption
    if (symmetric) {
        uint16_t min_mtu = std::min(optimal_outgoing, optimal_incoming);
        optimal_outgoing = optimal_incoming = min_mtu;
    }
    
    return std::make_pair(optimal_outgoing, optimal_incoming);
}

// Beispiel für die Verwendung des Error-Managers, um spezielle MTU-Fehler zu melden
void PathMtuManager::report_mtu_blackhole(uint16_t detected_size, bool is_incoming) {
    // Erstelle einen detaillierten Fehlerbericht
    auto error = MAKE_ERROR(
        ErrorCategory::NETWORK,
        ErrorCode::MTU_BLACKHOLE,
        "MTU Blackhole für " + std::string(is_incoming ? "eingehende" : "ausgehende") + 
        " Pakete erkannt bei Größe " + std::to_string(detected_size)
    );
    
    // Melde den Fehler an den ErrorManager
    report_error(error);
}

} // namespace quicsand

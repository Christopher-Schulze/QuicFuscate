#ifndef QUIC_PATH_MTU_MANAGER_HPP
#define QUIC_PATH_MTU_MANAGER_HPP

#include <cstdint>
#include <chrono>
#include <memory>
#include <vector>
#include <mutex>
#include <map>
#include <set>
#include "error_handling.hpp"

namespace quicsand {

// Forward-Deklarationen
class QuicConnection;

/**
 * @brief MTU-Status für einen Netzwerkpfad
 */
enum class MtuStatus {
    UNKNOWN,        // Noch keine Daten zur MTU vorhanden
    SEARCHING,      // MTU Discovery läuft
    VALIDATED,      // MTU wurde validiert
    BLACKHOLE,      // MTU Blackhole wurde erkannt
    UNSTABLE        // MTU ist instabil (mehrere Wechsel erkannt)
};

/**
 * @brief Struktur für MTU-Änderungserkennung
 */
struct MtuChange {
    uint16_t old_mtu;                     // Vorherige MTU
    uint16_t new_mtu;                     // Neue MTU
    std::chrono::steady_clock::time_point timestamp; // Zeitpunkt der Änderung
    bool triggered_by_probe;              // Ob durch Probe oder Paketverlust ausgelöst
};

/**
 * @brief Manager für Path MTU Discovery
 * 
 * Diese Klasse implementiert bidirektionale Path MTU Discovery für QUIC-Verbindungen.
 * Sie unterstützt dynamische MTU-Anpassung und robuste Black-Hole-Erkennung.
 */
class PathMtuManager {
public:
    /**
     * @brief Konstruktor für den Path MTU Manager
     * 
     * @param connection Referenz auf die QUIC-Verbindung
     * @param min_mtu Minimale MTU (Standard: 1200 Bytes)
     * @param max_mtu Maximale MTU (Standard: 1500 Bytes)
     * @param step_size Schrittgröße für MTU-Proben (Standard: 10 Bytes)
     * @param blackhole_threshold Schwellenwert für Blackhole-Erkennung (Standard: 3)
     */
    PathMtuManager(QuicConnection& connection, 
                  uint16_t min_mtu = 1200, 
                  uint16_t max_mtu = 1500, 
                  uint16_t step_size = 10,
                  uint8_t blackhole_threshold = 3);
    
    /**
     * @brief Destruktor
     */
    ~PathMtuManager();
    
    /**
     * @brief Aktiviert bidirektionale MTU Discovery
     * 
     * @param enable True zum Aktivieren, False zum Deaktivieren
     * @return Result<void> Erfolg oder detaillierte Fehlerinformation
     */
    Result<void> enable_bidirectional_discovery(bool enable);
    
    /**
     * @brief Prüft, ob bidirektionale MTU Discovery aktiviert ist
     * 
     * @return bool True, wenn aktiviert
     */
    bool is_bidirectional_discovery_enabled() const;
    
    /**
     * @brief Setzt die MTU für eingehende und ausgehende Pakete
     * 
     * @param mtu_size Neue MTU-Größe
     * @param apply_both True, um die MTU in beide Richtungen anzuwenden
     * @return Result<void> Erfolg oder detaillierte Fehlerinformation
     */
    Result<void> set_mtu_size(uint16_t mtu_size, bool apply_both = true);
    
    /**
     * @brief Gibt die aktuelle ausgehende MTU zurück
     * 
     * @return uint16_t Aktuelle ausgehende MTU
     */
    uint16_t get_outgoing_mtu() const;
    
    /**
     * @brief Gibt die aktuelle eingehende MTU zurück
     * 
     * @return uint16_t Aktuelle eingehende MTU
     */
    uint16_t get_incoming_mtu() const;
    
    /**
     * @brief Setzt Parameter für die MTU Discovery
     * 
     * @param min_mtu Minimale MTU
     * @param max_mtu Maximale MTU
     * @param step_size Schrittgröße für MTU-Proben
     * @param apply_both True, um die Parameter für beide Richtungen zu setzen
     */
    void set_discovery_params(uint16_t min_mtu, uint16_t max_mtu, uint16_t step_size, bool apply_both = true);
    
    /**
     * @brief Passt die MTU dynamisch an, wenn sich Netzwerkbedingungen ändern
     * 
     * @param packet_loss_rate Aktuelle Paketverlustrate (0.0 - 1.0)
     * @param rtt_ms Aktueller RTT in Millisekunden
     */
    void adapt_mtu_dynamically(float packet_loss_rate, uint32_t rtt_ms);
    
    /**
     * @brief Verarbeitet einen MTU Probe Response
     * 
     * @param probe_id ID der Probe
     * @param success True, wenn die Probe erfolgreich war
     * @param is_incoming True für eingehende, False für ausgehende Probe
     */
    void handle_probe_response(uint32_t probe_id, bool success, bool is_incoming);
    
    /**
     * @brief Verarbeitet eingehende MTU Probe Request
     * 
     * @param probe_id ID der eingehenden Probe
     * @param size Größe der Probe in Bytes
     */
    void handle_incoming_probe(uint32_t probe_id, uint16_t size);
    
    /**
     * @brief Überprüft, ob die MTU unstabil ist (häufige Änderungen)
     * 
     * @return bool True, wenn die MTU als unstabil gilt
     */
    bool is_mtu_unstable() const;
    
    /**
     * @brief Aktualisiert die MTU Discovery periodisch
     * 
     * Diese Methode sollte regelmäßig aufgerufen werden, um MTU-Proben zu senden
     * und Timeouts zu überprüfen.
     * 
     * @param now Aktueller Zeitpunkt
     */
    void update(const std::chrono::steady_clock::time_point& now);
    
    /**
     * @brief Gibt den aktuellen MTU-Status zurück
     * 
     * @param is_incoming True für eingehenden, False für ausgehenden Pfad
     * @return MtuStatus Aktueller Status
     */
    MtuStatus get_mtu_status(bool is_incoming) const;
    
    /**
     * @brief Setzt Callback für MTU-Änderungen
     * 
     * @param callback Funktion, die bei MTU-Änderungen aufgerufen wird
     */
    void set_mtu_change_callback(std::function<void(const MtuChange&)> callback);
    
private:
    /**
     * @brief MTU Discovery Status für einen Pfad
     */
    struct PathMtuState {
        uint16_t current_mtu;                           // Aktuelle MTU
        uint16_t last_successful_mtu;                   // Letzte erfolgreiche MTU
        uint16_t current_probe_mtu;                     // Aktuelle Probe-MTU
        uint16_t min_mtu;                               // Minimale MTU
        uint16_t max_mtu;                               // Maximale MTU
        uint16_t step_size;                             // Schrittgröße
        bool in_search_phase;                           // Ob Suchphase aktiv ist
        bool mtu_validated;                             // Ob MTU validiert wurde
        uint8_t consecutive_failures;                   // Aufeinanderfolgende Fehlschläge
        MtuStatus status;                               // Aktueller Status
        std::chrono::steady_clock::time_point last_probe_time; // Zeitpunkt der letzten Probe
        std::vector<MtuChange> recent_changes;          // Kürzliche MTU-Änderungen
    };
    
    QuicConnection& connection_;                       // Referenz auf die QUIC-Verbindung
    
    bool bidirectional_enabled_;                       // Flag für bidirektionale MTU Discovery
    uint8_t blackhole_detection_threshold_;            // Schwellenwert für Blackhole-Erkennung
    
    PathMtuState outgoing_path_;                       // Status für ausgehenden Pfad
    PathMtuState incoming_path_;                       // Status für eingehenden Pfad
    
    std::map<uint32_t, uint16_t> pending_outgoing_probes_; // Ausstehende ausgehende Proben
    std::map<uint32_t, uint16_t> pending_incoming_probes_; // Ausstehende eingehende Proben
    
    std::mutex mutex_;                                 // Mutex für Thread-Sicherheit
    
    std::function<void(const MtuChange&)> mtu_change_callback_; // Callback für MTU-Änderungen
    
    // Häufigkeit der MTU-Anpassung basierend auf Netzwerkbedingungen
    std::chrono::milliseconds adaptive_check_interval_{10000}; // 10 Sekunden
    std::chrono::steady_clock::time_point last_adaptive_check_; // Letzter Check
    
    // Häufigkeit der periodischen Probes nach erfolgreicher Validierung
    std::chrono::milliseconds periodic_probe_interval_{60000}; // 1 Minute
    
    // Timeout für ausstehende Proben
    std::chrono::milliseconds probe_timeout_{2000}; // 2 Sekunden
    
    // Private Hilfsmethoden
    
    /**
     * @brief Startet MTU Discovery für einen Pfad
     * 
     * @param state MTU-Status des Pfads
     * @param is_incoming True für eingehenden, False für ausgehenden Pfad
     */
    void start_discovery(PathMtuState& state, bool is_incoming);
    
    /**
     * @brief Sendet einen MTU Probe auf einem Pfad
     * 
     * @param size Größe der Probe in Bytes
     * @param is_incoming True für eingehenden, False für ausgehenden Pfad
     * @return uint32_t Probe-ID oder 0 bei Fehler
     */
    uint32_t send_probe(uint16_t size, bool is_incoming);
    
    /**
     * @brief Verarbeitet MTU-Änderung
     * 
     * @param state MTU-Status des Pfads
     * @param new_mtu Neue MTU
     * @param is_incoming True für eingehenden, False für ausgehenden Pfad
     * @param triggered_by_probe True, wenn durch Probe ausgelöst
     */
    void handle_mtu_change(PathMtuState& state, uint16_t new_mtu, bool is_incoming, bool triggered_by_probe);
    
    /**
     * @brief Erkennt MTU-Blackholes
     * 
     * @param state MTU-Status des Pfads
     * @return bool True, wenn Blackhole erkannt wurde
     */
    bool detect_blackhole(const PathMtuState& state) const;
    
    /**
     * @brief Generiert eine eindeutige Probe-ID
     * 
     * @return uint32_t Eindeutige Probe-ID
     */
    uint32_t generate_probe_id();
    
    /**
     * @brief Aktualisiert das Instabilitäts-Tracking
     * 
     * @param state MTU-Status des Pfads
     * @param new_mtu Neue MTU
     * @param triggered_by_probe True, wenn durch Probe ausgelöst
     */
    void update_stability_tracking(PathMtuState& state, uint16_t new_mtu, bool triggered_by_probe);
    
    /**
     * @brief Prüft auf Timeouts bei ausstehenden Proben
     * 
     * @param now Aktueller Zeitpunkt
     */
    void check_probe_timeouts(const std::chrono::steady_clock::time_point& now);
    
    /**
     * @brief Erstellt ein MTU Probe-Paket
     * 
     * @param probe_id ID der Probe
     * @param size Größe des Pakets
     * @param is_request True für Request, False für Response
     * @return std::vector<uint8_t> Erstelltes Paket oder leerer Vektor bei Fehler
     */
    std::vector<uint8_t> create_probe_packet(uint32_t probe_id, uint16_t size, bool is_request);
};

} // namespace quicsand

#endif // QUIC_PATH_MTU_MANAGER_HPP

#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <optional>
#include <string>

namespace quicsand {

/**
 * HTTP/3 Prioritätsmodell gemäß RFC 9218
 * https://datatracker.ietf.org/doc/html/rfc9218
 * 
 * Diese Implementierung unterstützt das aktuelle Prioritätsmodell,
 * das für HTTP/3 definiert wurde und Priority Frames verwendet.
 */

/**
 * Dringlichkeit (Urgency) eines Streams (0-7)
 * Niedrigere Werte haben höhere Priorität.
 */
enum class UrgencyLevel : uint8_t {
    HIGHEST = 0,  // Höchste Priorität
    HIGH = 1,     // Hohe Priorität
    MEDIUM_HIGH = 2,
    MEDIUM = 3,   // Mittlere Priorität (Standard)
    MEDIUM_LOW = 4,
    LOW = 5,      // Niedrige Priorität
    VERY_LOW = 6,
    LOWEST = 7    // Niedrigste Priorität
};

/**
 * Inkrementelles Prioritätsmodell
 * 
 * Wenn `incremental` auf true gesetzt ist, werden Ressourcen mit gleicher Dringlichkeit
 * nacheinander (round-robin) verarbeitet. Wenn `incremental` auf false gesetzt ist,
 * können Ressourcen mit gleicher Dringlichkeit parallel verarbeitet werden.
 */
struct PriorityParameters {
    UrgencyLevel urgency = UrgencyLevel::MEDIUM;  // Standard ist 3 (Medium)
    bool incremental = false;                     // Standard ist false (parallele Verarbeitung)
    
    // Standardkonstruktor
    PriorityParameters() = default;
    
    // Konstruktor mit Parametern
    PriorityParameters(UrgencyLevel u, bool inc)
        : urgency(u), incremental(inc) {}
};

/**
 * Priority Field Values gemäß RFC 9218, Abschnitt 4.1
 * Diese Struktur repräsentiert den "Priority"-Header
 */
struct PriorityFieldValue {
    std::optional<UrgencyLevel> urgency;
    std::optional<bool> incremental;
    
    // Konstruktor mit expliziten Werten
    PriorityFieldValue(std::optional<UrgencyLevel> u = std::nullopt, 
                      std::optional<bool> inc = std::nullopt)
        : urgency(u), incremental(inc) {}
    
    // Konstruktor aus einem String (parsing)
    explicit PriorityFieldValue(const std::string& header_value);
    
    // Konvertierung in einen String
    std::string to_string() const;
    
    // Anwenden auf ein PriorityParameters-Objekt
    void apply_to(PriorityParameters& params) const;
};

/**
 * PriorityScheduler - Verwaltet Prioritäten für HTTP/3-Streams
 * 
 * Diese Klasse implementiert einen Scheduler, der HTTP/3-Streams basierend
 * auf ihrer Priorität und dem inkrementellen Status verarbeitet.
 */
class PriorityScheduler {
public:
    PriorityScheduler();
    ~PriorityScheduler() = default;
    
    // Stream mit Prioritätsparametern hinzufügen
    void add_stream(uint64_t stream_id, const PriorityParameters& params);
    
    // Stream-Priorität aktualisieren
    void update_stream_priority(uint64_t stream_id, const PriorityParameters& params);
    
    // Stream entfernen
    void remove_stream(uint64_t stream_id);
    
    // Nächsten zu verarbeitenden Stream auswählen
    // Gibt die Stream-ID zurück oder 0, wenn kein Stream verfügbar ist
    uint64_t select_next_stream();
    
    // Stream als "bereit zur Verarbeitung" markieren
    void mark_stream_ready(uint64_t stream_id);
    
    // Stream als "nicht bereit" markieren (z.B. blockiert auf Flow Control)
    void mark_stream_not_ready(uint64_t stream_id);
    
    // Prioritätsparameter für einen Stream abrufen
    std::optional<PriorityParameters> get_stream_priority(uint64_t stream_id) const;
    
    // Alle registrierten Streams mit ihren Prioritäten abrufen
    std::map<uint64_t, PriorityParameters> get_all_streams() const;
    
private:
    // Mapping von Stream-IDs zu ihren Prioritätsparametern
    std::map<uint64_t, PriorityParameters> stream_priorities_;
    
    // Verarbeitungsreihenfolge für jede Dringlichkeitsstufe
    std::map<UrgencyLevel, std::set<uint64_t>> urgency_buckets_;
    
    // Streams, die bereit zur Verarbeitung sind
    std::set<uint64_t> ready_streams_;
    
    // Die zuletzt verarbeiteten Streams für jede Dringlichkeitsstufe (für inkrementelles Scheduling)
    std::map<UrgencyLevel, uint64_t> last_processed_streams_;
};

/**
 * Prioritätserweiterung, die einen PriorityScheduler für mehrere Verbindungen verwaltet
 */
class PriorityManager {
public:
    PriorityManager() = default;
    ~PriorityManager() = default;
    
    // Einen neuen Scheduler für eine Verbindung erstellen
    void create_scheduler(uint64_t connection_id);
    
    // Einen Scheduler für eine Verbindung entfernen
    void remove_scheduler(uint64_t connection_id);
    
    // Prioritätsparameter aus einem HTTP-Header extrahieren
    static PriorityParameters extract_priority_from_headers(
        const std::map<std::string, std::string>& headers);
    
    // Prioritätsheader für einen Stream generieren
    static std::string generate_priority_header(const PriorityParameters& params);
    
    // Zugriff auf einen Scheduler für eine bestimmte Verbindung
    PriorityScheduler* get_scheduler(uint64_t connection_id);
    
private:
    std::map<uint64_t, std::unique_ptr<PriorityScheduler>> schedulers_;
};

} // namespace quicsand

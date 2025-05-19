#ifndef FINGERPRINT_ROTATOR_HPP
#define FINGERPRINT_ROTATOR_HPP

#include "utls_client_configurator.hpp"
#include <vector>
#include <chrono>
#include <random>
#include <mutex>

namespace quicsand {

/**
 * FingerprintRotator - Eine Klasse zum periodischen Wechsel von TLS-Fingerprints
 * 
 * Diese Klasse ermöglicht es der Anwendung, regelmäßig zwischen verschiedenen
 * Browser-Fingerprints zu wechseln, um die Erkennung zu erschweren. Sie unterstützt
 * verschiedene Rotationsstrategien und kann mit einer vordefinierten Liste von
 * Fingerprints oder einem zufälligen Modus konfiguriert werden.
 */
class FingerprintRotator {
public:
    // Rotationsstrategien
    enum class RotationStrategy {
        SEQUENTIAL,       // Sequenziell durch die Liste der Fingerprints rotieren
        RANDOM,           // Zufällige Auswahl aus der Liste
        TIME_BASED,       // Basierend auf Tageszeit unterschiedliche Fingerprints
        CONNECTION_BASED  // Bei jeder neuen Verbindung wechseln
    };
    
    // Standardkonstruktor
    FingerprintRotator();
    
    // Konstruktor mit spezifischen Fingerprints und Strategie
    FingerprintRotator(const std::vector<BrowserFingerprint>& fingerprints, 
                      RotationStrategy strategy = RotationStrategy::RANDOM,
                      std::chrono::minutes rotation_interval = std::chrono::minutes(60));
    
    // Destruktor
    ~FingerprintRotator();
    
    // Startet die automatische Rotation
    void start_rotation();
    
    // Stoppt die automatische Rotation
    void stop_rotation();
    
    // Fügt einen Fingerprint zur Rotation hinzu
    void add_fingerprint(BrowserFingerprint fingerprint);
    
    // Entfernt einen Fingerprint aus der Rotation
    void remove_fingerprint(BrowserFingerprint fingerprint);
    
    // Setzt die Liste der zu rotierenden Fingerprints
    void set_fingerprints(const std::vector<BrowserFingerprint>& fingerprints);
    
    // Setzt die Rotationsstrategie
    void set_strategy(RotationStrategy strategy);
    
    // Setzt das Rotationsintervall
    void set_rotation_interval(std::chrono::minutes interval);
    
    // Holt den aktuellen Fingerprint
    BrowserFingerprint get_current_fingerprint();
    
    // Wechselt manuell zum nächsten Fingerprint
    BrowserFingerprint rotate_to_next();
    
    // Anwendung des aktuellen Fingerprints auf einen UTLSClientConfigurator
    bool apply_to_configurator(UTLSClientConfigurator& configurator, const std::string& hostname);
    
private:
    // Liste der Fingerprints zur Rotation
    std::vector<BrowserFingerprint> fingerprints_;
    
    // Aktueller Index in der Fingerprint-Liste (für sequentielle Rotation)
    size_t current_index_;
    
    // Aktueller Fingerprint
    BrowserFingerprint current_fingerprint_;
    
    // Rotationsstrategie
    RotationStrategy strategy_;
    
    // Rotationsintervall
    std::chrono::minutes rotation_interval_;
    
    // Letzter Rotationszeitpunkt
    std::chrono::steady_clock::time_point last_rotation_;
    
    // Ist die automatische Rotation aktiv?
    bool rotation_active_;
    
    // Thread für die automatische Rotation
    std::thread rotation_thread_;
    
    // Mutex für Thread-Sicherheit
    std::mutex mutex_;
    
    // Random Number Generator
    std::mt19937 rng_;
    
    // Private Hilfsmethoden
    void rotation_thread_function();
    BrowserFingerprint select_next_fingerprint();
    BrowserFingerprint get_time_based_fingerprint();
};

} // namespace quicsand

#endif // FINGERPRINT_ROTATOR_HPP

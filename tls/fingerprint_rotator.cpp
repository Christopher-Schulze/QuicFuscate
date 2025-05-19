/**
 * fingerprint_rotator.cpp
 * 
 * Implementierung der FingerprintRotator-Klasse für das QuicSand-Projekt.
 * Diese Klasse ermöglicht die Rotation von TLS-Fingerprints zur Erhöhung der Stealth-Fähigkeiten.
 */

#include "fingerprint_rotator.hpp"
#include <thread>
#include <algorithm>
#include <iostream>

namespace quicsand {

// Standardkonstruktor
FingerprintRotator::FingerprintRotator() 
    : current_index_(0),
      current_fingerprint_(BrowserFingerprint::CHROME_LATEST),
      strategy_(RotationStrategy::RANDOM),
      rotation_interval_(std::chrono::minutes(60)),
      last_rotation_(std::chrono::steady_clock::now()),
      rotation_active_(false) {
    
    // Standard-Fingerprints hinzufügen
    fingerprints_ = {
        BrowserFingerprint::CHROME_LATEST,
        BrowserFingerprint::FIREFOX_LATEST,
        BrowserFingerprint::SAFARI_LATEST,
        BrowserFingerprint::EDGE_CHROMIUM
    };
    
    // Zufallsgenerator initialisieren
    std::random_device rd;
    rng_.seed(rd());
}

// Konstruktor mit spezifischen Fingerprints und Strategie
FingerprintRotator::FingerprintRotator(const std::vector<BrowserFingerprint>& fingerprints, 
                                     RotationStrategy strategy,
                                     std::chrono::minutes rotation_interval)
    : fingerprints_(fingerprints),
      current_index_(0),
      strategy_(strategy),
      rotation_interval_(rotation_interval),
      last_rotation_(std::chrono::steady_clock::now()),
      rotation_active_(false) {
    
    // Wenn keine Fingerprints angegeben wurden, Standard verwenden
    if (fingerprints_.empty()) {
        fingerprints_ = {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST,
            BrowserFingerprint::EDGE_CHROMIUM
        };
    }
    
    // Initialen Fingerprint setzen
    current_fingerprint_ = fingerprints_[0];
    
    // Zufallsgenerator initialisieren
    std::random_device rd;
    rng_.seed(rd());
}

// Destruktor
FingerprintRotator::~FingerprintRotator() {
    // Rotation stoppen, wenn sie aktiv ist
    if (rotation_active_) {
        stop_rotation();
    }
}

// Startet die automatische Rotation
void FingerprintRotator::start_rotation() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (rotation_active_) {
        return; // Bereits aktiv
    }
    
    rotation_active_ = true;
    rotation_thread_ = std::thread(&FingerprintRotator::rotation_thread_function, this);
}

// Stoppt die automatische Rotation
void FingerprintRotator::stop_rotation() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!rotation_active_) {
            return; // Bereits gestoppt
        }
        
        rotation_active_ = false;
    }
    
    // Auf Thread warten
    if (rotation_thread_.joinable()) {
        rotation_thread_.join();
    }
}

// Fügt einen Fingerprint zur Rotation hinzu
void FingerprintRotator::add_fingerprint(BrowserFingerprint fingerprint) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Prüfe, ob der Fingerprint bereits existiert
    if (std::find(fingerprints_.begin(), fingerprints_.end(), fingerprint) == fingerprints_.end()) {
        fingerprints_.push_back(fingerprint);
    }
}

// Entfernt einen Fingerprint aus der Rotation
void FingerprintRotator::remove_fingerprint(BrowserFingerprint fingerprint) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find(fingerprints_.begin(), fingerprints_.end(), fingerprint);
    if (it != fingerprints_.end()) {
        fingerprints_.erase(it);
    }
    
    // Mindestens ein Fingerprint muss vorhanden sein
    if (fingerprints_.empty()) {
        fingerprints_.push_back(BrowserFingerprint::CHROME_LATEST);
        current_fingerprint_ = BrowserFingerprint::CHROME_LATEST;
        current_index_ = 0;
    }
    // Wenn der aktuelle Fingerprint entfernt wurde, wähle einen neuen
    else if (current_fingerprint_ == fingerprint) {
        current_index_ = 0;
        current_fingerprint_ = fingerprints_[0];
    }
}

// Setzt die Liste der zu rotierenden Fingerprints
void FingerprintRotator::set_fingerprints(const std::vector<BrowserFingerprint>& fingerprints) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Prüfe, ob die Liste nicht leer ist
    if (fingerprints.empty()) {
        return;
    }
    
    fingerprints_ = fingerprints;
    current_index_ = 0;
    current_fingerprint_ = fingerprints_[0];
}

// Setzt die Rotationsstrategie
void FingerprintRotator::set_strategy(RotationStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    strategy_ = strategy;
}

// Setzt das Rotationsintervall
void FingerprintRotator::set_rotation_interval(std::chrono::minutes interval) {
    std::lock_guard<std::mutex> lock(mutex_);
    rotation_interval_ = interval;
}

// Holt den aktuellen Fingerprint
BrowserFingerprint FingerprintRotator::get_current_fingerprint() {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_fingerprint_;
}

// Wechselt manuell zum nächsten Fingerprint
BrowserFingerprint FingerprintRotator::rotate_to_next() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    current_fingerprint_ = select_next_fingerprint();
    last_rotation_ = std::chrono::steady_clock::now();
    
    return current_fingerprint_;
}

// Anwendung des aktuellen Fingerprints auf einen UTLSClientConfigurator
bool FingerprintRotator::apply_to_configurator(UTLSClientConfigurator& configurator, const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Initialisiere den Konfigurator mit dem aktuellen Fingerprint
    // Übergebe true für use_session_tickets, um Session-Tickets standardmäßig zu aktivieren
    return configurator.initialize(current_fingerprint_, hostname, nullptr, true);
}

// Thread-Funktion für die automatische Rotation
void FingerprintRotator::rotation_thread_function() {
    while (rotation_active_) {
        auto now = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Prüfe, ob eine Rotation erforderlich ist
            if (now - last_rotation_ >= rotation_interval_) {
                // Wechsle zum nächsten Fingerprint
                current_fingerprint_ = select_next_fingerprint();
                last_rotation_ = now;
                
                std::cout << "Rotated to new fingerprint: " 
                          << UTLSClientConfigurator::fingerprint_to_string(current_fingerprint_)
                          << std::endl;
            }
        }
        
        // Schlafe für eine Sekunde, um CPU-Last zu reduzieren
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Wählt den nächsten Fingerprint basierend auf der aktuellen Strategie
BrowserFingerprint FingerprintRotator::select_next_fingerprint() {
    switch (strategy_) {
        case RotationStrategy::SEQUENTIAL:
            // Zum nächsten Fingerprint in der Sequenz wechseln
            current_index_ = (current_index_ + 1) % fingerprints_.size();
            return fingerprints_[current_index_];
            
        case RotationStrategy::RANDOM:
            // Zufälligen Fingerprint wählen (nicht den aktuellen)
            if (fingerprints_.size() > 1) {
                size_t new_index;
                do {
                    std::uniform_int_distribution<size_t> dist(0, fingerprints_.size() - 1);
                    new_index = dist(rng_);
                } while (new_index == current_index_);
                
                current_index_ = new_index;
            }
            return fingerprints_[current_index_];
            
        case RotationStrategy::TIME_BASED:
            return get_time_based_fingerprint();
            
        case RotationStrategy::CONNECTION_BASED:
            // Bei CONNECTION_BASED erfolgt die Rotation extern bei jeder neuen Verbindung
            return current_fingerprint_;
            
        default:
            return BrowserFingerprint::CHROME_LATEST;
    }
}

// Wählt einen Fingerprint basierend auf der Tageszeit
BrowserFingerprint FingerprintRotator::get_time_based_fingerprint() {
    // Aktuelle Uhrzeit abrufen
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    // Uhrzeit in lokale Zeit umwandeln
    struct tm local_time;
    #ifdef _WIN32
        localtime_s(&local_time, &time_t_now);
    #else
        localtime_r(&time_t_now, &local_time);
    #endif
    
    int hour = local_time.tm_hour;
    
    // Basierend auf der Tageszeit einen Fingerprint wählen
    if (hour >= 9 && hour < 17) {
        // Während der Arbeitszeit: hauptsächlich Chrome und Edge
        std::uniform_int_distribution<int> dist(0, 1);
        if (dist(rng_) == 0) {
            return BrowserFingerprint::CHROME_LATEST;
        } else {
            return BrowserFingerprint::EDGE_CHROMIUM;
        }
    } else if (hour >= 17 && hour < 23) {
        // Abendzeit: hauptsächlich Safari und Firefox
        std::uniform_int_distribution<int> dist(0, 1);
        if (dist(rng_) == 0) {
            return BrowserFingerprint::FIREFOX_LATEST;
        } else {
            return BrowserFingerprint::SAFARI_LATEST;
        }
    } else {
        // Nachtzeit: Mobile Browser-Profile
        std::uniform_int_distribution<int> dist(0, 1);
        if (dist(rng_) == 0) {
            return BrowserFingerprint::CHROME_ANDROID;
        } else {
            return BrowserFingerprint::SAFARI_IOS;
        }
    }
}

} // namespace quicsand

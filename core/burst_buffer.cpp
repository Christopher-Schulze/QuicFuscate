#include "burst_buffer.hpp"
#include <iostream>
#include <random>
#include <cmath>

namespace quicsand {

// Konstruktor mit Standardkonfiguration
BurstBuffer::BurstBuffer() 
    : config_(BurstConfig()), running_(false) {
    // Initialisiere den Zufallsgenerator mit Seed
    std::random_device rd;
    rng_ = std::mt19937(rd());
    
    // Initialisiere Metriken
    metrics_ = BurstMetrics();
    metrics_.last_burst_time = std::chrono::system_clock::now();
}

// Konstruktor mit benutzerdefinierter Konfiguration
BurstBuffer::BurstBuffer(const BurstConfig& config) 
    : config_(config), running_(false) {
    // Initialisiere den Zufallsgenerator mit Seed
    std::random_device rd;
    rng_ = std::mt19937(rd());
    
    // Initialisiere Metriken
    metrics_ = BurstMetrics();
    metrics_.last_burst_time = std::chrono::system_clock::now();
}

// Destruktor
BurstBuffer::~BurstBuffer() {
    // Sicherstellen, dass der Thread sauber beendet wird
    stop();
}

// Daten zum Puffer hinzufügen
bool BurstBuffer::add_data(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    
    // Prüfen, ob der Puffer zu groß werden würde
    if (current_buffer_size_ + size > config_.max_buffer_size) {
        // Optional: Buffer-Überlauf-Handling-Logik hier
        return false;
    }
    
    // Daten in den Puffer kopieren
    std::vector<uint8_t> data_copy(data, data + size);
    data_queue_.push(std::move(data_copy));
    current_buffer_size_ += size;
    
    // Aktualisieren der High-Watermark-Metrik
    metrics_.buffer_high_watermark = std::max(metrics_.buffer_high_watermark, current_buffer_size_);
    
    // Signalisiere dem Burst-Thread, dass neue Daten verfügbar sind
    cv_.notify_one();
    
    return true;
}

// Konfiguration setzen
void BurstBuffer::set_config(const BurstConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    config_ = config;
}

// Konfiguration abrufen
BurstConfig BurstBuffer::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    return config_;
}

// Metriken abrufen
BurstMetrics BurstBuffer::get_metrics() const {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    return metrics_;
}

// Handler für ausgehende Daten setzen
void BurstBuffer::set_data_handler(DataSendHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    data_handler_ = handler;
}

// Burst-Engine starten
bool BurstBuffer::start() {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    
    if (running_ || !data_handler_) {
        return false;
    }
    
    running_ = true;
    burst_thread_ = std::thread(&BurstBuffer::burst_processor, this);
    return true;
}

// Burst-Engine stoppen
bool BurstBuffer::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
        if (!running_) {
            return false;
        }
        
        running_ = false;
    }
    
    // Signalisiere dem Thread, dass er aufwachen soll, um den Stoppzustand zu erkennen
    cv_.notify_one();
    
    // Warte, bis der Thread beendet ist
    if (burst_thread_.joinable()) {
        burst_thread_.join();
    }
    
    return true;
}

// Puffer sofort leeren
void BurstBuffer::flush() {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    if (!running_ || !data_handler_ || data_queue_.empty()) {
        return;
    }
    
    // Erstelle einen Burst mit allen aktuell gepufferten Daten
    auto burst = create_burst(current_buffer_size_);
    
    // Aktualisiere Metriken
    metrics_.total_bursts_sent++;
    metrics_.total_bytes_sent += burst.size();
    metrics_.last_burst_time = std::chrono::system_clock::now();
    
    // Sende den Burst
    data_handler_(burst);
}

// Netzwerkbedingungen aktualisieren
void BurstBuffer::update_network_conditions(double latency_ms, double loss_rate, double bandwidth) {
    std::lock_guard<std::mutex> lock(mutex_); // Sperre den Mutex für Thread-Sicherheit
    metrics_.observed_latency_ms = latency_ms;
    metrics_.packet_loss_rate = loss_rate;
    metrics_.bandwidth_estimate = bandwidth;
    
    // Rufe die Anpassungsmethode auf, wenn adaptive Modi aktiviert sind
    if (config_.adaptive_timing || config_.adaptive_sizing) {
        adapt_to_network_conditions();
    }
}

// Hauptfunktion des Burst-Threads
void BurstBuffer::burst_processor() {
    // Performance-optimierter Burst-Prozessor mit minimaler Lock-Zeit
    while (true) {
        // Lokale Cache-Variablen für bessere Performance
        std::vector<uint8_t> burst;
        DataSendHandler handler_copy;
        uint32_t interval_ms;
        auto next_burst_time = std::chrono::steady_clock::now();
        bool should_adapt = false;
        
        // Erste Mutex-Phase: Nur prüfen ob wir laufen sollten und Intervall berechnen
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Thread-Beendigung prüfen
            if (!running_) break;
            
            // Berechne das Intervall (und cachiere es)
            interval_ms = calculate_burst_interval();
            
            // Handler kopieren für spätere Verwendung
            handler_copy = data_handler_;
        }
        
        // Warte AUSSERHALB des Locks bis zum nächsten Burst-Zeitpunkt
        // Das ist ein kritisches Performance-Enhancement
        next_burst_time += std::chrono::milliseconds(interval_ms);
        std::this_thread::sleep_until(next_burst_time);
        
        // Zweite Mutex-Phase: Burst-Erzeugung mit minimaler Lock-Zeit
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Schnelle Prüfung, ob wir weitermachen können
            if (!running_ || data_queue_.empty()) {
                continue;
            }
            
            // Cachiere diese Entscheidung für spätere Verwendung
            should_adapt = config_.adaptive_timing || config_.adaptive_sizing;
            
            // Optimierte Burst-Erstellung mit prä-berechneter Größe
            size_t optimal_size = calculate_optimal_burst_size();
            burst = create_burst(std::min(optimal_size, current_buffer_size_));
            
            // Wenn kein Burst erzeugt wurde, zum nächsten Durchlauf springen
            if (burst.empty()) {
                continue;
            }
            
            // Metriken-Update
            metrics_.total_bursts_sent++;
            metrics_.total_bytes_sent += burst.size();
            metrics_.last_burst_time = std::chrono::system_clock::now();
        }
        
        // Burst-Sendung AUSSERHALB des Locks für maximale Performance
        if (handler_copy && !burst.empty()) {
            handler_copy(burst);
        }
        
        // Dritte Mutex-Phase: Netzwerkanpassung nur wenn notwendig
        if (should_adapt) {
            std::lock_guard<std::mutex> lock(mutex_);
            // Nur anpassen, wenn der Thread noch läuft
            if (running_) {
                adapt_to_network_conditions();
            }
        }
    }
}

// Anpassungsmethode für Netzwerkbedingungen
void BurstBuffer::adapt_to_network_conditions() {
    // Adaptive Timing-Anpassung
    if (config_.adaptive_timing) {
        // Wenn Latenz zu hoch ist, reduziere das Burst-Intervall
        if (metrics_.observed_latency_ms > config_.target_latency_ms * 1.5) {
            config_.min_burst_interval_ms = std::max(10u, static_cast<uint32_t>(config_.min_burst_interval_ms * 0.9));
            config_.max_burst_interval_ms = std::max(50u, static_cast<uint32_t>(config_.max_burst_interval_ms * 0.9));
        }
        // Wenn Latenz gut ist, erhöhe das Burst-Intervall für bessere Effizienz
        else if (metrics_.observed_latency_ms < config_.target_latency_ms * 0.7) {
            config_.min_burst_interval_ms = std::min(200u, static_cast<uint32_t>(config_.min_burst_interval_ms * 1.1));
            config_.max_burst_interval_ms = std::min(500u, static_cast<uint32_t>(config_.max_burst_interval_ms * 1.1));
        }
    }
    
    // Adaptive Größenanpassung
    if (config_.adaptive_sizing) {
        // Bei hohem Paketverlust, reduziere die Burst-Größe
        if (metrics_.packet_loss_rate > 0.05) {
            config_.optimal_burst_size = std::max(size_t(512), static_cast<size_t>(config_.optimal_burst_size * 0.9));
        }
        // Bei geringem Paketverlust, erhöhe die Burst-Größe für besseren Durchsatz
        else if (metrics_.packet_loss_rate < 0.01 && metrics_.bandwidth_estimate > 0) {
            // Schätze optimale Burst-Größe basierend auf verfügbarer Bandbreite
            double bytes_per_ms = metrics_.bandwidth_estimate / 1000.0;
            size_t target_size = static_cast<size_t>(bytes_per_ms * metrics_.average_burst_interval_ms * 0.8);
            
            // Begrenze das Wachstum auf 10% pro Anpassung
            size_t max_growth = config_.optimal_burst_size * 1.1;
            config_.optimal_burst_size = std::min(max_growth, std::max(config_.optimal_burst_size, target_size));
            config_.optimal_burst_size = std::min(config_.max_burst_size, config_.optimal_burst_size);
        }
    }
    
    // Aktualisiere den Anpassungswert
    double latency_score = std::min(1.0, config_.target_latency_ms / std::max(1.0, metrics_.observed_latency_ms));
    double loss_score = 1.0 - std::min(1.0, metrics_.packet_loss_rate / 0.1);
    metrics_.adaptation_score = (latency_score * 0.6) + (loss_score * 0.4);
}

// Erstellt einen Burst mit der angegebenen Zielgröße
std::vector<uint8_t> BurstBuffer::create_burst(size_t target_size) {
    if (data_queue_.empty() || target_size == 0) {
        return {};
    }
    
    // Erstelle einen Vektor für den kombinierten Burst
    std::vector<uint8_t> burst;
    burst.reserve(target_size);
    
    size_t accumulated_size = 0;
    
    // Sammle Daten aus der Queue, bis die Zielgröße erreicht ist
    while (!data_queue_.empty() && accumulated_size < target_size) {
        auto& next_chunk = data_queue_.front();
        
        // Wenn das nächste Chunk vollständig hinzugefügt werden kann
        if (accumulated_size + next_chunk.size() <= target_size) {
            burst.insert(burst.end(), next_chunk.begin(), next_chunk.end());
            accumulated_size += next_chunk.size();
            current_buffer_size_ -= next_chunk.size();
            data_queue_.pop();
        }
        // Wenn nur ein Teil des Chunks hinzugefügt werden kann
        else {
            size_t bytes_to_take = target_size - accumulated_size;
            burst.insert(burst.end(), next_chunk.begin(), next_chunk.begin() + bytes_to_take);
            
            // Restliche Bytes im Chunk belassen
            std::vector<uint8_t> remaining(next_chunk.begin() + bytes_to_take, next_chunk.end());
            next_chunk.swap(remaining);
            
            accumulated_size += bytes_to_take;
            current_buffer_size_ -= bytes_to_take;
            break;
        }
    }
    
    // Wende das konfigurierte Framing auf den Burst an
    switch (config_.frame_type) {
        case BurstFrameType::HTTP3_CHUNKED:
            apply_http3_chunked_framing(burst);
            break;
        case BurstFrameType::WEBSOCKET:
            apply_websocket_framing(burst);
            break;
        case BurstFrameType::MEDIA_STREAMING:
            apply_media_streaming_framing(burst);
            break;
        case BurstFrameType::INTERACTIVE:
            apply_interactive_framing(burst);
            break;
        case BurstFrameType::RANDOMIZED:
            apply_random_framing(burst);
            break;
    }
    
    return burst;
}

// Berechnet die optimale Burst-Größe basierend auf aktuellen Bedingungen
size_t BurstBuffer::calculate_optimal_burst_size() const {
    // Cache für häufig verwendete Werte - reduziert wiederholte Zugriffe
    const size_t base_optimal = config_.optimal_burst_size;
    const size_t min_size = config_.min_burst_size;
    const size_t max_size = config_.max_burst_size;
    
    // Standardfall: Statische Größe, wenn keine Adaption aktiviert ist
    if (!config_.adaptive_sizing) {
        return base_optimal;
    }
    
    // Multi-Faktor-Adaptionsmodell für höchste Leistung unter verschiedenen Bedingungen
    double size_factor = 1.0; // Ausgangswert vor Anpassungen
    
    // Faktor 1: Paketverlustadaption (exponentiell fallend bei hohem Verlust)
    const double loss_rate = metrics_.packet_loss_rate;
    if (loss_rate > 0.01) { // Bereits bei 1% Verlust reagieren
        // Exponentiell fallende Kurve mit Basis 0.5 pro 10% Verlust
        size_factor *= std::pow(0.5, loss_rate * 10.0);
    }
    
    // Faktor 2: Optimierte Bandbreitennutzung
    if (metrics_.bandwidth_estimate > 0) {
        // Dynamisches Burst-Timing für optimale Bandbreitenausnutzung
        // Je höher die Bandbreite, desto mehr können wir senden
        double burst_window_ms = metrics_.average_burst_interval_ms;
        
        // Unterschiedliche Burst-Nutzungsgrade je nach Netzwerkbedingungen
        double burst_utilization = 0.8; // Standardnutzung: 80% des Intervalls
        
        // Bei schlechten Netzwerkbedingungen nutzen wir einen kleineren Teil des Intervalls
        if (loss_rate > 0.05 || metrics_.observed_latency_ms > config_.target_latency_ms * 1.5) {
            burst_utilization = 0.6; // Bei schlechten Bedingungen: 60% des Intervalls
        } else if (metrics_.adaptation_score > 0.8) { 
            // Bei sehr guten Bedingungen nutzen wir mehr des Intervalls
            burst_utilization = 0.9; // Bei sehr guten Bedingungen: 90% des Intervalls
        }
        
        // Maximum an Bytes, die wir in diesem Intervall senden können
        // Hier wird die verfügbare Bandbreite (Bytes/s) mit der Zeit (ms) multipliziert
        double max_bytes_by_bandwidth = (metrics_.bandwidth_estimate / 1000.0) * 
                                    (burst_window_ms * burst_utilization);
        
        // Finde die optimale Größe basierend auf Bandbreite und aktuellem Faktor
        size_t bandwidth_size = static_cast<size_t>(max_bytes_by_bandwidth * size_factor);
        
        // Stelle sicher, dass wir durch Bandbreitenanpassung nicht zu klein werden
        // aber trotzdem nicht über die verfügbare Bandbreite hinausgehen
        bandwidth_size = std::max(min_size, bandwidth_size);
        if (bandwidth_size < base_optimal) {
            // Wir limitieren durch Bandbreite, setze direkt
            return bandwidth_size;
        }
    }
    
    // Faktor 3: Latenzadaption
    const double latency_ms = metrics_.observed_latency_ms;
    const double target_ms = config_.target_latency_ms;
    if (latency_ms > 0 && target_ms > 0) {
        double latency_ratio = target_ms / latency_ms;
        
        // Bei hoher Latenz reduzieren wir die Burst-Größe
        // Bei niedriger Latenz erhöhen wir die Burst-Größe leicht
        if (latency_ms > target_ms * 1.2) {
            // Nichtlineare Abnahme bei hoher Latenz
            size_factor *= std::max(0.4, latency_ratio * 0.8);
        } else if (latency_ms < target_ms * 0.8) {
            // Leichte Erhöhung bei niedriger Latenz, aber nicht mehr als 20%
            size_factor *= std::min(1.2, 1.0 + (1.0 - latency_ratio) * 0.5);
        }
    }
    
    // Berechne die angepasste Größe
    size_t adapted_size = static_cast<size_t>(base_optimal * size_factor);
    
    // Begrenzen auf konfigurierte Min- und Max-Werte
    return std::max(min_size, std::min(max_size, adapted_size));
}

// Berechnet das optimale Burst-Intervall in Millisekunden mit optimierter Anpassungsfähigkeit
uint32_t BurstBuffer::calculate_burst_interval() const {
    // Vorkonfigurierte Konstanten für schnelleren Zugriff
    const uint32_t min_interval = config_.min_burst_interval_ms;
    const uint32_t max_interval = config_.max_burst_interval_ms;
    const double target_latency = config_.target_latency_ms;
    
    // Falls keine adaptive Anpassung aktiviert ist, verwenden wir den Standardalgorithmus
    // mit zusätzlichem Buffer-Füllstand für höhere Effizienz
    uint32_t base_interval = ((min_interval + max_interval) / 2);
    
    // Adaptive Anpassung basierend auf Netzwerkbedingungen
    if (config_.adaptive_timing) {
        // Optimiertes Multi-Faktor-Modell für das Burst-Intervall
        double interval_factor = 1.0; // Ausgangswert
        
        // Faktor 1: Latenzanpassung (wichtigster Faktor)
        const double latency_ms = metrics_.observed_latency_ms;
        if (latency_ms > 0) {
            double latency_ratio = target_latency / latency_ms;
            
            // Dynamisch angepasste Faktoren basierend auf Abweichung vom Zielwert
            if (latency_ms > target_latency * 1.5) {
                // Erheblich über dem Ziel: Starke Beschleunigung
                // Verwende einen quadratischen Faktor für stärkere Reaktion
                interval_factor *= std::max(0.4, latency_ratio * latency_ratio);
            } else if (latency_ms > target_latency) {
                // Leicht über dem Ziel: Moderate Beschleunigung
                interval_factor *= std::max(0.6, latency_ratio);
            } else if (latency_ms < target_latency * 0.5) {
                // Deutlich unter dem Ziel: Können langsamer werden
                // Erhöhung des Intervalls für bessere Tarnung
                interval_factor *= std::min(1.5, 1.0 / latency_ratio * 0.8);
            }
        }
        
        // Faktor 2: Paketverlustanpassung mit logarithmischer Skalierung
        const double loss_rate = metrics_.packet_loss_rate;
        if (loss_rate > 0.01) { // Ab 1% Paketverlust reagieren
            // Logarithmische Skalierung für sanftere Übergänge
            // Bei 5% Verlust +25%, bei 10% Verlust +50%, etc.
            interval_factor *= (1.0 + std::log10(loss_rate * 100) * 0.25);
        }
        
        // Faktor 3: Bandbreitenanpassung
        if (metrics_.bandwidth_estimate > 0) {
            // Berechne optimale Burstgröße pro MB/s Bandbreite
            const double bw_mbps = metrics_.bandwidth_estimate / (1024 * 1024);
            
            if (bw_mbps < 1.0) {
                // Bei niedriger Bandbreite verzögern wir Bursts
                interval_factor *= std::min(1.5, 1.0 + (1.0 - bw_mbps) * 0.5);
            } else if (bw_mbps > 10.0) {
                // Bei sehr hoher Bandbreite können wir schneller Bursts senden
                // Aber wir limitieren die Reduktion zur Verbesserung der Stealth
                interval_factor *= std::max(0.7, 1.0 - std::log10(bw_mbps/10) * 0.1);
            }
        }
        
        // Faktor 4: Adaption basierend auf Buffer-Füllstand
        if (current_buffer_size_ > 0) {
            const double buffer_ratio = static_cast<double>(current_buffer_size_) / config_.max_buffer_size;
            
            // Bei hohem Füllstand beschleunigen wir die Burst-Rate
            if (buffer_ratio > 0.8) { 
                // Fast voller Puffer: Schnellere Bursts
                interval_factor *= std::max(0.5, 1.0 - buffer_ratio * 0.5);
            } else if (buffer_ratio < 0.2) {
                // Fast leerer Puffer: Wir können langsamer senden
                interval_factor *= std::min(1.25, 1.0 + (0.2 - buffer_ratio));
            }
        }
        
        // Anwenden des kombinierten Faktors mit Hysterese
        // Hysterese verhindert zu häufige kleine Änderungen
        static constexpr double HYSTERESIS_THRESHOLD = 0.15; // 15% Änderungsschwelle
        static double last_factor = 1.0;
        
        if (std::abs(interval_factor - last_factor) > HYSTERESIS_THRESHOLD) {
            // Größere Änderung: Faktor vollständig anwenden
            last_factor = interval_factor;
        } else {
            // Kleine Änderung: Verwende gewichteten Durchschnitt für sanfteren Übergang
            interval_factor = last_factor * 0.7 + interval_factor * 0.3;
            last_factor = interval_factor;
        }
        
        // Anwenden des Faktors auf das Basis-Intervall
        base_interval = static_cast<uint32_t>(base_interval * interval_factor);
    }
    
    // Sicherstellen, dass das Intervall innerhalb der konfigurierten Grenzen bleibt
    base_interval = std::max(min_interval, std::min(max_interval, base_interval));
    
    // Realistische Jitter-Emulation, falls aktiviert
    if (config_.mimic_realistic_patterns) {
        // Wir verwenden einen bimodalen Jitter für realistischere Netzwerk-Patterns
        // Internet-Traffic hat oft kleine Variationen, aber gelegentlich auch größere Spitzen
        
        // Haupt-Jitter (kleine Variationen)
        std::uniform_real_distribution<double> small_jitter(-0.1, 0.1);
        
        // Gelegentliche größere Spitzen (mit geringer Wahrscheinlichkeit)
        std::uniform_real_distribution<double> spike_chance(0.0, 1.0);
        double jitter = 1.0 + small_jitter(rng_);
        
        // In 10% der Fälle einen größeren Jitter hinzufügen
        if (spike_chance(rng_) < 0.1) {
            std::uniform_real_distribution<double> large_jitter(-0.3, 0.4);
            jitter += large_jitter(rng_);
        }
        
        // Anwenden des Jitters, aber mit Begrenzung
        base_interval = static_cast<uint32_t>(base_interval * std::max(0.7, std::min(1.5, jitter)));
    }
    
    return base_interval;
}

// HTTP/3 Chunked Transfer Framing mit verbesserter Realitätstreue
void BurstBuffer::apply_http3_chunked_framing(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Realistischeres HTTP/3 Frame-Format:
    // HTTP/3 verwendet variable Längenfelder und mehrere Frame-Typen
    // Basierend auf QUIC und HTTP/3 IETF-Spezifikationen
    
    // Bestimme, ob wir einen einzelnen Frame oder mehrere Frames erstellen
    // Bei größeren Bursts sind mehrere Frames realistischer
    const size_t original_size = data.size();
    bool use_multiple_frames = original_size > 1400 || (original_size > 800 && std::rand() % 3 == 0);
    std::vector<uint8_t> framed_data;
    
    // Verschiedene HTTP/3 Frame-Typen (gemäß IETF HTTP/3-Spezifikation)
    enum FrameType {
        DATA = 0x00,
        HEADERS = 0x01,
        PUSH_PROMISE = 0x05,
        SETTINGS = 0x04,
        PRIORITY = 0x02
    };
    
    // Bei realistischem HTTP/3-Traffic können verschiedene Frame-Typen auftreten
    // Abhängig von der Burst-Größe wählen wir einen geeigneten Mix
    
    if (use_multiple_frames) {
        // Mehrere Frames - realistischer für größere Übertragungen
        framed_data.reserve(original_size + 20); // Reserviere Platz für mehrere Header
        
        // 1. Zuerst ein HEADERS-Frame (bei neuen Requests/Responses üblich)
        if (std::rand() % 10 < 8) { // 80% Wahrscheinlichkeit
            // HEADERS-Frame mit kleinen Metadaten
            const size_t headers_size = 30 + (std::rand() % 70); // 30-100 Bytes für Headers
            const uint8_t var_len_size = 1; // Variable Länge 1 Byte für kleine Frames
            
            // Hier verwenden wir variable Längencodierung wie in HTTP/3
            framed_data.push_back(var_len_size << 6 | HEADERS); // Längenformat und Frame-Typ
            framed_data.push_back(static_cast<uint8_t>(headers_size)); // Länge
            
            // Dummy-Header-Daten simulieren (QPACK-Format)
            for (size_t i = 0; i < headers_size; i++) {
                framed_data.push_back(std::rand() % 256); // Zufällige Header-Bytes
            }
        }
        
        // 2. Optional ein SETTINGS-Frame (bei neuen Verbindungen)
        if (std::rand() % 20 < 3) { // 15% Wahrscheinlichkeit
            const size_t settings_size = 10 + (std::rand() % 10); // 10-20 Bytes für Settings
            
            framed_data.push_back(0x40 | SETTINGS); // 1-Byte Länge + Frame-Typ
            framed_data.push_back(static_cast<uint8_t>(settings_size)); // Länge
            
            // Dummy-Settings-Daten
            for (size_t i = 0; i < settings_size; i++) {
                framed_data.push_back(std::rand() % 256);
            }
        }
        
        // 3. Die Hauptdaten in DATA-Frames aufteilen
        size_t remaining = original_size;
        size_t offset = 0;
        
        while (remaining > 0) {
            // Typische Chunk-Größen für HTTP/3 variieren
            size_t chunk_size = std::min(remaining, 1200ul + (std::rand() % 400)); // 1200-1600 Bytes
            remaining -= chunk_size;
            
            // Bestimme Längencodierung basierend auf Chunk-Größe
            uint8_t length_field;
            std::vector<uint8_t> length_bytes;
            
            if (chunk_size < 64) {
                // Länge passt in 6 Bits
                framed_data.push_back(static_cast<uint8_t>((0 << 6) | DATA)); // 0 = 6-Bit Länge
                framed_data.push_back(static_cast<uint8_t>(chunk_size));
            } else if (chunk_size < 16384) {
                // Länge passt in 14 Bits (2-Byte-Codierung)
                framed_data.push_back(static_cast<uint8_t>((1 << 6) | DATA)); // 1 = 14-Bit Länge
                framed_data.push_back(static_cast<uint8_t>(chunk_size >> 8));
                framed_data.push_back(static_cast<uint8_t>(chunk_size & 0xFF));
            } else {
                // Länge erfordert mehr Bytes (selten in HTTP/3)
                framed_data.push_back(static_cast<uint8_t>((2 << 6) | DATA)); // 2 = 30-Bit Länge
                framed_data.push_back(static_cast<uint8_t>(chunk_size >> 16));
                framed_data.push_back(static_cast<uint8_t>((chunk_size >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(chunk_size & 0xFF));
            }
            
            // Chunk-Daten hinzufügen
            framed_data.insert(framed_data.end(), data.begin() + offset, data.begin() + offset + chunk_size);
            offset += chunk_size;
        }
    } else {
        // Einfacher einzelner DATA-Frame für kleine Übertragungen
        framed_data.reserve(original_size + 5); // Reserviere Platz für Header + Daten
        
        // Längencodierung basierend auf Datengröße
        if (original_size < 64) {
            // 6-Bit Länge (1 Byte)
            framed_data.push_back(static_cast<uint8_t>((0 << 6) | DATA));
            framed_data.push_back(static_cast<uint8_t>(original_size));
        } else if (original_size < 16384) {
            // 14-Bit Länge (2 Bytes)
            framed_data.push_back(static_cast<uint8_t>((1 << 6) | DATA));
            framed_data.push_back(static_cast<uint8_t>(original_size >> 8));
            framed_data.push_back(static_cast<uint8_t>(original_size & 0xFF));
        } else {
            // 30-Bit Länge (4 Bytes)
            framed_data.push_back(static_cast<uint8_t>((2 << 6) | DATA));
            framed_data.push_back(static_cast<uint8_t>(original_size >> 16));
            framed_data.push_back(static_cast<uint8_t>((original_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(original_size & 0xFF));
        }
        
        // Payload hinzufügen
        framed_data.insert(framed_data.end(), data.begin(), data.end());
    }
    
    // Ersetze ursprüngliche Daten durch die HTTP/3-geframten Daten
    data.swap(framed_data);
}

// WebSocket Framing mit realistischer Segmentierung und Maskierung
void BurstBuffer::apply_websocket_framing(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Realistisches WebSocket-Frame-Format gemäß RFC 6455:
    // [1-2 bytes flags+opcode][1 byte mask+payload len][0-8 bytes extended len][0-4 bytes mask][payload]
    
    const size_t original_size = data.size();
    std::vector<uint8_t> framed_data;
    
    // Fragmentierung für größere Nachrichten (realistischer Browser-Traffic)
    bool fragment_message = original_size > 4000 || (original_size > 1000 && std::rand() % 4 == 0);
    
    if (fragment_message) {
        // Mehrere Fragmente für größere Nachrichten - realistischer WebSocket-Traffic
        framed_data.reserve(original_size + 50); // Reserviere Platz für mehrere Header
        
        size_t remaining = original_size;
        size_t offset = 0;
        bool first_frame = true;
        
        while (remaining > 0) {
            // Bestimme die Fragmentgröße (variierende Größen sind realistischer)
            size_t fragment_size;
            if (remaining < 1000) {
                // Letztes Fragment
                fragment_size = remaining;
            } else {
                // Variiere die Fragmentgröße für natürlicheren Traffic
                fragment_size = 1000 + (std::rand() % 3000);
                fragment_size = std::min(fragment_size, remaining);
            }
            
            // Flags und Opcode
            uint8_t flags;
            if (first_frame) {
                flags = 0x02; // Nicht-finales Binär-Frame
                first_frame = false;
            } else if (remaining == fragment_size) {
                flags = 0x80; // Finales Continuation-Frame
            } else {
                flags = 0x00; // Nicht-finales Continuation-Frame
            }
            framed_data.push_back(flags);
            
            // Mask-Bit (Browser-Clients verwenden immer Maskierung)
            uint8_t mask_bit = 0x80;
            
            // Payload-Länge und Maske
            if (fragment_size < 126) {
                framed_data.push_back(mask_bit | static_cast<uint8_t>(fragment_size));
            } else if (fragment_size < 65536) {
                framed_data.push_back(mask_bit | 126);
                framed_data.push_back(static_cast<uint8_t>(fragment_size >> 8));
                framed_data.push_back(static_cast<uint8_t>(fragment_size & 0xFF));
            } else {
                framed_data.push_back(mask_bit | 127);
                for (int i = 7; i >= 0; --i) {
                    framed_data.push_back(static_cast<uint8_t>((fragment_size >> (i * 8)) & 0xFF));
                }
            }
            
            // Maskierungsschlüssel (4 Bytes)
            uint8_t mask_key[4];
            for (int i = 0; i < 4; ++i) {
                mask_key[i] = std::rand() % 256;
                framed_data.push_back(mask_key[i]);
            }
            
            // Maskierte Daten erzeugen und hinzufügen
            for (size_t i = 0; i < fragment_size; ++i) {
                uint8_t masked_byte = data[offset + i] ^ mask_key[i % 4];
                framed_data.push_back(masked_byte);
            }
            
            offset += fragment_size;
            remaining -= fragment_size;
        }
    } else {
        // Einzelnes Frame für kleinere Nachrichten
        framed_data.reserve(original_size + 14); // Max Header: 2 + 8 (ext_len) + 4 (mask) Bytes
        
        // Standard-WebSocket-Frame
        uint8_t opcode;
        
        // Verschiedene Opcodes für realistischeren Traffic
        if (std::rand() % 10 < 8) {
            opcode = 0x02; // Binary frame (häufigster Typ)
        } else if (std::rand() % 10 < 5) {
            opcode = 0x01; // Text frame
        } else {
            opcode = std::rand() % 2 == 0 ? 0x09 : 0x0A; // Ping/Pong (selten)
        }
        
        uint8_t flags = 0x80 | opcode; // FIN bit + Opcode
        framed_data.push_back(flags);
        
        // Mask-Bit (Browser-Clients verwenden immer Maskierung)
        uint8_t mask_bit = 0x80;
        
        // Payload Length mit Maskierung
        if (original_size < 126) {
            framed_data.push_back(mask_bit | static_cast<uint8_t>(original_size));
        } else if (original_size < 65536) {
            framed_data.push_back(mask_bit | 126);
            framed_data.push_back(static_cast<uint8_t>(original_size >> 8));
            framed_data.push_back(static_cast<uint8_t>(original_size & 0xFF));
        } else {
            framed_data.push_back(mask_bit | 127);
            for (int i = 7; i >= 0; --i) {
                framed_data.push_back(static_cast<uint8_t>((original_size >> (i * 8)) & 0xFF));
            }
        }
        
        // Maskierungsschlüssel (4 Bytes)
        uint8_t mask_key[4];
        for (int i = 0; i < 4; ++i) {
            mask_key[i] = std::rand() % 256;
            framed_data.push_back(mask_key[i]);
        }
        
        // Maskierte Daten erzeugen und hinzufügen
        for (size_t i = 0; i < original_size; ++i) {
            uint8_t masked_byte = data[i] ^ mask_key[i % 4];
            framed_data.push_back(masked_byte);
        }
    }
    
    // Ersetze ursprüngliche Daten durch realistisch geframte WebSocket-Daten
    data.swap(framed_data);
}

// Media Streaming Framing mit realistischen Medien-Formaten
void BurstBuffer::apply_media_streaming_framing(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Realistischere Media-Streaming-Protokolle implementieren
    // Basierend auf HLS, DASH und RTP/RTSP-Patterns
    
    const size_t original_size = data.size();
    std::vector<uint8_t> framed_data;
    
    // Entscheiden, welches Streaming-Protokoll wir emulieren
    enum StreamingProtocol {
        HLS_SEGMENT = 0,    // HTTP Live Streaming Segment
        DASH_FRAGMENT = 1,  // MPEG-DASH Fragment
        RTP_PACKET = 2,     // Real-time Transport Protocol
        FLV_STREAM = 3      // Flash Video Stream (immer noch verbreitet)
    };
    
    // Wähle zufällig ein Protokoll oder basierend auf Datengröße
    StreamingProtocol protocol;
    
    if (original_size > 10000) {
        // Größere Pakete ähneln eher HLS- oder DASH-Segmenten
        protocol = (std::rand() % 2 == 0) ? HLS_SEGMENT : DASH_FRAGMENT;
    } else if (original_size < 1500) {
        // Kleinere Pakete ähneln eher RTP
        protocol = RTP_PACKET;
    } else {
        // Mittlere Größe - zufällige Auswahl aller Protokolle
        protocol = static_cast<StreamingProtocol>(std::rand() % 4);
    }
    
    switch (protocol) {
        case HLS_SEGMENT: {
            // HLS-Segment (MPEG-TS Container oder fMP4)
            framed_data.reserve(original_size + 188); // MPEG-TS Header + Daten
            
            // MPEG-TS Header hinzufügen (188 Byte pro Paket)
            const size_t ts_packet_size = 188;
            
            // Sync byte (immer 0x47)
            framed_data.push_back(0x47);
            
            // Transport Error Indicator, Payload Unit Start Indicator, Transport Priority
            // und PID (Packet Identifier) - 13 Bits
            uint16_t pid = 0x1000 + (std::rand() % 0x0FFF); // Zufälliger PID im Bereich 0x1000-0x1FFF
            uint8_t flags = 0x40; // Payload Unit Start
            framed_data.push_back(flags | ((pid >> 8) & 0x1F));
            framed_data.push_back(static_cast<uint8_t>(pid & 0xFF));
            
            // Continuity Counter und Adaptation Field Control
            static uint8_t continuity_counter = 0;
            bool has_adaptation = (std::rand() % 4 == 0); // 25% Wahrscheinlichkeit für Adaptation Field
            uint8_t adaptation_ctrl = has_adaptation ? 0x30 : 0x10; // Mit oder ohne Adaptation Field
            framed_data.push_back(adaptation_ctrl | (continuity_counter & 0x0F));
            continuity_counter = (continuity_counter + 1) % 16;
            
            if (has_adaptation) {
                // Adaptation Field hinzufügen
                uint8_t adaptation_length = std::min(std::rand() % 30 + 1, 183); // 1-30 Bytes
                framed_data.push_back(adaptation_length);
                
                // Flags im Adaptation Field
                uint8_t adaptation_flags = 0;
                if (std::rand() % 2 == 0) adaptation_flags |= 0x10; // PCR Flag
                if (std::rand() % 5 == 0) adaptation_flags |= 0x08; // OPCR Flag
                if (std::rand() % 10 == 0) adaptation_flags |= 0x04; // Splicing Point Flag
                framed_data.push_back(adaptation_flags);
                
                // Zufällige Daten für den Rest des Adaptation Fields
                for (int i = 0; i < adaptation_length - 1; i++) {
                    framed_data.push_back(std::rand() % 256);
                }
            }
            
            // PES Header (Packetized Elementary Stream) für den ersten MPEG-TS-Paket
            if (framed_data.size() < 188 - 14) { // Wenn genug Platz im Paket übrig ist
                // PES Start Code (0x000001)
                framed_data.push_back(0x00);
                framed_data.push_back(0x00);
                framed_data.push_back(0x01);
                
                // Stream ID (Video, Audio, etc.)
                uint8_t stream_id = 0xE0; // Video stream
                if (std::rand() % 3 == 0) stream_id = 0xC0; // Audio stream
                framed_data.push_back(stream_id);
                
                // PES Paketlänge (restliche Bytes im Paket)
                uint16_t pes_length = std::min<uint16_t>(static_cast<uint16_t>(original_size), 0xFFFF);
                framed_data.push_back(static_cast<uint8_t>((pes_length >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(pes_length & 0xFF));
                
                // PES Header Flags
                framed_data.push_back(0x80); // Marker bits + Original/Copy
                uint8_t pes_flags = 0x80; // PTS Flag gesetzt
                if (std::rand() % 2 == 0) pes_flags |= 0x40; // DTS Flag
                framed_data.push_back(pes_flags);
                
                // PES Header Length (immer 5 Bytes für PTS, 10 für PTS+DTS)
                uint8_t pes_header_length = (pes_flags & 0x40) ? 10 : 5;
                framed_data.push_back(pes_header_length);
                
                // PTS (Presentation Time Stamp)
                uint64_t pts = (timestamp & 0x1FFFFFFFF) * 90; // 90kHz Takt
                uint8_t pts_prefix = 0x20 | ((pts >> 29) & 0x0E) | 0x01;
                framed_data.push_back(pts_prefix);
                framed_data.push_back(static_cast<uint8_t>((pts >> 22) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(((pts >> 14) & 0xFE) | 0x01));
                framed_data.push_back(static_cast<uint8_t>((pts >> 7) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(((pts << 1) & 0xFE) | 0x01));
                
                // Optional DTS (Decoding Time Stamp)
                if (pes_flags & 0x40) {
                    uint64_t dts = pts - (std::rand() % 1000) * 90; // Leicht vor PTS
                    uint8_t dts_prefix = 0x10 | ((dts >> 29) & 0x0E) | 0x01;
                    framed_data.push_back(dts_prefix);
                    framed_data.push_back(static_cast<uint8_t>((dts >> 22) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(((dts >> 14) & 0xFE) | 0x01));
                    framed_data.push_back(static_cast<uint8_t>((dts >> 7) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(((dts << 1) & 0xFE) | 0x01));
                }
            }
            
            // Fülle das erste MPEG-TS-Paket mit Nutzdaten auf
            size_t header_size = framed_data.size();
            size_t available_bytes = ts_packet_size - header_size;
            size_t bytes_to_copy = std::min(available_bytes, original_size);
            
            framed_data.insert(framed_data.end(), data.begin(), data.begin() + bytes_to_copy);
            
            // Fülle mit Stuffing-Bytes auf, falls notwendig
            if (framed_data.size() < ts_packet_size) {
                framed_data.resize(ts_packet_size, 0xFF); // Stuffing-Bytes
            }
            
            // Füge restliche Daten als weitere MPEG-TS-Pakete hinzu
            size_t remaining = original_size - bytes_to_copy;
            size_t offset = bytes_to_copy;
            
            while (remaining > 0) {
                // Sync byte
                framed_data.push_back(0x47);
                
                // PID und Flags (Continuation)
                framed_data.push_back(((pid >> 8) & 0x1F));
                framed_data.push_back(static_cast<uint8_t>(pid & 0xFF));
                
                // Continuity Counter erhöhen
                framed_data.push_back(0x10 | (continuity_counter & 0x0F));
                continuity_counter = (continuity_counter + 1) % 16;
                
                // Nutzdaten für dieses Paket
                size_t ts_payload_size = std::min(remaining, ts_packet_size - 4ul); // 4 Bytes für Header
                framed_data.insert(framed_data.end(), 
                                  data.begin() + offset, 
                                  data.begin() + offset + ts_payload_size);
                
                // Stuffing-Bytes, falls notwendig
                size_t current_packet_size = (framed_data.size() % ts_packet_size);
                if (current_packet_size > 0 && current_packet_size < ts_packet_size) {
                    framed_data.resize(framed_data.size() + (ts_packet_size - current_packet_size), 0xFF);
                }
                
                offset += ts_payload_size;
                remaining -= ts_payload_size;
            }
            break;
        }
        
        case DASH_FRAGMENT: {
            // MPEG-DASH Segment mit MP4 Header-Pattern
            framed_data.reserve(original_size + 48);
            
            // MP4/ISOBMFF Box Structure: [size][type][data]
            // Outer 'moof' box (movie fragment)
            uint32_t moof_size = 8 + 16 + 24 + original_size; // Gesamtgröße des moof-Containers
            framed_data.push_back(static_cast<uint8_t>((moof_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((moof_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((moof_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(moof_size & 0xFF));
            framed_data.push_back('m'); framed_data.push_back('o'); 
            framed_data.push_back('o'); framed_data.push_back('f');
            
            // 'mfhd' box (movie fragment header)
            uint32_t mfhd_size = 16; // Header + Sequence Number
            framed_data.push_back(static_cast<uint8_t>((mfhd_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((mfhd_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((mfhd_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(mfhd_size & 0xFF));
            framed_data.push_back('m'); framed_data.push_back('f'); 
            framed_data.push_back('h'); framed_data.push_back('d');
            
            // Version and flags (usually 0)
            framed_data.push_back(0); framed_data.push_back(0);
            framed_data.push_back(0); framed_data.push_back(0);
            
            // Sequence number
            static uint32_t sequence_number = 1;
            framed_data.push_back(static_cast<uint8_t>((sequence_number >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((sequence_number >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((sequence_number >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(sequence_number & 0xFF));
            sequence_number++;
            
            // 'traf' box (track fragment)
            uint32_t traf_size = 8 + 16 + original_size; // traf box + tfhd box + Daten
            framed_data.push_back(static_cast<uint8_t>((traf_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((traf_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((traf_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(traf_size & 0xFF));
            framed_data.push_back('t'); framed_data.push_back('r'); 
            framed_data.push_back('a'); framed_data.push_back('f');
            
            // 'tfhd' box (track fragment header)
            uint32_t tfhd_size = 16; // header + track ID
            framed_data.push_back(static_cast<uint8_t>((tfhd_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((tfhd_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((tfhd_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(tfhd_size & 0xFF));
            framed_data.push_back('t'); framed_data.push_back('f'); 
            framed_data.push_back('h'); framed_data.push_back('d');
            
            // Version and flags (default-base-is-moof)
            framed_data.push_back(0); framed_data.push_back(0);
            framed_data.push_back(0); framed_data.push_back(0x20); // flag for default-base-is-moof
            
            // Track ID
            uint32_t track_id = 1; // Meistens 1 für Video, 2 für Audio
            framed_data.push_back(static_cast<uint8_t>((track_id >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((track_id >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((track_id >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(track_id & 0xFF));
            
            // 'mdat' box (media data)
            uint32_t mdat_size = 8 + original_size; // mdat-header + Daten
            framed_data.push_back(static_cast<uint8_t>((mdat_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((mdat_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((mdat_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(mdat_size & 0xFF));
            framed_data.push_back('m'); framed_data.push_back('d'); 
            framed_data.push_back('a'); framed_data.push_back('t');
            
            // Nutzlast (eigentliche Daten)
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
        
        case RTP_PACKET: {
            // Real-time Transport Protocol (z.B. für Video-Conferencing)
            framed_data.reserve(original_size + 12);
            
            // RTP Header
            uint8_t first_byte = 0x80; // Version 2, no padding, no extension, no CSRC
            if (std::rand() % 10 == 0) first_byte |= 0x20; // Marker bit (z.B. für Keyframe)
            framed_data.push_back(first_byte);
            
            // Payload Type (z.B. VP8=96, H264=97, Opus=111)
            uint8_t payload_type;
            switch (std::rand() % 5) {
                case 0: payload_type = 96; break;  // VP8
                case 1: payload_type = 97; break;  // H264
                case 2: payload_type = 98; break;  // VP9
                case 3: payload_type = 111; break; // Opus Audio
                default: payload_type = 110; break; // AAC Audio
            }
            framed_data.push_back(payload_type);
            
            // Sequence Number (16 bits, inkrementierend)
            static uint16_t rtp_seq = std::rand() % 65536;
            framed_data.push_back(static_cast<uint8_t>((rtp_seq >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(rtp_seq & 0xFF));
            rtp_seq = (rtp_seq + 1) % 65536;
            
            // Timestamp (32 bits, meist basierend auf 90kHz Takt für Video)
            uint32_t rtp_timestamp = timestamp * 90; // 90kHz Takt
            framed_data.push_back(static_cast<uint8_t>((rtp_timestamp >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((rtp_timestamp >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((rtp_timestamp >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(rtp_timestamp & 0xFF));
            
            // SSRC (Synchronization Source Identifier) - konstant für einen Sender
            static uint32_t ssrc = std::rand();
            framed_data.push_back(static_cast<uint8_t>((ssrc >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((ssrc >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((ssrc >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(ssrc & 0xFF));
            
            // Nutzlast (für VP8/VP9 mit Payload Descriptor)
            if (payload_type == 96 || payload_type == 98) { // VP8/VP9
                // VP8/VP9 Payload Descriptor (vereinfacht)
                framed_data.push_back(0x10); // Key Frame Indicator + Start of Partition
            } else if (payload_type == 97) { // H264
                // NALU Header mit typischen Werten
                uint8_t nalu_type = std::rand() % 10 == 0 ? 0x05 : 0x01; // 5=IDR, 1=Non-IDR
                framed_data.push_back(nalu_type);
            }
            
            // Eigentliche Daten
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
        
        case FLV_STREAM: {
            // Flash Video Stream Format
            framed_data.reserve(original_size + 15);
            
            // FLV Tag Header
            const bool is_video = (std::rand() % 4 != 0); // 75% Video, 25% Audio
            
            // Tag Type
            framed_data.push_back(is_video ? 0x09 : 0x08); // 9=Video, 8=Audio
            
            // Tag Data Size (3 Bytes)
            const uint32_t data_size = original_size + (is_video ? 5 : 2); // FLV Tag + Data Size
            framed_data.push_back(static_cast<uint8_t>((data_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((data_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(data_size & 0xFF));
            
            // Timestamp (3 Bytes + 1 Byte Extended)
            framed_data.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(timestamp & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF)); // Extended Timestamp
            
            // Stream ID (always 0)
            framed_data.push_back(0); framed_data.push_back(0); framed_data.push_back(0);
            
            if (is_video) {
                // Video tag data (1 Byte Frame Type + Codec ID)
                uint8_t frame_type = (std::rand() % 10 == 0) ? 0x10 : 0x20; // 1=keyframe, 2=inter frame
                uint8_t codec_id = 0x07; // 7=AVC (H.264)
                framed_data.push_back(frame_type | codec_id);
                
                // AVC Packet Type (0=AVC sequence header, 1=AVC NALU, 2=AVC end of sequence)
                framed_data.push_back(0x01); // 1=AVC NALU
                
                // Composition Time (3 Bytes)
                int32_t composition_time = (std::rand() % 2000) - 1000; // Zwischen -1000 und +1000 ms
                framed_data.push_back(static_cast<uint8_t>((composition_time >> 16) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((composition_time >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(composition_time & 0xFF));
            } else {
                // Audio tag data (1 Byte for sound format, rate, size, and type)
                uint8_t audio_tag = 0xAF; // 10=AAC, 3=44kHz, 1=16-bit, 1=Stereo
                framed_data.push_back(audio_tag);
                
                // AAC Packet Type (0=AAC sequence header, 1=AAC raw)
                framed_data.push_back(0x01); // 1=AAC raw
            }
            
            // Actual data
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            
            // Previous Tag Size (always original_size + 11 for the header)
            uint32_t prev_tag_size = data_size + 11;
            framed_data.push_back(static_cast<uint8_t>((prev_tag_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((prev_tag_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((prev_tag_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(prev_tag_size & 0xFF));
            break;
        }
    }
    
    // Ersetze ursprüngliche Daten durch die realistisch geframten Medien-Daten
    data.swap(framed_data);
}

// Interactive Traffic Framing mit realistischen Protokollen
void BurstBuffer::apply_interactive_framing(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Emuliere realistische interaktive Protokolle wie:
    // - Remote Desktop Protocol (RDP)
    // - Virtual Network Computing (VNC)
    // - Game Networking (Steam, Battle.net, etc.)
    
    const size_t original_size = data.size();
    std::vector<uint8_t> framed_data;
    
    // Entscheide, welches interaktive Protokoll wir emulieren
    enum InteractiveProtocol {
        RDP_TRAFFIC = 0,       // Remote Desktop Protocol
        VNC_TRAFFIC = 1,       // Virtual Network Computing
        GAME_TRAFFIC = 2,      // Spielverkehr (z.B. Steam, Blizzard)
        VOIP_TRAFFIC = 3       // Voice over IP (z.B. Discord, Teams)
    };
    
    // Wähle zufällig ein Protokoll oder basierend auf Datengröße
    InteractiveProtocol protocol;
    if (original_size < 100) {
        // Kleine Pakete sind typisch für Eingabeevents oder Heartbeats
        protocol = (std::rand() % 2 == 0) ? GAME_TRAFFIC : VOIP_TRAFFIC;
    } else if (original_size > 4000) {
        // Größere Pakete sind typisch für Screen-Updates
        protocol = (std::rand() % 2 == 0) ? RDP_TRAFFIC : VNC_TRAFFIC;
    } else {
        // Mittlere Größe - zufällige Auswahl aller Protokolle
        protocol = static_cast<InteractiveProtocol>(std::rand() % 4);
    }
    
    switch (protocol) {
        case RDP_TRAFFIC: {
            // Remote Desktop Protocol (RDP) Framing
            // Basierend auf MS-RDPBCGR-Spezifikation
            framed_data.reserve(original_size + 24);
            
            // TPKT Header (RFC 1006)
            framed_data.push_back(0x03); // Version
            framed_data.push_back(0x00); // Reserved
            uint16_t length = static_cast<uint16_t>(original_size + 24); // Gesamtlänge
            framed_data.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(length & 0xFF));
            
            // X.224 Data TPDU, entsprechend MS-RDPBCGR
            framed_data.push_back(0x02); // X.224 Data TPDU (Class 0)
            framed_data.push_back(0xF0); // Destination reference (DST-REF)
            framed_data.push_back(0x80); // Source reference (SRC-REF)
            
            // MCS Header
            static uint8_t channel_id = 0;
            uint8_t mcs_header = 0x64 + (++channel_id % 5); // Typisch für verschiedene Kanäle
            framed_data.push_back(mcs_header);
            framed_data.push_back(0x00); // Priority
            
            // Security Header (optional)
            if (std::rand() % 2 == 0) {
                uint32_t sec_flags = 0x00000001; // SEC_ENCRYPT
                framed_data.push_back(static_cast<uint8_t>(sec_flags & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((sec_flags >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((sec_flags >> 16) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((sec_flags >> 24) & 0xFF));
            }
            
            // Share Control Header
            static uint16_t share_id = 0x1000;
            framed_data.push_back(static_cast<uint8_t>(share_id & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((share_id >> 8) & 0xFF));
            
            // PDU Type und PDU Source
            uint16_t pdu_type = 0; // DATA PDU
            static uint16_t pdu_source = 0x03EA; // MCS_GLOBAL_CHANNEL
            if (std::rand() % 10 == 0) {
                // Gelegentlich andere PDU-Typen senden
                pdu_type = (std::rand() % 3) + 1; // CONFIRM_ACTIVE_PDU, DEACTIVATE_ALL, etc.
            }
            framed_data.push_back(static_cast<uint8_t>(pdu_type & 0x0F));
            framed_data.push_back(static_cast<uint8_t>(pdu_source & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((pdu_source >> 8) & 0xFF));
            
            // Komprimierungsbits und komprimierte Länge
            uint16_t compression_bits = 0x0000; // Keine Komprimierung
            framed_data.push_back(static_cast<uint8_t>(compression_bits & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((compression_bits >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(original_size & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((original_size >> 8) & 0xFF));
            
            // Payload Data
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
        
        case VNC_TRAFFIC: {
            // Virtual Network Computing (VNC) Framing
            // Basierend auf RFB (Remote Framebuffer) Protokoll
            framed_data.reserve(original_size + 12);
            
            // Message Type
            uint8_t message_type;
            if (original_size < 20) {
                // Kleine Nachrichten sind typisch für Eingabeevents
                message_type = (std::rand() % 3) + 4; // 4=KeyEvent, 5=PointerEvent, 6=ClientCutText
            } else {
                // Größere Nachrichten sind typisch für FramebufferUpdates
                message_type = 0; // FramebufferUpdate
            }
            framed_data.push_back(message_type);
            
            if (message_type == 0) {
                // FramebufferUpdate
                framed_data.push_back(0x00); // Padding
                
                // Anzahl der Rechtecke
                uint16_t num_rectangles = 1 + (std::rand() % 3); // 1-3 Rechtecke
                framed_data.push_back(static_cast<uint8_t>((num_rectangles >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(num_rectangles & 0xFF));
                
                // Für jedes Rechteck
                for (int i = 0; i < num_rectangles; i++) {
                    // X-Position (16 bit)
                    uint16_t x_pos = std::rand() % 1000;
                    framed_data.push_back(static_cast<uint8_t>((x_pos >> 8) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(x_pos & 0xFF));
                    
                    // Y-Position (16 bit)
                    uint16_t y_pos = std::rand() % 800;
                    framed_data.push_back(static_cast<uint8_t>((y_pos >> 8) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(y_pos & 0xFF));
                    
                    // Width (16 bit)
                    uint16_t width = 100 + (std::rand() % 400);
                    framed_data.push_back(static_cast<uint8_t>((width >> 8) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(width & 0xFF));
                    
                    // Height (16 bit)
                    uint16_t height = 100 + (std::rand() % 300);
                    framed_data.push_back(static_cast<uint8_t>((height >> 8) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(height & 0xFF));
                    
                    // Encoding Type (32 bit)
                    uint32_t encoding;
                    switch (std::rand() % 3) {
                        case 0: encoding = 0; break; // Raw Encoding
                        case 1: encoding = 16; break; // ZRLE Encoding
                        default: encoding = 2; break; // RRE Encoding
                    }
                    framed_data.push_back(static_cast<uint8_t>((encoding >> 24) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>((encoding >> 16) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>((encoding >> 8) & 0xFF));
                    framed_data.push_back(static_cast<uint8_t>(encoding & 0xFF));
                }
            } else if (message_type == 4) {
                // KeyEvent
                uint8_t down_flag = std::rand() % 2; // 0=up, 1=down
                framed_data.push_back(down_flag);
                
                // Padding
                framed_data.push_back(0x00);
                framed_data.push_back(0x00);
                
                // Key (32 bit)
                uint32_t key = 0x20 + (std::rand() % 100); // ASCII codes
                framed_data.push_back(static_cast<uint8_t>((key >> 24) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((key >> 16) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>((key >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(key & 0xFF));
            } else if (message_type == 5) {
                // PointerEvent
                uint8_t button_mask = std::rand() % 8; // Bit 0-2 für Maustasten
                framed_data.push_back(button_mask);
                
                // X-Position (16 bit)
                uint16_t x_pos = std::rand() % 1920;
                framed_data.push_back(static_cast<uint8_t>((x_pos >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(x_pos & 0xFF));
                
                // Y-Position (16 bit)
                uint16_t y_pos = std::rand() % 1080;
                framed_data.push_back(static_cast<uint8_t>((y_pos >> 8) & 0xFF));
                framed_data.push_back(static_cast<uint8_t>(y_pos & 0xFF));
            }
            
            // Payload Data (je nach Message-Type verarbeitet)
            size_t header_size = framed_data.size();
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
        
        case GAME_TRAFFIC: {
            // Spiele-Netzwerkverkehr (z.B. Steam, Battle.net, etc.)
            framed_data.reserve(original_size + 16);
            
            // Paket-Header (Beispiel für Steam-ähnliches Protokoll)
            uint32_t magic = 0xFFFFFFFF; // Magic number
            framed_data.push_back(static_cast<uint8_t>((magic >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((magic >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(magic & 0xFF));
            
            // Protokoll-Version
            framed_data.push_back(0x0A); // Version 10
            
            // Pakettyp
            uint8_t packet_type;
            if (original_size < 100) {
                // Kleine Pakete sind typisch für Heartbeats oder Eingaben
                packet_type = (std::rand() % 2 == 0) ? 0x01 : 0x03; // Heartbeat oder Input
            } else {
                // Größere Pakete für State Updates oder Chat
                packet_type = (std::rand() % 2 == 0) ? 0x02 : 0x04; // State oder Chat
            }
            framed_data.push_back(packet_type);
            
            // Payload Size
            framed_data.push_back(static_cast<uint8_t>((original_size >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((original_size >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((original_size >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(original_size & 0xFF));
            
            // Sequence Number
            static uint32_t game_seq = std::rand();
            framed_data.push_back(static_cast<uint8_t>((game_seq >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((game_seq >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((game_seq >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(game_seq & 0xFF));
            game_seq++;
            
            // Checksum (Dummy)
            uint32_t checksum = std::rand();
            framed_data.push_back(static_cast<uint8_t>((checksum >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((checksum >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((checksum >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(checksum & 0xFF));
            
            // Payload
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
        
        case VOIP_TRAFFIC: {
            // Voice over IP Traffic (z.B. Discord, Teams, etc.)
            framed_data.reserve(original_size + 12);
            
            // RTP-ähnlicher Header (Real-time Transport Protocol)
            // Version (2), Padding (0), Extension (0), CSRC Count (0)
            framed_data.push_back(0x80);
            
            // Marker (0), Payload Type (typisch für Opus oder andere Audio-Codecs)
            framed_data.push_back(0x78); // Opus ähnlicher Codec
            
            // Sequence Number
            static uint16_t voip_seq = std::rand() % 65536;
            framed_data.push_back(static_cast<uint8_t>((voip_seq >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(voip_seq & 0xFF));
            voip_seq = (voip_seq + 1) % 65536;
            
            // Timestamp (basierend auf 8kHz oder 16kHz Sample Rate)
            static uint32_t voip_timestamp = std::rand();
            voip_timestamp += 160; // 20ms bei 8kHz
            framed_data.push_back(static_cast<uint8_t>((voip_timestamp >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((voip_timestamp >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((voip_timestamp >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(voip_timestamp & 0xFF));
            
            // SSRC (Synchronization Source Identifier)
            static uint32_t voip_ssrc = std::rand();
            framed_data.push_back(static_cast<uint8_t>((voip_ssrc >> 24) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((voip_ssrc >> 16) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>((voip_ssrc >> 8) & 0xFF));
            framed_data.push_back(static_cast<uint8_t>(voip_ssrc & 0xFF));
            
            // Payload
            framed_data.insert(framed_data.end(), data.begin(), data.end());
            break;
        }
    }
    
    // Ersetze ursprüngliche Daten durch realistisch geframte interaktive Daten
    data.swap(framed_data);
}

// Zufälliges Framing
void BurstBuffer::apply_random_framing(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Wähle einen Framing-Typ zufällig aus
    std::uniform_int_distribution<int> dist(0, 3);
    int framing_choice = dist(rng_);
    
    switch (framing_choice) {
        case 0:
            apply_http3_chunked_framing(data);
            break;
        case 1:
            apply_websocket_framing(data);
            break;
        case 2:
            apply_media_streaming_framing(data);
            break;
        case 3:
            apply_interactive_framing(data);
            break;
    }
}

} // namespace quicsand

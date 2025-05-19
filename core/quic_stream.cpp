#include "quic_stream.hpp"
#include "quic_connection.hpp"
#include <iostream>
#include <algorithm>

namespace quicsand {

// Konstruktor mit Standard-BurstBuffer-Konfiguration
QuicStream::QuicStream(boost::shared_ptr<QuicConnection> conn, int id, StreamType type)
    : conn_(conn), id_(id), type_(type) {
    // Standard-BurstBuffer-Konfiguration
    BurstConfig default_config;
    setup_burst_buffer(default_config);
}

// Konstruktor mit benutzerdefinierter BurstBuffer-Konfiguration
QuicStream::QuicStream(boost::shared_ptr<QuicConnection> conn, int id, StreamType type, const BurstConfig& burst_config)
    : conn_(conn), id_(id), type_(type) {
    setup_burst_buffer(burst_config);
}

// Destruktor - Stoppt den BurstBuffer und schließt den Stream
QuicStream::~QuicStream() {
    if (debug_output_) {
        std::cout << "Closing stream " << id_ << ", sent " << bytes_sent_ << " bytes" << std::endl;
    }
    
    // BurstBuffer herunterfahren, wenn vorhanden
    if (burst_buffer_) {
        burst_buffer_->stop();
    }
    
    close();
}

// Hilfsmethode zum Einrichten des BurstBuffers
void QuicStream::setup_burst_buffer(const BurstConfig& config) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Erstelle den BurstBuffer mit der angegebenen Konfiguration
    burst_buffer_ = std::make_unique<BurstBuffer>(config);
    
    // Setze den Handler für ausgehende Daten
    burst_buffer_->set_data_handler([this](const std::vector<uint8_t>& data) {
        this->handle_burst_data(data);
    });
    
    // Standardmäßig ist Burst-Buffering deaktiviert, bis explizit aktiviert
    burst_buffering_enabled_ = false;
}

// Handler für Daten aus dem BurstBuffer
void QuicStream::handle_burst_data(const std::vector<uint8_t>& data) {
    if (closed_ || !conn_) {
        return;
    }
    
    // Direktes Senden der Daten über die Verbindung
    direct_send(data.data(), data.size());
}

// Direkte Sendung ohne BurstBuffer
void QuicStream::direct_send(const uint8_t* data, size_t size) {
    if (closed_ || !conn_ || !data || size == 0) {
        return;
    }
    
    if (debug_output_) {
        std::cout << "Directly sending " << size << " bytes on stream " << id_ << std::endl;
    }
    
    // Hier muss die tatsächliche Implementierung zum Senden der Daten über QUIC erfolgen
    // Für jetzt ein Dummy/Beispiel:
    std::cout << "[Stream " << id_ << "] Sending " << size << " bytes" << std::endl;
    
    // Byte-Zähler aktualisieren
    bytes_sent_ += size;
}

// Daten an BurstBuffer oder direkt senden je nach Konfiguration
void QuicStream::send_data(const uint8_t* data, size_t size) {
    if (closed_ || !conn_ || !data || size == 0) {
        return;
    }
    
    // Überprüfe Flow-Control-Limits
    if (bytes_sent_ + size > flow_control_limit_) {
        // Flow-Control-Logik implementieren (z.B. blockieren oder Daten verwerfen)
        if (debug_output_) {
            std::cout << "Flow control limit reached on stream " << id_ << ", dropping data" << std::endl;
        }
        return;
    }
    
    // Je nach Konfiguration Daten puffern oder direkt senden
    if (burst_buffering_enabled_ && burst_buffer_) {
        if (debug_output_) {
            std::cout << "Adding " << size << " bytes to burst buffer for stream " << id_ << std::endl;
        }
        
        if (!burst_buffer_->add_data(data, size)) {
            // Puffer-Fehler, direkt senden als Fallback
            direct_send(data, size);
        }
    } else {
        // Direkt senden ohne Burst-Buffering
        direct_send(data, size);
    }
}

// Sendet Daten aus einem std::vector
void QuicStream::send_data(const std::vector<uint8_t>& data) {
    send_data(data.data(), data.size());
}

// Sendet String-Daten
void QuicStream::send_data(const std::string& data) {
    send_data(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// Aktiviert oder deaktiviert Burst-Buffering
void QuicStream::enable_burst_buffering(bool enable) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (enable == burst_buffering_enabled_) {
        return; // Keine Änderung notwendig
    }
    
    if (enable) {
        // Starte den Burst-Buffer, wenn er aktiviert wird
        if (burst_buffer_) {
            burst_buffer_->start();
        }
    } else {
        // Stoppe den Burst-Buffer und leere ihn
        if (burst_buffer_) {
            burst_buffer_->flush();
            burst_buffer_->stop();
        }
    }
    
    burst_buffering_enabled_ = enable;
    
    if (debug_output_) {
        std::cout << "Burst buffering " << (enable ? "enabled" : "disabled") 
                  << " for stream " << id_ << std::endl;
    }
}

// Gibt zurück, ob Burst-Buffering aktiviert ist
bool QuicStream::is_burst_buffering_enabled() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return burst_buffering_enabled_;
}

// Leert den Burst-Buffer sofort
void QuicStream::flush_burst_buffer() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (burst_buffer_ && burst_buffering_enabled_) {
        burst_buffer_->flush();
    }
}

// Konfiguration des Burst-Buffers setzen
void QuicStream::set_burst_config(const BurstConfig& config) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (burst_buffer_) {
        burst_buffer_->set_config(config);
    }
}

// Konfiguration des Burst-Buffers abrufen
BurstConfig QuicStream::get_burst_config() const {
    std::unique_lock<std::mutex> lock(mutex_);
    if (burst_buffer_) {
        return burst_buffer_->get_config();
    }
    return BurstConfig(); // Default-Konfiguration als Fallback
}

// Metriken des Burst-Buffers abrufen
BurstMetrics QuicStream::get_burst_metrics() const {
    std::unique_lock<std::mutex> lock(mutex_);
    if (burst_buffer_) {
        return burst_buffer_->get_metrics();
    }
    return BurstMetrics(); // Default-Metriken als Fallback
}

// Gibt zurück, ob der Stream geschlossen ist
bool QuicStream::is_closed() const {
    return closed_;
}

// Schließt den Stream
void QuicStream::close() {
    // Verhindere doppeltes Schließen
    if (closed_.exchange(true)) {
        return;
    }
    
    // BurstBuffer herunterfahren und leeren
    if (burst_buffer_) {
        burst_buffer_->flush();
        burst_buffer_->stop();
    }
    
    // Weitere Stream-Schließen-Logik hier...
    if (debug_output_) {
        std::cout << "Stream " << id_ << " closed, total bytes sent: " << bytes_sent_ << std::endl;
    }
}

// Überprüft, ob der Stream beschreibbar ist
bool QuicStream::is_writable() const {
    return !closed_ && conn_ != nullptr;
}

// Setzt das Flow-Control-Limit
void QuicStream::set_flow_control_limit(size_t limit) {
    flow_control_limit_ = limit;
}

// Gibt das Flow-Control-Limit zurück
size_t QuicStream::get_flow_control_limit() const {
    return flow_control_limit_;
}

// Gibt die Anzahl der gesendeten Bytes zurück
size_t QuicStream::get_bytes_sent() const {
    return bytes_sent_;
}

// Gibt die Anzahl der empfangenen Bytes zurück
size_t QuicStream::get_bytes_received() const {
    return bytes_received_;
}

} // namespace quicsand

#pragma once

#include "quic.hpp"  // Für StreamType und QuicConnection
#include "burst_buffer.hpp"  // Für BurstBuffer-Funktionalität
#include <boost/shared_ptr.hpp>
#include <iostream>
#include <atomic>
#include <mutex>

namespace quicsand {

class QuicConnection; // Forward-Deklaration

class QuicStream {
public:
    // Konstruktor mit Standard-BurstBuffer-Konfiguration
    QuicStream(boost::shared_ptr<QuicConnection> conn, int id, StreamType type);
    
    // Konstruktor mit benutzerdefinierter BurstBuffer-Konfiguration
    QuicStream(boost::shared_ptr<QuicConnection> conn, int id, StreamType type, const BurstConfig& burst_config);
    
    // Destruktor
    ~QuicStream();
    
    // Daten-Übertragungsmethoden
    void send_data(const uint8_t* data, size_t size);
    void send_data(const std::vector<uint8_t>& data);
    void send_data(const std::string& data);
    
    // BurstBuffer-Konfigurationsmethoden
    void set_burst_config(const BurstConfig& config);
    BurstConfig get_burst_config() const;
    BurstMetrics get_burst_metrics() const;
    
    // Steuerungsmethoden
    bool is_writable() const;
    bool is_closed() const;
    void close();
    
    // Stream-Eigenschaften
    int id() const { return id_; }
    StreamType type() const { return type_; }
    
    // Flow-Control-Methoden
    void set_flow_control_limit(size_t limit);
    size_t get_flow_control_limit() const;
    size_t get_bytes_sent() const;
    size_t get_bytes_received() const;
    
    // Burst-Control-Spezifische Methoden
    void enable_burst_buffering(bool enable = true);
    bool is_burst_buffering_enabled() const;
    void flush_burst_buffer(); // Sofortige Übertragung gepufferter Daten
    
    // Debug-Methoden
    void set_debug_output(bool enable) { debug_output_ = enable; }
    bool get_debug_output() const { return debug_output_; }
    
private:
    // Private Hilfsmethoden
    void setup_burst_buffer(const BurstConfig& config);
    void handle_burst_data(const std::vector<uint8_t>& data);
    void direct_send(const uint8_t* data, size_t size);
    
    // Private Member-Variablen
    boost::shared_ptr<QuicConnection> conn_;
    int id_;
    StreamType type_;
    std::unique_ptr<BurstBuffer> burst_buffer_;
    bool burst_buffering_enabled_ = false;
    std::atomic<bool> closed_ = {false};
    std::atomic<size_t> bytes_sent_ = {0};
    std::atomic<size_t> bytes_received_ = {0};
    size_t flow_control_limit_ = 1024 * 1024; // Default: 1MB
    bool debug_output_ = false;
    mutable std::mutex mutex_;
};

} // namespace quicsand

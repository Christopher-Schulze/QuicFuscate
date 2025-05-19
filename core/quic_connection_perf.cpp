#include "quic_connection.hpp"
#include "zero_copy.hpp"
#include "burst_buffer.hpp"
#include "bbr_v2.hpp"
#include "zero_rtt.hpp"
#include <iostream>
#include <sstream>
#include <chrono>
#include <openssl/err.h>

namespace quicsand {

// Zero-Copy-spezifische Methoden

bool QuicConnection::enable_zero_copy(bool enable) {
    if (enable == zero_copy_enabled_) {
        return true; // Keine Änderung notwendig
    }
    
    if (enable) {
        // Aktiviere Zero-Copy
        setup_zero_copy();
    } else {
        // Deaktiviere Zero-Copy
        cleanup_zero_copy();
    }
    
    zero_copy_enabled_ = enable;
    return true;
}

bool QuicConnection::is_zero_copy_enabled() const {
    return zero_copy_enabled_;
}

void QuicConnection::setup_zero_copy() {
    // Initialisiere Zero-Copy-Komponenten, falls noch nicht geschehen
    if (!send_buffer_) {
        send_buffer_ = std::make_unique<ZeroCopyBuffer>();
    }
    
    if (!recv_zero_copy_) {
        recv_zero_copy_ = std::make_unique<ZeroCopyReceiver>();
    }
    
    // Initialisiere Memory-Pool
    init_memory_pool();
}

void QuicConnection::cleanup_zero_copy() {
    // Bereinige Zero-Copy-Komponenten
    send_buffer_.reset();
    recv_zero_copy_.reset();
    memory_pool_.reset();
}

void QuicConnection::send_datagram_zero_copy(ZeroCopyBuffer& buffer) {
    if (!zero_copy_enabled_) {
        std::cerr << "Zero-Copy ist nicht aktiviert" << std::endl;
        return;
    }
    
    std::lock_guard<std::mutex> lock(socket_mutex_);
    
    if (!socket_.is_open()) {
        std::cerr << "Socket ist nicht geöffnet" << std::endl;
        return;
    }
    
    // Konvertiere den Socket-Deskriptor (platform-spezifisch)
    #ifdef _WIN32
    int fd = socket_.native_handle();
    #else
    int fd = socket_.native_handle();
    #endif
    
    // Führe Zero-Copy-Senden durch
    ssize_t bytes_sent = 0;
    
    if (remote_endpoint_.address().is_unspecified() || remote_endpoint_.port() == 0) {
        // Direktes Senden ohne spezifische Zieladresse
        bytes_sent = buffer.send(fd);
    } else {
        // Senden an eine spezifische Zieladresse
        struct sockaddr_storage addr_storage;
        socklen_t addr_len = 0;
        
        // Konvertiere endpoint in sockaddr
        if (remote_endpoint_.protocol() == boost::asio::ip::udp::v4()) {
            struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(&addr_storage);
            addr_in->sin_family = AF_INET;
            addr_in->sin_port = htons(remote_endpoint_.port());
            memcpy(&addr_in->sin_addr, remote_endpoint_.address().to_v4().to_bytes().data(), 4);
            addr_len = sizeof(struct sockaddr_in);
        } else {
            struct sockaddr_in6* addr_in6 = reinterpret_cast<struct sockaddr_in6*>(&addr_storage);
            addr_in6->sin6_family = AF_INET6;
            addr_in6->sin6_port = htons(remote_endpoint_.port());
            memcpy(&addr_in6->sin6_addr, remote_endpoint_.address().to_v6().to_bytes().data(), 16);
            addr_len = sizeof(struct sockaddr_in6);
        }
        
        bytes_sent = buffer.sendto(fd, reinterpret_cast<struct sockaddr*>(&addr_storage), addr_len);
    }
    
    if (bytes_sent < 0) {
        // Fehler beim Senden
        std::cerr << "Fehler beim Zero-Copy-Senden: " << strerror(errno) << std::endl;
    } else {
        // Aktualisiere Statistiken
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.bytes_sent += bytes_sent;
        stats_.packets_sent++;
    }
}

void QuicConnection::receive_datagram_zero_copy(ZeroCopyReceiver& receiver) {
    if (!zero_copy_enabled_) {
        std::cerr << "Zero-Copy ist nicht aktiviert" << std::endl;
        return;
    }
    
    std::lock_guard<std::mutex> lock(socket_mutex_);
    
    if (!socket_.is_open()) {
        std::cerr << "Socket ist nicht geöffnet" << std::endl;
        return;
    }
    
    // Konvertiere den Socket-Deskriptor (platform-spezifisch)
    #ifdef _WIN32
    int fd = socket_.native_handle();
    #else
    int fd = socket_.native_handle();
    #endif
    
    // Führe Zero-Copy-Empfang durch
    struct sockaddr_storage addr_storage;
    socklen_t addr_len = sizeof(addr_storage);
    
    ssize_t bytes_received = receiver.recvfrom(
        fd, 
        reinterpret_cast<struct sockaddr*>(&addr_storage), 
        &addr_len
    );
    
    if (bytes_received < 0) {
        // Fehler beim Empfangen
        std::cerr << "Fehler beim Zero-Copy-Empfangen: " << strerror(errno) << std::endl;
    } else if (bytes_received > 0) {
        // Aktualisiere Statistiken
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.bytes_received += bytes_received;
        stats_.packets_received++;
        
        // Konvertiere sockaddr in endpoint für weitere Verarbeitung
        if (addr_len > 0) {
            struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&addr_storage);
            if (addr->sa_family == AF_INET) {
                struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(addr);
                boost::asio::ip::address_v4 address(
                    ntohl(addr_in->sin_addr.s_addr)
                );
                remote_endpoint_ = boost::asio::ip::udp::endpoint(address, ntohs(addr_in->sin_port));
            } else if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6* addr_in6 = reinterpret_cast<struct sockaddr_in6*>(addr);
                boost::asio::ip::address_v6::bytes_type addr_bytes;
                memcpy(addr_bytes.data(), &addr_in6->sin6_addr, 16);
                boost::asio::ip::address_v6 address(addr_bytes);
                remote_endpoint_ = boost::asio::ip::udp::endpoint(address, ntohs(addr_in6->sin6_port));
            }
        }
    }
}

// Memory-Pool-Methoden

void QuicConnection::init_memory_pool(size_t block_size, size_t initial_blocks) {
    // Initialisiere den Memory-Pool
    memory_pool_ = std::make_unique<MemoryPool>(block_size, initial_blocks);
}

void* QuicConnection::allocate_from_pool() {
    if (!memory_pool_) {
        // Wenn kein Memory-Pool initialisiert wurde, erstelle einen Standardpool
        init_memory_pool();
    }
    
    return memory_pool_->allocate();
}

void QuicConnection::deallocate_to_pool(void* block) {
    if (memory_pool_ && block) {
        memory_pool_->deallocate(block);
    }
}

// Burst-Buffering-spezifische Methoden

bool QuicConnection::enable_burst_buffering(bool enable) {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    if (enable == burst_buffering_enabled_) {
        return true; // Keine Änderung notwendig
    }
    
    if (enable) {
        // Aktiviere Burst-Buffering
        setup_burst_buffer();
        
        if (burst_buffer_) {
            burst_buffer_->start();
        }
    } else {
        // Deaktiviere Burst-Buffering
        if (burst_buffer_) {
            burst_buffer_->flush();
            burst_buffer_->stop();
        }
    }
    
    burst_buffering_enabled_ = enable;
    return true;
}

bool QuicConnection::is_burst_buffering_enabled() const {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    return burst_buffering_enabled_;
}

void QuicConnection::set_burst_config(const BurstConfig& config) {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    burst_config_ = config;
    
    if (burst_buffer_) {
        burst_buffer_->set_config(config);
    }
}

BurstConfig QuicConnection::get_burst_config() const {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    if (burst_buffer_) {
        return burst_buffer_->get_config();
    }
    
    return burst_config_;
}

void QuicConnection::flush_burst_buffer() {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    if (burst_buffer_ && burst_buffering_enabled_) {
        burst_buffer_->flush();
    }
}

void QuicConnection::setup_burst_buffer() {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    // Initialisiere Burst-Buffer, falls noch nicht geschehen
    if (!burst_buffer_) {
        burst_buffer_ = std::make_unique<BurstBuffer>(burst_config_);
        
        // Setze den Handler für ausgehende Daten
        burst_buffer_->set_data_handler([this](const std::vector<uint8_t>& data) {
            this->handle_burst_data(data);
        });
    }
}

void QuicConnection::handle_burst_data(const std::vector<uint8_t>& data) {
    // Diese Methode wird vom Burst-Buffer aufgerufen, wenn Daten gesendet werden sollen
    if (data.empty()) {
        return;
    }
    
    // Verwende Zero-Copy, wenn aktiviert, sonst normale Übertragung
    if (zero_copy_enabled_ && send_buffer_) {
        ZeroCopyBuffer buffer;
        buffer.add_buffer(data);
        send_datagram_zero_copy(buffer);
    } else {
        send_datagram(data.data(), data.size());
    }
    
    // Aktualisiere Burst-Statistiken
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.bursts_sent++;
    
    // Berechne durchschnittliche Burst-Größe mit exponentieller Glättung
    if (stats_.avg_burst_size == 0.0) {
        stats_.avg_burst_size = static_cast<double>(data.size());
    } else {
        stats_.avg_burst_size = 0.9 * stats_.avg_burst_size + 0.1 * static_cast<double>(data.size());
    }
}

void QuicConnection::send_datagram_burst(const uint8_t* data, size_t size, bool urgent) {
    if (!data || size == 0) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(burst_mutex_);
    
    if (!burst_buffering_enabled_ || !burst_buffer_ || urgent) {
        // Wenn Burst-Buffering deaktiviert ist oder die Daten dringend sind,
        // sende direkt
        send_datagram(data, size);
        return;
    }
    
    // Füge Daten zum Burst-Buffer hinzu
    if (!burst_buffer_->add_data(data, size)) {
        // Bei Fehler, sende direkt
        send_datagram(data, size);
    }
}

// Congestion-Control-Methoden

void QuicConnection::set_congestion_algorithm(CongestionAlgorithm algorithm) {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    congestion_algorithm_ = algorithm;
}

CongestionAlgorithm QuicConnection::get_congestion_algorithm() const {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    return congestion_algorithm_;
}

void QuicConnection::update_congestion_state(uint64_t rtt_us, double loss_rate, double bandwidth_estimate) {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // Aktualisiere RTT-Statistiken
    update_rtt_stats(rtt_us);
    
    // Aktualisiere BBRv2-Status
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 || 
        congestion_algorithm_ == CongestionAlgorithm::ADAPTIVE) {
        update_bbr_state(rtt_us, loss_rate, bandwidth_estimate);
    }
    
    // Andere Congestion-Control-Algorithmen...
}

void QuicConnection::update_bbr_state(uint64_t rtt_us, double loss_rate, double bandwidth_estimate) {
    // Aktualisiere die BBRv2-spezifischen Variablen
    
    // Minimale RTT aktualisieren
    if (rtt_us < min_rtt_us_ || min_rtt_us_ == UINT64_MAX) {
        min_rtt_us_ = rtt_us;
    }
    
    // Aktualisiere Pacing-Gain basierend auf dem Zustand
    if (probe_bw_state_) {
        // Zyklisches Pacing-Gain-Muster im PROBE_BW-Zustand
        static const double kPacingGainCycle[8] = {
            1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
        };
        
        // Aktualisiere den Index alle 2 RTTs
        uint64_t now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
        
        static uint64_t last_cycle_update = 0;
        static int cycle_index = 0;
        
        if (now - last_cycle_update > 2 * min_rtt_us_) {
            cycle_index = (cycle_index + 1) % 8;
            last_cycle_update = now;
            pacing_gain_ = kPacingGainCycle[cycle_index];
        }
    } else if (probe_rtt_state_) {
        // Reduziertes Pacing während PROBE_RTT
        pacing_gain_ = 0.75;
    } else {
        // Standard-Pacing in anderen Zuständen
        pacing_gain_ = 1.0;
    }
    
    // Aktualisiere die inflight-Grenzen basierend auf der Bandbreitenschätzung
    if (bandwidth_estimate > 0) {
        // BDP (Bandwidth-Delay Product) in Bytes
        uint64_t bdp = static_cast<uint64_t>((bandwidth_estimate / 8.0) * (min_rtt_us_ / 1e6));
        
        // Setze inflight_hi_ auf 2 * BDP
        inflight_hi_ = 2 * bdp;
        
        // Setze inflight_lo_ auf 0.5 * BDP
        inflight_lo_ = bdp / 2;
    }
    
    // Aktualisiere die Statistiken
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.pacing_gain = pacing_gain_;
    stats_.cwnd_gain = cwnd_gain_;
    stats_.inflight_hi = inflight_hi_;
    stats_.inflight_lo = inflight_lo_;
    stats_.bandwidth_estimate_bps = bandwidth_estimate;
    stats_.loss_rate = loss_rate;
}

void QuicConnection::enter_probe_bw_state() {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    probe_bw_state_ = true;
    probe_rtt_state_ = false;
    
    // Starte mit dem ersten Eintrag im Pacing-Gain-Zyklus (typischerweise 1.25)
    pacing_gain_ = 1.25;
}

void QuicConnection::enter_probe_rtt_state() {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    probe_rtt_state_ = true;
    probe_bw_state_ = false;
    
    // Reduziere Pacing und CWND während PROBE_RTT
    pacing_gain_ = 0.75;
    cwnd_gain_ = 0.75;
}

void QuicConnection::exit_probe_rtt_state() {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    probe_rtt_state_ = false;
    
    // Gehe zurück in den PROBE_BW-Zustand
    enter_probe_bw_state();
}

void QuicConnection::update_congestion_window() {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 ||
        congestion_algorithm_ == CongestionAlgorithm::ADAPTIVE) {
        // Berechne das Congestion-Window basierend auf dem BBRv2-Status
        
        // Basis-CWND ist das BDP mit einem Gain-Faktor
        uint64_t bdp = static_cast<uint64_t>((stats_.bandwidth_estimate_bps / 8.0) * (min_rtt_us_ / 1e6));
        uint64_t cwnd = static_cast<uint64_t>(bdp * cwnd_gain_);
        
        // Stelle sicher, dass das CWND nicht zu klein ist
        uint64_t min_cwnd = 4 * 1024;
        cwnd = std::max(cwnd, min_cwnd);
        
        // Aktualisiere die Statistik
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.congestion_window = cwnd;
    }
}

// Zero-RTT-bezogene Methoden

bool QuicConnection::enable_zero_rtt(bool enable) {
    zero_rtt_config_.enabled = enable;
    
    if (enable) {
        setup_zero_rtt();
    }
    
    return true;
}

bool QuicConnection::is_zero_rtt_enabled() const {
    return zero_rtt_config_.enabled;
}

void QuicConnection::set_zero_rtt_config(const ZeroRttConfig& config) {
    zero_rtt_config_ = config;
}

ZeroRttConfig QuicConnection::get_zero_rtt_config() const {
    return zero_rtt_config_;
}

void QuicConnection::setup_zero_rtt() {
    // Initialisiere den Token-Schlüssel, wenn er noch nicht gesetzt ist
    if (token_key_.empty()) {
        token_key_.resize(32);
        if (RAND_bytes(token_key_.data(), static_cast<int>(token_key_.size())) != 1) {
            // Fehler bei der Generierung des Token-Schlüssels
            std::cerr << "Fehler bei der Generierung des Zero-RTT-Token-Schlüssels" << std::endl;
            return;
        }
        
        // Setze den Master-Key im ZeroRttManager
        ZeroRttManager::getInstance().setMasterKey(token_key_);
    }
}

bool QuicConnection::generate_token(std::vector<uint8_t>& token, const std::string& hostname) {
    // Verwende den ZeroRttManager, um ein Token zu generieren
    ZeroRttToken zero_rtt_token = ZeroRttManager::getInstance().generateToken(hostname, zero_rtt_config_);
    
    // Speichere das Token für zukünftige Verbindungen
    ZeroRttManager::getInstance().storeToken(hostname, zero_rtt_token);
    
    // Kopiere die Token-Daten in den Ausgabeparameter
    token = zero_rtt_token.token_data;
    
    return !token.empty();
}

bool QuicConnection::validate_token(const std::vector<uint8_t>& token, const std::string& hostname) {
    // Erstelle ein Token-Objekt aus den Daten
    ZeroRttToken zero_rtt_token;
    zero_rtt_token.hostname = hostname;
    zero_rtt_token.token_data = token;
    zero_rtt_token.timestamp = std::chrono::system_clock::now() - std::chrono::seconds(1); // Annahme: Token wurde gerade eben erstellt
    zero_rtt_token.lifetime_s = zero_rtt_config_.max_token_lifetime_s;
    
    // Validiere das Token
    return ZeroRttManager::getInstance().validateToken(zero_rtt_token, hostname);
}

bool QuicConnection::attempt_zero_rtt_handshake(const std::string& hostname) {
    if (!zero_rtt_config_.enabled) {
        return false;
    }
    
    // Prüfe, ob Zero-RTT möglich ist
    if (!ZeroRttManager::getInstance().isZeroRttPossible(hostname, zero_rtt_config_)) {
        if (zero_rtt_config_.reject_if_no_token) {
            // Verbindung ablehnen, da kein gültiges Token verfügbar ist
            std::cerr << "Zero-RTT-Verbindung abgelehnt: Kein gültiges Token für " << hostname << std::endl;
            return false;
        }
        
        // Fahre mit regulärem Handshake fort
        zero_rtt_attempted_ = false;
        return false;
    }
    
    // Hole das gespeicherte Token
    ZeroRttToken token = ZeroRttManager::getInstance().getToken(hostname);
    
    // Implementierung des Zero-RTT-Handshakes mit Quiche
    if (quiche_config_) {
        // Konvertiere das Token in ein Base64-Format für quiche
        std::string token_b64;
        token_b64.reserve(token.token_data.size() * 4 / 3 + 4); // Schätze die benötigte Größe
        
        // Einfache Base64-Kodierung
        static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const unsigned char* bin_data = token.token_data.data();
        size_t bin_size = token.token_data.size();
        
        for (size_t i = 0; i < bin_size; i += 3) {
            unsigned char b1 = bin_data[i];
            unsigned char b2 = (i + 1 < bin_size) ? bin_data[i + 1] : 0;
            unsigned char b3 = (i + 2 < bin_size) ? bin_data[i + 2] : 0;
            
            token_b64.push_back(b64_table[b1 >> 2]);
            token_b64.push_back(b64_table[((b1 & 0x03) << 4) | (b2 >> 4)]);
            token_b64.push_back((i + 1 < bin_size) ? b64_table[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=');
            token_b64.push_back((i + 2 < bin_size) ? b64_table[b3 & 0x3F] : '=');
        }
        
        // Setze Zero-RTT-Parameter in der Quiche-Konfiguration
        quiche_config_set_max_idle_timeout(quiche_config_, 30000); // 30s
        quiche_config_set_initial_max_data(quiche_config_, zero_rtt_config_.max_early_data);
        quiche_config_set_initial_max_stream_data_bidi_local(quiche_config_, zero_rtt_config_.max_early_data / 4);
        quiche_config_set_initial_max_stream_data_bidi_remote(quiche_config_, zero_rtt_config_.max_early_data / 4);
        
        // Aktiviere Early Data (Zero-RTT) in der Quiche-Konfiguration
        quiche_config_enable_early_data(quiche_config_);
        
        // Setze das Session-Ticket/Token
        const uint8_t* token_data = reinterpret_cast<const uint8_t*>(token_b64.data());
        quiche_config_set_session_ticket(quiche_config_, token_data, token_b64.size());
        
        // Wenn Quiche uTLS Erweiterungen unterstützt, aktiviere sie
        if (utls_enabled_ && utls_client_configurator_) {
            std::cout << "Aktiviere uTLS TLS-Extensions für Zero-RTT" << std::endl;
            // Nutze Browser-Fingerprint Extensions für besseres Zero-RTT-Verhalten
            // (Diese Methode muss in der uTLS-Integration existieren)
            utls_client_configurator_->apply_zero_rtt_extensions(quiche_config_, browser_fingerprint_);
        }
        
        std::cout << "Zero-RTT mit Session-Ticket aktiviert für " << hostname << std::endl;
    } else {
        std::cerr << "Zero-RTT-Konfiguration fehlgeschlagen: quiche_config nicht initialisiert" << std::endl;
        return false;
    }
    
    // Markiere, dass Zero-RTT versucht wurde
    zero_rtt_attempted_ = true;
    
    // Aktualisiere Statistiken
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.zero_rtt_attempts++;
    
    return true;
}

// Statistik-bezogene Methoden

ConnectionStats QuicConnection::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void QuicConnection::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = ConnectionStats();
}

void QuicConnection::update_stats(const std::vector<uint8_t>& data, bool is_send) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (is_send) {
        stats_.bytes_sent += data.size();
        stats_.packets_sent++;
    } else {
        stats_.bytes_received += data.size();
        stats_.packets_received++;
    }
}

void QuicConnection::update_rtt_stats(uint64_t rtt_us) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Aktualisiere minimale RTT
    if (stats_.min_rtt_us == 0 || rtt_us < stats_.min_rtt_us) {
        stats_.min_rtt_us = rtt_us;
    }
    
    // Aktualisiere neueste RTT
    stats_.latest_rtt_us = rtt_us;
    
    // Aktualisiere geglättete RTT und Varianz mit EWMA
    constexpr double kRttSmoothingFactor = 0.125;
    constexpr double kRttVarianceFactor = 0.25;
    
    if (stats_.smoothed_rtt_us == 0) {
        // Erste Messung
        stats_.smoothed_rtt_us = rtt_us;
        stats_.rtt_variance_us = rtt_us / 2;
    } else {
        // EWMA für RTT und Varianz
        uint64_t rtt_diff = (rtt_us > stats_.smoothed_rtt_us) 
                            ? (rtt_us - stats_.smoothed_rtt_us) 
                            : (stats_.smoothed_rtt_us - rtt_us);
                            
        stats_.rtt_variance_us = (1.0 - kRttVarianceFactor) * stats_.rtt_variance_us + 
                                 kRttVarianceFactor * rtt_diff;
                                 
        stats_.smoothed_rtt_us = (1.0 - kRttSmoothingFactor) * stats_.smoothed_rtt_us + 
                                 kRttSmoothingFactor * rtt_us;
    }
}

} // namespace quicsand

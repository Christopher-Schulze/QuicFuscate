#include "quic_connection.hpp"
#include "ebpf_zero_copy.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <functional>

namespace quicsand {

// XDP-Integration für QuicConnection

bool QuicConnection::enable_xdp_zero_copy(const std::string& interface) {
    if (xdp_enabled_) {
        return true; // Bereits aktiviert
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Initialisiere den XDP-Kontext
    auto& xdp_context = QuicSandXdpContext::instance();
    if (!xdp_context.initialize(interface)) {
        log_error("Failed to initialize XDP context for interface: " + interface);
        return false;
    }
    
    // Prüfe, ob XDP unterstützt wird
    if (!xdp_context.is_xdp_supported()) {
        log_error("XDP is not supported on this system or interface");
        return false;
    }
    
    // Erstelle XDP-Socket
    uint16_t port = remote_endpoint_.port(); // Verwende den Port der aktuellen Verbindung
    xdp_socket_ = xdp_context.create_socket(port);
    if (!xdp_socket_) {
        log_error("Failed to create XDP socket");
        return false;
    }
    
    // Setze Paket-Handler für eingehende Pakete
    xdp_socket_->set_packet_handler([this](const void* data, size_t len, 
                                         const struct sockaddr* addr, socklen_t addrlen) {
        this->handle_xdp_packet(data, len, addr, addrlen);
    });
    
    xdp_enabled_ = true;
    std::cout << "XDP Zero-Copy enabled for interface: " << interface << std::endl;
    
    return true;
}

bool QuicConnection::disable_xdp_zero_copy() {
    if (!xdp_enabled_) {
        return true; // Bereits deaktiviert
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Bereinige XDP-Socket
    xdp_socket_.reset();
    xdp_enabled_ = false;
    
    std::cout << "XDP Zero-Copy disabled" << std::endl;
    
    return true;
}

bool QuicConnection::is_xdp_zero_copy_enabled() const {
    return xdp_enabled_;
}

void QuicConnection::handle_xdp_packet(const void* data, size_t len, 
                                      const struct sockaddr* addr, socklen_t addrlen) {
    // Konvertiere sockaddr in boost::asio::ip::udp::endpoint
    boost::asio::ip::udp::endpoint sender_endpoint;
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);
        boost::asio::ip::address_v4 address(ntohl(addr_in->sin_addr.s_addr));
        sender_endpoint = boost::asio::ip::udp::endpoint(address, ntohs(addr_in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* addr_in6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
        boost::asio::ip::address_v6::bytes_type addr_bytes;
        memcpy(addr_bytes.data(), &addr_in6->sin6_addr, 16);
        boost::asio::ip::address_v6 address(addr_bytes);
        sender_endpoint = boost::asio::ip::udp::endpoint(address, ntohs(addr_in6->sin6_port));
    } else {
        log_error("Unknown address family: " + std::to_string(addr->sa_family));
        return;
    }
    
    // Verarbeite das Paket
    handle_packet(static_cast<const uint8_t*>(data), len, sender_endpoint);
    
    // Aktualisiere Statistiken
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.xdp_packets_received++;
    }
}

void QuicConnection::send_datagram_xdp(const uint8_t* data, size_t len) {
    if (!xdp_enabled_ || !xdp_socket_) {
        // Fallback auf normale Übertragung, wenn XDP nicht aktiviert ist
        send_datagram(data, len);
        return;
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Bereite die Zieladresse vor
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
    
    // Sende die Daten mit Zero-Copy
    bool success = xdp_socket_->send_zero_copy(
        data, len, 
        reinterpret_cast<const struct sockaddr*>(&addr_storage), 
        addr_len,
        [this, len](size_t bytes_sent, int error) {
            if (error != 0) {
                log_error("XDP send error: " + std::string(strerror(error)));
            } else {
                // Aktualisiere Statistiken
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.xdp_packets_sent++;
                stats_.bytes_sent += bytes_sent;
            }
        }
    );
    
    if (!success) {
        log_error("Failed to send datagram via XDP");
        
        // Fallback auf normale Übertragung
        send_datagram(data, len);
    }
}

void QuicConnection::send_datagram_batch_xdp(const std::vector<std::pair<const uint8_t*, size_t>>& datagrams) {
    if (!xdp_enabled_ || !xdp_socket_) {
        // Fallback auf normale Übertragung, wenn XDP nicht aktiviert ist
        for (const auto& [data, len] : datagrams) {
            send_datagram(data, len);
        }
        return;
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Bereite die Zieladresse vor
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
    
    // Konvertiere Daten in das richtige Format für die Batch-Übertragung
    std::vector<std::pair<const void*, size_t>> buffers;
    buffers.reserve(datagrams.size());
    for (const auto& [data, len] : datagrams) {
        buffers.emplace_back(static_cast<const void*>(data), len);
    }
    
    // Sende die Daten mit Zero-Copy-Batch
    bool success = xdp_socket_->send_zero_copy_batch(
        buffers, 
        reinterpret_cast<const struct sockaddr*>(&addr_storage), 
        addr_len,
        [this, count = datagrams.size()](size_t bytes_sent, int error) {
            if (error != 0) {
                log_error("XDP batch send error: " + std::string(strerror(error)));
            } else {
                // Aktualisiere Statistiken
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.xdp_packets_sent += count;
                stats_.bytes_sent += bytes_sent;
            }
        }
    );
    
    if (!success) {
        log_error("Failed to send datagram batch via XDP");
        
        // Fallback auf normale Übertragung
        for (const auto& [data, len] : datagrams) {
            send_datagram(data, len);
        }
    }
}

bool QuicConnection::optimize_for_core(int core_id) {
    if (!xdp_enabled_ || !xdp_socket_) {
        log_error("XDP not enabled, cannot optimize for core");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    if (!xdp_socket_->pin_to_core(core_id)) {
        log_error("Failed to pin XDP socket to core " + std::to_string(core_id));
        return false;
    }
    
    // Optimiere auch die QUIC-Processing-Threads für diesen Core
    cpu_core_id_ = core_id;
    
    // Setze Thread-Affinität für Haupt-Processing-Thread
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    
    int ret = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (ret != 0) {
        log_error("Failed to set thread affinity: " + std::string(strerror(ret)));
        return false;
    }
    
    std::cout << "QuicConnection optimized for core " << core_id << std::endl;
    
    return true;
}

bool QuicConnection::optimize_numa() {
    if (!xdp_enabled_) {
        log_error("XDP not enabled, cannot optimize NUMA");
        return false;
    }
    
    auto& xdp_context = QuicSandXdpContext::instance();
    if (!xdp_context.setup_memory_numa_aware()) {
        log_error("Failed to set up NUMA-aware memory");
        return false;
    }
    
    std::cout << "QuicConnection NUMA optimization applied" << std::endl;
    
    return true;
}

void QuicConnection::set_xdp_batch_size(uint32_t size) {
    if (!xdp_enabled_ || !xdp_socket_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    xdp_socket_->set_tx_burst_size(size);
}

// Erweiterte Statistiken für XDP
XdpStats QuicConnection::get_xdp_stats() const {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    
    XdpStats xdp_stats;
    xdp_stats.packets_sent = stats_.xdp_packets_sent;
    xdp_stats.packets_received = stats_.xdp_packets_received;
    xdp_stats.bytes_sent = stats_.bytes_sent;
    xdp_stats.bytes_received = stats_.bytes_received;
    
    // Berechne Durchsatz
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - xdp_start_time_).count();
    
    if (elapsed_ms > 0) {
        xdp_stats.throughput_mbps = (xdp_stats.bytes_sent * 8.0 / 1000000.0) / (elapsed_ms / 1000.0);
    }
    
    return xdp_stats;
}

} // namespace quicsand

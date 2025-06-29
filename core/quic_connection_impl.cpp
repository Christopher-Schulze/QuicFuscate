/**
 * @file quic_connection_impl.cpp
 * @brief Consolidated QUIC connection implementation
 * 
 * This file consolidates all QUIC connection implementation methods that were
 * previously split across multiple files:
 * - quic_connection_congestion.cpp (congestion control methods)
 * - quic_connection_mtu.cpp (MTU discovery methods)
 * - quic_connection_perf.cpp (performance and zero-copy methods)
 * - quic_connection_update.cpp (periodic updates and packet processing)
 * - quic_connection_xdp.cpp (XDP integration methods)
 */

#include "quic_connection.hpp"
#include "quic_constants.hpp"
#include "../optimize/unified_optimizations.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <random>
#include <cassert>
#include <sstream>
#include <openssl/err.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <functional>

namespace quicfuscate {

namespace {
bool sockaddr_to_endpoint(const struct sockaddr* addr, socklen_t len,
                          boost::asio::ip::udp::endpoint& endpoint) {
    if (!addr) {
        return false;
    }
    if (addr->sa_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        auto addr_in = reinterpret_cast<const sockaddr_in*>(addr);
        endpoint = boost::asio::ip::udp::endpoint(
            boost::asio::ip::address_v4(ntohl(addr_in->sin_addr.s_addr)),
            ntohs(addr_in->sin_port));
        return true;
    }
    if (addr->sa_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        auto addr_in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), &addr_in6->sin6_addr, 16);
        endpoint = boost::asio::ip::udp::endpoint(
            boost::asio::ip::address_v6(bytes),
            ntohs(addr_in6->sin6_port));
        return true;
    }
    return false;
}
} // anonymous namespace

// =============================================================================
// Congestion Control Methods (from quic_connection_congestion.cpp)
// =============================================================================

bool QuicConnection::enable_bbr_congestion_control(bool enable) {
    if (quiche_conn_ == nullptr) {
        std::cerr << "Cannot enable congestion control without an active QUIC connection" << std::endl;
        return false;
    }
    
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // If BBRv2 is already in the desired state, do nothing
    if ((congestion_algorithm_ == CongestionAlgorithm::BBRv2) == enable) {
        return true;
    }
    
    if (enable) {
        std::cout << "Enabling BBRv2 congestion control" << std::endl;
        congestion_algorithm_ = CongestionAlgorithm::BBRv2;
        
        // Initialize BBRv2 parameters if not already done
        BBRParams bbr_params;
        bbr_params.startup_gain = 2.885;
        bbr_params.drain_gain = 0.75;
        bbr_params.probe_rtt_gain = 0.75;
        bbr_params.cwnd_gain = 2.0;
        bbr_params.startup_cwnd_gain = 2.885;
        
        // Create BBRv2 instance if not already present
        if (!bbr_) {
            bbr_ = std::make_unique<BBRv2>(bbr_params);
        } else {
            bbr_->set_params(bbr_params);
        }
        
        // BBRv2 is configured via quiche_config
    } else {
        std::cout << "Switching to default congestion control (Cubic)" << std::endl;
        congestion_algorithm_ = CongestionAlgorithm::CUBIC;
        
        // Cubic is configured as default algorithm via quiche_config
    }
    
    return true;
}

bool QuicConnection::is_bbr_congestion_control_enabled() const {
    std::lock_guard<std::mutex> lock(cc_mutex_);
    return congestion_algorithm_ == CongestionAlgorithm::BBRv2;
}

void QuicConnection::update_congestion_window() {
    if (!bbr_ || congestion_algorithm_ != CongestionAlgorithm::BBRv2) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(cc_mutex_);
    
    // Get current network metrics from quiche
    quiche_stats stats;
    quiche_conn_stats(quiche_conn_, &stats);
    
    // Update BBRv2 with current metrics
    NetworkMetrics metrics;
    metrics.rtt_us = stats.rtt;
    metrics.bandwidth_bps = stats.delivery_rate;
    metrics.cwnd_bytes = stats.cwnd;
    metrics.bytes_in_flight = stats.bytes_in_flight;
    metrics.lost_packets = stats.lost;
    
    bbr_->update_metrics(metrics);
    
    // Apply BBRv2 recommendations
    auto recommendations = bbr_->get_recommendations();
    if (recommendations.new_cwnd > 0) {
        // Apply new congestion window via quiche if possible
        // Note: quiche manages cwnd internally, this is for monitoring
    }
}

// =============================================================================
// MTU Discovery Methods (from quic_connection_mtu.cpp)
// =============================================================================

bool QuicConnection::enable_mtu_discovery(bool enable) {
    if (!quiche_conn_) {
        std::cerr << "Cannot enable MTU discovery without an active QUIC connection" << std::endl;
        return false;
    }
    
    if (enable && !mtu_discovery_enabled_) {
        std::cout << "Enabling MTU discovery (min=" << min_mtu_ << ", max=" << max_mtu_ 
                  << ", step=" << mtu_step_size_ << ")" << std::endl;
        
        // Initialize the process
        mtu_discovery_enabled_ = true;
        current_mtu_ = min_mtu_; // Start with minimum MTU
        last_successful_mtu_ = min_mtu_;
        mtu_validated_ = false;
        plpmtu_ = min_mtu_;
        
        // Set MTU in quiche connection
        if (quiche_conn_) {
            quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
        }
        
        // Start discovery process
        start_mtu_discovery();
    } else if (!enable && mtu_discovery_enabled_) {
        std::cout << "Disabling MTU discovery, final MTU = " << current_mtu_ << std::endl;
        mtu_discovery_enabled_ = false;
        
        // Set MTU to last successful value
        if (quiche_conn_) {
            quiche_conn_set_max_send_udp_payload_size(quiche_conn_, last_successful_mtu_);
        }
    }
    
    return true;
}

bool QuicConnection::is_mtu_discovery_enabled() const {
    return mtu_discovery_enabled_;
}

void QuicConnection::start_mtu_discovery() {
    if (!mtu_discovery_enabled_) {
        return;
    }
    
    std::cout << "Starting MTU discovery process" << std::endl;
    
    // Reset discovery state
    probe_counter_ = 0;
    max_probe_attempts_ = 5;
    mtu_probe_interval_s_ = 2;
    last_mtu_update_ = std::chrono::steady_clock::now();
    in_search_phase_ = true;
    
    // Start with first probe
    probe_next_mtu();
}

void QuicConnection::probe_next_mtu() {
    if (!mtu_discovery_enabled_ || probe_counter_ >= max_probe_attempts_) {
        return;
    }
    
    uint16_t probe_mtu = current_mtu_ + mtu_step_size_;
    if (probe_mtu > max_mtu_) {
        probe_mtu = max_mtu_;
    }
    
    std::cout << "Probing MTU: " << probe_mtu << " (attempt " << (probe_counter_ + 1) << "/" << max_probe_attempts_ << ")" << std::endl;
    
    // Send probe packet with target MTU size
    send_mtu_probe(probe_mtu);
    
    probe_counter_++;
    last_mtu_update_ = std::chrono::steady_clock::now();
}

void QuicConnection::send_mtu_probe(uint16_t mtu_size) {
    if (!quiche_conn_) {
        return;
    }
    
    // Create probe packet with specified size
    std::vector<uint8_t> probe_data(mtu_size - 28, 0); // Account for IP+UDP headers
    
    // Send probe via quiche
    ssize_t written = quiche_conn_send(quiche_conn_, probe_data.data(), probe_data.size());
    if (written < 0) {
        std::cerr << "Failed to send MTU probe: " << written << std::endl;
    }
}

void QuicConnection::handle_mtu_probe_response(bool success, uint16_t mtu) {
    if (!mtu_discovery_enabled_) {
        return;
    }
    
    if (success) {
        std::cout << "MTU probe successful for size: " << mtu << std::endl;
        last_successful_mtu_ = mtu;
        current_mtu_ = mtu;
        
        // Update quiche connection
        if (quiche_conn_) {
            quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
        }
        
        // Continue probing if not at maximum
        if (current_mtu_ < max_mtu_) {
            probe_counter_ = 0; // Reset counter for next probe
            probe_next_mtu();
        } else {
            in_search_phase_ = false;
            mtu_validated_ = true;
            std::cout << "MTU discovery completed. Final MTU: " << current_mtu_ << std::endl;
        }
    } else {
        std::cout << "MTU probe failed for size: " << mtu << std::endl;
        
        // If we've exhausted attempts, finalize with last successful MTU
        if (probe_counter_ >= max_probe_attempts_) {
            in_search_phase_ = false;
            mtu_validated_ = true;
            current_mtu_ = last_successful_mtu_;
            
            if (quiche_conn_) {
                quiche_conn_set_max_send_udp_payload_size(quiche_conn_, current_mtu_);
            }
            
            std::cout << "MTU discovery completed after max attempts. Final MTU: " << current_mtu_ << std::endl;
        }
    }
}

// =============================================================================
// Performance and Zero-Copy Methods (from quic_connection_perf.cpp)
// =============================================================================

bool QuicConnection::enable_zero_copy(bool enable) {
    if (enable == zero_copy_enabled_) {
        return true; // No change necessary
    }
    
    if (enable) {
        // Enable Zero-Copy
        setup_zero_copy();
    } else {
        // Disable Zero-Copy
        cleanup_zero_copy();
    }
    
    zero_copy_enabled_ = enable;
    return true;
}

bool QuicConnection::is_zero_copy_enabled() const {
    return zero_copy_enabled_;
}

void QuicConnection::setup_zero_copy() {
    // Initialize Zero-Copy components if not already done
    if (!send_buffer_) {
        send_buffer_ = std::make_unique<ZeroCopyBuffer>();
    }
    
    if (!recv_zero_copy_) {
        recv_zero_copy_ = std::make_unique<ZeroCopyReceiver>();
    }
    
    // Initialize Memory Pool
    init_memory_pool();
}

void QuicConnection::cleanup_zero_copy() {
    // Clean up Zero-Copy components
    send_buffer_.reset();
    recv_zero_copy_.reset();
    
    // Clean up memory pool
    cleanup_memory_pool();
}

void QuicConnection::init_memory_pool() {
    if (!memory_pool_) {
        MemoryPoolConfig config;
        config.initial_pool_size = 1024 * 1024; // 1MB
        config.max_pool_size = 16 * 1024 * 1024; // 16MB
        config.block_size = 4096; // 4KB blocks
        config.alignment = 64; // Cache line alignment
        
        memory_pool_ = std::make_unique<MemoryPool>(config);
        
        if (!memory_pool_->initialize()) {
            std::cerr << "Failed to initialize memory pool" << std::endl;
            memory_pool_.reset();
        } else {
            std::cout << "Memory pool initialized successfully" << std::endl;
        }
    }
}

void QuicConnection::cleanup_memory_pool() {
    if (memory_pool_) {
        memory_pool_->cleanup();
        memory_pool_.reset();
        std::cout << "Memory pool cleaned up" << std::endl;
    }
}

// =============================================================================
// Periodic Updates and Packet Processing (from quic_connection_update.cpp)
// =============================================================================

void QuicConnection::update_state_periodic() {
    if (!quiche_conn_) {
        return;
    }
    
    // Update Congestion Control if BBRv2 is enabled
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 && bbr_) {
        update_congestion_window();
    }
    
    // Update MTU Discovery if enabled
    if (mtu_discovery_enabled_ && !in_search_phase_ && 
        current_mtu_ < max_mtu_ && 
        probe_counter_ < max_probe_attempts_) {
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_mtu_update_).count();
        
        // Periodically send MTU probes if time since last update has elapsed
        if (elapsed >= mtu_probe_interval_s_) {
            probe_next_mtu();
        }
    }
    
    // Check if connection migration is necessary
    if (migration_enabled_) {
        check_network_changes();
    }
    
    // Check for expired tokens if Zero-RTT is enabled
    if (zero_rtt_manager_) {
        zero_rtt_manager_->clean_expired_tokens();
    }
}

void QuicConnection::process_packet(const uint8_t* data, size_t len, const boost::asio::ip::udp::endpoint& remote_endpoint) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    
    if (!quiche_conn_) {
        std::cerr << "Cannot process packet: connection not initialized" << std::endl;
        return;
    }
    
    // Process packet through quiche
    ssize_t recv_len = quiche_conn_recv(quiche_conn_, const_cast<uint8_t*>(data), len);
    
    if (recv_len < 0) {
        if (recv_len != QUICHE_ERR_DONE) {
            std::cerr << "Failed to process packet: " << recv_len << std::endl;
        }
        return;
    }
    
    // Update congestion control with packet reception
    if (congestion_algorithm_ == CongestionAlgorithm::BBRv2 && bbr_) {
        update_congestion_window();
    }
    
    // Handle any resulting packets that need to be sent
    send_pending_packets();
}

void QuicConnection::send_pending_packets() {
    if (!quiche_conn_) {
        return;
    }
    
    static uint8_t out[DEFAULT_INITIAL_MTU]; // Standard MTU size buffer
    
    while (true) {
        ssize_t written = quiche_conn_send(quiche_conn_, out, sizeof(out));
        
        if (written == QUICHE_ERR_DONE) {
            break; // No more packets to send
        }
        
        if (written < 0) {
            std::cerr << "Failed to create packet: " << written << std::endl;
            break;
        }
        
        // Send packet via UDP socket
        send_udp_packet(out, written);
    }
}

void QuicConnection::send_udp_packet(const uint8_t* data, size_t len) {
    if (!socket_) {
        std::cerr << "Cannot send packet: socket not initialized" << std::endl;
        return;
    }
    
    boost::system::error_code ec;
    socket_->send_to(boost::asio::buffer(data, len), remote_endpoint_, 0, ec);
    
    if (ec) {
        std::cerr << "Failed to send UDP packet: " << ec.message() << std::endl;
    }
}

void QuicConnection::check_network_changes() {
    // Implementation for network change detection
    // This would typically involve checking for new network interfaces,
    // changes in IP addresses, or network quality metrics
    
    // Placeholder implementation
    static auto last_check = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_check).count() >= 30) {
        // Check for network changes every 30 seconds
        last_check = now;
        
        // Actual network change detection would go here
        // For now, this is a placeholder
    }
}

// =============================================================================
// XDP Integration Methods (from quic_connection_xdp.cpp)
// =============================================================================

bool QuicConnection::enable_xdp_zero_copy(const std::string& interface) {
    if (xdp_enabled_) {
        return true; // Already enabled
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Initialize XDP context
    auto& xdp_context = QuicFuscateXdpContext::instance();
    if (!xdp_context.initialize(interface)) {
        log_error("Failed to initialize XDP context for interface: " + interface);
        return false;
    }
    
    // Check if XDP is supported
    if (!xdp_context.is_xdp_supported()) {
        log_error("XDP is not supported on this system or interface");
        return false;
    }
    
    // Create XDP socket
    uint16_t port = remote_endpoint_.port(); // Use port of current connection
    xdp_socket_ = xdp_context.create_socket(port);
    if (!xdp_socket_) {
        log_error("Failed to create XDP socket");
        return false;
    }
    
    // Set packet handler for incoming packets
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
        return true; // Already disabled
    }
    
    std::lock_guard<std::mutex> lock(xdp_mutex_);
    
    // Clean up XDP socket
    if (xdp_socket_) {
        xdp_socket_.reset();
    }
    
    xdp_enabled_ = false;
    std::cout << "XDP Zero-Copy disabled" << std::endl;
    
    return true;
}

bool QuicConnection::is_xdp_enabled() const {
    return xdp_enabled_;
}

void QuicConnection::handle_xdp_packet(const void* data, size_t len, 
                                     const struct sockaddr* addr, socklen_t addrlen) {
    if (!xdp_enabled_ || !data || len == 0) {
        return;
    }
    
    boost::asio::ip::udp::endpoint endpoint;
    if (!sockaddr_to_endpoint(addr, addrlen, endpoint)) {
        log_error("Unsupported address family in XDP packet");
        return;
    }
    
    // Process packet through normal QUIC processing
    process_packet(static_cast<const uint8_t*>(data), len, endpoint);
}

void QuicConnection::log_error(const std::string& message) {
    std::cerr << "[QuicConnection Error] " << message << std::endl;
}

} // namespace quicfuscate

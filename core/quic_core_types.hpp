#ifndef QUIC_CORE_TYPES_HPP

/**
 * @file quic_core_types.hpp
 * @brief Consolidated QUIC core types and definitions
 * 
 * This file consolidates the basic QUIC types, packet definitions, and stream
 * declarations that were previously split across multiple header files:
 * - quic.hpp (basic types and config)
 * - quic_packet.hpp (packet types and structures)
 * - quic_stream.hpp (stream class declaration)
 * - quic_base.hpp (enumerations and data structures)
 */

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <openssl/ssl.h>
#include "quiche.h"
#include "../optimize/unified_optimizations.hpp"  // For BurstConfig and related types
#include "error_handling.hpp"

namespace quicfuscate {

// =============================================================================
// Forward Declarations
// =============================================================================

class QuicConnection;
class QuicStream;

// =============================================================================
// QUIC Path Migration Strategy (moved from quic_base.hpp)
// =============================================================================

/**
 * @brief QUIC path migration strategies
 */
enum class PathMigrationStrategy {
    NONE,                    // No path migration
    PROACTIVE,              // Migrate before connection issues
    REACTIVE,               // Migrate after detecting issues
    RANDOM,                 // Random migration for stealth
    LOAD_BALANCED,          // Migrate based on load
    LATENCY_OPTIMIZED       // Migrate to lowest latency path
};

// =============================================================================
// Basic QUIC Configuration and Types (from quic.hpp)
// =============================================================================

/**
 * @brief QUIC connection configuration
 */
struct QuicConfig {
    std::string server_name;
    uint16_t port;
    // Additional configuration parameters...

    // For uTLS integration with quiche_conn_new_with_tls
    SSL* utls_ssl = nullptr; // May be less relevant with _ctx approach
    SSL_CTX* utls_ssl_ctx = nullptr; // For quiche_conn_new_with_tls_ctx
    quiche_config* utls_quiche_config = nullptr; // For uTLS integration
};

/**
 * @brief Stream type enumeration
 */
enum class StreamType : uint8_t {
    DATA = 0,
    CONTROL = 1,
    HEADER = 2,
    QPACK_ENCODER = 3,
    QPACK_DECODER = 4
};

// =============================================================================
// Data Structures (moved from quic_base.hpp)
// =============================================================================

/**
 * @brief Path information for QUIC migration
 */
struct QuicPath {
    std::string local_address;
    uint16_t local_port;
    std::string remote_address;
    uint16_t remote_port;
    uint32_t path_id;
    
    // Path metrics
    uint32_t rtt_ms;
    uint32_t bandwidth_kbps;
    double packet_loss_rate;
    uint32_t congestion_window;
    
    // Path state
    bool is_active;
    bool is_validated;
    std::chrono::steady_clock::time_point last_used;
    
    // Statistics
    uint64_t bytes_sent;
    uint64_t bytes_received;
};

/**
 * @brief Stream optimization configuration
 */
struct StreamOptimizationConfig {
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_window_size;
    uint32_t stream_buffer_size;
    bool enable_flow_control;
    bool enable_prioritization;
    bool enable_multiplexing;
    double congestion_threshold;
};

// =============================================================================
// QUIC Packet Types and Structures (from quic_packet.hpp)
// =============================================================================

/**
 * @brief QUIC packet types
 */
enum class PacketType : uint8_t {
    INITIAL = 0x00,
    ZERO_RTT = 0x01,
    HANDSHAKE = 0x02,
    RETRY = 0x03
};

/**
 * @brief QUIC packet header structure
 */
struct QuicPacketHeader {
    PacketType type;
    uint32_t version;
    uint64_t connection_id;
    uint64_t packet_number;
    uint32_t payload_length;
    uint8_t flags;
    
    QuicPacketHeader() 
        : type(PacketType::INITIAL), version(0x00000001), 
          connection_id(0), packet_number(0), payload_length(0), flags(0) {}
};

/**
 * @brief QUIC packet class
 */
class QuicPacket {
public:
    // Constructors
    QuicPacket();
    QuicPacket(const QuicPacketHeader& header);
    QuicPacket(PacketType type, uint32_t version = 0x00000001);
    QuicPacket(const QuicPacket& other);
    QuicPacket(QuicPacket&& other) noexcept;
    
    // Assignment operators
    QuicPacket& operator=(const QuicPacket& other);
    QuicPacket& operator=(QuicPacket&& other) noexcept;
    
    // Destructor
    ~QuicPacket() = default;
    
    // Header access
    const QuicPacketHeader& header() const { return header_; }
    QuicPacketHeader& header() { return header_; }
    void set_header(const QuicPacketHeader& header) { header_ = header; }
    
    // Payload access
    const std::vector<uint8_t>& payload() const { return payload_; }
    std::vector<uint8_t>& payload() { return payload_; }
    void set_payload(const std::vector<uint8_t>& payload) { payload_ = payload; }
    void set_payload(std::vector<uint8_t>&& payload) { payload_ = std::move(payload); }
    
    // Packet type methods
    void set_packet_type(PacketType type);
    bool is_initial() const;
    bool is_handshake() const;
    bool is_stream() const;
    bool is_one_rtt() const;
    
    // Utility methods
    size_t size() const;
    bool is_valid() const;
    std::string to_string() const;
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
    static std::shared_ptr<QuicPacket> deserialize(const std::vector<uint8_t>& data);
    
    // Comparison operators
    bool operator==(const QuicPacket& other) const;
    bool operator!=(const QuicPacket& other) const;
    
private:
    QuicPacketHeader header_;
    std::vector<uint8_t> payload_;
};

// =============================================================================
// QUIC Stream Class Declaration (from quic_stream.hpp)
// =============================================================================

/**
 * @brief QUIC stream class for data transmission
 */
class QuicStream {
public:
    // Constructor with default BurstBuffer configuration
    QuicStream(std::shared_ptr<QuicConnection> conn, int id, StreamType type);
    
    // Constructor with custom BurstBuffer configuration
    QuicStream(std::shared_ptr<QuicConnection> conn, int id, StreamType type, const BurstConfig& burst_config);
    
    // Destructor
    ~QuicStream();
    
    // Data transmission methods
    void send_data(const uint8_t* data, size_t size);
    void send_data(const std::vector<uint8_t>& data);
    void send_data(const std::string& data);
    
    // Legacy data methods (from quic_base.cpp)
    bool write_data(const std::vector<uint8_t>& data);
    std::vector<uint8_t> read_data();
    bool is_readable() const;
    
    // BurstBuffer configuration methods
    void set_burst_config(const BurstConfig& config);
    BurstConfig get_burst_config() const;
    BurstMetrics get_burst_metrics() const;
    
    // Control methods
    bool is_writable() const;
    bool is_closed() const;
    void close();
    
    // Stream properties
    int id() const { return id_; }
    StreamType type() const { return type_; }
    
    // Flow control methods
    void set_flow_control_limit(size_t limit);
    size_t get_flow_control_limit() const;
    size_t get_bytes_sent() const;
    size_t get_bytes_received() const;
    
    // Burst control specific methods
    void enable_burst_mode(bool enable);
    bool is_burst_mode_enabled() const;
    void flush_burst_buffer();
    
private:
    std::shared_ptr<QuicConnection> connection_;
    int id_;
    StreamType type_;
    
    // Flow control state
    std::atomic<size_t> bytes_sent_{0};
    std::atomic<size_t> bytes_received_{0};
    std::atomic<size_t> flow_control_limit_{0};
    std::atomic<bool> closed_{false};
    
    // Burst buffer configuration and state
    BurstConfig burst_config_;
    std::unique_ptr<BurstBuffer> burst_buffer_;
    mutable std::mutex burst_mutex_;
    std::atomic<bool> burst_mode_enabled_{false};
    
    // Legacy buffer state (from quic_base.cpp)
    std::vector<uint8_t> buffer;
    mutable std::mutex buffer_mutex;
    std::condition_variable data_available_cv_;
};

// =============================================================================
// QUIC Integration and Management Classes
// =============================================================================

/**
 * @brief QUIC connection state enumeration
 */
enum class QuicConnectionState : uint8_t {
    INITIAL,
    HANDSHAKE,
    ESTABLISHED,
    CLOSING,
    CLOSED,
    ERROR
};

/**
 * @brief QUIC integration class for managing connections and streams
 */
class QuicIntegration {
public:
    QuicIntegration();
    ~QuicIntegration() = default;
    
    // Initialization and configuration
    bool initialize(const std::map<std::string, std::string>& config);
    
    // Packet processing
    bool process_outgoing_packet(std::shared_ptr<QuicPacket> packet);
    bool process_incoming_packet(std::shared_ptr<QuicPacket> packet);
    
    // Statistics and monitoring
    uint64_t get_packets_sent() const { return packets_sent_; }
    uint64_t get_packets_received() const { return packets_received_; }
    uint64_t get_bytes_sent() const { return bytes_sent_; }
    uint64_t get_bytes_received() const { return bytes_received_; }
    
private:
    bool validate_packet(std::shared_ptr<QuicPacket> packet);
    void update_statistics(std::shared_ptr<QuicPacket> packet, bool outgoing);
    
    QuicConnectionState connection_state_;
    std::mutex integration_mutex_;
    
    // Statistics
    std::atomic<uint64_t> packets_sent_{0};
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> bytes_received_{0};
    std::atomic<uint64_t> streams_created_{0};
    std::atomic<uint64_t> migrations_performed_{0};
};

/**
 * @brief Unified QUIC manager
 */
class QuicUnifiedManager {
public:
    static QuicUnifiedManager& instance();

    QuicUnifiedManager();
    ~QuicUnifiedManager() = default;

    Result<void> initialize(const std::map<std::string, std::string>& config);
    Result<QuicIntegration*> get_integration();
    void shutdown();

private:
    std::mutex manager_mutex_;
    bool is_initialized_{false};
    std::unique_ptr<QuicIntegration> integration_;
};

} // namespace quicfuscate

#endif // QUIC_CORE_TYPES_HPP

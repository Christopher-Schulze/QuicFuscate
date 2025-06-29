/**
 * @file quic_integration_impl.cpp
 * @brief Implementation of QUIC Integration and Unified Manager
 * 
 * This file implements the QUIC integration and management functionality
 * that was moved from core/quic_base.cpp.
 */

#include "quic_core_types.hpp"
#include "../stealth/stealth_gov.hpp"
#include "../optimize/unified_optimizations.hpp"
#include <algorithm>
#include <cassert>

namespace quicfuscate {

// =============================================================================
// QuicIntegration Implementation
// =============================================================================

QuicIntegration::QuicIntegration() 
    : connection_state_(QuicConnectionState::INITIAL),
      packets_sent_(0),
      packets_received_(0),
      bytes_sent_(0),
      bytes_received_(0),
      streams_created_(0),
      migrations_performed_(0) {
}

bool QuicIntegration::initialize(const std::map<std::string, std::string>& config) {
    std::lock_guard<std::mutex> lock(integration_mutex_);
    
    connection_state_ = QuicConnectionState::HANDSHAKE;
    return true;
}

bool QuicIntegration::process_outgoing_packet(std::shared_ptr<QuicPacket> packet) {
    if (!validate_packet(packet)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(integration_mutex_);
    
    update_statistics(packet, true);
    
    return true;
}

bool QuicIntegration::process_incoming_packet(std::shared_ptr<QuicPacket> packet) {
    if (!validate_packet(packet)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(integration_mutex_);
    
    update_statistics(packet, false);
    
    if (connection_state_ == QuicConnectionState::HANDSHAKE) {
        connection_state_ = QuicConnectionState::ESTABLISHED;
    }
    
    return true;
}

std::shared_ptr<QuicStream> QuicIntegration::create_stream(uint64_t stream_id) {
    std::lock_guard<std::mutex> lock(integration_mutex_);
    
    if (active_streams_.size() >= 100) { // Max streams limit
        return nullptr;
    }
    
    auto stream = std::make_shared<QuicStream>(stream_id);
    
    active_streams_[stream_id] = stream;
    streams_created_++;
    
    return stream;
}

bool QuicIntegration::close_stream(uint64_t stream_id) {
    std::lock_guard<std::mutex> lock(integration_mutex_);
    
    auto it = active_streams_.find(stream_id);
    if (it != active_streams_.end()) {
        it->second->close();
        active_streams_.erase(it);
        return true;
    }
    
    return false;
}

QuicConnectionState QuicIntegration::get_connection_state() const {
    return connection_state_;
}

bool QuicIntegration::migrate_connection() {
    migrations_performed_++;
    return true;
}

std::map<std::string, uint64_t> QuicIntegration::get_statistics() const {
    return {
        {"packets_sent", packets_sent_.load()},
        {"packets_received", packets_received_.load()},
        {"bytes_sent", bytes_sent_.load()},
        {"bytes_received", bytes_received_.load()},
        {"streams_created", streams_created_.load()},
        {"migrations_performed", migrations_performed_.load()}
    };
}

bool QuicIntegration::validate_packet(std::shared_ptr<QuicPacket> packet) const {
    return packet != nullptr && !packet->data.empty();
}

void QuicIntegration::update_statistics(std::shared_ptr<QuicPacket> packet, bool outgoing) {
    if (outgoing) {
        packets_sent_++;
        bytes_sent_ += packet->data.size();
    } else {
        packets_received_++;
        bytes_received_ += packet->data.size();
    }
}

// =============================================================================
// QuicUnifiedManager Implementation
// =============================================================================

QuicUnifiedManager& QuicUnifiedManager::instance() {
    static QuicUnifiedManager instance;
    return instance;
}

bool QuicUnifiedManager::initialize(const std::map<std::string, std::string>& config) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    
    if (is_initialized_) {
        return true;
    }
    
    integration_ = std::make_unique<QuicIntegration>();
    if (!integration_->initialize(config)) {
        return false;
    }
    
    is_initialized_ = true;
    return true;
}

QuicIntegration& QuicUnifiedManager::get_integration() {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    assert(integration_ != nullptr);
    return *integration_;
}

void QuicUnifiedManager::shutdown() {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    integration_.reset();
    is_initialized_ = false;
}

} // namespace quicfuscate

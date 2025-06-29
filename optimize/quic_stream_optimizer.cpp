/**
 * @file quic_stream_optimizer.cpp
 * @brief Implementation of QUIC Stream Optimizer
 * 
 * This file implements the QUIC stream optimization functionality that was moved
 * from core/quic_base.cpp. Stream optimization is a performance feature that
 * belongs in the optimize module.
 */

#include "unified_optimizations.hpp"
#include "../core/quic_core_types.hpp"
#include <algorithm>
#include <cassert>

namespace quicfuscate {

// =============================================================================
// QuicStreamOptimizer Implementation
// =============================================================================

QuicStreamOptimizer::QuicStreamOptimizer() {
    // Initialize with default configuration
    config_.max_concurrent_streams = 100;
    config_.initial_window_size = 65536;
    config_.max_window_size = 1048576;
    config_.stream_buffer_size = 32768;
    config_.enable_flow_control = true;
    config_.enable_prioritization = true;
    config_.enable_multiplexing = true;
    config_.congestion_threshold = 0.8;
}

bool QuicStreamOptimizer::initialize(const StreamOptimizationConfig& config) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    config_ = config;
    return true;
}

bool QuicStreamOptimizer::optimize_stream(std::shared_ptr<QuicStream> stream) {
    if (!stream) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(streams_mutex_);
    
    // Initialize stream window if not exists
    if (stream_windows_.find(stream->stream_id) == stream_windows_.end()) {
        stream_windows_[stream->stream_id] = config_.initial_window_size;
    }
    
    // Adjust window size based on congestion
    if (is_stream_congested(stream->stream_id)) {
        uint32_t current_window = stream_windows_[stream->stream_id];
        stream_windows_[stream->stream_id] = std::max(current_window / 2, config_.initial_window_size / 4);
    } else {
        uint32_t current_window = stream_windows_[stream->stream_id];
        stream_windows_[stream->stream_id] = std::min(current_window * 2, config_.max_window_size);
    }
    
    return true;
}

bool QuicStreamOptimizer::set_stream_priority(uint64_t stream_id, uint8_t priority) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    stream_priorities_[stream_id] = priority;
    return true;
}

bool QuicStreamOptimizer::update_flow_control_window(uint64_t stream_id, uint32_t window_size) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    
    if (window_size > config_.max_window_size) {
        return false;
    }
    
    stream_windows_[stream_id] = window_size;
    return true;
}

bool QuicStreamOptimizer::can_send_data(uint64_t stream_id, uint32_t data_size) const {
    // Note: Using const_cast for mutex in const method - this is acceptable for synchronization
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(streams_mutex_));
    
    auto it = stream_windows_.find(stream_id);
    if (it == stream_windows_.end()) {
        return data_size <= config_.initial_window_size;
    }
    
    return data_size <= it->second;
}

uint32_t QuicStreamOptimizer::get_optimal_chunk_size(uint64_t stream_id) const {
    // Note: Using const_cast for mutex in const method - this is acceptable for synchronization
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(streams_mutex_));
    
    auto it = stream_windows_.find(stream_id);
    uint32_t window_size = (it != stream_windows_.end()) ? it->second : config_.initial_window_size;
    
    // Return a chunk size that's a fraction of the window
    return std::min(window_size / 4, static_cast<uint32_t>(1400)); // MTU consideration
}

std::vector<uint64_t> QuicStreamOptimizer::schedule_streams() {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    
    std::vector<std::pair<uint64_t, uint8_t>> stream_priority_pairs;
    
    for (const auto& [stream_id, priority] : stream_priorities_) {
        stream_priority_pairs.emplace_back(stream_id, priority);
    }
    
    // Sort by priority (lower number = higher priority)
    std::sort(stream_priority_pairs.begin(), stream_priority_pairs.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });
    
    std::vector<uint64_t> scheduled_streams;
    for (const auto& [stream_id, priority] : stream_priority_pairs) {
        scheduled_streams.push_back(stream_id);
    }
    
    return scheduled_streams;
}

uint32_t QuicStreamOptimizer::calculate_optimal_window_size(uint64_t stream_id) const {
    // Simple calculation based on stream type and current conditions
    auto it = stream_priorities_.find(stream_id);
    uint8_t priority = (it != stream_priorities_.end()) ? it->second : 128;
    
    // Higher priority streams get larger windows
    double priority_factor = 1.0 + (255 - priority) / 255.0;
    return static_cast<uint32_t>(config_.initial_window_size * priority_factor);
}

bool QuicStreamOptimizer::is_stream_congested(uint64_t stream_id) const {
    // Simple congestion detection based on buffer usage
    auto it = stream_buffers_.find(stream_id);
    if (it == stream_buffers_.end()) {
        return false;
    }
    
    double usage_ratio = static_cast<double>(it->second) / config_.stream_buffer_size;
    return usage_ratio > config_.congestion_threshold;
}

} // namespace quicfuscate
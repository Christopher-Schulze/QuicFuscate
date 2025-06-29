/**
 * @file quic_stream_impl.cpp
 * @brief Implementation of QUIC stream functionality
 * 
 * This file contains the implementation of QuicStream methods that were
 * previously in quic_base.cpp. The implementation has been moved here
 * to support the consolidated QuicStream class in quic_core_types.hpp.
 */

#include "quic_core_types.hpp"
#include <algorithm>

namespace quicfuscate {

// =============================================================================
// QuicStream Legacy Implementation (from quic_base.cpp)
// =============================================================================

bool QuicStream::write_data(const std::vector<uint8_t>& data) {
    if (closed_.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(buffer_mutex);
    buffer.insert(buffer.end(), data.begin(), data.end());
    bytes_sent_.fetch_add(data.size());
    
    data_available_cv_.notify_one();
    return true;
}

std::vector<uint8_t> QuicStream::read_data() {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    
    if (buffer.empty()) {
        return {};
    }
    
    std::vector<uint8_t> data = std::move(buffer);
    buffer.clear();
    bytes_received_.fetch_add(data.size());
    
    return data;
}

bool QuicStream::is_readable() const {
    // Note: Using const_cast for mutex in const method - this is acceptable for synchronization
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(buffer_mutex));
    return !buffer.empty() && !closed_.load();
}

} // namespace quicfuscate

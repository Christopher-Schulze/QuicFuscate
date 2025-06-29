#include "XOR_Obfuscation.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <map>

// Include SIMD headers if available
#ifdef __x86_64__
#include <immintrin.h>
#include <cpuid.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace quicfuscate::stealth {

// Hash function for key derivation
static uint64_t hash_fnv1a(const uint8_t* data, size_t size) {
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

// SIMD capability detection
static bool detect_simd_support() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_SSE4_1) != 0;
    }
#elif defined(__aarch64__)
    return true; // NEON is standard on AArch64
#endif
    return false;
}

// Forward declarations for utility classes
class XOROperations {
public:
    static void xor_arrays(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size);
    static void xor_with_key(const uint8_t* data, const uint8_t* key, uint8_t* result, size_t data_size, size_t key_size);
    static void position_dependent_xor(uint8_t* data, size_t size, const uint8_t* base_key, size_t key_size);
    static void simd_xor_arrays(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size);
    static bool is_simd_available();
    static size_t get_simd_block_size();
};

class XORKeyDerivation {
public:
    static std::vector<uint8_t> derive_key(uint64_t context_id, const std::vector<uint8_t>& salt, size_t key_size);
    static std::vector<uint8_t> derive_key_from_string(const std::string& context, const std::vector<uint8_t>& salt, size_t key_size);
    static std::vector<uint8_t> generate_secure_key(size_t key_size);
    static std::vector<uint8_t> expand_key(const std::vector<uint8_t>& key, size_t target_size);
};

class XORPatterns {
public:
    static std::vector<uint8_t> get_fec_pattern(size_t size);
    static std::vector<uint8_t> get_header_pattern(const std::string& header_name, size_t size);
    static std::vector<uint8_t> get_payload_pattern(uint32_t transformation_id, size_t size);
    static std::vector<uint8_t> get_anti_dpi_pattern(size_t size);
};

class XORObfuscator::Impl {
public:
    explicit Impl(const XORConfig& config)
        : config_(config), packet_counter_(0), key_rotation_counter_(0),
          simd_available_(detect_simd_support() && config.enable_simd_optimization),
          rng_(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {
        
        // Initialize static key if provided
        if (!config_.static_key.empty()) {
            current_key_ = config_.static_key;
        } else {
            generate_new_key();
        }
        
        // Initialize statistics
        stats_ = {};
        stats_.simd_acceleration_active = simd_available_;
    }
    
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data, 
                                   XORPattern pattern, uint64_t context_id) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<uint8_t> result = data;
        obfuscate_inplace(result, pattern, context_id);
        
        update_statistics(data.size(), start_time);
        return result;
    }
    
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data,
                                     XORPattern pattern, uint64_t context_id) {
        // XOR is symmetric, so deobfuscation is the same as obfuscation
        return obfuscate(data, pattern, context_id);
    }
    
    void obfuscate_inplace(std::vector<uint8_t>& data, XORPattern pattern, uint64_t context_id) {
        if (data.empty()) return;
        
        switch (pattern) {
            case XORPattern::SIMPLE:
                apply_simple_xor(data.data(), data.size(), context_id);
                break;
            case XORPattern::LAYERED:
                apply_layered_xor(data.data(), data.size(), context_id);
                break;
            case XORPattern::POSITION_BASED:
                apply_position_based_xor(data.data(), data.size(), context_id);
                break;
            case XORPattern::CRYPTO_SECURE:
                apply_crypto_secure_xor(data.data(), data.size(), context_id);
                break;
            case XORPattern::FEC_OPTIMIZED:
                apply_fec_optimized_xor(data.data(), data.size(), context_id);
                break;
            case XORPattern::HEADER_SPECIFIC:
                apply_header_specific_xor(data.data(), data.size(), context_id);
                break;
        }
        
        // Check if key rotation is needed
        if (config_.enable_dynamic_keys && 
            ++key_rotation_counter_ >= config_.key_rotation_interval) {
            rotate_keys();
        }
        
        ++packet_counter_;
    }
    
    std::vector<uint8_t> generate_context_key(uint64_t context_id, size_t key_size) {
        return XORKeyDerivation::derive_key(context_id, {}, key_size);
    }
    
    std::vector<uint8_t> obfuscate_quic_payload(const std::vector<uint8_t>& payload, uint64_t packet_number) {
        return obfuscate(payload, XORPattern::CRYPTO_SECURE, packet_number);
    }
    
    std::vector<uint8_t> obfuscate_fec_metadata(const std::vector<uint8_t>& metadata, uint32_t block_id) {
        return obfuscate(metadata, XORPattern::FEC_OPTIMIZED, block_id);
    }
    
    std::vector<uint8_t> obfuscate_http3_headers(const std::vector<uint8_t>& headers, uint64_t stream_id) {
        return obfuscate(headers, XORPattern::HEADER_SPECIFIC, stream_id);
    }
    
    void update_config(const XORConfig& config) {
        config_ = config;
        simd_available_ = detect_simd_support() && config.enable_simd_optimization;
        stats_.simd_acceleration_active = simd_available_;
        
        if (!config_.static_key.empty()) {
            current_key_ = config_.static_key;
        }
    }
    
    void rotate_keys() {
        if (config_.enable_dynamic_keys) {
            generate_new_key();
            key_rotation_counter_ = 0;
            ++stats_.key_rotations;
        }
    }
    
    XORObfuscator::Statistics get_statistics() const { return stats_; }
    
    void reset_statistics() {
        stats_ = {};
        stats_.simd_acceleration_active = simd_available_;
    }
    
    bool is_simd_enabled() const {
        return simd_available_;
    }
    
    std::map<XORPattern, double> benchmark_patterns(size_t data_size, size_t iterations) {
        std::map<XORPattern, double> results;
        std::vector<uint8_t> test_data(data_size, 0x42);
        
        std::vector<XORPattern> patterns = {
            XORPattern::SIMPLE,
            XORPattern::LAYERED,
            XORPattern::POSITION_BASED,
            XORPattern::CRYPTO_SECURE,
            XORPattern::FEC_OPTIMIZED,
            XORPattern::HEADER_SPECIFIC
        };
        
        for (auto pattern : patterns) {
            auto start = std::chrono::high_resolution_clock::now();
            
            for (size_t i = 0; i < iterations; ++i) {
                auto temp_data = test_data;
                obfuscate_inplace(temp_data, pattern, i);
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            
            double mbps = (static_cast<double>(data_size * iterations) / (1024 * 1024)) / 
                         (duration.count() / 1000000.0);
            results[pattern] = mbps;
        }
        
        return results;
    }

private:
    void generate_new_key() {
        current_key_ = XORKeyDerivation::generate_secure_key(32);
    }
    
    void apply_simple_xor(uint8_t* data, size_t size, uint64_t context_id) {
        auto key = get_context_key(context_id);
        
        if (simd_available_ && size >= 16) {
            apply_simd_xor(data, key.data(), size, key.size());
        } else {
            XOROperations::xor_with_key(data, key.data(), data, size, key.size());
        }
    }
    
    void apply_layered_xor(uint8_t* data, size_t size, uint64_t context_id) {
        if (!config_.enable_multi_layer) {
            apply_simple_xor(data, size, context_id);
            return;
        }
        
        // Apply multiple XOR layers with different keys
        for (uint8_t layer = 0; layer < config_.obfuscation_strength; ++layer) {
            auto key = get_context_key(context_id + layer);
            XOROperations::xor_with_key(data, key.data(), data, size, key.size());
        }
    }
    
    void apply_position_based_xor(uint8_t* data, size_t size, uint64_t context_id) {
        auto base_key = get_context_key(context_id);
        XOROperations::position_dependent_xor(data, size, base_key.data(), base_key.size());
    }
    
    void apply_crypto_secure_xor(uint8_t* data, size_t size, uint64_t context_id) {
        // Generate a cryptographically secure key for this specific context
        auto secure_key = XORKeyDerivation::generate_secure_key(std::max(size, static_cast<size_t>(32)));
        
        // Mix with context
        uint64_t context_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(&context_id), sizeof(context_id));
        for (size_t i = 0; i < secure_key.size(); ++i) {
            secure_key[i] ^= static_cast<uint8_t>(context_hash >> (8 * (i % 8)));
        }
        
        XOROperations::xor_with_key(data, secure_key.data(), data, size, secure_key.size());
    }
    
    void apply_fec_optimized_xor(uint8_t* data, size_t size, uint64_t context_id) {
        // Use FEC-specific pattern
        auto pattern = XORPatterns::get_fec_pattern(size);
        
        // Mix with context
        auto context_key = get_context_key(context_id);
        for (size_t i = 0; i < pattern.size() && i < context_key.size(); ++i) {
            pattern[i] ^= context_key[i];
        }
        
        XOROperations::xor_with_key(data, pattern.data(), data, size, pattern.size());
    }
    
    void apply_header_specific_xor(uint8_t* data, size_t size, uint64_t context_id) {
        // Use header-specific pattern
        auto pattern = XORPatterns::get_header_pattern("", size);
        
        // Mix with context
        auto context_key = get_context_key(context_id);
        for (size_t i = 0; i < std::min(pattern.size(), context_key.size()); ++i) {
            pattern[i] ^= context_key[i];
        }
        
        XOROperations::xor_with_key(data, pattern.data(), data, size, pattern.size());
    }
    
    void apply_simd_xor(uint8_t* data, const uint8_t* key, size_t size, size_t key_size) {
#ifdef __x86_64__
        // SSE2 implementation
        size_t simd_blocks = size / 16;
        size_t remaining = size % 16;
        
        for (size_t i = 0; i < simd_blocks; ++i) {
            __m128i data_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i * 16));
            
            // Create key vector by repeating key bytes
            __m128i key_vec;
            uint8_t key_block[16];
            for (int j = 0; j < 16; ++j) {
                key_block[j] = key[(i * 16 + j) % key_size];
            }
            key_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key_block));
            
            __m128i result = _mm_xor_si128(data_vec, key_vec);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(data + i * 16), result);
        }
        
        // Handle remaining bytes
        for (size_t i = simd_blocks * 16; i < size; ++i) {
            data[i] ^= key[i % key_size];
        }
#elif defined(__aarch64__)
        // NEON implementation
        size_t simd_blocks = size / 16;
        size_t remaining = size % 16;
        
        for (size_t i = 0; i < simd_blocks; ++i) {
            uint8x16_t data_vec = vld1q_u8(data + i * 16);
            
            // Create key vector
            uint8_t key_block[16];
            for (int j = 0; j < 16; ++j) {
                key_block[j] = key[(i * 16 + j) % key_size];
            }
            uint8x16_t key_vec = vld1q_u8(key_block);
            
            uint8x16_t result = veorq_u8(data_vec, key_vec);
            vst1q_u8(data + i * 16, result);
        }
        
        // Handle remaining bytes
        for (size_t i = simd_blocks * 16; i < size; ++i) {
            data[i] ^= key[i % key_size];
        }
#else
        // Fallback to scalar implementation
        XOROperations::xor_with_key(data, key, data, size, key_size);
#endif
    }
    
    std::vector<uint8_t> get_context_key(uint64_t context_id) {
        if (!config_.enable_dynamic_keys && !current_key_.empty()) {
            return current_key_;
        }
        
        // Derive key from current key and context
        std::vector<uint8_t> context_bytes(sizeof(context_id));
        std::memcpy(context_bytes.data(), &context_id, sizeof(context_id));
        
        return XORKeyDerivation::derive_key(context_id, current_key_, 32);
    }
    
    void update_statistics(size_t bytes_processed, 
                          std::chrono::high_resolution_clock::time_point start_time) {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        
        stats_.total_bytes_processed += bytes_processed;
        stats_.total_operations++;
        stats_.total_processing_time += duration;
        
        // Calculate average throughput
        if (stats_.total_processing_time.count() > 0) {
            double seconds = stats_.total_processing_time.count() / 1e9;
            double mb_processed = stats_.total_bytes_processed / (1024.0 * 1024.0);
            stats_.average_throughput_mbps = mb_processed / seconds;
        }
    }
    
    XORConfig config_;
    std::vector<uint8_t> current_key_;
    uint64_t packet_counter_;
    uint64_t key_rotation_counter_;
    bool simd_available_;
    std::mt19937 rng_;
    XORObfuscator::Statistics stats_;
};

// XORObfuscator implementation
XORObfuscator::XORObfuscator(const XORConfig& config)
    : pimpl_(std::make_unique<Impl>(config)) {}

XORObfuscator::~XORObfuscator() = default;

std::vector<uint8_t> XORObfuscator::obfuscate(const std::vector<uint8_t>& data, 
                                             XORPattern pattern, uint64_t context_id) {
    return pimpl_->obfuscate(data, pattern, context_id);
}

std::vector<uint8_t> XORObfuscator::deobfuscate(const std::vector<uint8_t>& data,
                                               XORPattern pattern, uint64_t context_id) {
    return pimpl_->deobfuscate(data, pattern, context_id);
}

void XORObfuscator::obfuscate_inplace(std::vector<uint8_t>& data,
                                     XORPattern pattern, uint64_t context_id) {
    pimpl_->obfuscate_inplace(data, pattern, context_id);
}

std::vector<uint8_t> XORObfuscator::obfuscate_quic_payload(const std::vector<uint8_t>& payload,
                                                          uint64_t packet_number) {
    return pimpl_->obfuscate_quic_payload(payload, packet_number);
}

std::vector<uint8_t> XORObfuscator::obfuscate_fec_metadata(const std::vector<uint8_t>& metadata,
                                                          uint32_t block_id) {
    return pimpl_->obfuscate_fec_metadata(metadata, block_id);
}

std::vector<uint8_t> XORObfuscator::obfuscate_http3_headers(const std::vector<uint8_t>& headers,
                                                           uint64_t stream_id) {
    return pimpl_->obfuscate_http3_headers(headers, stream_id);
}

std::vector<uint8_t> XORObfuscator::generate_context_key(uint64_t context_id, size_t key_size) {
    return pimpl_->generate_context_key(context_id, key_size);
}

void XORObfuscator::update_config(const XORConfig& config) {
    pimpl_->update_config(config);
}

void XORObfuscator::rotate_keys() {
    pimpl_->rotate_keys();
}

XORObfuscator::Statistics XORObfuscator::get_statistics() const {
    return pimpl_->get_statistics();
}

void XORObfuscator::reset_statistics() {
    pimpl_->reset_statistics();
}

bool XORObfuscator::is_simd_enabled() const {
    return pimpl_->is_simd_enabled();
}

std::map<XORPattern, double> XORObfuscator::benchmark_patterns(size_t data_size, size_t iterations) {
    return pimpl_->benchmark_patterns(data_size, iterations);
}

// XOROperations implementation
void XOROperations::xor_arrays(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
}

void XOROperations::xor_with_key(const uint8_t* data, const uint8_t* key, uint8_t* result,
                                size_t data_size, size_t key_size) {
    for (size_t i = 0; i < data_size; ++i) {
        result[i] = data[i] ^ key[i % key_size];
    }
}

void XOROperations::position_dependent_xor(uint8_t* data, size_t size,
                                          const uint8_t* base_key, size_t key_size) {
    for (size_t i = 0; i < size; ++i) {
        uint8_t position_modifier = static_cast<uint8_t>(i & 0xFF);
        uint8_t key_byte = base_key[i % key_size];
        data[i] ^= key_byte ^ position_modifier;
    }
}

void XOROperations::simd_xor_arrays(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
    if (!is_simd_available()) {
        xor_arrays(a, b, result, size);
        return;
    }
    
#ifdef __x86_64__
    size_t simd_blocks = size / 16;
    for (size_t i = 0; i < simd_blocks; ++i) {
        __m128i a_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i * 16));
        __m128i b_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i * 16));
        __m128i result_vec = _mm_xor_si128(a_vec, b_vec);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(result + i * 16), result_vec);
    }
    
    // Handle remaining bytes
    for (size_t i = simd_blocks * 16; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
#elif defined(__aarch64__)
    size_t simd_blocks = size / 16;
    for (size_t i = 0; i < simd_blocks; ++i) {
        uint8x16_t a_vec = vld1q_u8(a + i * 16);
        uint8x16_t b_vec = vld1q_u8(b + i * 16);
        uint8x16_t result_vec = veorq_u8(a_vec, b_vec);
        vst1q_u8(result + i * 16, result_vec);
    }
    
    // Handle remaining bytes
    for (size_t i = simd_blocks * 16; i < size; ++i) {
        result[i] = a[i] ^ b[i];
    }
#endif
}

bool XOROperations::is_simd_available() {
    return detect_simd_support();
}

size_t XOROperations::get_simd_block_size() {
#if defined(__x86_64__) || defined(__aarch64__)
    return 16; // 128-bit SIMD
#else
    return 1; // Scalar fallback
#endif
}

// XORKeyDerivation implementation
std::vector<uint8_t> XORKeyDerivation::derive_key(uint64_t context_id,
                                                 const std::vector<uint8_t>& salt,
                                                 size_t key_size) {
    std::vector<uint8_t> key(key_size);
    
    // Simple key derivation using hash function
    uint64_t hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(&context_id), sizeof(context_id));
    
    if (!salt.empty()) {
        uint64_t salt_hash = hash_fnv1a(salt.data(), salt.size());
        hash ^= salt_hash;
    }
    
    // Expand hash to key size
    for (size_t i = 0; i < key_size; ++i) {
        key[i] = static_cast<uint8_t>(hash >> (8 * (i % 8)));
        if (i % 8 == 7) {
            hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(&hash), sizeof(hash));
        }
    }
    
    return key;
}

std::vector<uint8_t> XORKeyDerivation::derive_key_from_string(const std::string& context,
                                                            const std::vector<uint8_t>& salt,
                                                            size_t key_size) {
    uint64_t context_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(context.c_str()), context.length());
    return derive_key(context_hash, salt, key_size);
}

std::vector<uint8_t> XORKeyDerivation::generate_secure_key(size_t key_size) {
    std::vector<uint8_t> key(key_size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (size_t i = 0; i < key_size; ++i) {
        key[i] = dis(gen);
    }
    
    return key;
}

std::vector<uint8_t> XORKeyDerivation::expand_key(const std::vector<uint8_t>& key, size_t target_size) {
    if (key.empty()) {
        return generate_secure_key(target_size);
    }
    
    std::vector<uint8_t> expanded_key(target_size);
    for (size_t i = 0; i < target_size; ++i) {
        expanded_key[i] = key[i % key.size()];
    }
    
    return expanded_key;
}

// XORPatterns implementation
std::vector<uint8_t> XORPatterns::get_fec_pattern(size_t size) {
    std::vector<uint8_t> pattern(size);
    
    // FEC-optimized pattern with good distribution
    const uint8_t fec_base[] = {0x5A, 0xA5, 0x3C, 0xC3, 0x0F, 0xF0, 0x55, 0xAA};
    
    for (size_t i = 0; i < size; ++i) {
        pattern[i] = fec_base[i % sizeof(fec_base)] ^ static_cast<uint8_t>(i & 0xFF);
    }
    
    return pattern;
}

std::vector<uint8_t> XORPatterns::get_header_pattern(const std::string& header_name, size_t size) {
    std::vector<uint8_t> pattern(size);
    
    // Header-specific pattern
    uint64_t name_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(header_name.c_str()), header_name.length());
    
    for (size_t i = 0; i < size; ++i) {
        pattern[i] = static_cast<uint8_t>(name_hash >> (8 * (i % 8))) ^ static_cast<uint8_t>(i);
    }
    
    return pattern;
}

std::vector<uint8_t> XORPatterns::get_payload_pattern(uint32_t transformation_id, size_t size) {
    std::vector<uint8_t> pattern(size);
    
    // Payload transformation pattern
    for (size_t i = 0; i < size; ++i) {
        pattern[i] = static_cast<uint8_t>(transformation_id >> (8 * (i % 4))) ^ 
                    static_cast<uint8_t>((i * 0x9E3779B9) >> 24);
    }
    
    return pattern;
}

std::vector<uint8_t> XORPatterns::get_anti_dpi_pattern(size_t size) {
    std::vector<uint8_t> pattern(size);
    
    // Anti-DPI pattern designed to break common DPI signatures
    const uint8_t anti_dpi_base[] = {
        0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, // "HTTP/1.1" obfuscated
        0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54  // "GET / HT" obfuscated
    };
    
    for (size_t i = 0; i < size; ++i) {
        pattern[i] = anti_dpi_base[i % sizeof(anti_dpi_base)] ^ 
                    static_cast<uint8_t>((i * 0x12345678) >> 16);
    }
    
    return pattern;
}

// Utility functions implementation
namespace xor_utils {
    
    std::vector<uint8_t> generate_secure_key(size_t size) {
        return XORKeyDerivation::generate_secure_key(size);
    }
    
    std::vector<uint8_t> derive_key_pbkdf2(const std::string& password,
                                           const std::vector<uint8_t>& salt,
                                           uint32_t iterations,
                                           size_t key_length) {
        // Simplified PBKDF2 implementation
        std::vector<uint8_t> key(key_length);
        
        uint64_t password_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(password.c_str()), password.length());
        uint64_t salt_hash = hash_fnv1a(salt.data(), salt.size());
        
        uint64_t combined_hash = password_hash ^ salt_hash;
        
        for (uint32_t i = 0; i < iterations; ++i) {
            combined_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(&combined_hash), sizeof(combined_hash));
        }
        
        for (size_t i = 0; i < key_length; ++i) {
            key[i] = static_cast<uint8_t>(combined_hash >> (8 * (i % 8)));
            if (i % 8 == 7) {
                combined_hash = hash_fnv1a(reinterpret_cast<const uint8_t*>(&combined_hash), sizeof(combined_hash));
            }
        }
        
        return key;
    }
    
    double calculate_entropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;
        
        std::array<size_t, 256> counts = {};
        for (uint8_t byte : data) {
            counts[byte]++;
        }
        
        double entropy = 0.0;
        double data_size = static_cast<double>(data.size());
        
        for (size_t count : counts) {
            if (count > 0) {
                double probability = count / data_size;
                entropy -= probability * std::log2(probability);
            }
        }
        
        return entropy;
    }
    
    QualityMetrics analyze_obfuscation_quality(const std::vector<uint8_t>& original,
                                               const std::vector<uint8_t>& obfuscated) {
        QualityMetrics metrics;
        
        if (original.size() != obfuscated.size() || original.empty()) {
            return metrics;
        }
        
        // Calculate entropy improvement
        double original_entropy = calculate_entropy(original);
        double obfuscated_entropy = calculate_entropy(obfuscated);
        metrics.entropy_improvement = obfuscated_entropy - original_entropy;
        
        // Calculate correlation reduction (simplified)
        size_t differences = 0;
        for (size_t i = 0; i < original.size(); ++i) {
            if (original[i] != obfuscated[i]) {
                differences++;
            }
        }
        metrics.correlation_reduction = static_cast<double>(differences) / original.size();
        
        // Pattern disruption (simplified)
        metrics.pattern_disruption = metrics.correlation_reduction;
        
        // Basic randomness test
        metrics.passes_randomness_test = (obfuscated_entropy > 7.0) && (metrics.correlation_reduction > 0.5);
        
        return metrics;
    }
    
    XORConfig optimize_config_for_data(const std::vector<uint8_t>& sample_data,
                                       XORPattern target_pattern) {
        XORConfig config;
        
        // Analyze sample data characteristics
        double entropy = calculate_entropy(sample_data);
        
        if (entropy < 4.0) {
            // Low entropy data needs stronger obfuscation
            config.enable_multi_layer = true;
            config.obfuscation_strength = 5;
        } else if (entropy < 6.0) {
            // Medium entropy data
            config.enable_multi_layer = true;
            config.obfuscation_strength = 3;
        } else {
            // High entropy data
            config.enable_multi_layer = false;
            config.obfuscation_strength = 1;
        }
        
        // Adjust for target pattern
        switch (target_pattern) {
            case XORPattern::CRYPTO_SECURE:
                config.enable_dynamic_keys = true;
                config.key_rotation_interval = 100;
                break;
            case XORPattern::FEC_OPTIMIZED:
                config.enable_simd_optimization = true;
                config.key_rotation_interval = 1000;
                break;
            default:
                break;
        }
        
        return config;
    }
}

// SIMD operations implementation
namespace simd_xor {
    
    void xor_simd(uint8_t* data, const uint8_t* key, size_t size) {
        if (!is_simd_available()) {
            for (size_t i = 0; i < size; ++i) {
                data[i] ^= key[i % 32]; // Assume 32-byte key
            }
            return;
        }
        
#ifdef __x86_64__
        size_t simd_blocks = size / 16;
        for (size_t i = 0; i < simd_blocks; ++i) {
            __m128i data_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i * 16));
            __m128i key_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + (i * 16) % 32));
            __m128i result = _mm_xor_si128(data_vec, key_vec);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(data + i * 16), result);
        }
        
        // Handle remaining bytes
        for (size_t i = simd_blocks * 16; i < size; ++i) {
            data[i] ^= key[i % 32];
        }
#elif defined(__aarch64__)
        size_t simd_blocks = size / 16;
        for (size_t i = 0; i < simd_blocks; ++i) {
            uint8x16_t data_vec = vld1q_u8(data + i * 16);
            uint8x16_t key_vec = vld1q_u8(key + (i * 16) % 32);
            uint8x16_t result = veorq_u8(data_vec, key_vec);
            vst1q_u8(data + i * 16, result);
        }
        
        // Handle remaining bytes
        for (size_t i = simd_blocks * 16; i < size; ++i) {
            data[i] ^= key[i % 32];
        }
#endif
    }
    
    bool is_simd_available() {
        return detect_simd_support();
    }
    
    size_t get_simd_block_size() {
#if defined(__x86_64__) || defined(__aarch64__)
        return 16;
#else
        return 1;
#endif
    }
}

// Integration helpers implementation
namespace stealth_integration {
    
    std::unique_ptr<XORObfuscator> create_quic_obfuscator(bool enable_advanced) {
        XORConfig config;
        config.enable_dynamic_keys = true;
        config.enable_multi_layer = enable_advanced;
        config.enable_simd_optimization = true;
        config.key_rotation_interval = 500;
        config.obfuscation_strength = enable_advanced ? 3 : 1;
        
        return std::make_unique<XORObfuscator>(config);
    }
    
    std::unique_ptr<XORObfuscator> create_fec_obfuscator(size_t fec_block_size) {
        XORConfig config;
        config.enable_dynamic_keys = true;
        config.enable_multi_layer = false;
        config.enable_simd_optimization = true;
        config.key_rotation_interval = fec_block_size;
        config.obfuscation_strength = 2;
        
        return std::make_unique<XORObfuscator>(config);
    }
    
    std::unique_ptr<XORObfuscator> create_http3_obfuscator(bool header_compression) {
        XORConfig config;
        config.enable_dynamic_keys = true;
        config.enable_multi_layer = header_compression;
        config.enable_simd_optimization = true;
        config.key_rotation_interval = 200;
        config.obfuscation_strength = header_compression ? 4 : 2;
        
        return std::make_unique<XORObfuscator>(config);
    }
}

} // namespace quicfuscate::stealth

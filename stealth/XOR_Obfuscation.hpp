#ifndef XOR_OBFUSCATION_HPP
#define XOR_OBFUSCATION_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <random>
#include <array>

namespace quicfuscate::stealth {

/**
 * @brief XOR obfuscation configuration
 */
struct XORConfig {
    bool enable_dynamic_keys = true;        ///< Use dynamic key generation
    bool enable_multi_layer = false;        ///< Apply multiple XOR layers
    bool enable_simd_optimization = true;    ///< Use SIMD optimizations when available
    size_t key_rotation_interval = 1000;    ///< Rotate keys every N packets
    uint8_t obfuscation_strength = 3;        ///< Obfuscation strength (1-5)
    std::vector<uint8_t> static_key;         ///< Static key for consistent obfuscation
};

/**
 * @brief XOR obfuscation patterns for different use cases
 */
enum class XORPattern {
    SIMPLE,           ///< Simple XOR with rotating key
    LAYERED,          ///< Multiple XOR layers
    POSITION_BASED,   ///< Position-dependent XOR
    CRYPTO_SECURE,    ///< Cryptographically secure XOR
    FEC_OPTIMIZED,    ///< Optimized for FEC metadata
    HEADER_SPECIFIC   ///< Specialized for header obfuscation
};

/**
 * @brief High-performance XOR obfuscation for QUIC stealth operations
 * 
 * This class provides various XOR obfuscation techniques optimized for:
 * - QUIC packet payload obfuscation
 * - FEC metadata hiding
 * - Header field obfuscation
 * - DPI evasion
 * - SIMD-accelerated operations
 */
class XORObfuscator {
public:
    /**
     * @brief Constructor with configuration
     * @param config XOR obfuscation configuration
     */
    explicit XORObfuscator(const XORConfig& config = XORConfig{});
    
    /**
     * @brief Destructor
     */
    ~XORObfuscator();
    
    /**
     * @brief Obfuscate data using specified pattern
     * @param data Input data to obfuscate
     * @param pattern XOR pattern to use
     * @param context_id Context identifier for key derivation
     * @return Obfuscated data
     */
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data, 
                                   XORPattern pattern = XORPattern::SIMPLE,
                                   uint64_t context_id = 0);
    
    /**
     * @brief Deobfuscate data using specified pattern
     * @param data Obfuscated data to restore
     * @param pattern XOR pattern that was used
     * @param context_id Context identifier for key derivation
     * @return Original data
     */
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data,
                                     XORPattern pattern = XORPattern::SIMPLE,
                                     uint64_t context_id = 0);
    
    /**
     * @brief In-place obfuscation for performance
     * @param data Data to obfuscate in-place
     * @param pattern XOR pattern to use
     * @param context_id Context identifier for key derivation
     */
    void obfuscate_inplace(std::vector<uint8_t>& data, 
                          XORPattern pattern = XORPattern::SIMPLE,
                          uint64_t context_id = 0);
    
    /**
     * @brief Obfuscate QUIC packet payload
     * @param payload Packet payload data
     * @param packet_number QUIC packet number for key derivation
     * @return Obfuscated payload
     */
    std::vector<uint8_t> obfuscate_quic_payload(const std::vector<uint8_t>& payload,
                                                uint64_t packet_number);
    
    /**
     * @brief Obfuscate FEC metadata
     * @param metadata FEC metadata to hide
     * @param block_id FEC block identifier
     * @return Obfuscated metadata
     */
    std::vector<uint8_t> obfuscate_fec_metadata(const std::vector<uint8_t>& metadata,
                                                uint32_t block_id);
    
    /**
     * @brief Obfuscate HTTP/3 headers
     * @param headers Serialized header data
     * @param stream_id HTTP/3 stream identifier
     * @return Obfuscated headers
     */
    std::vector<uint8_t> obfuscate_http3_headers(const std::vector<uint8_t>& headers,
                                                 uint64_t stream_id);
    
    /**
     * @brief Generate obfuscation key for specific context
     * @param context_id Context identifier
     * @param key_size Desired key size in bytes
     * @return Generated key
     */
    std::vector<uint8_t> generate_context_key(uint64_t context_id, size_t key_size = 32);
    
    /**
     * @brief Update obfuscation configuration
     * @param config New configuration
     */
    void update_config(const XORConfig& config);
    
    /**
     * @brief Force key rotation
     */
    void rotate_keys();
    
    /**
     * @brief Get current obfuscation statistics
     * @return Performance and usage statistics
     */
    struct Statistics {
        uint64_t total_bytes_processed = 0;
        uint64_t total_operations = 0;
        double average_throughput_mbps = 0.0;
        uint64_t key_rotations = 0;
        bool simd_acceleration_active = false;
        std::chrono::nanoseconds total_processing_time{0};
    };
    
    Statistics get_statistics() const;
    
    /**
     * @brief Reset statistics counters
     */
    void reset_statistics();
    
    /**
     * @brief Check if SIMD acceleration is available
     * @return True if SIMD is supported and enabled
     */
    bool is_simd_enabled() const;
    
    /**
     * @brief Benchmark different XOR patterns
     * @param data_size Size of test data
     * @param iterations Number of benchmark iterations
     * @return Performance results for each pattern
     */
    std::map<XORPattern, double> benchmark_patterns(size_t data_size = 1024 * 1024,
                                                    size_t iterations = 100);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * @brief Utility functions for XOR obfuscation
 */
namespace xor_utils {
    
    /**
     * @brief Generate cryptographically secure random key
     * @param size Key size in bytes
     * @return Random key
     */
    std::vector<uint8_t> generate_secure_key(size_t size);
    
    /**
     * @brief Derive key from password using PBKDF2
     * @param password Input password
     * @param salt Salt for key derivation
     * @param iterations Number of PBKDF2 iterations
     * @param key_length Desired key length
     * @return Derived key
     */
    std::vector<uint8_t> derive_key_pbkdf2(const std::string& password,
                                           const std::vector<uint8_t>& salt,
                                           uint32_t iterations = 10000,
                                           size_t key_length = 32);
    
    /**
     * @brief Calculate entropy of data
     * @param data Input data
     * @return Shannon entropy value
     */
    double calculate_entropy(const std::vector<uint8_t>& data);
    
    /**
     * @brief Test XOR pattern effectiveness
     * @param original Original data
     * @param obfuscated Obfuscated data
     * @return Quality metrics
     */
    struct QualityMetrics {
        double entropy_improvement = 0.0;
        double correlation_reduction = 0.0;
        double pattern_disruption = 0.0;
        bool passes_randomness_test = false;
    };
    
    QualityMetrics analyze_obfuscation_quality(const std::vector<uint8_t>& original,
                                               const std::vector<uint8_t>& obfuscated);
    
    /**
     * @brief Optimize XOR configuration for specific data patterns
     * @param sample_data Representative data sample
     * @param target_pattern Desired obfuscation pattern
     * @return Optimized configuration
     */
    XORConfig optimize_config_for_data(const std::vector<uint8_t>& sample_data,
                                       XORPattern target_pattern = XORPattern::CRYPTO_SECURE);
}

/**
 * @brief SIMD-optimized XOR operations
 */
namespace simd_xor {
    
    /**
     * @brief SIMD XOR operation (when available)
     * @param data Input/output data
     * @param key XOR key
     * @param size Data size
     */
    void xor_simd(uint8_t* data, const uint8_t* key, size_t size);
    
    /**
     * @brief Check SIMD availability
     * @return True if SIMD XOR is supported
     */
    bool is_simd_available();
    
    /**
     * @brief Get optimal SIMD block size
     * @return Block size for SIMD operations
     */
    size_t get_simd_block_size();
}

/**
 * @brief Integration helpers for stealth components
 */
namespace stealth_integration {
    
    /**
     * @brief Create XOR obfuscator for QUIC stealth
     * @param enable_advanced Enable advanced obfuscation features
     * @return Configured XOR obfuscator
     */
    std::unique_ptr<XORObfuscator> create_quic_obfuscator(bool enable_advanced = true);
    
    /**
     * @brief Create XOR obfuscator for FEC stealth
     * @param fec_block_size FEC block size for optimization
     * @return Configured XOR obfuscator
     */
    std::unique_ptr<XORObfuscator> create_fec_obfuscator(size_t fec_block_size = 1024);
    
    /**
     * @brief Create XOR obfuscator for HTTP/3 stealth
     * @param header_compression Enable header-specific optimizations
     * @return Configured XOR obfuscator
     */
    std::unique_ptr<XORObfuscator> create_http3_obfuscator(bool header_compression = true);
}

} // namespace quicfuscate::stealth

#endif // XOR_OBFUSCATION_HPP

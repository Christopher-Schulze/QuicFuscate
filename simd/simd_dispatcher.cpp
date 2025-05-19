#include "../core/simd_optimizations.hpp"
#include <stdexcept>

namespace quicsand {
namespace simd {

// Implementierung des SIMD-Dispatchers
SIMDDispatcher::SIMDDispatcher() : supported_features_(detect_cpu_features()) {}

// XOR-Buffer-Optimierungen je nach verfügbaren SIMD-Features
void SIMDDispatcher::xor_buffers(uint8_t* dst, const uint8_t* src, size_t size) {
#ifdef __ARM_NEON
    // ARM-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::NEON)) {
        xor_buffers_neon(dst, src, size);
    } else {
        // Fallback auf skalare Implementierung
        for (size_t i = 0; i < size; i++) {
            dst[i] ^= src[i];
        }
    }
#else
    // x86-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::AVX2)) {
        xor_buffers_avx2(dst, src, size);
    } else if (is_feature_supported(SIMDSupport::SSE2)) {
        xor_buffers_sse(dst, src, size);
    } else {
        // Fallback auf skalare Implementierung
        for (size_t i = 0; i < size; i++) {
            dst[i] ^= src[i];
        }
    }
#endif
}

// AES-GCM-Implementierungen auswählen basierend auf verfügbaren SIMD-Features
std::vector<uint8_t> SIMDDispatcher::aes_128_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    size_t tag_len) {
    
#ifdef __ARM_NEON
    // ARM-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::CRYPTO)) {
        return aes_128_gcm_encrypt_neon(plaintext, key, iv, aad, tag_len);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("ARM Crypto Extensions nicht verfügbar, Software-Fallback nicht implementiert");
    }
#else
    // x86-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::AESNI) && is_feature_supported(SIMDSupport::AVX2)) {
        return aes_128_gcm_encrypt_avx2(plaintext, key, iv, aad, tag_len);
    } else if (is_feature_supported(SIMDSupport::AESNI)) {
        return aes_128_gcm_encrypt_aesni(plaintext, key, iv, aad, tag_len);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("AES-NI nicht unterstützt, Software-Fallback nicht implementiert");
    }
#endif
}

std::vector<uint8_t> SIMDDispatcher::aes_128_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    size_t tag_len) {
    
#ifdef __ARM_NEON
    // ARM-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::CRYPTO)) {
        return aes_128_gcm_decrypt_neon(ciphertext, key, iv, aad, tag_len);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("ARM Crypto Extensions nicht verfügbar, Software-Fallback nicht implementiert");
    }
#else
    // x86-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::AESNI) && is_feature_supported(SIMDSupport::AVX2)) {
        return aes_128_gcm_decrypt_avx2(ciphertext, key, iv, aad, tag_len);
    } else if (is_feature_supported(SIMDSupport::AESNI)) {
        return aes_128_gcm_decrypt_aesni(ciphertext, key, iv, aad, tag_len);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("AES-NI nicht unterstützt, Software-Fallback nicht implementiert");
    }
#endif
}

// Tetrys-FEC-Encoding mit optimalen SIMD-Features
std::vector<std::vector<uint8_t>> SIMDDispatcher::tetrys_encode(
    const std::vector<std::vector<uint8_t>>& source_packets,
    size_t packet_size,
    double redundancy_ratio) {
    
#ifdef __ARM_NEON
    // ARM-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::NEON)) {
        return tetrys_encode_neon(source_packets, packet_size, redundancy_ratio);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("NEON nicht verfügbar, Software-Fallback nicht implementiert");
    }
#else
    // x86-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::AVX2)) {
        return tetrys_encode_avx2(source_packets, packet_size, redundancy_ratio);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("AVX2 nicht verfügbar, Software-Fallback nicht implementiert");
    }
#endif
}

// Tetrys-FEC-Decoding mit optimalen SIMD-Features
std::vector<std::vector<uint8_t>> SIMDDispatcher::tetrys_decode(
    const std::vector<std::vector<uint8_t>>& received_packets,
    const std::vector<uint16_t>& packet_indices,
    size_t packet_size,
    size_t total_packets) {
    
#ifdef __ARM_NEON
    // ARM-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::NEON)) {
        return tetrys_decode_neon(received_packets, packet_indices, packet_size, total_packets);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("NEON nicht verfügbar, Software-Fallback nicht implementiert");
    }
#else
    // x86-spezifische Implementierungen
    if (is_feature_supported(SIMDSupport::AVX2)) {
        return tetrys_decode_avx2(received_packets, packet_indices, packet_size, total_packets);
    } else {
        // Fallback auf Software-Implementation
        throw std::runtime_error("AVX2 nicht verfügbar, Software-Fallback nicht implementiert");
    }
#endif
}

} // namespace simd
} // namespace quicsand

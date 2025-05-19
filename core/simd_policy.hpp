#ifndef SIMD_POLICY_HPP
#define SIMD_POLICY_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <type_traits>

#ifdef __ARM_NEON
#include <arm_neon.h>  // ARM NEON
#else
#include <immintrin.h>  // AVX, AVX2, AVX-512
#include <wmmintrin.h>  // AES-NI
#endif

namespace quicsand {
namespace simd {

// Konstanten
constexpr size_t BLOCK_SIZE = 16;

// Basis-Policy-Klasse für SIMD-Operationen
template<typename VectorType>
struct SimdPolicy {
    using vector_type = VectorType;
    
    // Reine virtuelle Methoden, die von spezifischen Policies implementiert werden müssen
    static vector_type load(const void* ptr);
    static void store(void* ptr, vector_type v);
    static vector_type set_zero();
    static vector_type bitwise_xor(vector_type a, vector_type b);
    static vector_type bitwise_and(vector_type a, vector_type b);
    static vector_type bitwise_or(vector_type a, vector_type b);
    static vector_type shift_left(vector_type a, int count);
    static vector_type shift_right(vector_type a, int count);
};

// Spezialisierung für x86 mit __m128i
#ifndef __ARM_NEON
struct SimdPolicyX86 : public SimdPolicy<__m128i> {
    using vector_type = __m128i;
    
    static inline vector_type load(const void* ptr) {
        return _mm_loadu_si128(reinterpret_cast<const vector_type*>(ptr));
    }
    
    static inline void store(void* ptr, vector_type v) {
        _mm_storeu_si128(reinterpret_cast<vector_type*>(ptr), v);
    }
    
    static inline vector_type set_zero() {
        return _mm_setzero_si128();
    }
    
    static inline vector_type bitwise_xor(vector_type a, vector_type b) {
        return _mm_xor_si128(a, b);
    }
    
    static inline vector_type bitwise_and(vector_type a, vector_type b) {
        return _mm_and_si128(a, b);
    }
    
    static inline vector_type bitwise_or(vector_type a, vector_type b) {
        return _mm_or_si128(a, b);
    }
    
    static inline vector_type shift_left(vector_type a, int count) {
        return _mm_slli_epi64(a, count);
    }
    
    static inline vector_type shift_right(vector_type a, int count) {
        return _mm_srli_epi64(a, count);
    }
    
    // AES-spezifische Operationen
    static inline vector_type aes_encrypt_round(vector_type state, vector_type key) {
        return _mm_aesenc_si128(state, key);
    }
    
    static inline vector_type aes_encrypt_last_round(vector_type state, vector_type key) {
        return _mm_aesenclast_si128(state, key);
    }
    
    static inline vector_type aes_decrypt_round(vector_type state, vector_type key) {
        return _mm_aesdec_si128(state, key);
    }
    
    static inline vector_type aes_decrypt_last_round(vector_type state, vector_type key) {
        return _mm_aesdeclast_si128(state, key);
    }
    
    // GCM-spezifische Operationen (falls PCLMULQDQ vorhanden)
    static inline vector_type gf_multiply(vector_type a, vector_type b, int imm) {
        return _mm_clmulepi64_si128(a, b, imm);
    }
};

// AVX2-spezifische Operationen (für breitere Vektoren)
struct SimdPolicyAVX2 {
    using vector_type = __m256i;
    
    static inline vector_type load(const void* ptr) {
        return _mm256_loadu_si256(reinterpret_cast<const vector_type*>(ptr));
    }
    
    static inline void store(void* ptr, vector_type v) {
        _mm256_storeu_si256(reinterpret_cast<vector_type*>(ptr), v);
    }
    
    static inline vector_type set_zero() {
        return _mm256_setzero_si256();
    }
    
    static inline vector_type bitwise_xor(vector_type a, vector_type b) {
        return _mm256_xor_si256(a, b);
    }
    
    static inline vector_type bitwise_and(vector_type a, vector_type b) {
        return _mm256_and_si256(a, b);
    }
    
    static inline vector_type bitwise_or(vector_type a, vector_type b) {
        return _mm256_or_si256(a, b);
    }
    
    static inline vector_type shift_left(vector_type a, int count) {
        // In AVX2 gibt es keine direkte 64-bit Shift-Operation für den gesamten Vektor
        // Stattdessen verwenden wir eine Kombination aus Extraktion, Shift und Zusammenführung
        __m128i lo = _mm256_extracti128_si256(a, 0);
        __m128i hi = _mm256_extracti128_si256(a, 1);
        
        lo = _mm_slli_epi64(lo, count);
        hi = _mm_slli_epi64(hi, count);
        
        return _mm256_set_m128i(hi, lo);
    }
    
    static inline vector_type shift_right(vector_type a, int count) {
        __m128i lo = _mm256_extracti128_si256(a, 0);
        __m128i hi = _mm256_extracti128_si256(a, 1);
        
        lo = _mm_srli_epi64(lo, count);
        hi = _mm_srli_epi64(hi, count);
        
        return _mm256_set_m128i(hi, lo);
    }
};

#else // __ARM_NEON
// Spezialisierung für ARM NEON
struct SimdPolicyNeon : public SimdPolicy<uint8x16_t> {
    using vector_type = uint8x16_t;
    
    static inline vector_type load(const void* ptr) {
        return vld1q_u8(reinterpret_cast<const uint8_t*>(ptr));
    }
    
    static inline void store(void* ptr, vector_type v) {
        vst1q_u8(reinterpret_cast<uint8_t*>(ptr), v);
    }
    
    static inline vector_type set_zero() {
        return vdupq_n_u8(0);
    }
    
    static inline vector_type bitwise_xor(vector_type a, vector_type b) {
        return veorq_u8(a, b);
    }
    
    static inline vector_type bitwise_and(vector_type a, vector_type b) {
        return vandq_u8(a, b);
    }
    
    static inline vector_type bitwise_or(vector_type a, vector_type b) {
        return vorrq_u8(a, b);
    }
    
    static inline vector_type shift_left(vector_type a, int count) {
        // In NEON arbeiten wir mit 64-bit Elementen für Shifts
        uint64x2_t a64 = vreinterpretq_u64_u8(a);
        uint64x2_t shifted = vshlq_n_u64(a64, count);
        return vreinterpretq_u8_u64(shifted);
    }
    
    static inline vector_type shift_right(vector_type a, int count) {
        uint64x2_t a64 = vreinterpretq_u64_u8(a);
        uint64x2_t shifted = vshrq_n_u64(a64, count);
        return vreinterpretq_u8_u64(shifted);
    }
    
    // AES-spezifische Operationen (falls unterstützt)
#ifdef __ARM_FEATURE_CRYPTO
    static inline vector_type aes_encrypt_round(vector_type state, vector_type key) {
        return vaeseq_u8(state, key);
    }
    
    static inline vector_type aes_encrypt_last_round(vector_type state, vector_type key) {
        return veorq_u8(vaeseq_u8(state, vdupq_n_u8(0)), key);
    }
    
    static inline vector_type aes_decrypt_round(vector_type state, vector_type key) {
        return vaesdq_u8(state, key);
    }
    
    static inline vector_type aes_decrypt_last_round(vector_type state, vector_type key) {
        return veorq_u8(vaesdq_u8(state, vdupq_n_u8(0)), key);
    }
#endif
};
#endif

// Standardpolicy basierend auf Architektur auswählen
#ifdef __ARM_NEON
using DefaultSimdPolicy = SimdPolicyNeon;
#else
using DefaultSimdPolicy = SimdPolicyX86;
#endif

// Template-Funktionen für generische SIMD-Operationen

// AES Encryption mit Policy-basiertem Design
template<typename Policy>
std::vector<uint8_t> aes_encrypt_template(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16
) {
    // Implementierung später - hier nur Signatur als Beispiel
    return std::vector<uint8_t>();
}

// AES Decryption mit Policy-basiertem Design
template<typename Policy>
std::vector<uint8_t> aes_decrypt_template(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16
) {
    // Implementierung später - hier nur Signatur als Beispiel
    return std::vector<uint8_t>();
}

// Forward Error Correction mit Policy-basiertem Design
template<typename Policy>
std::vector<std::vector<uint8_t>> fec_encode_template(
    const std::vector<std::vector<uint8_t>>& source_packets,
    size_t packet_size,
    double redundancy_ratio
) {
    // Implementierung später - hier nur Signatur als Beispiel
    return std::vector<std::vector<uint8_t>>();
}

template<typename Policy>
std::vector<std::vector<uint8_t>> fec_decode_template(
    const std::vector<std::vector<uint8_t>>& received_packets,
    const std::vector<uint16_t>& packet_indices,
    size_t packet_size,
    size_t total_packets
) {
    // Implementierung später - hier nur Signatur als Beispiel
    return std::vector<std::vector<uint8_t>>();
}

} // namespace simd
} // namespace quicsand

#endif // SIMD_POLICY_HPP

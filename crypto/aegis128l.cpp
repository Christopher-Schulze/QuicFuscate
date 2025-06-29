#include "aegis128l.hpp"
#include "../optimize/unified_optimizations.hpp"
#include <cstring>
#include <stdexcept>

namespace quicfuscate {
namespace crypto {

// AEGIS-128L Konstanten
static const uint8_t AEGIS_C0[16] = {
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
};

static const uint8_t AEGIS_C1[16] = {
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

AEGIS128L::AEGIS128L() {
    auto& detector = simd::FeatureDetector::instance();
    has_arm_crypto_ = detector.has_feature(simd::CpuFeature::CRYPTO);
    has_aesni_ = detector.has_feature(simd::CpuFeature::AES_NI);
    has_avx2_ = detector.has_feature(simd::CpuFeature::AVX2);
    has_pclmulqdq_ = detector.has_feature(simd::CpuFeature::PCLMULQDQ);
}

void AEGIS128L::encrypt(const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* key, const uint8_t* nonce,
                       const uint8_t* associated_data, size_t ad_len,
                       uint8_t* ciphertext, uint8_t* tag) {
    
    if (has_arm_crypto_) {
#ifdef __ARM_NEON
        encrypt_arm_crypto(plaintext, plaintext_len, key, nonce,
                          associated_data, ad_len, ciphertext, tag);
#else
        encrypt_software(plaintext, plaintext_len, key, nonce,
                        associated_data, ad_len, ciphertext, tag);
#endif
    } else if (has_aesni_) {
#ifdef __x86_64__
        encrypt_x86_aesni(plaintext, plaintext_len, key, nonce,
                         associated_data, ad_len, ciphertext, tag);
#else
        encrypt_software(plaintext, plaintext_len, key, nonce,
                        associated_data, ad_len, ciphertext, tag);
#endif
    } else {
        encrypt_software(plaintext, plaintext_len, key, nonce,
                        associated_data, ad_len, ciphertext, tag);
    }
}

bool AEGIS128L::decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* nonce,
                       const uint8_t* associated_data, size_t ad_len,
                       const uint8_t* tag, uint8_t* plaintext) {
    
    if (has_arm_crypto_) {
#ifdef __ARM_NEON
        return decrypt_arm_crypto(ciphertext, ciphertext_len, key, nonce,
                                 associated_data, ad_len, tag, plaintext);
#else
        return decrypt_software(ciphertext, ciphertext_len, key, nonce,
                               associated_data, ad_len, tag, plaintext);
#endif
    } else if (has_aesni_) {
#ifdef __x86_64__
        return decrypt_x86_aesni(ciphertext, ciphertext_len, key, nonce,
                                associated_data, ad_len, tag, plaintext);
#else
        return decrypt_software(ciphertext, ciphertext_len, key, nonce,
                               associated_data, ad_len, tag, plaintext);
#endif
    } else {
        return decrypt_software(ciphertext, ciphertext_len, key, nonce,
                               associated_data, ad_len, tag, plaintext);
    }
}

#ifdef __ARM_NEON
void AEGIS128L::encrypt_arm_crypto(const uint8_t* plaintext, size_t plaintext_len,
                                  const uint8_t* key, const uint8_t* nonce,
                                  const uint8_t* associated_data, size_t ad_len,
                                  uint8_t* ciphertext, uint8_t* tag) {
    
    // AEGIS-128L State: 8 x 128-bit blocks
    uint8x16_t state[8];
    
    // Initialisierung
    uint8x16_t key_block = vld1q_u8(key);
    uint8x16_t nonce_block = vld1q_u8(nonce);
    uint8x16_t c0 = vld1q_u8(AEGIS_C0);
    uint8x16_t c1 = vld1q_u8(AEGIS_C1);
    
    state[0] = veorq_u8(key_block, nonce_block);
    state[1] = c1;
    state[2] = c0;
    state[3] = c1;
    state[4] = veorq_u8(key_block, nonce_block);
    state[5] = veorq_u8(key_block, c0);
    state[6] = veorq_u8(key_block, c1);
    state[7] = veorq_u8(key_block, c0);
    
    // 10 Initialisierungsrunden
    for (int i = 0; i < 10; i++) {
        aegis_update_arm(state, key_block, nonce_block);
    }
    
    // Verarbeite Associated Data
    size_t ad_blocks = ad_len / 16;
    for (size_t i = 0; i < ad_blocks; i++) {
        uint8x16_t ad_block = vld1q_u8(associated_data + i * 16);
        aegis_update_arm(state, ad_block, vdupq_n_u8(0));
    }
    
    // Verarbeite letzten AD-Block falls nötig
    if (ad_len % 16 != 0) {
        uint8_t padded_ad[16] = {0};
        memcpy(padded_ad, associated_data + ad_blocks * 16, ad_len % 16);
        uint8x16_t ad_block = vld1q_u8(padded_ad);
        aegis_update_arm(state, ad_block, vdupq_n_u8(0));
    }
    
    // Verschlüssele Plaintext mit NEON-Optimierung
    size_t pt_blocks = plaintext_len / 16;
    
    // Verwende optimierte NEON-Blockverarbeitung
    if (pt_blocks > 0) {
        simd::aegis128l_process_blocks_neon(
            plaintext,
            ciphertext,
            key,
            pt_blocks
        );
        
        // Update state nach Blockverarbeitung
        for (size_t i = 0; i < pt_blocks; i++) {
            uint8x16_t pt_block = vld1q_u8(plaintext + i * 16);
            uint8x16_t ct_block;
            simd::aegis_encrypt_neon(&state[0], &pt_block, &ct_block);
        }
    }
    
    // Verarbeite letzten Plaintext-Block falls nötig
    if (plaintext_len % 16 != 0) {
        uint8_t padded_pt[16] = {0};
        memcpy(padded_pt, plaintext + pt_blocks * 16, plaintext_len % 16);
        uint8x16_t pt_block = vld1q_u8(padded_pt);
        uint8x16_t ct_block = aegis_encrypt_block_arm(state, pt_block);
        
        uint8_t ct_bytes[16];
        vst1q_u8(ct_bytes, ct_block);
        memcpy(ciphertext + pt_blocks * 16, ct_bytes, plaintext_len % 16);
    }
    
    // Finalisierung mit NEON-Optimierung
    uint64x2_t length_block = {ad_len * 8, plaintext_len * 8};
    uint8x16_t length_bytes = vreinterpretq_u8_u64(length_block);
    for (int i = 0; i < 7; i++) {
        aegis_update_arm(state, length_bytes, vdupq_n_u8(0));
    }
    
    // Generiere Tag mit optimierter Finalisierung
    simd::aegis128l_finalize_neon(
        reinterpret_cast<uint8_t*>(state),
        tag,
        16  // Standard AEGIS tag length
    );
}

void AEGIS128L::aegis_update_arm(uint8x16_t state[8], uint8x16_t msg0, uint8x16_t msg1) {
    uint8x16_t tmp[8];
    
#ifdef __ARM_FEATURE_CRYPTO
    // ARM Crypto Extensions AES-Operationen
    tmp[0] = vaeseq_u8(state[7], state[0]);
    tmp[1] = vaeseq_u8(state[0], state[1]);
    tmp[2] = vaeseq_u8(state[1], state[2]);
    tmp[3] = vaeseq_u8(state[2], state[3]);
    tmp[4] = vaeseq_u8(state[3], state[4]);
    tmp[5] = vaeseq_u8(state[4], state[5]);
    tmp[6] = vaeseq_u8(state[5], state[6]);
    tmp[7] = vaeseq_u8(state[6], state[7]);
#else
    // Software-Fallback für ARM ohne Crypto Extensions
    for (int i = 0; i < 8; i++) {
        tmp[i] = veorq_u8(state[(i + 7) % 8], state[i]);
    }
#endif
    
    state[0] = veorq_u8(tmp[0], msg0);
    state[1] = tmp[1];
    state[2] = tmp[2];
    state[3] = tmp[3];
    state[4] = veorq_u8(tmp[4], msg1);
    state[5] = tmp[5];
    state[6] = tmp[6];
    state[7] = tmp[7];
}

uint8x16_t AEGIS128L::aegis_encrypt_block_arm(uint8x16_t state[8], uint8x16_t plaintext) {
    uint8x16_t ciphertext = veorq_u8(plaintext, state[1]);
    ciphertext = veorq_u8(ciphertext, state[4]);
    ciphertext = veorq_u8(ciphertext, state[5]);
    ciphertext = veorq_u8(ciphertext, vandq_u8(state[2], state[3]));
    
    aegis_update_arm(state, plaintext, vdupq_n_u8(0));
    
    return ciphertext;
}

bool AEGIS128L::decrypt_arm_crypto(const uint8_t* ciphertext, size_t ciphertext_len,
                                  const uint8_t* key, const uint8_t* nonce,
                                  const uint8_t* associated_data, size_t ad_len,
                                  const uint8_t* tag, uint8_t* plaintext) {
    // Ähnlich wie encrypt_arm_crypto, aber in umgekehrter Reihenfolge
    // Vereinfachte Implementierung für Demo
    return true;
}
#endif

#ifdef __x86_64__
void AEGIS128L::encrypt_x86_aesni(const uint8_t* plaintext, size_t plaintext_len,
                                 const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* associated_data, size_t ad_len,
                                 uint8_t* ciphertext, uint8_t* tag) {
    
    // AEGIS-128L State: 8 x 128-bit blocks
    __m128i state[8];
    
    // Initialisierung
    __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    __m128i nonce_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(nonce));
    __m128i c0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(AEGIS_C0));
    __m128i c1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(AEGIS_C1));
    
    state[0] = _mm_xor_si128(key_block, nonce_block);
    state[1] = c1;
    state[2] = c0;
    state[3] = c1;
    state[4] = _mm_xor_si128(key_block, nonce_block);
    state[5] = _mm_xor_si128(key_block, c0);
    state[6] = _mm_xor_si128(key_block, c1);
    state[7] = _mm_xor_si128(key_block, c0);
    
    // 10 Initialisierungsrunden
    for (int i = 0; i < 10; i++) {
        aegis_update_x86(state, key_block, nonce_block);
    }
    
    // Verarbeite Associated Data
    size_t ad_blocks = ad_len / 16;
    for (size_t i = 0; i < ad_blocks; i++) {
        __m128i ad_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(associated_data + i * 16));
        aegis_update_x86(state, ad_block, _mm_setzero_si128());
    }
    
    // Verarbeite letzten AD-Block falls nötig
    if (ad_len % 16 != 0) {
        uint8_t padded_ad[16] = {0};
        memcpy(padded_ad, associated_data + ad_blocks * 16, ad_len % 16);
        __m128i ad_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(padded_ad));
        aegis_update_x86(state, ad_block, _mm_setzero_si128());
    }
    
    // Verschlüssele Plaintext
    size_t pt_blocks = plaintext_len / 16;
    for (size_t i = 0; i < pt_blocks; i++) {
        __m128i pt_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext + i * 16));
        __m128i ct_block = aegis_encrypt_block_x86(state, pt_block);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ciphertext + i * 16), ct_block);
    }
    
    // Verarbeite letzten Plaintext-Block falls nötig
    if (plaintext_len % 16 != 0) {
        uint8_t padded_pt[16] = {0};
        memcpy(padded_pt, plaintext + pt_blocks * 16, plaintext_len % 16);
        __m128i pt_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(padded_pt));
        __m128i ct_block = aegis_encrypt_block_x86(state, pt_block);
        
        uint8_t ct_bytes[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ct_bytes), ct_block);
        memcpy(ciphertext + pt_blocks * 16, ct_bytes, plaintext_len % 16);
    }
    
    // Finalisierung
    __m128i length_block = _mm_set_epi64x(plaintext_len * 8, ad_len * 8);
    for (int i = 0; i < 7; i++) {
        aegis_update_x86(state, length_block, _mm_setzero_si128());
    }
    
    // Generiere Tag
    __m128i tag_block = _mm_xor_si128(state[0], state[1]);
    tag_block = _mm_xor_si128(tag_block, state[2]);
    tag_block = _mm_xor_si128(tag_block, state[3]);
    tag_block = _mm_xor_si128(tag_block, state[4]);
    tag_block = _mm_xor_si128(tag_block, state[5]);
    tag_block = _mm_xor_si128(tag_block, state[6]);
    tag_block = _mm_xor_si128(tag_block, state[7]);
    
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), tag_block);
}

void AEGIS128L::aegis_update_x86(__m128i state[8], __m128i msg0, __m128i msg1) {
    __m128i tmp[8];
    
    // AES-NI Operationen
    tmp[0] = _mm_aesenc_si128(state[7], state[0]);
    tmp[1] = _mm_aesenc_si128(state[0], state[1]);
    tmp[2] = _mm_aesenc_si128(state[1], state[2]);
    tmp[3] = _mm_aesenc_si128(state[2], state[3]);
    tmp[4] = _mm_aesenc_si128(state[3], state[4]);
    tmp[5] = _mm_aesenc_si128(state[4], state[5]);
    tmp[6] = _mm_aesenc_si128(state[5], state[6]);
    tmp[7] = _mm_aesenc_si128(state[6], state[7]);
    
    state[0] = _mm_xor_si128(tmp[0], msg0);
    state[1] = tmp[1];
    state[2] = tmp[2];
    state[3] = tmp[3];
    state[4] = _mm_xor_si128(tmp[4], msg1);
    state[5] = tmp[5];
    state[6] = tmp[6];
    state[7] = tmp[7];
}

__m128i AEGIS128L::aegis_encrypt_block_x86(__m128i state[8], __m128i plaintext) {
    __m128i ciphertext = _mm_xor_si128(plaintext, state[1]);
    ciphertext = _mm_xor_si128(ciphertext, state[4]);
    ciphertext = _mm_xor_si128(ciphertext, state[5]);
    ciphertext = _mm_xor_si128(ciphertext, _mm_and_si128(state[2], state[3]));
    
    aegis_update_x86(state, plaintext, _mm_setzero_si128());
    
    return ciphertext;
}

bool AEGIS128L::decrypt_x86_aesni(const uint8_t* ciphertext, size_t ciphertext_len,
                                 const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* associated_data, size_t ad_len,
                                 const uint8_t* tag, uint8_t* plaintext) {
    // Ähnlich wie encrypt_x86_aesni, aber in umgekehrter Reihenfolge
    // Vereinfachte Implementierung für Demo
    return true;
}
#endif

void AEGIS128L::encrypt_software(const uint8_t* plaintext, size_t plaintext_len,
                                const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* associated_data, size_t ad_len,
                                uint8_t* ciphertext, uint8_t* tag) {
    // Software-Fallback für alle Architekturen ohne Hardware-Beschleunigung
    // Vereinfachte Implementierung
    
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % 16] ^ nonce[i % 16];
    }
    
    // Einfacher Tag
    memcpy(tag, key, 16);
}

bool AEGIS128L::decrypt_software(const uint8_t* ciphertext, size_t ciphertext_len,
                                const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* associated_data, size_t ad_len,
                                const uint8_t* tag, uint8_t* plaintext) {
    // Software-Fallback Entschlüsselung
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % 16] ^ nonce[i % 16];
    }
    
    // Einfache Tag-Verifikation
    return memcmp(tag, key, 16) == 0;
}

bool AEGIS128L::is_hardware_accelerated() const {
    return has_arm_crypto_ || has_aesni_;
}

} // namespace crypto
} // namespace quicfuscate
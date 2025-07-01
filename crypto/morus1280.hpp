#pragma once

#include <cstdint>
#include <cstring>

namespace quicfuscate {
namespace crypto {

[[deprecated("Use Rust implementation in rust/crypto")]]
class MORUS1280 {
public:
    MORUS1280();
    
    // AEAD Verschlüsselung
    void encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                uint8_t* ciphertext, uint8_t* tag);
    
    // AEAD Entschlüsselung
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                const uint8_t* tag, uint8_t* plaintext);
    
private:
    // MORUS-1280-128 State (5 x 256-bit words)
    struct State {
        uint64_t s[20]; // 5 * 4 = 20 uint64_t words
    };
    
    // MORUS-1280-128 Permutation
    void morus_permutation(State& state);
    
    // Hilfsfunktionen
    void load_key_nonce(State& state, const uint8_t* key, const uint8_t* nonce);
    void process_associated_data(State& state, const uint8_t* ad, size_t ad_len);
    void process_plaintext(State& state, const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext);
    void finalize(State& state, size_t ad_len, size_t pt_len, uint8_t* tag);
    
    // Bitwise operations
    void rotl_256(uint64_t* dst, const uint64_t* src, int bits);
    void xor_256(uint64_t* dst, const uint64_t* a, const uint64_t* b);
    void and_256(uint64_t* dst, const uint64_t* a, const uint64_t* b);
    
    // Utility functions
    void bytes_to_words(uint64_t* words, const uint8_t* bytes, size_t len);
    void words_to_bytes(uint8_t* bytes, const uint64_t* words, size_t len);
};

} // namespace crypto
} // namespace quicfuscate

#pragma once
#include <cstdint>
#include <cstring>

namespace quicfuscate {
namespace crypto {

[[deprecated("Use Rust implementation in rust/crypto")]]
class MORUS {
public:
    MORUS();
    
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
    // MORUS Permutation
    void morus_permutation(uint64_t state[5], int rounds);
    
    // Hilfsfunktionen
    uint64_t bytes_to_u64(const uint8_t* bytes);
    void u64_to_bytes(uint64_t value, uint8_t* bytes);
    uint64_t rotr64(uint64_t value, int shift);
};

} // namespace crypto
} // namespace quicfuscate

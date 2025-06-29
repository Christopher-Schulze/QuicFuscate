#include "crypto/aegis128l.hpp"
#include <cstring>

namespace quicfuscate::crypto {
AEGIS128L::AEGIS128L()
    : has_arm_crypto_(false), has_aesni_(false), has_avx2_(false), has_pclmulqdq_(false) {}

void AEGIS128L::encrypt(const uint8_t* plaintext, size_t len,
                        const uint8_t* key, const uint8_t* /*nonce*/,
                        const uint8_t* /*ad*/, size_t /*ad_len*/,
                        uint8_t* ciphertext, uint8_t* tag) {
    for (size_t i = 0; i < len; ++i) {
        ciphertext[i] = plaintext[i] ^ key[i % KEY_SIZE];
    }
    std::memset(tag, 0, TAG_SIZE);
}

bool AEGIS128L::decrypt(const uint8_t* ciphertext, size_t len,
                        const uint8_t* key, const uint8_t* /*nonce*/,
                        const uint8_t* /*ad*/, size_t /*ad_len*/,
                        const uint8_t* /*tag*/, uint8_t* plaintext) {
    for (size_t i = 0; i < len; ++i) {
        plaintext[i] = ciphertext[i] ^ key[i % KEY_SIZE];
    }
    return true;
}

bool AEGIS128L::is_hardware_accelerated() const { return false; }
}

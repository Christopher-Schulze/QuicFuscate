#include <vector>
#include "ascon.hpp"  // Selbstreferenz für Header

namespace quicsand::crypto {

Ascon::Ascon(const std::vector<uint8_t>& key) {
    // Initialize Ascon with key
}

std::vector<uint8_t> Ascon::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& nonce) {
    // Implement Ascon-128a encryption stub
    return {};
}

std::vector<uint8_t> Ascon::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& nonce) {
    // Implement Ascon-128a decryption stub
    return {};
}

} // namespace quicsand::crypto

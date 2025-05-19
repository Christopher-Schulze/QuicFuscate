#ifndef ASCON_HPP
#define ASCON_HPP

#include <vector>

namespace quicsand::crypto {

class Ascon {
public:
    Ascon(const std::vector<uint8_t>& key);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& nonce);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& nonce);
};

} // namespace quicsand::crypto

#endif // ASCON_HPP

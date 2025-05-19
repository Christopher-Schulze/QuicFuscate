#ifndef AES128GCM_HPP
#define AES128GCM_HPP

#include <vector>

namespace quicsand::crypto {

class Aes128Gcm {
public:
    Aes128Gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    ~Aes128Gcm();
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& tag);
};

} // namespace quicsand::crypto

#endif // AES128GCM_HPP

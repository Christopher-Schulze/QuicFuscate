#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace quicsand {

class AesGcm {
public:
    AesGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    ~AesGcm();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad,
                                 std::vector<uint8_t>& tag);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& aad,
                                 const std::vector<uint8_t>& tag);

private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
};

} // namespace quicsand

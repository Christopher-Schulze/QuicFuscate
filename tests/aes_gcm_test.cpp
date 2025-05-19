#include <iostream>
#include <vector>
#include <cassert>
#include "crypto/aes_gcm.hpp"

int main() {
    using namespace quicsand;

    // Test AES-GCM
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> iv(12, 0x02);
    AesGcm aead(key, iv);
    std::string msg = "AES-GCM test message";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());
    std::vector<uint8_t> aad = {0x00, 0x01, 0x02};
    std::vector<uint8_t> tag;

    auto ciphertext = aead.encrypt(plaintext, aad, tag);
    assert(!ciphertext.empty());
    assert(tag.size() == 16);

    auto decrypted = aead.decrypt(ciphertext, aad, tag);
    assert(decrypted == plaintext);

    std::cout << "AES-GCM encryption/decryption test passed." << std::endl;
    return 0;
}

#include "../crypto/morus.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate::crypto;

TEST(MORUSTest, EncryptDecryptRoundtrip) {
    MORUS cipher;
    const char* msg = "hello morus";
    uint8_t key[16] = {};
    uint8_t nonce[16] = {};
    uint8_t ciphertext[sizeof("hello morus")];
    uint8_t tag[16];

    cipher.encrypt(reinterpret_cast<const uint8_t*>(msg), sizeof("hello morus"),
                   key, nonce, nullptr, 0, ciphertext, tag);

    uint8_t decrypted[sizeof("hello morus")];
    ASSERT_TRUE(cipher.decrypt(ciphertext, sizeof("hello morus"), key, nonce,
                               nullptr, 0, tag, decrypted));

    std::string result(reinterpret_cast<char*>(decrypted), sizeof("hello morus"));
    EXPECT_EQ(result, std::string("hello morus", sizeof("hello morus")));
}

#include "../crypto/aegis128l.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate::crypto;

TEST(AEGIS128LTest, EncryptDecryptRoundtrip) {
    AEGIS128L cipher;
    const char* msg = "hello aegis";
    uint8_t key[AEGIS128L::KEY_SIZE] = {};
    uint8_t nonce[AEGIS128L::NONCE_SIZE] = {};
    uint8_t ciphertext[sizeof("hello aegis")];
    uint8_t tag[AEGIS128L::TAG_SIZE];

    cipher.encrypt(reinterpret_cast<const uint8_t*>(msg), sizeof("hello aegis"),
                   key, nonce, nullptr, 0, ciphertext, tag);

    uint8_t decrypted[sizeof("hello aegis")];
    ASSERT_TRUE(cipher.decrypt(ciphertext, sizeof("hello aegis"), key, nonce,
                               nullptr, 0, tag, decrypted));

    std::string result(reinterpret_cast<char*>(decrypted), sizeof("hello aegis"));
    EXPECT_EQ(result, std::string("hello aegis", sizeof("hello aegis")));
}

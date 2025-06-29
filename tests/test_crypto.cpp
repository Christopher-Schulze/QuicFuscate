#include <catch2/catch_test_macros.hpp>
#include "crypto/aegis128l.hpp"
#include "crypto/morus.hpp"

using namespace quicfuscate::crypto;

TEST_CASE("AEGIS128L encrypt/decrypt cycle", "[crypto]") {
    AEGIS128L cipher;
    const uint8_t key[AEGIS128L::KEY_SIZE] = {0};
    const uint8_t nonce[AEGIS128L::NONCE_SIZE] = {0};
    const uint8_t ad[1] = {0};
    const char msg[] = "hello";
    constexpr size_t len = sizeof(msg) - 1;
    uint8_t ciphertext[len];
    uint8_t tag[AEGIS128L::TAG_SIZE];
    cipher.encrypt(reinterpret_cast<const uint8_t*>(msg), len,
                   key, nonce, ad, sizeof(ad), ciphertext, tag);
    uint8_t decrypted[len];
    REQUIRE(cipher.decrypt(ciphertext, len, key, nonce, ad, sizeof(ad), tag, decrypted));
    REQUIRE(std::string(reinterpret_cast<char*>(decrypted), len) == std::string(msg));
}

TEST_CASE("MORUS encrypt/decrypt cycle", "[crypto]") {
    MORUS cipher;
    const uint8_t key[16] = {0};
    const uint8_t nonce[16] = {0};
    const uint8_t ad[1] = {0};
    const char msg[] = "world";
    constexpr size_t len = sizeof(msg) - 1;
    uint8_t ciphertext[len];
    uint8_t tag[16];
    cipher.encrypt(reinterpret_cast<const uint8_t*>(msg), len,
                   key, nonce, ad, sizeof(ad), ciphertext, tag);
    uint8_t decrypted[len];
    cipher.decrypt(ciphertext, len, key, nonce, ad, sizeof(ad), tag, decrypted);
    REQUIRE(std::string(reinterpret_cast<char*>(decrypted), len) == std::string(msg));
}

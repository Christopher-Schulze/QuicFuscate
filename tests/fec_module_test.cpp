#include <gtest/gtest.h>
#include "../fec/FEC_Modul.hpp"
#include "../stealth/XOR_Obfuscation.hpp"
#include <numeric>

using namespace quicfuscate::stealth;

TEST(FECModule, EncodeDecode) {
    ASSERT_EQ(fec_module_init(), 0);
    const char msg[] = "hello";
    uint8_t* enc = nullptr;
    size_t enc_size = 0;
    ASSERT_EQ(fec_module_encode(reinterpret_cast<const uint8_t*>(msg), sizeof(msg), &enc, &enc_size), 0);
    EXPECT_GT(enc_size, 0u);
    fec_module_free_buffer(enc);
    fec_module_cleanup();
}

TEST(Crypto, DeriveKeyDeterministic) {
    std::vector<uint8_t> salt = {0,1,2,3};
    auto k1 = xor_utils::derive_key_pbkdf2("password", salt, 5, 16);
    auto k2 = xor_utils::derive_key_pbkdf2("password", salt, 5, 16);
    EXPECT_EQ(k1, k2);
    EXPECT_EQ(k1.size(), 16u);
}

TEST(Crypto, EntropyCalculation) {
    std::vector<uint8_t> data(256);
    std::iota(data.begin(), data.end(), 0);
    double entropy = xor_utils::calculate_entropy(data);
    EXPECT_NEAR(entropy, 8.0, 0.01);
}

TEST(Stealth, XORObfuscatorRoundTrip) {
    XORObfuscator obf;
    std::vector<uint8_t> msg{'h','e','l','l','o'};
    auto enc = obf.obfuscate(msg, XORPattern::SIMPLE, 42);
    auto dec = obf.deobfuscate(enc, XORPattern::SIMPLE, 42);
    EXPECT_EQ(dec, msg);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

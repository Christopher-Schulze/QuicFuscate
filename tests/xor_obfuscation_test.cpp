#include "../stealth/XOR_Obfuscation.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace quicfuscate::stealth;

TEST(XORObfuscationTest, EncodeDecodeRoundtrip) {
    XORObfuscator obf;
    std::vector<uint8_t> data{1,2,3,4,5};
    auto encoded = obf.obfuscate(data, XORPattern::SIMPLE, 42);
    EXPECT_EQ(encoded.size(), data.size());
    auto decoded = obf.deobfuscate(encoded, XORPattern::SIMPLE, 42);
    EXPECT_EQ(decoded, data);
}

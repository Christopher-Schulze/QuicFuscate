#include "../fec/FEC_Modul.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate::stealth;

TEST(FECModuleTest, EncodeDecode) {
    ASSERT_EQ(0, fec_module_init());
    const char msg[] = "hello";
    auto enc = fec_module_encode(reinterpret_cast<const uint8_t*>(msg), sizeof(msg));
    ASSERT_FALSE(enc.empty());
    auto dec = fec_module_decode(enc.data(), enc.size());
    fec_module_cleanup();
    ASSERT_EQ(dec.size(), sizeof(msg));
    EXPECT_EQ(std::string(dec.begin(), dec.end()), std::string(msg, sizeof(msg)));
}

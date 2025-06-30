#include "../core/quic_path_mtu_manager.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate;

TEST(PathMtuManagerTest, Constants) {
    EXPECT_GE(DEFAULT_MIN_MTU, 1200);
    EXPECT_LE(DEFAULT_MIN_MTU, DEFAULT_MAX_MTU);
}

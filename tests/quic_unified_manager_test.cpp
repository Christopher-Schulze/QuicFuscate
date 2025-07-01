#include "../core/quic_core_types.hpp"
#include <gtest/gtest.h>

using namespace quicfuscate;

TEST(QuicUnifiedManagerTest, GetIntegrationFailsWhenUninitialized) {
    auto& manager = QuicUnifiedManager::instance();
    manager.shutdown();
    auto result = manager.get_integration();
    EXPECT_FALSE(result.success());
}

TEST(QuicUnifiedManagerTest, InitializeAndRetrieve) {
    auto& manager = QuicUnifiedManager::instance();
    manager.shutdown();
    std::map<std::string, std::string> cfg;
    auto init_result = manager.initialize(cfg);
    ASSERT_TRUE(init_result.success());
    auto get_result = manager.get_integration();
    ASSERT_TRUE(get_result.success());
    EXPECT_NE(get_result.value(), nullptr);
    manager.shutdown();
}

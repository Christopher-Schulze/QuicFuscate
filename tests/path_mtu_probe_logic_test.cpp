#include "../core/quic_path_mtu_manager.hpp"
#include <gtest/gtest.h>
#include <type_traits>

using namespace quicfuscate;

TEST(PathMtuManagerTest, HasProbeMethods) {
    static_assert(std::is_member_function_pointer_v<decltype(&PathMtuManager::send_probe)>);
    static_assert(std::is_member_function_pointer_v<decltype(&PathMtuManager::handle_probe_response)>);
    SUCCEED();
}

#include "../core/quic_connection.hpp"
#include <gtest/gtest.h>
#include <type_traits>

using namespace quicfuscate;

TEST(ConnectionFeatureTest, HasMigrationDetection) {
    static_assert(std::is_member_function_pointer_v<decltype(&QuicConnection::detect_network_change)>);
    SUCCEED();
}

TEST(ConnectionFeatureTest, HasMtuProbeScheduler) {
    static_assert(std::is_member_function_pointer_v<decltype(&QuicConnection::schedule_next_probe)>);
    SUCCEED();
}

TEST(ConnectionFeatureTest, HasXdpMethods) {
    static_assert(std::is_member_function_pointer_v<decltype(&QuicConnection::send_datagram_xdp)>);
    static_assert(std::is_member_function_pointer_v<decltype(&QuicConnection::send_datagram_batch_xdp)>);
    SUCCEED();
}

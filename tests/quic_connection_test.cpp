#include "../core/quic_connection.hpp"
#include <gtest/gtest.h>
#include <type_traits>

using namespace quicfuscate;

TEST(QuicConnectionTest, Constructible) {
    static_assert(std::is_constructible_v<QuicConnection, boost::asio::io_context&, const QuicConfig&>,
                  "QuicConnection should be constructible with io_context and QuicConfig");
    SUCCEED();
}

#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <vector>

namespace quicfuscate {
class MockQuicStream {};

class MockQuicConnection {
public:
    std::shared_ptr<MockQuicStream> create_stream() {
        auto stream = std::make_shared<MockQuicStream>();
        streams.push_back(stream);
        return stream;
    }
    std::vector<std::shared_ptr<MockQuicStream>> streams;
};
} // namespace quicfuscate

TEST_CASE("QUIC connection creates streams", "[quic]") {
    quicfuscate::MockQuicConnection conn;
    auto s1 = conn.create_stream();
    REQUIRE(s1 != nullptr);
    REQUIRE(conn.streams.size() == 1);
    auto s2 = conn.create_stream();
    REQUIRE(conn.streams.size() == 2);
}

#include <catch2/catch_test_macros.hpp>
#include "fec/FEC_Modul.hpp"

using namespace quicfuscate::stealth;

TEST_CASE("FEC encode/decode cycle", "[fec]") {
    FECModule fec;
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto packets = fec.encode_packet(data);
    auto decoded = fec.decode(packets);
    REQUIRE(decoded == data);
}

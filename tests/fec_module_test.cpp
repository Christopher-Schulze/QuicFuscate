#include "../fec/FEC_Modul.hpp"
#include <cassert>
int main() {
    using namespace quicfuscate::stealth;
    assert(fec_module_init() == 0);
    const char msg[] = "hello";
    auto enc = fec_module_encode(reinterpret_cast<const uint8_t*>(msg), sizeof(msg));
    assert(!enc.empty());

    auto dec = fec_module_decode(enc.data(), enc.size());
    fec_module_cleanup();
    return 0;
}

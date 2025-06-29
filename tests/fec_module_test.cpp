#include "../fec/FEC_Modul.hpp"
#include <cassert>
int main() {
    using namespace quicfuscate::stealth;
    assert(fec_module_init() == 0);
    const char msg[] = "hello";
    uint8_t* enc = nullptr;
    size_t enc_size = 0;
    assert(fec_module_encode(reinterpret_cast<const uint8_t*>(msg), sizeof(msg), &enc, &enc_size) == 0);
    uint8_t* dec = nullptr;
    size_t dec_size = 0;
    int res = fec_module_decode(enc, enc_size, &dec, &dec_size);
    (void)res;
    fec_module_free_buffer(enc);
    if (res == 0) {
        fec_module_free_buffer(dec);
    }
    fec_module_cleanup();
    return 0;
}

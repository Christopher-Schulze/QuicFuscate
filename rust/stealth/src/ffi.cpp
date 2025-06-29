#include "../../../stealth/XOR_Obfuscation.hpp"
#include <cstdlib>
#include <cstring>
using namespace quicfuscate::stealth;
extern "C" {
XORObfuscator* xor_obfuscator_new() { return new XORObfuscator(); }
void xor_obfuscator_free(XORObfuscator* x) { delete x; }
int xor_obfuscator_obfuscate(XORObfuscator* x,
                             const uint8_t* data,
                             size_t len,
                             uint8_t** out,
                             size_t* out_len) {
    if(!x || !data || !out || !out_len) return -1;
    std::vector<uint8_t> input(data, data + len);
    auto result = x->obfuscate(input);
    *out_len = result.size();
    *out = (uint8_t*)malloc(result.size());
    if(!*out) return -1;
    memcpy(*out, result.data(), result.size());
    return 0;
}
}

#include <iostream>
#include <vector>
#include <cassert>
#include "stealth/stealth.hpp"

int main() {
    using namespace quicsand;
    Stealth stealth;
    std::vector<uint8_t> data = { 'H', 'i', '!', 0x00, 0xFF };
    auto wrapped = stealth.obfuscate(data);
    // Wrapped should have 5 byte header + payload
    assert(wrapped.size() == data.size() + 5);
    // Check header bytes
    assert(wrapped[0] == 0x17);
    assert(wrapped[1] == 0x03 && wrapped[2] == 0x03);
    uint16_t len = (wrapped[3] << 8) | wrapped[4];
    assert(len == data.size());
    // Deobfuscate and compare
    auto original = stealth.deobfuscate(wrapped);
    assert(original == data);
    std::cout << "Stealth fake-TLS test passed." << std::endl;
    return 0;
}

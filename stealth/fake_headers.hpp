#ifndef FAKE_HEADERS_HPP
#define FAKE_HEADERS_HPP

#include <vector>

namespace quicsand::stealth {

class FakeHeaders {
public:
    FakeHeaders();
    std::vector<uint8_t> inject_fake_headers();
};

} // namespace quicsand::stealth

#endif // FAKE_HEADERS_HPP

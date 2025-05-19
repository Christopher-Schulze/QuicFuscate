#include <vector>

namespace quicsand::stealth {

class FakeHeaders {
public:
    FakeHeaders();
    std::vector<uint8_t> inject_fake_headers();
    // Stub for header injection
};

} // namespace quicsand::stealth

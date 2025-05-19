#include <vector>

namespace quicsand::stealth {

class FakeTLS {
public:
    FakeTLS();
    void perform_fake_handshake();
    // Stub for fake TLS handshake
};

} // namespace quicsand::stealth

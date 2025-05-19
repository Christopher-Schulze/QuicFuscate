#ifndef FAKE_TLS_HPP
#define FAKE_TLS_HPP

namespace quicsand::stealth {

class FakeTLS {
public:
    FakeTLS();
    void perform_fake_handshake();
};

} // namespace quicsand::stealth

#endif // FAKE_TLS_HPP

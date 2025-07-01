#pragma once
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <sys/socket.h>

namespace quicfuscate {

class XdpSocket {
public:
    using PacketHandler = std::function<void(const void*, size_t,
                                             const struct sockaddr*, socklen_t)>;
    explicit XdpSocket(uint16_t port) : port_(port) {}

    bool send(const void* data, size_t len) {
        (void)data;
        (void)len;
        return true;
    }

    bool send_batch(const std::vector<std::pair<const uint8_t*, size_t>>& bufs) {
        (void)bufs;
        return true;
    }

    void set_packet_handler(PacketHandler handler) { handler_ = std::move(handler); }
    void set_batch_size(uint32_t size) { batch_size_ = size; }

private:
    uint16_t port_;
    uint32_t batch_size_{1};
    PacketHandler handler_{};
};

class QuicFuscateXdpContext {
public:
    static QuicFuscateXdpContext& instance() {
        static QuicFuscateXdpContext ctx;
        return ctx;
    }

    bool initialize(const std::string& interface) {
        interface_ = interface;
        return true;
    }

    bool is_xdp_supported() const { return true; }

    std::shared_ptr<XdpSocket> create_socket(uint16_t port) {
        return std::make_shared<XdpSocket>(port);
    }

private:
    std::string interface_;
};

} // namespace quicfuscate


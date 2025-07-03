#pragma once
#include <openssl/ssl.h>
#include <stdexcept>

namespace quicfuscate {

class SslCtx {
public:
    explicit SslCtx(const SSL_METHOD* method) {
        ctx_ = SSL_CTX_new(method);
        if (!ctx_) {
            throw std::runtime_error("SSL_CTX_new failed");
        }
    }
    SslCtx(const SslCtx&) = delete;
    SslCtx& operator=(const SslCtx&) = delete;
    SslCtx(SslCtx&& other) noexcept : ctx_(other.ctx_) { other.ctx_ = nullptr; }
    SslCtx& operator=(SslCtx&& other) noexcept {
        if (this != &other) {
            cleanup();
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }
    ~SslCtx() { cleanup(); }
    SSL_CTX* get() const { return ctx_; }
private:
    void cleanup() {
        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }
    SSL_CTX* ctx_{nullptr};
};

class Ssl {
public:
    explicit Ssl(SSL_CTX* ctx) {
        ssl_ = SSL_new(ctx);
        if (!ssl_) {
            throw std::runtime_error("SSL_new failed");
        }
    }
    Ssl(const Ssl&) = delete;
    Ssl& operator=(const Ssl&) = delete;
    Ssl(Ssl&& other) noexcept : ssl_(other.ssl_) { other.ssl_ = nullptr; }
    Ssl& operator=(Ssl&& other) noexcept {
        if (this != &other) {
            cleanup();
            ssl_ = other.ssl_;
            other.ssl_ = nullptr;
        }
        return *this;
    }
    ~Ssl() { cleanup(); }
    SSL* get() const { return ssl_; }
private:
    void cleanup() {
        if (ssl_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }
    SSL* ssl_{nullptr};
};

} // namespace quicfuscate

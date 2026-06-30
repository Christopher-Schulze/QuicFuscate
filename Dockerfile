# syntax=docker/dockerfile:1.7
# ==============================================================================
# QuicFuscate Container Image - Multi-stage Build
# ==============================================================================
# Builder stage compiles the release binary from source using the Rust stable
# channel (rust-toolchain.toml => stable). Runtime stage ships a
# minimal Debian bookworm-slim image with only the dynamic libraries and
# networking utilities required to operate the server.
#
# Required runtime privileges (server mode with TUN bridging):
#   --device /dev/net/tun   # TUN device passthrough for the VPN interface
#   --cap-add NET_ADMIN     # create/configure TUN interfaces + iptables rules
#   --cap-add NET_BIND_SERVICE  # bind UDP 443 (privileged port)
#
# Build:
#   docker build -t quicfuscate:0.4.0 .
#
# Run (server):
#   docker run -d --name quicfuscate \
#     --device /dev/net/tun --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
#     -p 443:443/udp -p 8080:8080/tcp \
#     -v $(pwd)/config:/etc/quicfuscate:ro \
#     -v $(pwd)/certs:/etc/quicfuscate/certs:ro \
#     -v quicfuscate-logs:/var/log/quicfuscate \
#     -e QUICFUSCATE_ADMIN_USER=admin \
#     -e QUICFUSCATE_ADMIN_PASSWORD=change-me \
#     -e QUICFUSCATE_QKEY_ENC_KEY=<64-hex-chars> \
#     quicfuscate:0.4.0
# ==============================================================================

# ------------------------------------------------------------------------------
# Builder stage
# ------------------------------------------------------------------------------
FROM rust:bookworm AS builder

# Avoid interactive prompts and cache apt metadata for reproducibility.
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

# Build dependencies for native crates (e.g. ring, zstd-sys). pkg-config and
# libssl-dev are required for the rustls-native-certs and openssl-sys paths.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pre-copy manifests to leverage Docker layer caching for dependency builds.
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY src/ ./src/
COPY assets/ ./assets/
COPY examples/ ./examples/
COPY benches/ ./benches/
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY apps/ ./apps/
COPY packages/ ./packages/

# Build the release binary with the default feature set
# (client + server + rate_limiter). LTO=thin + codegen-units=1 are already
# configured in [profile.release] of Cargo.toml.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin quicfuscate \
    && cp target/release/quicfuscate /quicfuscate

# ------------------------------------------------------------------------------
# Runtime stage
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    RUST_LOG=info \
    QUICFUSCATE_CONFIG=/etc/quicfuscate/quicfuscate.toml

# Runtime dependencies:
#   iptables   - firewall/NAT rules for the TUN bridge
#   iproute2   - ip/link/route configuration for the quicfuse0 interface
#   libssl3    - rustls native CA store + TLS runtime support
#   ca-certificates - system trust store for peer certificate validation
#   libgcc-s1  - GCC runtime required by the Rust binary
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        libssl3 \
        libgcc-s1 \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system quicfuscate \
    && adduser --system --ingroup quicfuscate --no-create-home --home /nonexistent quicfuscate

# Configuration, certificates, state and log directories.
# Config and certs are expected to be supplied via bind mounts / volumes.
RUN mkdir -p /etc/quicfuscate/certs \
             /var/lib/quicfuscate \
             /var/log/quicfuscate \
             /var/lib/quicfuscate/assets/web-admin \
    && chown -R quicfuscate:quicfuscate /var/lib/quicfuscate /var/log/quicfuscate

# Copy the release binary from the builder stage.
COPY --from=builder /quicfuscate /usr/local/bin/quicfuscate

# Copy the bundled web-admin assets for the admin HTTP dashboard.
COPY --from=builder /build/assets/web-admin /var/lib/quicfuscate/assets/web-admin

# Copy the canonical server config as a fallback default. Operators should
# override this with a bind-mounted /etc/quicfuscate/quicfuscate.toml.
COPY config/server-linux.default.toml /etc/quicfuscate/quicfuscate.toml.default

# QUIC transport listens on UDP 443; the admin HTTP dashboard on TCP 8080.
EXPOSE 443/udp
EXPOSE 8080/tcp

USER quicfuscate

# tini reaps zombie processes and forwards signals for graceful shutdown.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Server entrypoint. The listen address, cert/key paths and admin web bind are
# driven by environment variables so the same image works across environments.
CMD ["sh", "-c", "exec quicfuscate server \
    --listen 0.0.0.0:${QUICFUSCATE_LISTEN_PORT:-443} \
    --cert ${QUICFUSCATE_CERT:-/etc/quicfuscate/certs/server.crt} \
    --key ${QUICFUSCATE_KEY:-/etc/quicfuscate/certs/server.key} \
    --config ${QUICFUSCATE_CONFIG:-/etc/quicfuscate/quicfuscate.toml} \
    --tun --tun-name ${QUICFUSCATE_TUN_NAME:-quicfuse0} \
    --admin-web ${QUICFUSCATE_ADMIN_WEB:-0.0.0.0:8080} \
    --admin-web-root /var/lib/quicfuscate/assets/web-admin \
    --admin-web-user ${QUICFUSCATE_ADMIN_USER:-admin} \
    --admin-web-password ${QUICFUSCATE_ADMIN_PASSWORD}"]

# Health check probes the admin HTTP server. The root path (GET /) serves the
# web-admin index.html with HTTP 200 and requires no authentication, making it
# a reliable liveness signal. A dedicated unauthenticated /api/health endpoint
# does not yet exist (all /api/* routes except /api/login and /api/logout
# require session auth and return 401). TODO: add /api/health to
# admin_http.rs and switch this probe to it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ || exit 1

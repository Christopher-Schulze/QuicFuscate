---
id: TODO-447
title: "Container deployment (Docker only; stale manifests removed)"
severity: HIGH
phase: "I"
priority: P1
status: DEFERRED
created: 2026-07-23
depends_on: ["TODO-444", "TODO-446"]
---

# TODO-447: Container Deployment (Docker only; stale manifests removed)

## Goal
Keep Docker as the only retained container artifact surface for GitHub/CI image work. Stale manifest sets are not active deployment targets in this repository.

## Scope Status

Deferred from the current production-readiness pass by explicit user instruction: Docker may remain for GitHub/CI, but local Docker is not required and stale manifest sets must not be presented as supported deployment surfaces.

## Current Scope Snapshot

Current repository truth: `Dockerfile`, `.dockerignore`, and `docker-compose.yml` remain. The stale manifest directories were removed because they were not validated and created false production-readiness signals. Treat the remaining sections below as historical planning context only, not as current verified deployment truth.

## Historical Audit (not validated in current pass)

### Install script exists
`scripts/install/install-server-linux.sh` - installs binary, assets, config, systemd unit on Linux. This is a VM-based deployment script, not container-based. It installs:
- Binary -> `/usr/local/bin/quicfuscate`
- Config -> `/etc/quicfuscate/quicfuscate.toml`
- QKey registry -> `/var/lib/quicfuscate/qkeys.json`
- Systemd unit -> `/etc/systemd/system/quicfuscate.service`

### Server config template
`config/server-linux.default.toml` - comprehensive server config template with sections for engine, connection, anti-replay, crypto, stealth, FEC, transport, optimization, interface, telemetry, logging. All values are commented out except `[engine] mode = "server"`, `[connection] remote = "0.0.0.0:4433"`, `[stealth] mode = "performance"`, `[anti_replay] enabled = true`, `[logging] level = "info"`.

### TUN device requirements
QuicFuscate requires:
1. TUN device (`/dev/net/tun` on Linux) - not available by default in containers
2. `NET_ADMIN` capability - for TUN creation, IP assignment, iptables/nftables
3. `iptables` or `nft` binary - routing manager shells out to these
4. `iproute2` (`ip` command) - `detect_wan_interface()` uses `ip route show default`

### Admin HTTP server
The server has an admin HTTP interface (configured via `--admin-web` in the install script, default `127.0.0.1:9000`). Docker health checks can probe the unauthenticated root route until a dedicated unauthenticated health endpoint exists.

## Problem Analysis

A production VPN server can be deployed through retained Docker artifacts or through the VM/systemd installer. Stale manifest deployment is not an active repository target.

Key challenges:
1. **TUN device in containers**: `/dev/net/tun` is not available by default. Docker validation must pass it through via `--device /dev/net/tun`.
2. **NET_ADMIN capability**: Creating TUN, setting IPs, and configuring firewall rules all require `CAP_NET_ADMIN`. Default containers don't have this.
3. **Minimal image vs. tool requirements**: The routing manager needs `iptables`, `nft`, `iproute2` binaries. A distroless or scratch image won't have these. Must use `debian-slim` or `alpine` with these packages installed.
4. **State persistence**: QKey registry (`qkeys.json`) and TLS certs must persist across container restarts. Need volume mounts.
5. **12-factor compliance**: All config should be overridable via environment variables for container deployments.
6. **Manifest scope**: stale deployment manifests are intentionally not retained as active repository artifacts.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Container Deployment Stack                       │
│                                                                   │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  Dockerfile (multi-stage)                            │        │
│  │  Stage 1: rust:bookworm (stable builder)             │        │
│  │    → cargo build --release                           │        │
│  │  Stage 2: debian:bookworm-slim (runtime)             │        │
│  │    → binary + iptables + iproute2 + nftables         │        │
│  │    → ~80-100MB image                                 │        │
│  └─────────────────────────────────────────────────────┘        │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────────────────┐         │
│  │ docker-compose   │  │ GitHub/CI image validation     │         │
│  │ server + client  │  │ no local Docker requirement    │         │
│  │ --device /dev/   │  │ stale manifests not active     │         │
│  │   net/tun        │  │                                │         │
│  │ --cap-add        │  │                                │         │
│  │   NET_ADMIN      │  │                                │         │
│  └──────────────────┘  └──────────────────────────────┘         │
│                                                                   │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  Stale manifests: removed from active repo scope      │        │
│  │  Reintroduce only through a dedicated validation task │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Multi-stage Dockerfile
```dockerfile
# Dockerfile
FROM rust:bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release || true
RUN rm -rf src
COPY . .
RUN touch src/main.rs
RUN cargo build --release --bin quicfuscate

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/quicfuscate /usr/local/bin/quicfuscate
COPY config/server-linux.default.toml /etc/quicfuscate/quicfuscate.toml
EXPOSE 443/udp
ENTRYPOINT ["/usr/local/bin/quicfuscate"]
CMD ["server", "--config", "/etc/quicfuscate/quicfuscate.toml"]
```

### Step 2: .dockerignore
```
target/
.git/
docs/
*.md
scripts/
.cargo/
```

### Step 3: docker-compose.yml
```yaml
version: "3.8"
services:
  server:
    build: { context: ., dockerfile: Dockerfile }
    container_name: quicfuscate-server
    devices: ["/dev/net/tun"]
    cap_add: [NET_ADMIN]
    ports: ["443:443/udp"]
    volumes:
      - ./config/server-linux.default.toml:/etc/quicfuscate/quicfuscate.toml:ro
      - ./certs:/etc/quicfuscate/certs:ro
      - quicfuscate-state:/var/lib/quicfuscate
      - quicfuscate-logs:/var/log/quicfuscate
    sysctls: [net.ipv4.ip_forward=1]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3
volumes:
  quicfuscate-state:
  quicfuscate-logs:
```

### Step 4: Manifest scope
Stale deployment manifests are intentionally removed from the active repository. If this deployment target is reintroduced later, it must be implemented as a separate, fully validated task instead of being kept as stale manifests.

### Step 7: Environment variable config
Support `CONFIG_FILE` env var and all config via env vars for 12-factor compliance. The existing `QUICFUSCATE_*` env var pattern (used in `limits.rs:46-50`) should be extended to all config sections.

### Step 8: Health checks
Docker health checks should probe the admin HTTP root route (`GET /`) because it currently serves the web-admin index with HTTP 200 and does not require authentication. A dedicated unauthenticated `/api/health` endpoint is still preferable before switching the Dockerfile health check away from `/`.

### Step 9: Runtime sizing
Docker runtime sizing should be validated by CI or a dedicated Linux host because local Docker is not required on the development Mac. The retained target is a small server image with explicit TUN, firewall, state, and logging requirements, not a cluster scaling profile.

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| Base image (builder) | `rust:bookworm` | Uses the Rust stable Docker channel and Debian bookworm builder base |
| Base image (runtime) | `debian:bookworm-slim` | Has apt for installing iptables/iproute2/nftables; ~75MB; widely used |
| Alternative: `alpine` | Considered | Smaller (~5MB) but musl libc can cause issues with Rust binaries; needs `apk add iptables iproute2 nftables` |
| Alternative: distroless | Rejected | No shell, no iptables/nft/ip command - required for routing/kill switch |
| Container orchestration | Docker-only retained scope | Stale manifest artifacts are removed from the active repository |
| Config management | Bind mounts + environment variables | Keep config/certs/state external to the image; never bake secrets |
| Health checks | Admin HTTP root route for now | `/api/health` is still a follow-up before switching probes |
| State persistence | Volume mounts | `/var/lib/quicfuscate` for qkeys.json; `/etc/quicfuscate/certs` for TLS |
| TUN device access | Docker `--device /dev/net/tun` | Host must provide TUN; container gets only the explicit device/caps |

## Stealth/Efficiency Considerations

- **Image size**: ~80-100MB (debian-slim 75MB + binary 10MB + packages). Smaller than full Debian; larger than distroless but required for firewall tools.
- **Container startup**: target < 2s (binary start + config parse + TUN create), to be validated in Docker CI or on a Linux host.
- **Memory (idle)**: ~20-50MB (Rust binary + Tokio runtime). Fits in 128Mi request.
- **Network mode**: Server uses bridge networking with port mapping (`-p 443:443/udp`). Client needs host networking for VPN routing (`network_mode: host`).
- **Stealth in containers**: The container's network namespace is isolated. TUN device and firewall rules apply within the container's namespace - no conflict with host firewall.
- **Sysctl**: `net.ipv4.ip_forward=1` must be set inside the container with Docker `--sysctl`.
- **Log volume**: Use TODO-446's structured JSON logging with rotation. In containers, logs typically go to stdout (collected by container runtime). File logging is optional for persistent storage.
- **QKey encryption key**: The `QUICFUSCATE_QKEY_ENC_KEY` env var (used in `qkey_registry.rs:11`) must be passed at runtime via an external secret manager, CI secret, or host secret, never baked into an image layer.

## Testing Plan

### Docker tests
- `test_docker_build` - `docker build -t quicfuscate/server:latest .` succeeds
- `test_image_size` - image size < 100MB
- `test_docker_run_server` - `docker run --device /dev/net/tun --cap-add NET_ADMIN quicfuscate/server:latest server --config /etc/quicfuscate/quicfuscate.toml` starts
- `test_tun_creation_in_container` - server creates TUN device inside container
- `test_docker_logs` - `docker logs` shows startup logs
- `test_client_connects_to_docker_server` - client connects to server running in Docker (UDP 443 reachable)
- `test_docker_compose_up` - `docker-compose up` starts server and client
- `test_container_has_firewall_tools` - `docker exec quicfuscate-server which iptables nft ip` returns paths
- `test_ip_forward_sysctl` - `docker exec quicfuscate-server cat /proc/sys/net/ipv4/ip_forward` returns 1

### Stale manifest tests
Not active. There are no stale manifest repository artifacts to validate.

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `Dockerfile` | Retain | Multi-stage build (Rust stable builder + debian-slim runtime) |
| `.dockerignore` | Retain | Exclude target/, .git/, docs/, scripts/ |
| `docker-compose.yml` | Retain | Server + optional client quick-start |
| `docs/DOCUMENTATION.md` | Modify | Document retained Docker-only container scope |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `/dev/net/tun` not available in container runtime | High | Document host TUN requirement for Docker-based validation |
| `NET_ADMIN` capability security concern | Medium | Keep container docs explicit about required capability and host-level trust |
| Docker build takes 5-10 min (cold) | Low | Use layer caching; Cargo dependency layer cached separately |
| Image size > 100MB | Low | debian-slim is already minimal; binary is ~10MB; packages are required |
| QKey encryption key leaked in image layers | High | Never bake secrets into image; pass via env var or external secret manager |
| Container restart loses in-memory sessions | Medium | Sessions are ephemeral by design; clients reconnect automatically |
| iptables-nft vs iptables-legacy in container | Low | Install both; TODO-444 auto-detection handles this |
| Stale unsupported manifests reappear | Medium | Keep stale manifests out of active repo scope unless a dedicated validated task is opened |

## Completion Criteria

- [ ] `docker build -t quicfuscate/server:latest .` succeeds
- [ ] Image size < 100MB
- [ ] `docker run --device /dev/net/tun --cap-add NET_ADMIN quicfuscate/server:latest server` starts
- [ ] Server creates TUN device inside container
- [ ] `docker logs` shows startup logs
- [ ] Client can connect to server running in Docker (UDP 443 reachable)
- [ ] `docker-compose up` starts both server and client
- [ ] Stale manifests remain absent from active repository artifacts unless a dedicated validated task reintroduces them
- [ ] Container has `iptables`, `ip`, `nft` binaries available
- [ ] `ip_forward` sysctl is set inside container
- [ ] No secrets in plain text in git and no secrets baked into image layers
- [ ] qkeys.json persists across container restarts (volume mount)

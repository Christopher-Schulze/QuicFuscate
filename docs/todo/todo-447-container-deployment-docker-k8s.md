---
id: TODO-447
title: "Container deployment (Docker, docker-compose, Kubernetes, Helm)"
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: ["TODO-444", "TODO-446"]
---

# TODO-447: Container Deployment (Docker, docker-compose, Kubernetes)

## Goal
Create a complete container deployment infrastructure for QuicFuscate: a multi-stage Dockerfile (builder + minimal runtime), docker-compose.yml for quick-start, Kubernetes manifests (Deployment, Service, ConfigMap, Secret), and a Helm chart. The container must support TUN device access (`/dev/net/tun`), `NET_ADMIN` capability for iptables/nftables, all config via environment variables (12-factor compliance), health checks via admin HTTP, and volume mounts for state (qkeys.json, certs).

## Current State (verified against code)

### No container infrastructure
No `Dockerfile`, no `.dockerignore`, no `docker-compose.yml`, no `k8s/` directory, no `helm/` directory exists in the project root.

### Install script exists
`scripts/install/install-server-linux.sh` — installs binary, assets, config, systemd unit on Linux. This is a VM-based deployment script, not container-based. It installs:
- Binary → `/usr/local/bin/quicfuscate`
- Config → `/etc/quicfuscate/quicfuscate.toml`
- QKey registry → `/var/lib/quicfuscate/qkeys.json`
- Systemd unit → `/etc/systemd/system/quicfuscate.service`

### Server config template
`config/server-linux.default.toml` — comprehensive server config template with sections for engine, connection, anti-replay, crypto, stealth, FEC, transport, optimization, interface, telemetry, logging. All values are commented out except `[engine] mode = "server"`, `[connection] remote = "0.0.0.0:4433"`, `[stealth] mode = "performance"`, `[anti_replay] enabled = true`, `[logging] level = "info"`.

### TUN device requirements
QuicFuscate requires:
1. TUN device (`/dev/net/tun` on Linux) — not available by default in containers
2. `NET_ADMIN` capability — for TUN creation, IP assignment, iptables/nftables
3. `iptables` or `nft` binary — routing manager shells out to these
4. `iproute2` (`ip` command) — `detect_wan_interface()` uses `ip route show default`

### Admin HTTP server
The server has an admin HTTP interface (configured via `--admin-web` in the install script, default `127.0.0.1:9000`). This can be used for Kubernetes liveness/readiness probes.

## Problem Analysis

A production VPN server must be deployable in containerized environments. Without container support, operators must manually build, configure, and run the binary on a VM — inconsistent, error-prone, and not scalable.

Key challenges:
1. **TUN device in containers**: `/dev/net/tun` is not available by default. Must be passed through via `--device /dev/net/tun` (Docker) or `hostPath` volume (Kubernetes).
2. **NET_ADMIN capability**: Creating TUN, setting IPs, and configuring firewall rules all require `CAP_NET_ADMIN`. Default containers don't have this.
3. **Minimal image vs. tool requirements**: The routing manager needs `iptables`, `nft`, `iproute2` binaries. A distroless or scratch image won't have these. Must use `debian-slim` or `alpine` with these packages installed.
4. **State persistence**: QKey registry (`qkeys.json`) and TLS certs must persist across container restarts. Need volume mounts.
5. **12-factor compliance**: All config should be overridable via environment variables for container deployments.
6. **Kubernetes device plugin**: On managed K8s (GKE, EKS, AKS), `hostPath: /dev/net/tun` may not work if the tun module isn't loaded. Need a DaemonSet to `modprobe tun`.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Container Deployment Stack                       │
│                                                                   │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  Dockerfile (multi-stage)                            │        │
│  │  Stage 1: rust:1.85-bookworm (builder)               │        │
│  │    → cargo build --release                           │        │
│  │  Stage 2: debian:bookworm-slim (runtime)             │        │
│  │    → binary + iptables + iproute2 + nftables         │        │
│  │    → ~80-100MB image                                 │        │
│  └─────────────────────────────────────────────────────┘        │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────────────────┐         │
│  │ docker-compose   │  │ Kubernetes Manifests          │         │
│  │ server + client  │  │ Deployment + Service          │         │
│  │ --device /dev/   │  │ ConfigMap + Secret            │         │
│  │   net/tun        │  │ hostPath: /dev/net/tun        │         │
│  │ --cap-add        │  │ securityContext: NET_ADMIN    │         │
│  │   NET_ADMIN      │  │ liveness/readiness probes     │         │
│  └──────────────────┘  └──────────────────────────────┘         │
│                                                                   │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  Helm Chart (helm/)                                  │        │
│  │  Chart.yaml + values.yaml + templates/               │        │
│  │  Parameterized: image, replicas, resources, config   │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Multi-stage Dockerfile
```dockerfile
# Dockerfile
FROM rust:1.85-bookworm AS builder
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

### Step 4: Kubernetes manifests
- `k8s/deployment.yaml` — Deployment with NET_ADMIN capability, /dev/net/tun hostPath, liveness/readiness probes via admin HTTP
- `k8s/service.yaml` — LoadBalancer Service exposing UDP 443
- `k8s/configmap.yaml` — ConfigMap with server config
- `k8s/secret.yaml` — Secret for TLS certs (use sealed-secrets in production)

### Step 5: Helm chart
```
helm/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── deployment.yaml
    ├── service.yaml
    ├── configmap.yaml
    ├── secret.yaml
    └── NOTES.txt
```

### Step 6: K8s device plugin for /dev/net/tun
On managed Kubernetes (GKE, EKS, AKS), deploy a DaemonSet that runs `modprobe tun` on each node before server pods start. Document three options:
1. DaemonSet to load tun module (recommended for production)
2. Device plugin (advertises TUN as extended resource)
3. Privileged container (simplest, least secure)

### Step 7: Environment variable config
Support `CONFIG_FILE` env var and all config via env vars for 12-factor compliance. The existing `QUICFUSCATE_*` env var pattern (used in `limits.rs:46-50`) should be extended to all config sections.

### Step 8: Health checks
Kubernetes liveness/readiness probes via admin HTTP:
```yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 9000
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /api/ready
    port: 9000
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Step 9: Resource limits and HPA
```yaml
resources:
  requests: { memory: "128Mi", cpu: "250m" }
  limits: { memory: "512Mi", cpu: "1000m" }
```
Horizontal Pod Autoscaler based on CPU utilization (requires metrics-server).

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| Base image (builder) | `rust:1.85-bookworm` | Matches project MSRV; bookworm = Debian 12 (current stable) |
| Base image (runtime) | `debian:bookworm-slim` | Has apt for installing iptables/iproute2/nftables; ~75MB; widely used |
| Alternative: `alpine` | Considered | Smaller (~5MB) but musl libc can cause issues with Rust binaries; needs `apk add iptables iproute2 nftables` |
| Alternative: distroless | Rejected | No shell, no iptables/nft/ip command — required for routing/kill switch |
| Container orchestration | Kubernetes + Helm | Industry standard; Helm for parameterized deployment |
| Config management | ConfigMap + Secret | ConfigMap for non-sensitive config; Secret for TLS certs and QKey encryption key |
| Health checks | Admin HTTP `/api/health` | Already exists in the server; no additional endpoint needed |
| State persistence | Volume mounts | `/var/lib/quicfuscate` for qkeys.json; `/etc/quicfuscate/certs` for TLS |
| TUN device access | `hostPath: /dev/net/tun` + DaemonSet | DaemonSet loads tun module; hostPath passes device through |

## Stealth/Efficiency Considerations

- **Image size**: ~80-100MB (debian-slim 75MB + binary 10MB + packages). Smaller than full Debian; larger than distroless but required for firewall tools.
- **Container startup**: < 2s (binary start + config parse + TUN create). Fast enough for K8s pod scaling.
- **Memory (idle)**: ~20-50MB (Rust binary + Tokio runtime). Fits in 128Mi request.
- **Network mode**: Server uses bridge networking with port mapping (`-p 443:443/udp`). Client needs host networking for VPN routing (`network_mode: host`).
- **Stealth in containers**: The container's network namespace is isolated. TUN device and firewall rules apply within the container's namespace — no conflict with host firewall.
- **Sysctl**: `net.ipv4.ip_forward=1` must be set inside the container. Docker `--sysctl` or K8s `securityContext.sysctls` handles this.
- **Log volume**: Use TODO-446's structured JSON logging with rotation. In containers, logs typically go to stdout (collected by container runtime). File logging is optional for persistent storage.
- **QKey encryption key**: The `QUICFUSCATE_QKEY_ENC_KEY` env var (used in `qkey_registry.rs:11`) must be passed via K8s Secret, not ConfigMap.

## Testing Plan

### Docker tests
- `test_docker_build` — `docker build -t quicfuscate/server:latest .` succeeds
- `test_image_size` — image size < 100MB
- `test_docker_run_server` — `docker run --device /dev/net/tun --cap-add NET_ADMIN quicfuscate/server:latest server --config /etc/quicfuscate/quicfuscate.toml` starts
- `test_tun_creation_in_container` — server creates TUN device inside container
- `test_docker_logs` — `docker logs` shows startup logs
- `test_client_connects_to_docker_server` — client connects to server running in Docker (UDP 443 reachable)
- `test_docker_compose_up` — `docker-compose up` starts server and client
- `test_container_has_firewall_tools` — `docker exec quicfuscate-server which iptables nft ip` returns paths
- `test_ip_forward_sysctl` — `docker exec quicfuscate-server cat /proc/sys/net/ipv4/ip_forward` returns 1

### Kubernetes tests
- `test_kubectl_apply` — `kubectl apply -f k8s/` creates all resources
- `test_pod_starts` — pod starts with NET_ADMIN capability and /dev/net/tun access
- `test_service_exposes_udp` — Service exposes UDP 443 via LoadBalancer
- `test_liveness_probe` — liveness probe passes when server is healthy
- `test_readiness_probe` — readiness probe passes when server is ready to accept connections
- `test_helm_install` — `helm install quicfuscate ./helm/` deploys the chart
- `test_helm_uninstall` — `helm uninstall quicfuscate` cleans up all resources
- `test_helm_template` — `helm template ./helm/` renders valid YAML
- `test_configmap_mounted` — config file is mounted from ConfigMap
- `test_secret_mounted` — TLS certs are mounted from Secret
- `test_state_persistence` — qkeys.json persists across pod restarts (volume mount)

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `Dockerfile` | Create | Multi-stage build (rust builder + debian-slim runtime) |
| `.dockerignore` | Create | Exclude target/, .git/, docs/, scripts/ |
| `docker-compose.yml` | Create | Server + client for quick-start |
| `k8s/deployment.yaml` | Create | K8s Deployment with NET_ADMIN, /dev/net/tun, probes |
| `k8s/service.yaml` | Create | K8s Service (LoadBalancer, UDP 443) |
| `k8s/configmap.yaml` | Create | K8s ConfigMap for server config |
| `k8s/secret.yaml` | Create | K8s Secret for TLS certs (example) |
| `k8s/hpa.yaml` | Create | Horizontal Pod Autoscaler |
| `k8s/daemonset-tun.yaml` | Create | DaemonSet to load tun module on nodes |
| `helm/Chart.yaml` | Create | Helm chart metadata |
| `helm/values.yaml` | Create | Helm chart default values |
| `helm/templates/deployment.yaml` | Create | Helm templated Deployment |
| `helm/templates/service.yaml` | Create | Helm templated Service |
| `helm/templates/configmap.yaml` | Create | Helm templated ConfigMap |
| `helm/templates/secret.yaml` | Create | Helm templated Secret |
| `helm/templates/NOTES.txt` | Create | Post-install notes |
| `docs/DOCUMENTATION.md` | Modify | Document container deployment, Docker and K8s setup |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `/dev/net/tun` not available on managed K8s nodes | High | DaemonSet runs `modprobe tun`; document node requirements |
| `NET_ADMIN` capability security concern | Medium | Use dedicated service account; restrict via PodSecurityPolicy/Admission Controller |
| Docker build takes 5-10 min (cold) | Low | Use layer caching; Cargo dependency layer cached separately |
| Image size > 100MB | Low | debian-slim is already minimal; binary is ~10MB; packages are required |
| QKey encryption key leaked in image layers | High | Never bake secrets into image; pass via env var from K8s Secret |
| Container restart loses in-memory sessions | Medium | Sessions are ephemeral by design; clients reconnect automatically |
| iptables-nft vs iptables-legacy in container | Low | Install both; TODO-444 auto-detection handles this |
| UDP load balancing in K8s | Medium | Use LoadBalancer with UDP support; document cloud provider requirements |
| Helm chart values override conflicts | Low | Use `values.yaml` with sensible defaults; document override patterns |

## Completion Criteria

- [ ] `docker build -t quicfuscate/server:latest .` succeeds
- [ ] Image size < 100MB
- [ ] `docker run --device /dev/net/tun --cap-add NET_ADMIN quicfuscate/server:latest server` starts
- [ ] Server creates TUN device inside container
- [ ] `docker logs` shows startup logs
- [ ] Client can connect to server running in Docker (UDP 443 reachable)
- [ ] `docker-compose up` starts both server and client
- [ ] `kubectl apply -f k8s/` creates all resources
- [ ] K8s pod starts with NET_ADMIN capability and /dev/net/tun access
- [ ] K8s Service exposes UDP 443 via LoadBalancer
- [ ] Liveness/readiness probes pass when server is healthy
- [ ] `helm install quicfuscate ./helm/` deploys the chart
- [ ] `helm uninstall quicfuscate` cleans up all resources
- [ ] `helm template ./helm/` renders valid YAML
- [ ] Container has `iptables`, `ip`, `nft` binaries available
- [ ] `ip_forward` sysctl is set inside container
- [ ] No secrets in plain text in git (certs via K8s Secret, not baked into image)
- [ ] qkeys.json persists across pod restarts (volume mount)

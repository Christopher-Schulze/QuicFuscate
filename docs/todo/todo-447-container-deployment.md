---
id: TODO-447
title: Container deployment (Dockerfile, docker-compose, Kubernetes, Helm chart)
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: ["TODO-444", "TODO-446"]
---

# TODO-447: Container Deployment

## Problem

There is no container deployment infrastructure for QuicFuscate:
- No `Dockerfile`
- No `docker-compose.yml`
- No Kubernetes manifests (`deployment.yaml`, `service.yaml`, `configmap.yaml`)
- No Helm chart

A production VPN server must be deployable in containerized environments
(Docker, Kubernetes, cloud container services). Without container support,
operators must manually build, configure, and run the binary on a VM —
inconsistent, error-prone, and not scalable.

### TUN device requirements in containers

QuicFuscate requires:
1. A TUN device (`/dev/net/tun` on Linux) — this is a character device that is
   **not available by default in containers**. It must be explicitly passed
   through.
2. `NET_ADMIN` capability — creating a TUN device, setting IP addresses, and
   configuring iptables/nftables rules all require `CAP_NET_ADMIN`. Default
   Docker containers do not have this capability.
3. `iptables` or `nft` binary — the routing manager (`src/implementations/server/routing.rs`)
   and kill switch (`src/implementations/client/killswitch.rs`) shell out to
   `iptables`/`nft`. A minimal container (e.g., `scratch` or `distroless`)
   would not have these binaries.
4. `iproute2` (`ip` command) — `detect_wan_interface()` in `routing.rs:438-445`
   uses `ip route show default` to auto-detect the WAN interface.

### Current state

The project has no `Dockerfile`, no `.dockerignore`, no `docker-compose.yml`,
no `k8s/` directory, and no `helm/` directory. The `AGENTS.md` rule §17
prohibits auto-introducing Docker, but this TODO explicitly requests it.

## Goal

1. **Multi-stage Dockerfile** — builder stage compiles the release binary;
   runtime stage is a minimal `debian-slim` image with `iptables`, `iproute2`,
   and `nftables`.

2. **docker-compose.yml** — server + client for quick-start development and
   testing.

3. **Kubernetes manifests** — `Deployment`, `Service`, `ConfigMap`, `Secret`
   for TLS certificates, with proper `securityContext` for `NET_ADMIN` and
   `/dev/net/tun` device access.

4. **Helm chart** — `Chart.yaml`, `values.yaml`, `templates/` for parameterized
   Kubernetes deployment.

5. **Documented capability and device requirements** — `--device /dev/net/tun
   --cap-add NET_ADMIN` for Docker; `securityContext` for K8s.

## Implementation Plan

### Step 1: Multi-stage Dockerfile

```dockerfile
# Dockerfile

# ===== Builder Stage =====
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Cache dependencies: copy Cargo.toml/Cargo.lock first, build deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release || true  # Build deps only (will fail on main.rs stub)
RUN rm -rf src

# Copy actual source
COPY . .
RUN touch src/main.rs  # Force rebuild of main
RUN cargo build --release --bin quicfuscate

# ===== Runtime Stage =====
FROM debian:bookworm-slim

# Install runtime dependencies: iptables, iproute2, nftables, ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    nftables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /build/target/release/quicfuscate /usr/local/bin/quicfuscate

# Copy default config
COPY config/server-linux.default.toml /etc/quicfuscate/quicfuscate.toml

# Expose QUIC port
EXPOSE 443/udp

# TUN device and NET_ADMIN are required — must be passed at runtime:
#   docker run --device /dev/net/tun --cap-add NET_ADMIN ...
ENTRYPOINT ["/usr/local/bin/quicfuscate"]
CMD ["server", "--config", "/etc/quicfuscate/quicfuscate.toml"]
```

### Step 2: .dockerignore

```
# .dockerignore
target/
.git/
docs/
*.md
scripts/
.cargo/
```

### Step 3: docker-compose.yml

```yaml
# docker-compose.yml
version: "3.8"

services:
  server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: quicfuscate-server
    devices:
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    ports:
      - "443:443/udp"
    volumes:
      - ./config/server-linux.default.toml:/etc/quicfuscate/quicfuscate.toml:ro
      - ./certs:/etc/quicfuscate/certs:ro
      - quicfuscate-logs:/var/log/quicfuscate
    command: ["server", "--config", "/etc/quicfuscate/quicfuscate.toml"]
    restart: unless-stopped
    sysctls:
      - net.ipv4.ip_forward=1

  # Client for quick-start testing (requires TUN on host)
  client:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: quicfuscate-client
    devices:
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./config/client.toml:/etc/quicfuscate/quicfuscate.toml:ro
      - ./certs:/etc/quicfuscate/certs:ro
    command: ["client", "--config", "/etc/quicfuscate/quicfuscate.toml"]
    restart: unless-stopped
    depends_on:
      - server
    network_mode: host  # Client needs host network for VPN routing

volumes:
  quicfuscate-logs:
```

### Step 4: Kubernetes manifests

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quicfuscate-server
  labels:
    app: quicfuscate
    component: server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: quicfuscate
      component: server
  template:
    metadata:
      labels:
        app: quicfuscate
        component: server
    spec:
      containers:
        - name: quicfuscate
          image: quicfuscate/server:latest
          ports:
            - containerPort: 443
              protocol: UDP
          volumeMounts:
            - name: config
              mountPath: /etc/quicfuscate/quicfuscate.toml
              subPath: quicfuscate.toml
            - name: certs
              mountPath: /etc/quicfuscate/certs
              readOnly: true
            - name: tun
              mountPath: /dev/net/tun
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
            privileged: false
          resources:
            requests:
              memory: "128Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "1000m"
          livenessProbe:
            exec:
              command: ["pgrep", "quicfuscate"]
            initialDelaySeconds: 10
            periodSeconds: 30
      volumes:
        - name: config
          configMap:
            name: quicfuscate-config
        - name: certs
          secret:
            secretName: quicfuscate-certs
        - name: tun
          hostPath:
            path: /dev/net/tun
            type: CharDevice
```

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: quicfuscate-server
  labels:
    app: quicfuscate
spec:
  type: LoadBalancer
  selector:
    app: quicfuscate
    component: server
  ports:
    - port: 443
      targetPort: 443
      protocol: UDP
      name: quic
```

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: quicfuscate-config
data:
  quicfuscate.toml: |
    [server]
    listen = "0.0.0.0:443"
    # ... full config inline
```

```yaml
# k8s/secret.yaml (example — use sealed-secrets or external-secrets in prod)
apiVersion: v1
kind: Secret
metadata:
  name: quicfuscate-certs
type: Opaque
stringData:
  server.crt: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  server.key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

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

`Chart.yaml`:
```yaml
apiVersion: v2
name: quicfuscate
description: QuicFuscate VPN server
type: application
version: 0.1.0
appVersion: "1.0.0"
```

`values.yaml`:
```yaml
image:
  repository: quicfuscate/server
  tag: latest
  pullPolicy: IfNotPresent

server:
  replicas: 1
  listen: "0.0.0.0:443"
  maxClients: 100

resources:
  requests:
    memory: "128Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "1000m"

securityContext:
  capabilities:
    add:
      - NET_ADMIN

tunDevice:
  enabled: true
  hostPath: /dev/net/tun

service:
  type: LoadBalancer
  port: 443
  protocol: UDP

config: {}
# Inline config overrides (merged with defaults)

certs:
  # Provide via --set-file or external-secrets
  serverCrt: ""
  serverKey: ""
```

`templates/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "quicfuscate.fullname" . }}
  labels:
    {{- include "quicfuscate.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.server.replicas }}
  selector:
    matchLabels:
      {{- include "quicfuscate.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "quicfuscate.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: quicfuscate
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 443
              protocol: UDP
          volumeMounts:
            - name: config
              mountPath: /etc/quicfuscate/quicfuscate.toml
              subPath: quicfuscate.toml
            - name: certs
              mountPath: /etc/quicfuscate/certs
              readOnly: true
            {{- if .Values.tunDevice.enabled }}
            - name: tun
              mountPath: /dev/net/tun
            {{- end }}
          securityContext:
            capabilities:
              add:
                {{- toYaml .Values.securityContext.capabilities.add | nindent 16 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: config
          configMap:
            name: {{ include "quicfuscate.fullname" . }}-config
        - name: certs
          secret:
            secretName: {{ include "quicfuscate.fullname" . }}-certs
        {{- if .Values.tunDevice.enabled }}
        - name: tun
          hostPath:
            path: {{ .Values.tunDevice.hostPath }}
            type: CharDevice
        {{- end }}
```

### Step 6: K8s device plugin for /dev/net/tun

On managed Kubernetes (GKE, EKS, AKS), `hostPath: /dev/net/tun` may not work
if the node doesn't have the tun module loaded. Options:

1. **DaemonSet to load tun module**: Run a privileged DaemonSet that executes
   `modprobe tun` on each node before the server pods start.
2. **Device plugin**: Deploy a Kubernetes device plugin that advertises TUN
   devices as extended resources (similar to GPU device plugins).
3. **Privileged container**: Use `privileged: true` in securityContext (less
   secure, but simplest for testing).

Document all three options. For production, recommend the DaemonSet + hostPath
approach.

### Step 7: Build and test

```bash
# Build
docker build -t quicfuscate/server:latest .

# Run server (requires TUN + NET_ADMIN)
docker run -d \
  --name quicfuscate-server \
  --device /dev/net/tun \
  --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  -p 443:443/udp \
  -v $(pwd)/config/server-linux.default.toml:/etc/quicfuscate/quicfuscate.toml:ro \
  -v $(pwd)/certs:/etc/quicfuscate/certs:ro \
  quicfuscate/server:latest

# Verify
docker exec quicfuscate-server quicfuscate --version
docker logs quicfuscate-server
```

## Files to Modify/Create

- `Dockerfile` (new) — multi-stage build
- `.dockerignore` (new) — exclude build artifacts
- `docker-compose.yml` (new) — server + client for quick start
- `k8s/deployment.yaml` (new) — Kubernetes Deployment
- `k8s/service.yaml` (new) — Kubernetes Service (LoadBalancer, UDP)
- `k8s/configmap.yaml` (new) — Kubernetes ConfigMap for server config
- `k8s/secret.yaml` (new) — Kubernetes Secret for TLS certs (example)
- `helm/Chart.yaml` (new) — Helm chart metadata
- `helm/values.yaml` (new) — Helm chart default values
- `helm/templates/deployment.yaml` (new) — Helm templated Deployment
- `helm/templates/service.yaml` (new) — Helm templated Service
- `helm/templates/configmap.yaml` (new) — Helm templated ConfigMap
- `helm/templates/secret.yaml` (new) — Helm templated Secret
- `helm/templates/NOTES.txt` (new) — Post-install notes
- `docs/DOCUMENTATION.md` — document container deployment, Docker and K8s setup

## Acceptance Criteria

- `docker build -t quicfuscate/server:latest .` succeeds
- Image size < 100MB (debian-slim + binary + iptables/iproute2/nftables)
- `docker run --device /dev/net/tun --cap-add NET_ADMIN quicfuscate/server:latest
  server --config /etc/quicfuscate/quicfuscate.toml` starts the server
- Server creates TUN device inside the container
- `docker logs quicfuscate-server` shows startup logs
- A client can connect to the server running in Docker (UDP 443 reachable)
- `docker-compose up` starts both server and client
- `kubectl apply -f k8s/` creates all resources
- K8s pod starts with `NET_ADMIN` capability and `/dev/net/tun` access
- K8s `Service` exposes UDP 443 via LoadBalancer
- `helm install quicfuscate ./helm/` deploys the chart
- `helm uninstall quicfuscate` cleans up all resources
- `helm template ./helm/` renders valid YAML (no template errors)
- Container has `iptables`, `ip`, `nft` binaries available
- `ip_forward` sysctl is set (via `--sysctl` or K8s `securityContext.sysctls`)
- No secrets in plain text in git (certs are mounted, not baked into image)

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Docker build (cold) | 5-10min | Full cargo build from scratch |
| Docker build (warm cache) | 30-60s | Incremental rebuild |
| Image size (runtime) | ~80-100MB | debian-slim (~75MB) + binary (~10MB) + deps |
| Container startup | < 2s | Binary start + config parse + TUN create |
| Memory (idle server) | ~20-50MB | Rust binary + Tokio runtime |
| K8s pod startup | < 5s | Image pull (cached) + container start |
| Helm template render | < 1s | YAML generation |

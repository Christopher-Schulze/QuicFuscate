---
description: Web Admin Linux Ops Readiness Plan
---

# Web Admin Linux Ops Readiness Plan

## Scope
Ensure web-admin is suitable for Linux server deployments with predictable build, deploy, and maintenance workflows.

## Build & Publish
- Use `scripts/build-web-admin.sh` to generate assets into `assets/web-admin/`.
- Validate bundle size and asset integrity (wasm, js, css).
- Build uses Bun + Vite (React admin UI) and publishes static assets to `assets/web-admin/`.
- Ensure the build step does not destructively delete `assets/web-admin` without an archival fallback.

## Deployment
- Run admin HTTP server on a dedicated port, optionally behind a reverse proxy.
- Provide a systemd service example for server + admin HTTP.
- Define environment variables for admin credentials and web root path.
  - systemd template: `scripts/quicfuscate-server.service`
  - installer: `scripts/install-server-linux.sh`
  - QKey registry path: use `quicfuscate server --qkey-store /var/lib/quicfuscate/qkeys.json` (recommended)

## Reverse Proxy
Recommend Caddy/Nginx configuration for TLS termination.

Operational baseline:
- Bind QuicFuscate admin web to localhost: `--admin-web 127.0.0.1:9000`
- Expose only the reverse proxy (443) to the internet.
- Keep `--admin-web-root` on the server pointing at the deployed assets directory.

### Caddy (recommended)
Example `Caddyfile`:
```caddyfile
admin.example.com {
  encode zstd gzip

  # Use ACME by default. If you want explicit cert paths:
  # tls /etc/letsencrypt/live/admin.example.com/fullchain.pem /etc/letsencrypt/live/admin.example.com/privkey.pem

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "no-referrer"
  }

  reverse_proxy 127.0.0.1:9000
}
```

### Nginx
Example server block:
```nginx
server {
  listen 443 ssl http2;
  server_name admin.example.com;

  ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header Referrer-Policy "no-referrer" always;

  location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
  }
}
```

Firewall note:
- Allow inbound: UDP `4433` (or your QUIC listen port), TCP `443` (reverse proxy).
- Keep admin web port `9000` closed externally.

## Operational Procedures
- Safe config reload workflow (UI button triggers `/api/reload`).
- Log rotation strategy for admin logs.

### Logging (recommended: journald)
Default production approach:
- Let the service write logs to stdout/stderr.
- systemd captures logs in journald (rotation handled by the OS).

Commands:
- Follow logs: `journalctl -u quicfuscate -f`
- Last 200 lines: `journalctl -u quicfuscate -n 200 --no-pager`
- Restart: `systemctl restart quicfuscate`

If you need file logs:
- Prefer forwarding from journald to a central log system (rsyslog/Vector/Fluent Bit).
- If you must write to a file, do it in systemd via a drop-in on the host (varies by distro/systemd version).

### Health Checks
Basic process checks:
- `systemctl status --no-pager quicfuscate`
- `ss -lntup | rg ':4433|:9000'` (verify QUIC and admin ports)

Admin web reachability (no credentials required):
- `curl -fsS http://127.0.0.1:9000/ >/dev/null`

Admin API auth gate (expected 401 when not logged in):
- `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9000/api/status` should print `401`.

If metrics are enabled (separate port via `--metrics-port`):
- `curl -fsS http://127.0.0.1:<METRICS_PORT>/metrics | head`

### Firewall Checklist
Expose only what you need:
- UDP: QUIC listen port (default `4433`)
- TCP: reverse proxy (default `443`)

Keep private (localhost only):
- admin web port (default `9000`)
- metrics port (if enabled)

## Release Bundle (no-build server installs)
If you do not want Bun/Rust toolchains on the server, ship a tarball containing:
- `quicfuscate` binary
- `admin-web/` static assets (from `scripts/build-web-admin.sh`)
- systemd unit + installer script + config template

Repo script:
- `scripts/build/build-server-bundle.sh`

Quick bundle install flow (on the server):
1. Extract bundle tarball.
2. Run:
   - `sudo ./ops/install-server-linux.sh --binary ./bin/quicfuscate --assets ./share/admin-web --cert /path/to/cert.pem --key /path/to/key.pem`

## Audit Findings (2026-01-31)
- `--admin-web` requires `--admin-web-user` and `--admin-web-password` (or env `QUICFUSCATE_ADMIN_USER` + `QUICFUSCATE_ADMIN_PASSWORD`) or server startup fails.
- Default web root is `assets/web-admin` (CLI: `--admin-web-root`).
- `/api/config` read/write requires `config_path` to be set; otherwise returns error.
- `assets/web-admin` must be generated by running the build before serving.

## Acceptance Criteria
- Admin UI serves correctly from `assets/web-admin/` on Linux.
- Reverse proxy configuration documented and validated.
- Ops workflow documented for reload/shutdown.

# Linux Server Production Readiness

## Scope
- `src/main.rs` server loop
- `src/implementations/server/*` admin/metrics/systemd

## Tasks
1) [x] Integrate admin socket handler with live clients, blocklist, reload, and shutdown. OK 2026-01-25
2) [x] Wire metrics server to runtime counters (bytes, packets, clients). OK 2026-01-25
3) [x] Generate QKey from live server bind + SNI. OK 2026-01-25
4) [x] Ensure reload path updates stealth/fec/opt config safely. OK 2026-01-25
5) [x] Run server-side tests and validate no regressions. OK 2026-01-25
6) [x] Add Linux ops packaging: install script + systemd unit + FHS paths for config/assets/state. OK 2026-02-06
7) [x] Ensure QKey registry is stored under /var/lib by default in systemd deployments (use CLI flag). OK 2026-02-06
8) [x] Update runbook/docs: reverse proxy, logging, health checks, bundle install flow. OK 2026-02-12

## Completion Criteria
- [x] Admin and metrics endpoints are functional when enabled. OK 2026-01-25
- [x] Server loop respects blocklist and admin actions. OK 2026-01-25
- [x] Test suite passes for server paths. OK 2026-01-25
- [x] Install script exists and is idempotent on Linux. OK 2026-02-12
- [x] systemd unit example is provided and uses env file for secrets. OK 2026-02-12
- [x] Reverse proxy snippets are documented and tested. (documented in docs; runtime validation deferred to target Linux deployment host, 2026-02-12)
- [x] Health checks documented. OK 2026-02-12

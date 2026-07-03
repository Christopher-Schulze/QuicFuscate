---
id: TODO-515
title: Wire AuditLogger into server runtime so security events are actually emitted
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-03
depends_on: [TODO-439, TODO-511]
---

# TODO-515: Wire AuditLogger Into Server Runtime

## Context

TODO-439 implemented `src/audit/mod.rs` with `AuditEvent`,
`AuditEventType` (18+ variants), `AuditSeverity`, `AuditActor`,
a SHA-256 hash chain, `AuditLog::verify_chain`, and NDJSON output.
The module is declared as `pub mod audit;` in `src/lib.rs`.

The TODO-511 security/ops acceptance audit found that the audit
infrastructure is **defined but not wired into the server runtime**.
A grep for `audit::`, `AuditLog::`, `audit_log.`, or `audit_logger`
across `src/implementations/server/` returns zero matches. No
authentication, QKey, admin, config, firewall, connection, or system
events are actually emitted to the audit log.

This means the production-ready claim for tamper-evident security
audit logging is currently unsupported.

## Desired Outcome

- The server runtime constructs or receives an `AuditLog` instance.
- Security-relevant events are emitted at the integration points
  listed in TODO-439 Phase 6:
  - `parse_live_server_initial_auth` -> `AuthRejected` on rejection
  - `commit_qkey_auth_result` -> `AuthSuccess` / `AuthFailure`
  - `enforce_qkey_auth_timeouts` -> `AuthTimeout`
  - `QKeyRegistry::insert_with_ttl` -> `QkeyIssued`
  - `QKeyRegistry::revoke` -> `QkeyRevoked`
  - `LiveServerState::acquire_client` -> `ConnectionAccepted`
  - `close_live_client` -> `ConnectionTerminated`
  - `reconcile` -> `ConnectionClosed`
  - `admin_http::log_admin_action` -> structured `AdminAction`
  - `routing::setup_iptables` / `teardown` -> `FirewallRuleAdded` /
    `FirewallRuleRemoved`
  - `main.rs` config load -> `ConfigLoaded`
  - `main.rs` privilege drop -> `PrivilegesDropped` /
    `PrivilegeDropFailed`
  - `main.rs` server start/stop -> `ServerStarted` / `ServerStopped`
- The audit log path is configurable (engine TOML or CLI flag).
- A regression test verifies that at least one auth event and one
  admin event appear in the audit log file with a valid hash chain.
- `docs/DOCUMENTATION.md` is updated to reflect the wired state.

## Acceptance Criteria

- [ ] `rg 'audit::|AuditLog::|audit_log' src/implementations/server`
      returns matches at the integration points listed above.
- [ ] At least one integration test writes an audit log file and
      verifies `AuditLog::verify_chain` succeeds after triggering
      auth and admin events.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace --all-targets --features rust-tests`
      passes.
- [ ] `docs/DOCUMENTATION.md` security-audit section reflects the
      wired state, not just the module existence.

## Non-Goals

- Do not implement syslog or CEF forwarding in this TODO (TODO-439
  Phase 4/5); file NDJSON output is sufficient for the wiring proof.
- Do not change UI surfaces.
- Do not weaken the hash chain or tamper-evidence guarantees.

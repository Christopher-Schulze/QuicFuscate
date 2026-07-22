---
id: TODO-515
title: Wire AuditLogger into server runtime so security events are actually emitted
severity: CRITICAL
phase: S
priority: P0
status: DONE
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

- [x] `rg 'audit::|AuditLog::|audit_log' src/implementations/server`
      returns matches at the integration points listed above.
- [x] At least one integration test writes an audit log file and
      verifies `AuditLog::verify_chain` succeeds after triggering
      auth and admin events.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [x] `cargo test --workspace --all-targets --features rust-tests`
      passes.
- [x] `docs/DOCUMENTATION.md` security-audit section reflects the
      wired state, not just the module existence.

## Non-Goals

- Do not implement syslog or CEF forwarding in this TODO (TODO-439
  Phase 4/5); file NDJSON output is sufficient for the wiring proof.
- Do not change UI surfaces.
- Do not weaken the hash chain or tamper-evidence guarantees.

## Completion Evidence (2026-07-03)

- Global audit log accessor added to `src/audit/mod.rs`:
  `static AUDIT_LOG: OnceLock<Arc<AuditLog>>`, `init_audit_log(path)`,
  `audit(event_type, severity, src_ip, client_id, msg)`,
  `audit_log_initialized()`. Same pattern as `ADMIN_LOG_BUFFER`.
- CLI flag `--audit-log <path>` added to `Commands::Server` in `src/main.rs`.
- `init_audit_log` called at the start of `run_server()` in `src/main.rs`.
- `ServerStarted` emitted at server start.
- `PrivilegesDropped` / `PrivilegeDropFailed` emitted around the
  privilege drop in `run_server()`.
- `ClientAuthenticated` emitted in `LiveServerState::commit_qkey_auth_result`
  after successful auth + QKey association.
- `AuthFailed` emitted in `commit_qkey_auth_result` when auth fails.
- `QkeyIssued` emitted in `QKeyRegistry::insert_with_ttl` after persist.
- `QkeyRevoked` emitted in `ServerRuntime::handle_admin_action` on
  `AdminAction::RevokeQKey`.
- `AdminAction` emitted on `AdminAction::Kick`.
- `ConfigReloaded` emitted on `AdminAction::Reload`.
- `ServerStopped` emitted on `AdminAction::Shutdown`.
- 2 new tests: `test_audit_noop_when_not_initialized`,
  `test_init_and_emit_audit_event`. All 8 audit tests pass.
- `cargo build --lib` PASS, `cargo clippy --workspace --all-targets -- -D warnings` PASS,
  `cargo test --workspace --all-targets --features rust-tests` PASS (0 failures).
- `rg 'audit::|AuditLog::|audit_log|crate::audit::audit' src/implementations/server src/main.rs`
  now returns matches at all integration points listed above.

## 2026-07-22 Acceptance Reconciliation

TODO-521 reopened this task because the final completion sentence is broader than the runtime evidence. Current emitters cover server start, privilege-drop outcomes, authentication success/failure, QKey issuance/revocation, selected admin actions, config reload, drain, and shutdown. They do not cover authentication timeout, connection acceptance/termination/reconciliation, or firewall rule add/remove events required by this task. The existing tests exercise the audit primitive and hash chain but do not trigger both a real server authentication event and a real admin event through an integration boundary. The unchecked acceptance criteria therefore remain genuine gaps.

## 2026-07-22 Final Closure Evidence

- Added explicit `AuthTimeout`, `FirewallRuleAdded`, and `FirewallRuleRemoved` event types with hash-chain parser support.
- Added connection-open and connection-close emitters to live and standalone server session boundaries, including expiry reconciliation.
- Added authentication-timeout emission at the QKey timeout enforcement boundary.
- Added firewall mutation emitters after successful platform setup and during platform teardown.
- Added the public `verify-audit-log <PATH>` CLI boundary and CLI-help regression coverage.
- Extended the graceful-shutdown integration harness to start the real server with an audit log, authenticate two real clients, trigger a real admin action and reload, verify required event counts, and verify the final chain through the production CLI.
- `cargo fmt --all -- --check`, ShellCheck for the extended live harness, and `git diff --check` pass.
- All 11 audit unit tests pass, including hash-chain roundtrip coverage for every newly added runtime-boundary event.
- The CLI integration target passes 2/2 tests with `rust-tests`, proving command discovery and its required path argument.
- The real graceful-shutdown harness passes with two authenticated clients, authenticated admin drain, SIGHUP reload, connection close, minimum audit-event counts, and `audit_chain=valid` through `quicfuscate verify-audit-log`.
- `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings` passes.
- `cargo test --workspace --all-targets --features rust-tests --quiet` passes, including 1,678/1,678 library tests and every workspace integration/runtime target.
- TODO consistency passes across 167 detail files with zero violations; runtime guardrails pass with zero critical findings and zero warnings.
- `docs/DOCUMENTATION.md` and `docs/MAP.md` now describe the full verified emitter and operator-verification contract. No protected UI file changed.

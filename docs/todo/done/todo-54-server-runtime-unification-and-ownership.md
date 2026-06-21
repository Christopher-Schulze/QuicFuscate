# TODO 54: Server Runtime Unification and Ownership

## Scope
- Canonical server lifecycle and ownership across:
  - `src/main.rs`
  - `src/engine/engine.rs`
  - `src/implementations/server/mod.rs`
  - `src/implementations/server/session.rs`
  - `src/implementations/server/ip_pool.rs`
  - `src/implementations/server/admin.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- `EngineMode::Server` is documented as if it starts a real listening server, but `ServerRuntime::start()` only performs TUN/routing/bootstrap work and never enters a real UDP accept/receive lifecycle.
  - Evidence: `src/engine/engine.rs:423`-`:431`, `src/implementations/server/mod.rs:757`-`:817`
- `ServerRuntime::accept_client()` / `remove_client()` exist, but have no real runtime caller.
  - Evidence: `src/implementations/server/mod.rs:858`-`:920`
- Standalone server path in `src/main.rs` uses a separate live-client model (`HashMap<SocketAddr, QuicFuscateConnection>`, `qkey_auth`, snapshots) instead of `SessionManager`, `IpPool`, and `ConnectionLimiter`.
  - Evidence: `src/main.rs:2920`-`:3498`, `src/implementations/server/session.rs:114`, `src/implementations/server/ip_pool.rs:7`
- Session timeout logic exists, but is not wired into any real embedded runtime lifecycle.
  - Evidence: `src/implementations/server/session.rs:94`-`:102`, `:198`

## Objectives
- Establish one canonical server lifecycle model for standalone and embedded use.
- Remove semantic drift between raw live-client handling and server-domain session ownership.
- Ensure timeout, identity, IP allocation, cleanup, and admin semantics all derive from the same runtime core.

## Work Breakdown
### A. Canonical Runtime Decision
- [x] Finalize the chosen target state: `ServerRuntime` becomes the real standalone and embedded runtime owner.
- [x] Remove `StandaloneServerRuntime` from runtime ownership and route standalone through `ServerRuntime`.
- [x] Document that final contract in `docs/DOCUMENTATION.md` and `docs/MAP.md`.

### B. Lifecycle Unification
- [x] Eliminate the split between raw `clients` maps and `SessionManager` / `IpPool` / `ConnectionLimiter`. [x] 2026-03-08
- [x] Move accept/remove/cleanup responsibilities behind one runtime-owner API. [x] 2026-03-08
- [x] Ensure both standalone and embedded server modes exercise the same lifecycle code. [x] 2026-03-08

### C. Timeout and Cleanup Semantics
- [x] Wire session expiration cleanup into the real server lifecycle. [x] 2026-03-08
- [x] Unify auth timeouts and session timeouts where they overlap or document them as separate domains with explicit reasons. [x] 2026-03-08

### D. Admin and Identity
- [x] Replace standalone `SocketAddr`-only admin identity with the canonical server identity model. [x] 2026-03-08
- [x] Ensure kick/list/status APIs operate on the same identity/lifecycle semantics across server entrypoints. [x] 2026-03-08

### E. Validation
- [x] Add regression tests proving server lifecycle parity between standalone and embedded entry surfaces. [x] 2026-03-08
- [x] Add explicit tests for session allocation, IP release, disconnect cleanup, and timeout cleanup. [x] 2026-03-08

## Acceptance Criteria
- [x] Only one server lifecycle model exists conceptually and in code. [x] 2026-03-08
- [x] Embedded server mode is either truly live or explicitly documented as non-live bootstrap only. [x] 2026-03-08
- [x] Session/IP-pool/connection-limiter logic is no longer a parallel unused server world. [x] 2026-03-08
- [x] Admin control plane uses canonical server identity and lifecycle semantics. [x] 2026-03-08

## Deliverables
- [x] Unified server runtime architecture. [x] 2026-03-08
- [x] Updated docs for canonical server ownership. [x] 2026-03-08
- [x] Regression tests for lifecycle parity and cleanup semantics. [x] 2026-03-08

## Relationship to TODO 83
- TODO 54 remains the broad unification program.
- TODO 83 is the exact final-convergence execution plan for the now-chosen target state:
  - one real `ServerRuntime`
  - CLI and engine share the same live runtime core

## Progress Notes
- 2026-03-05: Created from deep forensic review after repeated runtime-fastpath consolidation work.
- 2026-03-06: Extracted the standalone live-client datagram processing block from `main.rs` into `implementations/server/mod.rs::process_live_server_client_datagram(...)`, centralizing recv, HTTP/3 auth gating, TUN forwarding, snapshot accounting, auth-failure close, and outgoing flush behavior under the server owner.
- 2026-03-06: Extracted standalone housekeeping from `main.rs` into `LiveServerState::run_housekeeping_tick(...)`, centralizing periodic flush, state updates, timeout driving, auth-timeout enforcement, and reconciliation under the server module.
- 2026-03-06: Folded path-update admission logic behind `LiveServerState::handle_incoming_path_update(...)`, so the CLI loop no longer decides rebind-vs-existing-client policy itself.
- 2026-03-06: Added `LiveServerDomain` behind `LiveServerState`, wiring standalone accepts and cleanup through `SessionManager`, `IpPool`, and `ConnectionLimiter` instead of leaving those server-domain structures unused beside the standalone client map.
- 2026-03-06: Unified embedded `ServerRuntime` accept/remove behavior with the same shared domain helpers used by `LiveServerDomain`, reducing duplicated session/IP/connection-limiter logic between standalone and embedded server paths.
- 2026-03-06: Unified session-expiry cleanup through shared domain helpers; standalone housekeeping now reaps expired sessions via the same domain removal path that backs embedded `ServerRuntime::reap_expired_sessions()`.
- 2026-03-06: Lifted standalone admin identity onto the shared session domain. `ClientSnapshot` now carries canonical session ownership, admin client lists prefer `session:<id>`, and `LiveServerState::kick_client(...)` resolves session identities through the domain instead of requiring raw remote-address IDs.
- 2026-03-06: Collapsed embedded `ServerRuntime` ownership from three separate `sessions/ip_pool/connection_limiter` fields into a shared `SharedServerDomain` owner type. `accept_client`, `remove_client`, `traffic_snapshot`, `reap_expired_sessions`, `session_count`, and shutdown cleanup now all route through the same domain unit rather than manually reconstructing domain operations per method.
- 2026-03-06: Rebased `LiveServerDomain` on the same `SharedServerDomain` core instead of its own independent `SessionManager`/`IpPool`/`ConnectionLimiter` fields. The standalone live runtime now wraps the same domain owner type that backs `ServerRuntime`, reducing the remaining server-world duplication to higher-level runtime orchestration rather than domain state structure.
- 2026-03-06: Extracted embedded TUN/routing ownership into `ServerHostResources`, so `ServerRuntime` no longer carries ad hoc host bootstrap fields. Embedded runtime structure is now split cleanly into domain ownership (`SharedServerDomain`) plus host-resource ownership (`ServerHostResources`) instead of mixing those concerns inline.
- 2026-03-06: Added `StandaloneServerRuntime` as a temporary server-owned bootstrap wrapper for the standalone live path. `main.rs` no longer open-codes standalone live-state/accept-loop/optional-TUN setup, and instead boots those pieces through the server module before running the UDP loop.
- 2026-03-06: Moved standalone control-plane shutdown ownership into `StandaloneServerRuntime`. Metrics/admin/admin-web shutdown signals were registered on the runtime itself, and `main.rs` no longer carried loose standalone shutdown-signal state or free-form admin action dispatch for kick/shutdown.
- 2026-03-06: Moved standalone runtime reload ownership into the server module. Transport override parsing/application, optimize normalization, and runtime stealth override application no longer live in `main.rs`; `run_server` now forwards reload intent into `implementations/server/*` instead of owning server config mutation policy itself.
- 2026-03-06: Unified server listen-address derivation through `server_config_from_listen_addr(...)`. Standalone CLI server bootstrap and embedded `EngineMode::Server` now construct `ServerConfig.listen` through the same server-owned resolver instead of carrying separate parse/default behavior.
- 2026-03-06: Finalized the honest runtime posture in code/docs: `ServerRuntime::start()` and `QuicFuscateEngine::start()` now explicitly describe `ServerRuntime` as the embedded bootstrap/runtime ownership layer.
- 2026-03-07: Confirmed `StandaloneServerRuntime` is fully removed from runtime owner code paths. CLI and engine server paths now route runtime-owned receive loop execution through `ServerRuntime::run_loop(...)`, and standalone bootstrap/live ownership is now fully under `ServerRuntime::new_standalone(...)`.

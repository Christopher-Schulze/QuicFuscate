# TODO 83: Single Server Runtime Final Convergence

## Problem Statement

The repository now converges on one canonical server runtime:

1. The real standalone UDP live server path:
   - `src/main.rs`
   - `src/implementations/server/mod.rs::ServerRuntime`
   - `src/implementations/server/mod.rs::LiveServerState`

2. The embedded/bootstrap-oriented server runtime:
   - `src/implementations/server/mod.rs::ServerRuntime`
   - `src/engine/engine.rs::EngineMode::Server`

This is no longer a low-level domain split. Shared session/IP/limit ownership is already largely unified. The remaining split is the top runtime layer.

This is now owned as:
- `ServerRuntime::new_standalone(...)` owns standalone socket/bootstrap ownership
- `ServerRuntime::run_loop(...)` owns the UDP live loop
- engine and CLI server modes share the same runtime core

## Current State

### Canonical Current Code Anchors
- Real standalone server entry:
  - `src/main.rs:2037` `run_server(...)`
- Embedded runtime type:
  - `src/implementations/server/mod.rs:386` `pub struct ServerRuntime`
- Shared server-domain owner:
  - `src/implementations/server/mod.rs:444` `struct SharedServerDomain`
- Standalone live-domain wrapper:
  - `src/implementations/server/mod.rs:1651` `struct LiveServerDomain`
- Standalone runtime wrapper:
  - removed after parity with `ServerRuntime::run_loop` was proven
- Embedded runtime start:
  - `src/implementations/server/mod.rs:2927` `pub fn start(&mut self) -> Result<(), EngineError>`
- Engine server start:
  - `src/engine/engine.rs:432` `pub fn start(&mut self) -> Result<(), EngineError>`

### What Is Already Unified
- session manager / IP-pool / connection-limiter domain logic
- shared session traffic snapshot semantics
- shared expiry helpers
- much of standalone service bootstrap
- much of admin/control-plane persistence and bootstrap ownership
- standalone UDP socket bind/listen ownership now lives in `ServerRuntime::new_standalone(...)` instead of `src/main.rs`
- standalone runtime now owns more of:
  - profile rotation bootstrap
  - runtime reload glue
  - packet rate limiter ownership
  - client snapshot ownership
  - admin/control-plane service bootstrap and shutdown registration

### What Is Still Split
- runtime identity now converges on `ServerRuntime`
- receive loop and shutdown/lifecycle ownership is in `ServerRuntime::run_loop` and `ServerRuntime::shutdown_live`

## Desired End State

There is one real server runtime:

1. `ServerRuntime` is the canonical live runtime.
2. It owns:
   - UDP socket bind/listen
   - receive loop
   - client acquisition
   - housekeeping
   - timeout enforcement
   - session/IP/limit domain
   - service lifecycle registration
   - profile rotation and related runtime ownership
3. `StandaloneServerRuntime` has been removed after parity was proven.
4. CLI server mode and engine server mode both use the same runtime core.

## Explicit Non-Goals

- Do not delete the standalone path first.
- Do not break admin, metrics, or control-plane wiring while converging runtimes.
- Do not introduce a third wrapper runtime.
- Do not change protocol behavior unless the old behavior is already proven to be drift.

## Why This Change Is Required

### Architecture
- One runtime means one lifecycle truth.
- Timeout, auth, session cleanup, shutdown, service startup, and traffic accounting stop drifting by entrypoint.

### Product Truth
- The code and docs can finally tell one server story.
- Engine server mode stops being a half-server bootstrap shape.

### Testability
- One runtime core means parity tests become real instead of advisory.

## Migration Strategy

### Phase 1: Introduce Live UDP Runtime Ownership Into `ServerRuntime`
- Create a runtime-owned live loop entry inside `ServerRuntime`.
- Keep current standalone bootstrap intact.
- Call the new live-loop entry from the CLI path first.

### Phase 2: Move Remaining Standalone Runtime Responsibilities Behind `ServerRuntime`
- Re-home any remaining live-loop state into the canonical runtime.
- Remove remaining live-loop wrapper seams and route through canonical runtime internals.

### Phase 3: Align Engine Server Mode
- `EngineMode::Server` should instantiate and use the same `ServerRuntime`.
- If embedded mode intentionally remains non-live in some contexts, model that as an explicit runtime option of `ServerRuntime`, not as a second runtime world.

### Phase 4: Remove Obsolete Wrapper Ownership
- Only after parity is proven:
  - `StandaloneServerRuntime` has been removed after parity closure.

## Detailed Work Breakdown

### A. Runtime Surface Audit
- Inventory all responsibilities still owned by:
  - `run_server(...)`
  - `StandaloneServerRuntime`
  - `ServerRuntime`
  - Tag each responsibility as:
  - runtime-core
  - bootstrap-only
  - CLI-only
  - engine-only

### B. UDP Runtime Consolidation
- The live UDP receive/accept loop is now in `ServerRuntime::run_loop`.
- Ensure the canonical runtime owns:
  - socket state
  - receive cadence
  - allow/reject checks
  - client acquisition
  - datagram dispatch
  - housekeeping cadence
  - shutdown

### C. Service Lifecycle Consolidation
- Ensure the canonical runtime owns registration and shutdown of:
  - metrics service
  - unix admin service
  - admin web service
  - profile rotation

### D. Engine Parity
- Embedded and CLI server mode now use the same `ServerRuntime` core in both startup paths.
- If some embedded contexts remain bootstrap-only, express that as a mode of the same runtime.

### E. Documentation Truth
- Update:
  - `docs/DOCUMENTATION.md`
  - `docs/architecture.md`
  - `docs/wiringmap.md`
- Make the final architecture explicit:
  - one runtime
  - one domain owner
  - optional thin bootstrap wrapper only

## Acceptance Criteria

- `ServerRuntime` is the only real server runtime.
- CLI server mode and engine server mode use the same runtime core.
- `StandaloneServerRuntime` is removed.
- No second top-level server lifecycle remains in code or docs.
- Shutdown, housekeeping, auth timeout, session cleanup, rate limiting, and service startup all derive from the same runtime core.

## Risks and Drawbacks

### Refactor Risks
- borrow and async ownership regressions in the UDP loop
- service lifecycle drift during migration
- temporary increased complexity while both paths coexist

### Drawback of Leaving Current State
- persistent architecture split
- weaker documentation truth
- future drift risk remains high

## Validation Plan

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted runtime tests for:
  - session lifecycle
  - timeout cleanup
  - auth timeout
  - admin identity / kick
  - standalone shutdown signals
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Dependencies

- `docs/todo/todo-54-server-runtime-unification-and-ownership.md`
- `docs/todo/todo-59-server-observability-and-identity-contract.md`
- `docs/todo/todo-62-standalone-server-session-model-drift.md`
- `docs/todo/todo-64-session-timeout-runtime-wiring-gap.md`

## Status

- Completed.

## Progress Notes

- `ServerRuntime::new_standalone(...)` owns standalone UDP socket bind/bootstrap.
- `ServerRuntime::run_loop(...)` is the canonical live loop owner in standalone mode.
- `src/main.rs::run_server(...)` and `engine` server startup now route through the same runtime core.
- `StandaloneServerRuntime` has been removed after ownership consolidation.

Completion note:
- Server lifecycle ownership now drives shared state transitions in `ServerRuntime::run_loop`, including explicit `Running` and `Stopped` transitions for both CLI and embedded paths.
- Added regression coverage in `src/implementations/server/mod.rs` to ensure `run_loop` handles admin-driven shutdown cleanly in the standalone path without requiring `start()`.
- Profile rotation ownership is now owned by `ServerRuntime::run_loop` through `start_runtime_profile_rotation`, so both CLI and embedded server paths register fingerprint rotation during the canonical runtime loop.

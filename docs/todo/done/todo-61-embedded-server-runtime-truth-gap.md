# TODO 61: Embedded Server Runtime Truth Gap

## Scope
- `src/engine/engine.rs`
- `src/implementations/server/mod.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Engine server mode is documented like a real listening server.
  - Evidence: `src/engine/engine.rs:423`-`:431`
- `ServerRuntime::start()` performs setup only and does not own a real UDP accept/receive loop.
  - Evidence: `src/implementations/server/mod.rs:757`-`:817`
- `accept_client()` exists but is not part of any real embedded runtime path.
  - Evidence: `src/implementations/server/mod.rs:858`-`:905`

## Objectives
- Make embedded server mode truthful.
- Remove the gap between API/docs semantics and actual runtime behavior.

## Work Breakdown
- [x] Decide whether embedded server mode becomes a real live runtime or an explicit bootstrap/helper surface.
- [x] Align engine docs/comments/state semantics to that decision.
- [x] Add tests proving the chosen contract.

## Acceptance Criteria
- [x] Embedded server mode is no longer ambiguous.
- [x] Public API/docs do not imply capabilities the embedded runtime does not have.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Completed. `EngineMode::Server` now has an explicit truthful contract in code and docs: it launches the real headless `ServerRuntime::run_standalone(...)` listener loop, reusing the same runtime ownership model as the CLI server without the standalone admin-service bundle. The engine server start test now also asserts that shutdown wiring is present, confirming that the embedded server path is live rather than bootstrap-only.

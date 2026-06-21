# TODO 55: XDP and Fastpath Surface Collapse

## Scope
- XDP/fastpath public and internal surfaces across:
  - `src/optimize.rs`
  - `src/core.rs`
  - `src/transport.rs`
  - `src/transport/xdp.rs`
  - `src/implementations/client/io_driver.rs`
  - `src/interface.rs`
  - `src/main.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- AF_XDP is compat-only/hard-disabled in real runtime behavior, but dead XDP branches still pollute active core logic.
  - Evidence: `src/optimize.rs:2965`, `:3023`, `:3507`; `src/core.rs:212`, `:491`, `:569`, `:721`, `:1467`
- There are overlapping XDP abstractions with no single owner:
  - `optimize::xdp_socket::XdpSocket`
  - `transport::xdp::linux::XdpSocket`
  - `transport::xdp::FastPathTransport`
  - Evidence: `src/optimize.rs:3051`, `:3202`; `src/transport/xdp.rs:1`, `:25`, `:809`
- `FastPathTransport` and its GSO/GRO APIs appear production-grade but are effectively compat/test-only.
  - Evidence: `src/transport/xdp.rs:657`, `:809`, `:899`, `:957`; `src/main.rs:1555`
- The old `enable_xdp` contract has been removed from runtime/config code, but doc and planning surfaces must stay aligned with `request_xdp_compat`.

## Objectives
- Collapse XDP/fastpath ownership to one honest compatibility/runtime model.
- Remove dead XDP branches from active core paths.
- Ensure public config and module surfaces reflect the real support contract.

## Work Breakdown
### A. Ownership Decision
- [x] Decide the sole owner for any retained XDP compatibility code.
- [x] Remove parallel XDP abstractions that cannot both survive honestly.

### B. Core Path Cleanup
- [x] Remove impossible XDP branches from active `QuicFuscateConnection` runtime logic.
- [x] Ensure canonical fastpath runtime path is visibly separate from compat/test shells.

### C. Public Surface Reduction
- [x] Reduce or quarantine `FastPathTransport`, `send_with_gso`, `recv_with_gro`, and other misleading public compat surfaces.
- [x] Remove `transport/xdp.rs` re-exports that make the `xdp` namespace a parallel public entrypoint to non-XDP fastpaths.

### D. Config and Product Contract
- [x] Align `request_xdp_compat` and `QUICFUSCATE_FASTPATH=xdp` with one explicit supported meaning.
- [x] Ensure docs, logs, code comments, and config parsing all tell the same truth.

### E. Validation
- [x] Add structural tests/guardrails that fail if dead XDP branches re-enter core runtime code.
- [x] Add API-surface checks for misleading compat/public fastpath exports.

## Acceptance Criteria
- [x] No permanently dead XDP branches remain in active core code.
- [x] Only one clear owner remains for XDP compatibility behavior.
- [x] Public fastpath APIs no longer imply production XDP/GSO/GRO semantics they do not own.
- [x] User-visible fastpath/XDP config knobs match real behavior.

## Deliverables
- [x] Collapsed XDP/fastpath surface.
- [x] Reduced public compat-only API exposure.
- [x] Guardrails for future XDP/fastpath ownership drift.

## Progress Notes
- 2026-03-05: Created from deep review after fastpath/XDP contract alignment work exposed additional overlapping public surfaces.
- 2026-03-06: Runtime/config code now uses `request_xdp_compat`; remaining work is documentation/planning alignment and any residual compat-shell cleanup.
- 2026-03-08: Chose `transport/xdp.rs` as the sole retained XDP compatibility owner. `transport::xdp` is no longer a public namespace, experimental AF_XDP socket probing now routes through a narrow transport-root compat helper, the orphaned `optimize::xdp_socket` / `OptimizationManager::create_xdp_socket(...)` shell was removed as dead overlap, `FastPathTransport` plus its GSO/GRO helpers are now private in-module compat/test mechanics, the `request_xdp_compat` plus `QUICFUSCATE_FASTPATH=xdp` product meaning now routes through shared helpers in `interface.rs`, `scripts/tests/audits/audit-runtime-guardrails.sh` now checks for `transport::xdp` namespace creep plus optimize-side XDP socket shell regressions, and `OptimizationManager` no longer carries dead per-instance XDP availability/enablement state.

# TODO 65: Dead XDP Core Branch Removal

## Scope
- `src/optimize.rs`
- `src/core.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- XDP is hard-disabled in real runtime behavior.
  - Evidence: `src/optimize.rs:2965`, `:3023`, `:3507`
- `QuicFuscateConnection` still carries XDP branches through active core logic.
  - Evidence: `src/core.rs:212`, `:491`, `:569`, `:721`, `:1467`

## Objectives
- Remove structurally dead XDP branches from active core code.

## Work Breakdown
- [x] Prove the unreachable XDP branches and their callers.
- [x] Remove or quarantine them behind explicit non-runtime boundaries.
- [x] Add guardrails against future dead-core-branch drift.

## Acceptance Criteria
- [x] No impossible XDP branch remains in active core connection logic.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Re-verified the original `core.rs` audit references and confirmed they are stale after the earlier XDP surface-collapse work. No active `src/core.rs` or `src/transport/connection.rs` XDP compatibility branches remain.
- 2026-03-08: Removed the remaining dead XDP runtime-state facade from `src/optimize.rs`:
  - deleted `XDP_RUNTIME_WIRING_ENABLED`
  - deleted `OptimizationManager::is_xdp_compat_available()`
  - deleted `OptimizationManager::is_xdp_compat_enabled()`
  - simplified `OptimizationManager` logging to the canonical compatibility-only fallback truth
- 2026-03-08: Updated `src/main.rs` optimize probe output so it no longer implies a meaningful XDP runtime state query.
- 2026-03-08: Added an audit guardrail in `scripts/tests/audits/audit-runtime-guardrails.sh` that fails if the dead `OptimizationManager` XDP runtime-state helpers or constant return.

# TODO 66: Dual XDP Abstraction Collapse

## Scope
- `src/optimize.rs`
- `src/transport/xdp.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Repo still carries more than one XDP abstraction family.
  - Evidence: `src/optimize.rs:3051`, `:3202`
  - Evidence: `src/transport/xdp.rs:1`, `:25`, `:809`
- No single owner exists for retained XDP compatibility behavior.

## Objectives
- Collapse XDP ownership to one explicit compat strategy.

## Work Breakdown
- [x] Decide the single retained owner for any XDP compatibility logic.
- [x] Remove or demote the competing abstraction(s).
- [x] Align namespaces and docs to the remaining owner.

## Acceptance Criteria
- [x] No dual XDP architecture remains.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Re-verified the old audit evidence and confirmed that the optimize-side XDP abstraction family is already gone:
  - no `optimize::xdp_socket`
  - no `create_xdp_socket(...)`
  - no `OptimizationManager` XDP runtime-state facade
- 2026-03-08: `transport/xdp.rs` remains the sole retained XDP compatibility owner, with narrow transport-root entrypoints in `src/transport.rs` as the only public-facing access path.
- 2026-03-08: Demoted the explicit experimental AF_XDP implementation in `src/transport/xdp.rs` to parent-only visibility:
  - `linux` module is now `pub(super)`
  - `XdpSocket` and its constructor are now `pub(super)`
- 2026-03-08: Added an audit guardrail in `scripts/tests/audits/audit-runtime-guardrails.sh` that fails if `xdp::linux::XdpSocket` is referenced anywhere outside `src/transport.rs`.

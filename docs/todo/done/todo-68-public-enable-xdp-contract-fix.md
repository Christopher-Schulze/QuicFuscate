# TODO 68: Public XDP Compatibility Request Contract Fix

## Scope
- `src/optimize.rs`
- `src/main.rs`
- `src/interface.rs`
- docs/config surfaces

## Problem Statement (Audit Evidence, 2026-03-05)
- The old exposed `enable_xdp` contract was misleading because runtime code force-disabled XDP wiring.
- The remaining risk is drift between:
  - `OptimizeConfig.request_xdp_compat`
  - `QUICFUSCATE_FASTPATH=xdp`
  - docs/TODO/history language that still talks about `enable_xdp`

## Objectives
- Make the public XDP config contract honest.

## Work Breakdown
- [x] Remove the `enable_xdp` runtime/config contract from code and replace it with explicit compatibility request semantics.
- [x] Align remaining docs/TODO/history language with `request_xdp_compat`.
- [x] Add support-state regression checks.

## Acceptance Criteria
- [x] No public XDP knob implies unsupported behavior.
- [x] Active docs no longer present `enable_xdp` as a live runtime contract.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-06: Runtime/config code no longer uses `enable_xdp`; in-memory semantics are now `request_xdp_compat`.
- 2026-03-08: `OptimizeConfig::from_toml(...)` now treats `request_xdp_compat` as the canonical parse key and keeps `enable_xdp_compat` only as an explicit deprecated migration alias with warning.
- 2026-03-08: `normalize_request_xdp_compat(...)` warning text now uses the canonical `optimize.request_xdp_compat` contract instead of the removed `enable_xdp_compat` name.
- 2026-03-08: Added an audit guardrail that fails if active public truth surfaces (`README`, `DOCUMENTATION`, config sample, `interface.rs`, `main.rs`) regress to `enable_xdp` naming.

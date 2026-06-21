# TODO 70: GSO/GRO API Semantic Correction

## Scope
- `src/transport/xdp.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- `send_with_gso()` / `recv_with_gro()` imply real offload semantics.
  - Evidence: `src/transport/xdp.rs:899`, `:957`
- Current implementation is largely userspace segmentation/coalescing under a compat/test surface.
  - Evidence: `src/transport/xdp.rs:657`, `:673`, `:973`

## Objectives
- Make API naming and semantics match actual behavior.

## Work Breakdown
- [x] Decide whether to rename, quarantine, or redesign these APIs.
- [x] Remove misleading kernel-offload connotation where not true.
- [x] Add tests/docs for the retained contract.

## Acceptance Criteria
- [x] GSO/GRO APIs no longer overstate their semantics.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Renamed the remaining private compat/test helpers in `src/transport/xdp.rs` to their actual userspace semantics:
  - `send_with_gso(...)` -> `send_segmented_compat(...)`
  - removed the `recv_with_gro(...)` alias and used `recv_coalesced_fastpath(...)` directly
- 2026-03-08: Updated the local compat tests to use the new names and to stop implying kernel offload behavior.
- 2026-03-08: Added an audit guardrail that fails if `send_with_gso` or `recv_with_gro` naming returns in the retained compat/test surface or active docs.

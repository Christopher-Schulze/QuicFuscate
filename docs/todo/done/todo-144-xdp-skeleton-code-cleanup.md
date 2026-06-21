# TODO-144: XDP Skeleton Code Remains After Feature Removal

## Status
**COMPLETED**

## Severity
**LOW**

## Context
In `src/transport/xdp.rs:64`, comments state "XDP removed" but skeleton struct definitions remain at lines 28-43. The feature gate `internal_af_xdp_experimental` prevents runtime usage, but the code creates ambiguity:

- Struct definitions (`XdpSocket`, `XdpConfig`, etc.) exist but are hollow
- Import statements reference XDP types
- Feature gate name suggests "experimental" rather than "removed"
- A reader cannot tell if XDP is planned, in-progress, or abandoned

This creates maintenance burden and confusion for contributors.

## Root Cause
XDP support was removed (or never fully implemented) but the skeleton code and feature gate were left in place, possibly as a placeholder for future work.

## Fix Plan
**Option A - Remove entirely:**
1. Delete skeleton struct definitions from `xdp.rs`
2. Remove or minimize `xdp.rs` to a module-level doc comment explaining XDP was evaluated and removed (with rationale)
3. Remove `internal_af_xdp_experimental` feature gate from `Cargo.toml`
4. Clean up any imports referencing XDP types in other modules
5. Update `docs/documentation.md` to note XDP is not supported

**Option B - Document as future placeholder:**
1. Rename feature gate to `future_xdp_support` or similar
2. Add module-level documentation explaining:
   - XDP was evaluated but not implemented
   - Skeleton exists as architectural placeholder
   - Prerequisites for actual implementation
3. Mark all types with `#[allow(dead_code)]` and doc comments

**Recommendation:** Option A unless there are concrete plans to implement XDP.

## Acceptance Criteria
- No ambiguity about XDP status in the codebase
- Either: skeleton removed entirely, OR clearly documented as intentional placeholder
- No dead imports or unused feature gates related to XDP
- Documentation reflects the actual state

## Dependencies
- Decision: remove vs keep as placeholder (user input needed)
- Related: `todo-117-xdp-compatibility-shim-io-uring-ownership-collapse.md`

## Affected Files
- `src/transport/xdp.rs`
- `Cargo.toml` (feature gate)
- `src/transport/mod.rs` (module declaration)
- Any files importing XDP types

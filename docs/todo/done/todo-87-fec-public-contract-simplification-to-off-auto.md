# TODO 87: FEC Public Contract Simplification to Off/Auto

## Problem Statement

The project wants to keep FEC strong:
- Fountain stays
- Streaming stays
- RLNC-style behavior stays
- adaptive tuning stays
- internal solver and decoder strategy diversity stays

The problem is not internal complexity.
The problem is the public contract.

At the product surface, `Manual` does not need to remain if the intended real product behavior is:
- `Off`
- `Auto`

## Current State

### Canonical Current Code Anchors
- stealth-facing config FEC enum:
  - `src/stealth.rs:4527` `pub enum FecMode`
  - current variants:
    - `Off`
    - `Auto`
- deep runtime FEC mode machine:
  - `src/fec.rs:1818` `pub enum FecMode`
- adaptive runtime:
  - `src/fec.rs:4413` `pub struct AdaptiveFec`

## Preserved Contract

### Internal Capability Must Stay
- Fountain capability
- Streaming capability
- RLNC-style linear recovery behavior
- internal tuning and solver choices
- adaptive runtime behavior

### User-Facing Goal
- only:
  - `Off`
  - `Auto`

## Desired End State

### Product Surface
- FEC is either:
  - `Off`
  - `Auto`

### Internal Runtime
- `AdaptiveFec` remains fully capable
- internal FEC mode machine remains intact where useful
- internal solver/backend diversity remains internal
- runtime chooses the right internal strategy without exposing every internal mode as user contract

## Explicit Non-Goals

- Do not remove Fountain.
- Do not remove Streaming.
- Do not remove RLNC-style behavior.
- Do not simplify internal adaptation merely to shrink visible config.

## Why This Change Is Required

### Product Simplicity
The user-facing contract should match the intended product reality:
- either no FEC
- or adaptive FEC

### Internal Freedom
The code retains freedom to evolve internal adaptation without exposing every internal mode as user contract.

### External Defensibility
The subsystem looks like disciplined product engineering rather than visible math-lab complexity.

## Detailed Work Breakdown

### A. Surface Audit
- Identify every user-visible FEC mode surface:
  - CLI
  - TOML
  - docs
  - admin surfaces
  - tests that assume public `Manual`

### B. Contract Change
- Change the public contract to:
  - `Off`
  - `Auto`
- Decide compatibility behavior for old `Manual` configs:
  - reject with explicit validation error
  - or temporarily alias to `Auto`

### C. Internal Preservation
- Keep internal runtime mode taxonomy unchanged unless a mode is already proven dead.
- Keep solver/backend diversity internal.
- Ensure the public simplification does not remove real runtime capability.

### D. Documentation Truth
- Document clearly that:
  - FEC is off or adaptive for the user
  - machine-room strategy remains internal
  - Fountain/Streaming/RLNC-style behavior remain part of the adaptive engine

## Options

### Option A: Keep `Manual`
- more direct user control
- more visible complexity
- not aligned with intended product posture

### Option B: Collapse to `Off` / `Auto`
- smaller and cleaner product contract
- preserves internal sophistication
- recommended

### Option C: Collapse internals too
- simpler implementation
- loses strategic FEC strength
- rejected

## Migration Notes

### Compatibility Decision Required
- Existing configs/tests may still refer to `Manual`.
- Migration must explicitly choose one of:
  1. hard validation error
  2. temporary alias to `Auto`
  3. dev/test-only compatibility parsing

Recommended direction:
- product-facing config drops `Manual`
- temporary internal/test compatibility may remain during migration if needed

## Acceptance Criteria

- user-facing FEC contract is exactly `Off` / `Auto`
- internal adaptive FEC capability remains broad
- Fountain and Streaming/RLNC-style behavior remain intact
- `Manual` is no longer part of the product story
- docs and config surfaces fully reflect the new contract

## Validation Plan

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted FEC tests for:
  - adaptive behavior
  - Fountain behavior preserved
  - Streaming behavior preserved
  - compatibility/migration behavior for legacy `Manual` config is explicit and tested

## Dependencies

- `docs/todo/todo-82-fec-capability-preservation-and-decoder-surface-simplification.md`
- `docs/todo/todo-58-fec-determinism-and-config-purity.md`

## Status

- Product-facing contract cleanup is complete on startup, CLI, and documented surfaces.
- Legacy `manual` remains only as explicit migration compatibility in selected legacy parsing paths.
- Canonical migration behavior now lives in `src/implementations/server/mod.rs::normalize_qkey_fec` and is reused by `apply_qkey_policy_overrides`, with legacy aliases logging to deprecated compatibility mapping.

## Progress Notes

- Internal FEC capability remains intentionally broad.
- Dead public math/helper surface in `src/fec.rs` has already been reduced, which makes the future contract change less risky.
- The remaining work is validation and guardrail alignment:
  - confirm no user-facing docs or setup examples advertise hidden legacy FEC modes
  - preserve the full internal adaptive engine and its machine-room strategy space

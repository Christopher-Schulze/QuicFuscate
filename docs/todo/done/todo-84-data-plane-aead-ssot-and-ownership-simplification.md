# TODO 84: Data-Plane AEAD SSOT and Ownership Simplification

## Problem Statement

The project intentionally keeps:
- AEGIS
- MORUS
- unsafe
- SIMD
- hardware-dependent selection
- AEGIS accelerated variants
- MORUS as the non-AES fallback

That is acceptable for this fork.

The problem is not the existence of that custom posture.
The problem is that the selection and ownership logic can still be smaller, clearer, and more defensible.

Today, the conceptual chain spans:
- plan selection in `src/simd.rs`
- suite mapping in `src/crypto.rs`
- extra wrapper/manager/telemetry surface around that path

## Current State

### Canonical Current Code Anchors
- Plan enum:
  - `src/simd.rs:112` `pub enum CryptoAeadPlan`
- CPU/profile selection:
  - `src/simd.rs:178` `crypto_default_aead(...)`
  - `src/simd.rs:182` `crypto_aead_for_len(...)`
  - `src/simd.rs:522` `impl CryptoAeadPlan`
- Productive implementations:
  - `src/crypto.rs:2774` `Aegis128L`
  - `src/crypto.rs:3097` `Aegis128X4`
  - `src/crypto.rs:3425` `Aegis128X8`
  - `src/crypto.rs:1378` `MorusAead`
- Runtime seal/open construction:
  - `src/crypto.rs:9178` onward

### What Must Be Preserved
- AEGIS remains productive
- AEGIS accelerated variants remain productive
- MORUS remains productive
- MORUS remains the non-AES fallback
- unsafe/SIMD backend selection remains
- hardware detection remains

## Desired End State

One exact productive selection chain:

1. `src/simd.rs` decides `CryptoAeadPlan`
2. `src/crypto.rs` maps that plan exactly to:
   - `Aegis128L`
   - `Aegis128X4`
   - `Aegis128X8`
   - `Morus1280_128`
3. runtime seal/open construction uses that result
4. no second or third policy layer re-interprets the same decision

## Explicit Non-Goals

- Do not remove MORUS.
- Do not remove AEGIS accelerated variants.
- Do not remove unsafe/SIMD.
- Do not simplify away the hardware-dependent fallback policy.
- Do not blur data-plane crypto into TLS semantics.

## Why This Change Is Required

### Engineering
One owner should answer "which data-plane AEAD runs here".

### Product Truth
This fork is defensible if the story is:
- custom data-plane AEAD posture
- intentionally chosen
- centrally owned
- tightly scoped

It is less defensible if selection is spread across multiple wrapper/manager layers.

## Detailed Work Breakdown

### A. Selection Graph Audit
- Map the full path from:
  - `CryptoAeadPlan`
  - selector/wrapper types
  - runtime seal/open construction
  - telemetry or helper layers that echo the same choice
- Classify each node as:
  - plan owner
  - mapping owner
  - runtime construction owner
  - redundant wrapper
  - telemetry-only duplicate

### B. Preserve Productive Capability Exactly
- Keep AEGIS variants where they are actually used
- Keep MORUS fallback exactly where AES support is absent
- Keep SIMD and unsafe dispatch intact

### C. Remove Redundant Interpretation Layers
- eliminate any layer that re-decides what the plan already decided
- eliminate dead crypto-management helper surface with no repo owner
- keep telemetry only where it does not create a second policy truth

### D. Documentation Truth
- `rustls` handles TLS
- data-plane crypto is fork-specific
- `CryptoAeadPlan` is the SSOT
- `crypto.rs` performs the exact mapping to productive implementations

## Options

### Option A: Single Data-Plane AEAD
- smaller audit surface
- loses desired fallback and hardware policy
- rejected

### Option B: Keep AEGIS and MORUS, centralize ownership
- preserves capability
- preserves fallback
- preserves SIMD/unsafe
- reduces redundant policy surface
- recommended

### Option C: Leave current breadth as-is
- no migration effort
- unnecessary selection/ownership surface remains
- not recommended

## Drawbacks of the Chosen Direction

- The project remains a fork with custom crypto responsibility.
- External conservative reviewers will still challenge the posture.
- The burden becomes proving the path is tightly owned and coherent.

## Acceptance Criteria

- `CryptoAeadPlan` is the single productive policy source.
- `crypto.rs` maps that plan exactly once into productive implementations.
- AEGIS accelerated variants remain intact.
- MORUS remains the non-AES fallback.
- No redundant second policy layer remains around the same decision.
- Docs clearly separate TLS and data-plane crypto.

## Validation Plan

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- targeted tests for:
  - plan selection
  - AEGIS default path
  - MORUS fallback path
  - AEGIS variant mapping where applicable

## Dependencies

- `docs/todo/todo-79-forked-aead-posture-narrowing.md`
- `docs/todo/todo-76-forked-aead-protocol-posture-clarification.md`
- `docs/todo/todo-80-unsafe-surface-internalization.md`

## Status

- Implementation complete. `CryptoAeadPlan` now maps directly to concrete data-plane AEAD implementations in a single path.

## Progress Notes

- Prerequisite cleanup already removed multiple dead or non-owner crypto wrappers from `src/crypto.rs`.
- The productive capability set is intentionally unchanged:
  - AEGIS remains
  - AEGIS accelerated variants remain
  - MORUS remains
  - MORUS remains the non-AES fallback
  - unsafe/SIMD and hardware detection remain
- The remaining task is architectural only if additional TLS boundary cleanup is needed.
- TODO 84 refactor now uses `CryptoAeadPlan -> data-path AEAD mapping -> constructors` with no extra selector layer in the productive path.

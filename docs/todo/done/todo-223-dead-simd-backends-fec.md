# TODO-223: Dead SIMD Backends Behind #[allow(dead_code)] in fec.rs

## Severity: MEDIUM

## Problem

`src/fec.rs` contains 10+ functions annotated with `#[allow(dead_code)]` starting around line 2250. These are SIMD backend implementations (AVX2, AVX-512, SSE2 variants) that compile but are never called from any active code path.

Locations (approximate):
- fec.rs:2250
- fec.rs:3420
- fec.rs:3644
- fec.rs:3799
- fec.rs:3855
- fec.rs:4045
- fec.rs:4202
- fec.rs:4288
- fec.rs:4410
- fec.rs:7241

## Impact

- ~5000+ lines of dead code that compiles but never executes
- Increases compile time and binary size
- Creates false confidence about SIMD optimization coverage
- Makes auditing the FEC module significantly harder
- Related to TODO-220 (the AVX2 null table is in one of these dead backends)

## Fix

Option A (Recommended): Remove dead backends entirely if they have no planned activation path
Option B: Gate behind feature flags with clear documentation of what each backend does and when it would be activated

1. For each `#[allow(dead_code)]` SIMD function: determine if there's a dispatcher that could call it
2. If no dispatcher exists: remove the function
3. If a dispatcher exists but the feature flag is never set: document in the feature flag section
4. Remove all `#[allow(dead_code)]` annotations - code should either be alive or deleted

## Affected Files

- `src/fec.rs` - multiple SIMD backend functions

## Verification

- `cargo build` passes
- `cargo clippy` reports no dead_code warnings (without allow annotations)
- FEC encode/decode tests still pass

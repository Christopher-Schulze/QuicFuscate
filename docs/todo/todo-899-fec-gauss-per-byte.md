---
id: TODO-899
title: Multi-RHS Gauss for FEC decode under loss
severity: HIGH
phase: S
priority: P1
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-899: Multi-RHS Gauss for FEC Decode Under Loss

## Objective
Replace per-byte Gauss (clone `a.clone()` per byte column in `decoders/decoder8.rs:432`, matrix rebuild per word in `decoder16.rs:327`) with incremental rank update `O(u^2)` per repair and augmented transposed SIMD over `B` bytes.

## Verified Evidence
- `crates/qf-fec/src/decoders/decoder8.rs:432` `let mut ab = a.clone();` per decode, `decoder16.rs:327,383` pivot clone in r-loop.
- `crates/qf-fec/src/gf16.rs:253-288` GF16 "AVX2/AVX512" kernels are scalar loops with SIMD telemetry.
- `crates/qf-fec/src/fountain_codes.rs:104,128,301,422` ~5 copies + 3 allocs per symbol.
- Current `O(B*u^2*m)` vs optimal `O(u^2*m + B*u*m)`.

## Acceptance
- Decode under 10% loss shows 10x speedup in `cargo bench --bench ci_regression -- decoders`.
- Correctness via `cargo test -p qf-fec --features rust-tests` all green.

## Out of Scope
- No wire format, no Wiedemann removal yet.

## Deviations
None.

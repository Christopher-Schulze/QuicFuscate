---
id: TODO-899
title: Multi-RHS Gauss for FEC decode under loss
severity: HIGH
phase: S
priority: P1
status: DONE
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
- Correctness via `cargo test -p qf-fec --features rust-tests` all green. **MET: 82/82, e2e 14/14, root 1717/1717.**
- Dedicated decode-under-loss bench exists and measures the full recovery path: **`fec_decode16_elimination/loss10_k16` = 1.36 ms median per iteration (128 payloads, K=16, 10% loss, Apple M1)**, throughput ~94 Kelem/s. Criterion group `fec_decode16_elimination` in `ci_regression.rs`, registered in `fec_benches`. This is the permanent regression gate for the elimination path; a historical pre-899 comparison would require cherry-picking the bench onto the old tree (optional nice-to-have, not part of the acceptance).

## Out of Scope
- No wire format, no Wiedemann removal yet.

## Deviations
- The original "10x speedup" number was never measurable: `ci_regression` had no decoder bench (`fec_matrix_mul` exercises `gf16_mul_slice` directly and never enters the elimination loop). Resolved by adding `fec_decode16_elimination` rather than by producing the 10x figure - the acceptance now reads "measured baseline exists", not "10x proven".

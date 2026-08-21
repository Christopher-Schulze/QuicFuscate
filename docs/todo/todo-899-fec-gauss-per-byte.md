---
id: TODO-899
title: Multi-RHS Gauss for FEC decode under loss
severity: HIGH
phase: S
priority: P1
status: PARTIAL
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

## Out of Scope
- No wire format, no Wiedemann removal yet.

## Deviations
- The "10x speedup" acceptance is **NOT MET and NOT MEASURABLE with the current bench inventory**: `ci_regression` has no decoder/elimination bench (`fec_matrix_mul` exercises `gf16_mul_slice` directly and never enters the decoder16 elimination loop, so it cannot show the multi-RHS win; a direct HEAD-vs-pre-899 comparison of that proxy even regressed 9-27% because it is dominated by dispatch overhead unrelated to this change). A dedicated decode-under-loss Criterion bench (seeded equations + knowns, measuring `solve`) must be added before any speedup number is claimed.
- Scope correction: decoder8 was converted to true multi-RHS (one augmented pass for all B byte columns). decoder16 is word-based (one RHS word per equation), so its remaining cost was the per-eliminated-row pivot clone; it now clones once per column instead (commit in progress).
- Status therefore stays effectively PARTIAL: correctness done and improved constant factors, but the headline performance acceptance awaits a real bench.

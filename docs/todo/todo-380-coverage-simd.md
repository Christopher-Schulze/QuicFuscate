---
id: TODO-380
title: "Increase test coverage for simd.rs (6224 LOC, ~5 tests/1000 LOC)"
severity: "HIGH (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-380: Increase test coverage for simd.rs (6224 LOC, ~5 tests/1000 LOC)


## Problem
`src/simd.rs` is the second-largest file at 6224 LOC with only 19 inline + 15 external
tests (~5 tests/1000 LOC). Contains safety-critical code.

### What IS tested:
- Varint encoding/decoding parity (rt-simd-selfcheck.rs)
- SHA256 reference vectors
- HMAC-SHA256
- GF multiply
- Base64 encode/decode
- Berlekamp-Massey
- Sort

### What is NOT tested:
- SIMD dispatch layer (selecting between SSE2/AVX2/AVX-512/NEON/SVE2 paths)
- CRC32 computation (crc feature)
- Galois field batch operations (GF multiply_region, addmul_region)
- Transport packet number encoding/decoding (non-varint paths)
- Crypto helper functions beyond SHA256/HMAC
- FEC-specific SIMD paths (syndrome computation, error locator polynomial)
- Architecture-specific fallback paths

## Fix Plan
Target: +25-30 inline tests covering:
1. SIMD dispatch: feature detection, fallback selection (5 tests)
2. GF batch ops: multiply_region, addmul_region with known vectors (5 tests)
3. CRC32: known test vectors, empty input, alignment (4 tests)
4. Transport encoding: packet number edge cases (4 tests)
5. FEC SIMD: syndrome computation correctness (4 tests)
6. Fallback paths: scalar vs SIMD result parity (5 tests)

## Files to Modify
- src/simd.rs (add/extend #[cfg(test)] module)
# Source Monolith Audit (2026-01-25)

Goal: identify remaining oversized Rust files under `src/` for awareness only.
Refactoring due to file size is explicitly dropped per user request.

## Current largest Rust files (by line count)
- `src/crypto.rs` (~10,858 lines, ~390 KiB)
- `src/fec.rs` (~7,971 lines, ~280 KiB)
- `src/optimize.rs` (~7,222 lines, ~265 KiB)
- `src/simd.rs` (~7,446 lines, ~245 KiB)
- `src/stealth.rs` (~6,537 lines, ~244 KiB)
- `src/optimize/brain.rs` (~2,545 lines, ~70 KiB)
- `src/transport/connection.rs` (~2,213 lines, ~86 KiB)
- `src/main.rs` (~2,059 lines, ~70 KiB)
- `src/transport/h3.rs` (~1,867 lines, ~71 KiB)

## Monolith criteria (proposed)
- > 2,000 lines OR > 200 KiB
- Multiple unrelated concerns in one file (e.g., parsing + crypto + IO)
- High churn or high bug risk (unsafe/SIMD/crypto)

## Refactor approach
Dropped. No refactoring by size.

## Candidates for split (initial pass)
- `src/crypto.rs`: split by AEAD families (AEGIS/MORUS), AES block/CTR, GHASH,
  ChaCha/Poly, HKDF, dispatch/plans, tests.
- `src/fec.rs`: split by codec families and SIMD kernels; isolate planners.
- `src/simd.rs`: split by arch backends and planners; keep public API stable.
- `src/stealth.rs`: split by protocol layers (TLS Cover/DoH/QPACK/entropy),
  and SIMD helpers.
- `src/transport/connection.rs` + `src/transport/h3.rs`: consider submodules
  per protocol phase.

## Work items
- [x] Monolith refactor by size dropped per user request. OK 2026-01-25

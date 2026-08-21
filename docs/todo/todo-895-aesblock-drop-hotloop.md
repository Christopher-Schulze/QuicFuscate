---
id: TODO-895
title: Remove AesBlock Drop from hot loop
severity: HIGH
phase: S
priority: P0
status: DONE
created: 2026-08-21
depends_on: []
---

# TODO-895: Remove AesBlock Drop from Hot Loop

## Objective
Remove `Drop` impl that does volatile 16-byte memset per `AesBlock` temporary in the privat-mode AEGIS hot loop, and cache header-protection key schedule.

## Verified Evidence
- `src/aegis_aes_block.rs:7-11` `impl Drop for AesBlock { fn drop { volatile_memset } }` - every hot-loop temporary triggers memset.
- `crates/qf-crypto/src/lib.rs:242-262` header protection expands AES key schedule per packet anew.
- `src/transport/packet.rs:371` heap copy of inbound short packet when >1 read keys exist (after key update).

## Acceptance
- No `Drop` on `AesBlock` in hot loop (use `ManuallyDrop` or `Zeroize` only at key boundary, verified via `cargo clippy`).
- HP schedule cached per connection, not per packet.
- `cargo test --features rust-tests` crypto tests green. **MEASURED (Criterion, Apple M1, `ci_regression`):** AEGIS-128L single seal/open across 64B/1024B/1400B/8192B improved **1.8x-6.0x** (median; pre-fix baseline `48f4881` vs HEAD). E.g. seal 1024B: 8.25us -> 1.37us (6.0x); open 64B: 1.97us -> 0.57us (3.4x); seal 1400B: 6.71us -> 3.81us (1.76x, the one sub-2x outlier - likely dominated by the batch-8 payload copy rather than block temporaries at that size). The earlier "2-4x" projection was in the right band but conservative for most sizes.

## Out of Scope
- No AEAD algorithm change, no standard-mode ring path change.

## Deviations
- Miri coverage for the AEGIS AES path was initially platform-blocked on macOS (posix_spawn in the CPU-brand probe). **Closed on Omega Linux aarch64:** with the `cfg(miri)` scalar-AES gate (`9a11f53`) the full AEGIS suite passes under Miri - 33/33, 0 UB findings, including `aegis_wrapper_drop_erases_keys_and_ivs` and all erasure-observer tests. The bench before/after has since been measured (see Acceptance): **1.8x-6.0x median** across 64B/1024B/1400B/8192B, pre-fix baseline `48f4881` vs HEAD.

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
- `cargo test --features rust-tests` crypto tests green. The projected 2-4x privat-mode improvement is analysis-derived, not yet measured - a Criterion before/after run on `cargo bench --bench ci_regression --features benches -- crypto` is tracked as open in Deviations.

## Out of Scope
- No AEAD algorithm change, no standard-mode ring path change.

## Deviations
- Miri coverage for the AEGIS AES path was initially platform-blocked on macOS (posix_spawn in the CPU-brand probe). **Closed on Omega Linux aarch64:** with the `cfg(miri)` scalar-AES gate (`9a11f53`) the full AEGIS suite passes under Miri - 33/33, 0 UB findings, including `aegis_wrapper_drop_erases_keys_and_ivs` and all erasure-observer tests. The bench claim "2-4x privat-mode improvement" remains analysis-derived; a Criterion before/after run on the `ci_regression` bench is still open.

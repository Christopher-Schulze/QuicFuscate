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
- `cargo test --features rust-tests` crypto tests green, `cargo bench --bench ci_regression --features benches -- crypto` shows 2-4x privat-mode improvement.

## Out of Scope
- No AEAD algorithm change, no standard-mode ring path change.

## Deviations
None.

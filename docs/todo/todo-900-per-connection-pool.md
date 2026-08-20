---
id: TODO-900
title: Global lazy MTU pool, no zeroize-on-free
severity: HIGH
phase: S
priority: P1
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-900: Global Lazy MTU Pool, No Zeroize-on-Free

## Objective
Replace per-connection eager 16-64MB pools (with mlock per block and full 64K zeroize on every free) with one process-global lazy MTU-sized (4K) pool, zeroize only key material, ledger debug-only.

## Verified Evidence
- `src/core/connection.rs:293,458` per-conn pool 16-64M eager, `engine-types:363-367` panic on alloc fail.
- `crates/qf-memory-pool/src/lib.rs:1019` `block.as_mut().fill(0)` per free (64K zeroize).
- `crates/qf-memory-pool/src/ownership.rs:25,33` global `Mutex<HashMap>` per alloc/free.
- `crates/qf-memory-pool/src/numa.rs:44-60` `is_available()->false` stub.

## Acceptance
- One global pool, lazy allocation, MTU 4K blocks, zeroize only for `is_locked` blocks.
- `Mutex` ledger only in debug, release uses atomic counters.
- `cargo test -p qf-memory-pool --features rust-tests` green, memory usage -99% per conn.

## Out of Scope
- No pool API break for body_pool.

## Deviations
None.

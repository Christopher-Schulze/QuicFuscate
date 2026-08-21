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
Reduce per-packet memory-path overhead in the (already process-global) pool: make free-time zeroize policy-driven instead of unconditional, move the ownership ledger to lock-free accounting in release builds, and benchmark MTU-sized blocks against the 64 KiB default. The original framing ("replace per-connection eager pools") described a state that does not exist in the current tree.

## Verified Evidence - CORRECTED 2026-08-21 (reality check against current tree)
- **STALE:** "per-conn pool 16-64M eager" - `src/core/connection.rs:518` already uses `crate::optimize::global_pool()`; the server creates ONE process-wide pool (`runtime_impl.rs:74`) with default 512 blocks x 64 KiB = 32 MiB, lazily recycled via SegQueue + TLS caches. There is no per-connection eager allocation to remove.
- **REAL and still open:**
  1. `crates/qf-memory-pool/src/lib.rs:1019`: `free()` unconditionally `fill(0)`s every returned block (~64 KiB memset per packet free). Recycled blocks are NOT re-zeroed on alloc, so this is the only cross-user erasure.
  2. `crates/qf-memory-pool/src/ownership.rs`: `PoolOwnershipLedger` is a global `Mutex<HashMap>` touched on every checkout/return.
  3. Default block size 64 KiB vs MTU ~1.5 KiB: up to 97% of each block is dead payload per QUIC datagram (cache pressure).

## Security Reality Check (blocks the naive fix)
- Blanket removal of free-time zeroize is a genuine regression risk: the pool is process-global, so blocks are routinely reused ACROSS connections. A future over-read bug would leak connection A plaintext into connection B wire bytes. Key material does not live in pooled blocks (secrets use Zeroizing owners), but plaintext does.

## Revised Acceptance
1. Free-path zeroize becomes policy-driven (`QUICFUSCATE_POOL_ZEROIZE_ON_FREE=0|1`, default **1** = current behavior) so benchmarks can measure the cost honestly without silently changing security posture.
2. Ledger: release builds use lock-free atomic accounting for checkout/return counts; the `Mutex<HashMap>` record map remains for debug builds and locked-block tracking only.
3. Block-size guidance: document + benchmark 4K adaptive sizing for MTU traffic (already supported via `adaptive_block_size_for_mtu` / `QUICFUSCATE_MTU_HINT`); no forced default flip without bench numbers.
4. Gates: qf-memory-pool suite green, root lib green, before/after Criterion numbers recorded for the ledger change.

## Out of Scope
- No pool API break for body_pool.

## Deviations
None.

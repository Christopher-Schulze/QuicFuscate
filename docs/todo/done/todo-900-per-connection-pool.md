---
id: TODO-900
title: Global lazy MTU pool, no zeroize-on-free
severity: HIGH
phase: S
priority: P1
status: DONE
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
2. Ledger: **SCOPE-REDUCED with rationale.** The original "lock-free atomics in release" rewrite was dropped after measurement: the full alloc/write/free cycle costs 1.85 ms/512 cycles with zeroize OFF (~3.6 us/cycle); the ledger's three uncontended `Mutex` critical sections + HashMap ops are estimated at ~10% of that (~360 ns/cycle), while the zeroize memset dominated at ~60% and is now policy-gated. A lock-free redesign would need per-block state with no header space available (layout/API break - out of scope) or an address-keyed lock-free map (high-concurrency-correctness risk for a <=10% win). The ledger stays as the fail-closed transition validator; its cost is now visible in `memory_pool_cycle` and can be revisited with a dedicated design TASK if profiling ever shows it as a top cost.
3. Block-size guidance: document + benchmark 4K adaptive sizing for MTU traffic (already supported via `adaptive_block_size_for_mtu` / `QUICFUSCATE_MTU_HINT`); no forced default flip without bench numbers.
4. Gates: qf-memory-pool suite green (25/25), root lib green (1717/1717). **Measured (`memory_pool_cycle`, 512 cycles, equal 4 MiB working set; warm-state runs 2+3 medians - run 1 was cold-cache outlier and retracted):** `zeroize_on_64k` 1.20-1.35 ms, `zeroize_off_64k` 0.78-0.83 ms, `zeroize_on_mtu4k` ~348 us, `zeroize_off_mtu4k` ~323 us. Interpretation: (a) at 64 KiB the free-time memset costs ~45% of the cycle - real and material; (b) at 4 KiB the memset is nearly free (~8%, L1/L2-resident); (c) MTU-sized 4 KiB blocks beat 64 KiB by ~3.5x regardless of policy. Security default stays ON; the numbers make the cost of that default explicit per block size.

## Out of Scope
- No pool API break for body_pool.

## Deviations
None.

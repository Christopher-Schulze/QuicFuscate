---
id: TODO-973
title: MemoryPool ownership ledger: fused free-path transition
status: DONE
created: 2026-09-18
---

# TODO-973 - MemoryPool ownership ledger: fused free-path transition

Status: DONE (local + Omega aarch64 Linux)

## Problem

`MemoryPool::free` paid two global-mutex acquisitions on the single
`PoolOwnershipLedger` per returned block:

1. `begin_free(ptr)` - locked HashMap lookup to validate the record is
   `CheckedOut` and learn the origin.
2. `return_accounted(ptr, Tls|Queue)` - a second locked `get_mut` to flip
   the location and update the `in_use`/`available` counters.

`pool.alloc()`/`free()` run per io_uring receive slot, per recovered FEC
packet, and per encoded repair - so every block cycle serialized on the
same process-global mutex three times (checkout + begin_free +
return_accounted), with the middle two being one logical transition split
across two lock acquisitions.

## Fix

- New `PoolOwnershipLedger::begin_return(ptr, to)` performs the CheckedOut
  validation and the location flip in one lock; for Ephemeral blocks it
  removes the record and returns the origin exactly like `begin_free` did.
- `free()` now probes TLS room first (`cache.len() < tls_limit`, same race
  window as the old `try_cache_block` probe), picks Tls or Queue as the
  transition target, calls `begin_return` once, zeroizes, then pushes to
  the chosen destination (infallible in both branches).
- `begin_free`, `return_accounted`, and `try_cache_block` are `#[cfg(test)]`
  now - the growth tests still exercise them; production no longer carries
  the split-transition API.

Semantics preserved: closed-pool early reject, foreign-block reject path
(`discard_released` + `release_locked_block`), Ephemeral zeroize-then-
release ordering, Queue-fallback error path (unreachable in practice -
`pools.get(node)` is always in range), and identical counter updates.

## Verification

- `cargo test -p qf-memory-pool` - 25/25 (growth tests still cover the
  cfg(test) single-step ops)
- `cargo test -p qf-fec` - 85/85 (pool consumer)
- `cargo clippy -p qf-memory-pool --all-targets` - clean; `cargo fmt` clean
- Omega (aarch64 Linux): qf-memory-pool 25/25 + qf-fec 85/85 native

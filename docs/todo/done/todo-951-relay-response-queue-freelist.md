---
id: TODO-951
title: MASQUE relay response queue: buffer freelist instead of alloc/drop per datagram
status: DONE
created: 2026-09-18
---

# TODO-951 - MASQUE relay response queue: buffer freelist instead of alloc/drop per datagram

## Status
DONE

## Problem
Every upstream UDP response on a MASQUE relay (NextHopUdp) flow paid a fresh
heap allocation: `receive_buffer[..n].to_vec()` on enqueue, then the `Vec` was
dropped after `send_masque_datagram` in `flush_masque_relay_responses`.
Alloc+free per relayed datagram, both directions of the queue's lifetime.

Second pre-existing breakage found while verifying: `cargo test -p
qf-transport-types` could not compile - same missing `rust-tests` feature on
the qf-common dependency that broke qf-stealth (TODO-950).

## Solution
- `MasqueRelayResponseQueue` gains a bounded `spare` buffer list (cap 64).
- `enqueue_slice(flow_id, &[u8])` fills a recycled `Vec` instead of a fresh one
  - the producer's `to_vec` is gone (payload memcpy kept; the queue must own
  the bytes).
- `recycle(Vec<u8>)` returns drained buffers; `flush_masque_relay_responses`
  recycles the payload after every outcome that consumes it (sent, missing
  binding, inactive flow). `DgramQueueFull` re-enqueues the same `Vec`
  unchanged - ordering and ownership semantics preserved.
- `discard_all` drains payloads into the spare list rather than freeing them.
- `masque_relay.rs` upstream path now calls `enqueue_slice` directly on the
  receive buffer - the intermediate `to_vec` is gone too.
- `qf-transport-types/Cargo.toml`: `rust-tests` enabled on qf-common dep (repo
  convention) - repairs the crate's test suite.

## Verification
- `cargo check --workspace --all-targets` clean locally and on Omega.
- `cargo clippy --lib --all-targets` clean; `cargo fmt` clean.
- qf-transport-types **43/43** (was: did not compile), masque 47/47 on Omega.

## Files
- `crates/qf-transport-types/src/masque.rs` - spare list, `enqueue_slice`,
  `recycle`, `discard_all` drain.
- `crates/qf-transport-types/Cargo.toml` - `rust-tests` on qf-common.
- `src/implementations/server/masque_relay.rs` - `enqueue_slice` callsite.
- `src/core/connection.rs` - `MasqueRelayResponse` re-export.
- `src/core/connection/h3_runtime.rs` - recycle in the flush loop.

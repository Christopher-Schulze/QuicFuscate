# TODO-947 - DATAGRAM queues: bounded buffer free-list instead of alloc/free per datagram

## Status
DONE

## Problem
In the default (non-`zero_copy_dgram`) build, every queued DATAGRAM paid a
heap allocation + copy + free:

- `dgram_send`: `buf.to_vec()` per MASQUE/datagram enqueue - hot on the VPN
  dataplane (every downlink IP packet becomes a DATAGRAM).
- `enqueue_received_datagram`: `data.into_owned()` per received DATAGRAM.
- Drained entries (`commit_staged_datagram_frame`, `dgram_recv`) dropped the
  `Vec` back to the allocator.

`zero_copy_dgram` exists and is tested, but stays non-default deliberately:
it parks a 64 KiB global-pool block per queued datagram, and the production
queue bound (`dgram_send_queue_len: 1024`) would pin up to ~64 MiB of blocks
per connection under backpressure - vs ~1.4 KiB per exact-fit `Vec`.

## Solution
Per-connection bounded buffer free-lists for the default build:

- `dgram_send_freelist` / `dgram_recv_freelist` (`Vec<Vec<u8>>`, cap 64).
- Enqueue pops a retained-capacity buffer and `extend_from_slice`s the
  payload - the memcpy stays (unavoidable: the queue must own the bytes)
  but the malloc/free pair per datagram is gone.
- `commit_staged_datagram_frame` and `dgram_recv` return the drained buffer
  to the free-list (cleared) instead of deallocating.
- `dgram_recv_vec` (test helper) still hands ownership to the caller;
  `dgram_purge_outgoing` keeps `retain` (rare path; removed entries just
  deallocate).
- The `zero_copy_dgram` lane is untouched - it already owns pooled blocks.

Adjacent micro-fix in the same sweep: `PooledBlock::pool_ref()` added and
used in `FecPacket::from_pooled_blocks` validation - `Arc::ptr_eq` identity
checks no longer clone an `Arc` per call (one atomic inc/dec less per
generated FEC packet).

## Verification
- `cargo check --all-targets` clean in **both** feature modes
  (default + `zero_copy_dgram`), locally and on Omega.
- `cargo clippy --lib --all-targets` clean; `cargo fmt` applied.
- Transport connection tests: **142/142** default, **145/145**
  `zero_copy_dgram` (local + Omega aarch64); qf-fec **84/84**.

## Files
- `src/transport/connection/state.rs` - free-list fields.
- `src/transport/connection/lifecycle.rs` - init.
- `src/transport/connection/api.rs` - `take`/`return_dgram_freelist`,
  enqueue/recv sites.
- `src/transport/connection/recv.rs` - commit recycle.
- `crates/qf-memory-pool/src/lib.rs` - `pool_ref()`.
- `crates/qf-fec/src/codecs.rs` - `ptr_eq` via `pool_ref()`.

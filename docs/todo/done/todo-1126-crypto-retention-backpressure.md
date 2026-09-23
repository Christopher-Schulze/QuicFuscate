---
id: TODO-1126
title: Preserve reliable CRYPTO ranges at the retention capacity boundary
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1124]
---

# TODO-1126: Replace CRYPTO retention eviction with bounded backpressure

## Why and evidence

`crates/qf-transport-crypto-stream/src/lib.rs::CryptoStream::next_crypto_frame`
drains fresh bytes into `unacked`, then `evict_unacked_overflow` deletes the
oldest unacknowledged ranges whenever retention exceeds 4 MiB. A later
`requeue_crypto` or `requeue_all_unacked` can only find the surviving ranges.
This is a source-level reliable-delivery loss even though the method returns a
successful CRYPTO frame to the packet builder. `send` can also queue an
unbounded buffer before any send. The same leaf type backs the local transport
and the QFTLS provider; both call paths must be checked before selecting a
single capacity policy.

## Target contract

- No unacknowledged CRYPTO byte is deleted solely to stay below a memory
  limit. A new fresh range is admitted only if retained bytes plus that range
  fit the configured finite cap; at the cap, `next_crypto_frame` yields no new
  range or a typed capacity/backpressure result without consuming `send_buf`
  or advancing `send_off`. Retransmissions remain eligible ahead of fresh data.
- Bound the unsent buffer as well, with a cap derived from the maximum legal
  TLS handshake flight and explicit configuration or a validated fixed policy.
  `send` rejects overflow before copying, preserving previously queued data.
  Avoid a retry loop that turns a full retention window into a fatal TLS error.
- ACK of exact ranges releases capacity, after which fresh bytes resume in
  order. Loss and PTO requeue all retained ranges without gaps, including a
  4 MiB boundary crossing and fragmented partial ACKs. Preserve offset and
  arithmetic checks, finite per-connection memory, and the existing provider
  API's typed error behavior.

## Implementation and proof

- [x] Inventory QFTLS and transport calls to `CryptoStream::send`,
      `next_crypto_frame`, `ack_crypto`, and requeue methods; validate the
      existing 4 MiB policy against real ClientHello/ServerHello output and
      full supported-persona handshakes.
- [x] Remove `evict_unacked_overflow` and preflight fresh-range admission
      before drain, offset change or retention insertion. Integrate available
      capacity into the Initial/Handshake transactional staging of TODO-1125
      without a parallel buffer implementation.
- [x] Bound unsent admission and propagate the typed limit through provider
      and transport callers. Keep already-queued bytes and state unchanged on
      rejection.
- [x] Add failable leaf and real transport/provider tests for exact-cap,
      cap-plus-one, partial ACK release, retransmit priority, loss/PTO after
      cap pressure, and queue overflow. Assert byte-exact peer completion and
      finite memory under repeated attempts.
- [x] Run leaf, transport, default/feature library, strict Clippy and format
      gates; update owning architecture and task documentation with counts.

## Acceptance

- No eviction of unacknowledged CRYPTO solely due to memory pressure; every
  accepted byte remains retransmittable until ACK or connection teardown.
- At both send and retention caps, new work is bounded and fail-closed without
  losing existing bytes, changing offsets, spinning or corrupting recovery.
- The exact-cap/loss/ACK/retry tests and required gates pass with evidence.

## Investigation record

- The existing `CryptoStream` limit applies only after fresh data has already
  been marked sent and retained; `evict_unacked_overflow` discards oldest
  unacknowledged ranges. `send` checks only integer overflow, and a zero
  `max_len` can currently create an empty retained range instead of yielding.
- QFTLS and the transport-local path share this leaf type. QFTLS
  `flush_handshake_io` consumes rustls `write_hs` output before queueing it;
  a bounded unsent queue must either retain a temporarily blocked rustls
  output chunk and its associated key change or terminate explicitly on a
  chunk that can never fit. A routine full queue must not lose the chunk.
- The existing 4 MiB retained limit is a suitable initial upper bound for
  each stream. The unsent limit and any one pending rustls output chunk need
  independent finite bounds; normal output can resume after ACK releases
  retained capacity. Native size measurement and tests determine whether the
  same 4 MiB bound is operationally valid for the shipped TLS profiles.
- `MAX_CRYPTO_BUFFERED_BYTES = 4 MiB` now bounds each encryption level's
  unsent bytes and separately its retained unacknowledged bytes. Fresh
  selection clamps to available retention capacity before draining or moving
  offsets. Zero packet budget returns `None` without creating an empty range;
  retransmission remains first in line at the retention cap. The old
  oldest-range eviction is gone.
- QFTLS retains one rustls-produced output chunk and associated `KeyChange`
  while the leaf send queue is full. A later poll transfers both in order;
  repeated blocked polls do not double-count output. An individual output
  chunk larger than 4 MiB returns a persistent `CryptoBufferExceeded` until
  transcript reset, instead of returning to a falsely healthy handshake.
  Transcript replacement clears the pending output and overflow latch.
- Three leaf regressions failed before the fix: oversized unsent input was
  admitted; fresh bytes displaced the oldest unacknowledged range; a zero
  packet budget created an empty retained range. The leaf suite is now `6/6`.
  Further tests cover 32 repeated full-window polls, exact-cap admission,
  partial ACK capacity release, loss/PTO requeue priority, an ACK-resumed
  peer-opened Initial, a held real ClientHello, and a blocked real ServerHello
  whose Handshake key change is installed only after output transfer.
- Default root library: `1,864 passed, 1 ignored`; feature-mode
  (`rust-tests,stream_ring_buffer,zero_copy_dgram`) root library:
  `1,869 passed, 1 ignored`. Strict library Clippy for the leaf and root,
  workspace format check, and diff hygiene pass. The normal real-persona TLS
  handshake regressions pass under both library gates; no native deployment
  or maximum certificate-chain size measurement is claimed. The inherited
  4 MiB limit remains a fixed policy and rejects a single larger output chunk.
- This task bounds send payload ownership. TODO-1127 owns the independent
  receive reassembly amplification; TODO-1128 owns quadratic retransmission
  queue scans and range-count benchmarking; TODO-1125 consumes the send-side
  capacity contract for transactional packet assembly.

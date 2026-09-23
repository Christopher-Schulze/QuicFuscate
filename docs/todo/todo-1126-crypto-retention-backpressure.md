---
id: TODO-1126
title: Preserve reliable CRYPTO ranges at the retention capacity boundary
severity: HIGH
phase: S
priority: P1
status: OPEN
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

- [ ] Inventory QFTLS and transport calls to `CryptoStream::send`,
      `next_crypto_frame`, `ack_crypto`, and requeue methods; measure legitimate
      handshake flight size and pick one documented finite send/retention cap.
- [ ] Remove `evict_unacked_overflow` and preflight fresh-range admission
      before drain, offset change or retention insertion. Integrate available
      capacity into the Initial/Handshake transactional staging of TODO-1125
      without a parallel buffer implementation.
- [ ] Bound unsent admission and propagate the typed limit through provider
      and transport callers. Keep already-queued bytes and state unchanged on
      rejection.
- [ ] Add failable leaf and real transport/provider tests for exact-cap,
      cap-plus-one, partial ACK release, retransmit priority, loss/PTO after
      cap pressure, and queue overflow. Assert byte-exact peer completion and
      finite memory under repeated attempts.
- [ ] Run leaf, transport, default/feature library, strict Clippy and format
      gates; update owning architecture and task documentation with counts.

## Acceptance

- No eviction of unacknowledged CRYPTO solely due to memory pressure; every
  accepted byte remains retransmittable until ACK or connection teardown.
- At both send and retention caps, new work is bounded and fail-closed without
  losing existing bytes, changing offsets, spinning or corrupting recovery.
- The exact-cap/loss/ACK/retry tests and required gates pass with evidence.

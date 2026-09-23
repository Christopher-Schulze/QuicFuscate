---
id: TODO-1122
title: Keep 1-RTT STREAM ownership and FIFO unchanged until seal
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1112]
---

# TODO-1122: Transactional 1-RTT STREAM send ownership

## Why and evidence

`src/transport/connection/recv.rs::maybe_flush_one_writable_stream` is called
while `send_admitted_batch` is still framing. A new STREAM range is copied to
a retained transmission, but `send_off`, `send_buffered_bytes`,
`conn_bytes_sent`, `stats.stream_sent_bytes`, the source send buffer/ring,
and writable-queue membership change before AEAD/HP sealing. Retransmission
splitting also inserts a tail ID before sealing. On abort,
`restore_held_stream_transmissions` pushes held IDs to the queue tail,
irrespective of their original positions. Basic payload retry succeeds,
but exact FIFO, FIN, flow-control and accounting preservation is unproved.
TODO-1112 stages control/ACK/PTO/DATAGRAM and transport-local cover effects;
this task owns the distinct STREAM state boundary for 1-RTT only.

## Target contract

- Build each 1-RTT STREAM frame from an immutable view of its pending bytes
  or retained retransmission. Until successful seal, do not advance stream
  or connection send offsets, remove bytes from `send_buf`/`send_ring`,
  change `send_buffered_bytes`/`conn_bytes_sent`/`stats.stream_sent_bytes`,
  consume FIN, alter retransmission FIFO, or publish a packet-number mapping.
- An eight-packet admitted run skips ranges staged by earlier packets without
  duplicate bytes or a second STREAM implementation. Commit each sealed
  range exactly once in packet order. The single-packet path uses the same
  commit function. Failed buffer, frame, AEAD or HP work leaves the exact
  original queue order and counters; packet numbers remain monotonic.
- Preserve existing stream and connection flow-control limits, bounded
  retained-transmission capacity, `stream_ring_buffer` behavior, early-data
  isolation, loss retransmission and late-ACK retirement. Do not clone the
  complete stream or connection state; hold only per-packet range metadata
  and the payload ownership needed for sealing.

## Implementation and proof

- [ ] Inventory all 1-RTT mutations in `maybe_flush_one_writable_stream`,
      `split_queued_stream_transmission`, `stage_stream_transmission`,
      `unqueue_stream_transmission`, `commit_stream_transmission`, and the
      writable queue. Record exact new-data, retransmit, partial-frame and
      FIN-only paths for default and `stream_ring_buffer` builds.
- [ ] Extend `AdmittedShortHeader` with staged STREAM range/FIN ownership.
      Read queued payload without advancing the source; reserve its range
      across the open batch; commit offsets, source drain, retained ID,
      counters and FIFO position after seal. Abort drops only speculative
      ownership. Keep the existing one-call `seal_batch` fast path.
- [ ] Add paired 1-RTT regressions that fail the pre-change code: second
      output too short and AEAD/HP failure after one new-data frame; mixed
      retransmit plus new data; partial frame and FIN-only frame; eight
      packets and queue-capacity boundary. Before retry, assert byte-for-byte
      send buffers/ring, offsets, FIFO IDs, retained bytes, send statistics
      and flow-control counters equal the pre-attempt values. After retry,
      assert ordered peer bytes/FIN exactly once and late ACK retirement.
- [ ] Run focused default and `stream_ring_buffer` transport tests, the
      root library gate, strict library Clippy and formatting. Keep the
      TODO-1051 batch seal count at one for eight compatible packets.

## Acceptance

- No failed 1-RTT send consumes STREAM bytes, FIN or flow-control credit or
  reports sent STREAM bytes; original retransmission FIFO is unchanged.
- One successful retry delivers each source byte and FIN exactly once; no
  stalled stream, duplicate range, lost retransmission or credit drift.
- Both stream-buffer feature modes and single/batch paths pass the same
  invariants. TODO-1123 separately proves Core outgoing ownership.

## Deviations

- Split from TODO-1112 after the mutation inventory showed STREAM source
  ownership is a separate state machine from control/ACK/PTO obligations.

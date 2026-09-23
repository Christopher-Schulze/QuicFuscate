---
id: TODO-1122
title: Keep 1-RTT and 0-RTT STREAM ownership unchanged until seal
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1112]
---

# TODO-1122: Transactional STREAM send ownership

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
this task owns the distinct STREAM state boundary. The same frame builder is
also called by `send_zero_rtt_packet` before its fallible padding and
`encrypt_and_protect` operations, so its 0-RTT mutation must be closed by the
same staging contract rather than left as a parallel implementation.

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
- The replay-safe 0-RTT branch uses the same non-consuming STREAM selection
  and commits only after its own successful AEAD/HP seal. A failed short
  output buffer or crypto operation preserves the source and original queue
  order. The STREAM wire-length check reserves the AEAD tag, and its minimum
  four-byte frame header also covers the HP sample gap, so no separate
  post-framing buffer failure is reachable through this builder.

## Implementation and proof

- [x] Inventory all 1-RTT mutations in `maybe_flush_one_writable_stream`,
      `split_queued_stream_transmission`, `stage_stream_transmission`,
      `unqueue_stream_transmission`, `commit_stream_transmission`, and the
      writable queue. Record exact new-data, retransmit, partial-frame and
      FIN-only paths for default and `stream_ring_buffer` builds.
- [x] Extend `AdmittedShortHeader` with staged STREAM range/FIN ownership.
      Read queued payload without advancing the source; reserve its range
      across the open batch; commit offsets, source drain, retained ID,
      counters and FIFO position after seal. Abort drops only speculative
      ownership. Keep the existing one-call `seal_batch` fast path.
- [x] Add paired 1-RTT regressions that fail the pre-change code: second
      output too short and AEAD/HP failure after one new-data frame; mixed
      retransmit plus new data; partial frame and FIN-only frame; eight
      packets and queue-capacity boundary. Before retry, assert byte-for-byte
      send buffers/ring, offsets, FIFO IDs, retained bytes, send statistics
      and flow-control counters equal the pre-attempt values. After retry,
      assert ordered peer bytes/FIN exactly once and late ACK retirement.
- [x] Run focused default and `stream_ring_buffer` transport tests, the
      root library gate, strict library Clippy and formatting. Keep the
      TODO-1051 batch seal count at one for eight compatible packets.
- [x] Exercise the shared 0-RTT frame builder with a short output buffer and
      failed HP seal after AEAD, followed by a successful replay-safe retry.
      Assert no pre-seal source, FIN, counter or queue mutation.

## Acceptance

- No failed 1-RTT send consumes STREAM bytes, FIN or flow-control credit or
  reports sent STREAM bytes; original retransmission FIFO is unchanged.
- One successful retry delivers each source byte and FIN exactly once; no
  stalled stream, duplicate range, lost retransmission or credit drift.
- Both stream-buffer feature modes and single/batch paths pass the same
  invariants. The shared 0-RTT branch passes the same rollback invariant.
  TODO-1123 separately proves Core outgoing ownership.

## Investigation record

- A real paired 1-RTT test asserts that a failed second output leaves
  STREAM send bytes, offsets, buffered bytes and both source queues unchanged.
  Before the fix it fails with `stream_sent_bytes=28` versus `0`, although
  `send_admitted_batch` returns `BufferTooShort` and gives no packet to its
  caller. This was the pre-fix red regression.
- The pre-fix new-data path drained `send_buf` or advanced `send_ring`, moved
  `send_off`, `send_buffered_bytes`, `conn_bytes_sent` and
  `stats.stream_sent_bytes`, then inserts a retained transmission before
  sealing. Retransmission splitting changes the original transmission,
  inserts a tail, updates lost-packet references and the retransmit FIFO.
  Abort appended held IDs at the queue tail. The replacement selects ranges
  from an immutable source view across the open batch and commits after seal.
- The implementation now stages one immutable fresh or retained STREAM range
  per packet. Earlier unsealed batch frames advance only speculative cursors;
  preflight checks source offsets, FIN, ledger capacity and transmission IDs
  before seal. Commit applies accepted ranges in packet order, including
  retained splits and packet-number ownership. This removes the abort-time
  retransmission requeue, which previously changed FIFO order.
- Review found that an emptied non-FIN stream must leave the writable queue
  after successful seal. Otherwise stale queue entries accumulate until the
  application appends more data. The commit now removes empty entries; a
  later `stream_send` re-enqueues the stream. A paired test covers both sends.
- Final local proof: default root library 1,856 passed (one existing ignored);
  `stream_ring_buffer,zero_copy_dgram` connection tests 177/177; strict
  library Clippy and formatting passed. The paired tests cover failed second
  output, missing 1-RTT AEAD and failed HP after sealing, mixed retained/new/
  FIN-only runs, split retransmission, eight STREAM packets under one
  `seal_batch`, retained-entry capacity and late-ACK release, ring wraparound,
  and failed/retried replay-safe 0-RTT HP. Peer output is read after retry.
- A separate no-key success branch in the public packet-encryption primitive
  remains outside this STREAM ownership change and is tracked by TODO-1124.

## Deviations

- Split from TODO-1112 after the mutation inventory showed STREAM source
  ownership is a separate state machine from control/ACK/PTO obligations.

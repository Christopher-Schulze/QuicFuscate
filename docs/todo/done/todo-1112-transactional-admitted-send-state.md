---
id: TODO-1112
title: Commit 1-RTT control and ACK state only after packet sealing
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
completed: 2026-09-23
depends_on: [TODO-1051]
---

# TODO-1112: Transactional admitted-send state

## Why and evidence

`src/transport/connection/send.rs::send_admitted_batch` calls
`send_with_datagram_overhead` repeatedly with `admitted_batch_defer=true`.
Before this change, the framing phase popped control frames, committed
Application ACK state and observer side effects, and removed a pending PTO
probe. The deferred packet had not yet passed
`seal_prepared_short_headers`. On a later framing or sealing error,
`abort_admitted_batch` restores held stream transmissions and resets batch
counters but never restores control, ACK, or PTO state. The caller receives
an error and no sealed packet. The normal production path reaches this
builder through `src/core/connection/send.rs::produce_admitted_batch` for
multi-DATAGRAM bursts; equal-size successful packets are covered by a test,
but a failed second frame or failed seal is not.

The same control/ACK commit-before-seal ordering exists in the ordinary
single-packet path; this task must address that shared ownership boundary
without making two parallel send implementations. TODO-1104 owns final
emitted-wire cover/trace reconciliation, separate from this transport-local
seal boundary.

## Target contract

- Framing is speculative: no queued control frame, ACK obligation, PTO
  probe, or observer/telemetry effect is consumed until its packet is
  sealed. A failed frame, buffer check, HP/AEAD seal, or batch preflight
  leaves each obligation eligible for exactly one later send. Packet
  numbers may be skipped after an attempted seal, but must never be reused.
- Both single-packet and admitted-batch sends use the same stage/commit
  contract. A successfully sealed packet is committed once; a failed
  packet restores control and ACK/probe state without duplicating DATAGRAM
  payloads. Terminal close priority and congestion-bypass rules remain
  intact. TODO-1122 owns exact STREAM/FIFO/counter rollback.
- PMTU, chaff and padding budget effects follow the successful transport
  seal; no speculative debit or phantom send timestamp survives a transport
  rollback. TODO-1104 owns the final wire-emission and trace-phase boundary;
  TODO-1123 owns the Core outgoing-queue handoff. Avoid a full connection
  clone or a second transport state machine.

## Implementation and proof

- [x] Trace every mutation between `send_with_datagram_overhead` framing
      and `seal_prepared_short_headers`, including `pending_control`,
      `pkt_spaces[2]`, `pending_probe_spaces`, stream and DATAGRAM queues,
      PMTU, observer callbacks and the ledger. Record which effects are
      reversible and which must be deferred until commitment.
- [x] Extend the existing `AdmittedShortHeader`/send result with the minimal
      staged effect metadata. Peek or skip queued controls/ACKs/probes while
      framing multiple packets, then commit after sealing. Use one commit
      path for batch and single sends; keep per-packet accounting exact.
- [x] Add real transport tests: first deferred packet contains an ACK,
      control frame and PTO probe, then a second too-small output fails;
      separately force a seal error after framing. In both cases assert no
      output ownership, obligations preserved, and the next valid send
      emits each once. Cover a successful eight-packet batch and a
      single-packet seal failure to prevent divergent behavior. Include
      PMTU rollback, staged wire budget, and one due chaff slot per batch.
- [x] Run focused transport tests, root library tests and the TODO-1051
      batch/peer-open gate. TODO-1071 owns the release-profile seal-batch
      performance comparison on representative hardware.

## Acceptance

- Every described transport failure returns no packet and preserves all
  unsent control/ACK/probe obligations; a subsequent valid send emits and
  the peer opens them exactly once. No duplicate DATAGRAM payload.
- Successful admitted runs still use one `seal_batch` for eight compatible
  packets, and the single-packet path shares the same commit semantics.
- No failed transport seal debits the ledger, advances the PMTU probe, or
  consumes the due chaff slot. TODO-1104/1123 verify actual wire-queue
  admission separately.

## Investigation record

- A real paired 1-RTT regression in
  `src/transport/connection/tests/flow_and_packet.rs` frames a first packet
  containing MAX_DATA, an Application ACK, a PTO PING, and a DATAGRAM; a
  one-byte second output makes `send_admitted_batch` return
  `BufferTooShort`. Against the original code, the first assertion failed:
  MAX_DATA had already been removed despite zero sealed output. The staged
  transport change makes the batch retry pass with two peer-opened DATAGRAMs
  and one delivered STREAM payload.
- The original speculative 1-RTT path also marked PMTU probes sent,
  consumed `pad_short_header_to`, debited the ledger for chaff/pad and noted
  wire sends before batch sealing. These effects now commit after seal.
  Packet numbers still advance monotonically during an attempted seal.
  STREAM source/counter and retransmission FIFO effects remain TODO-1122.
- `account_admitted_short_header` no longer has a fallible DATAGRAM pop
  after a committed prefix: queue capacity and staged indices are checked
  before one effect commit, then packet accounting is infallible. Core's
  `finish_produced_packet` can still fail after transport commitment and
  before `outgoing_fec_packets` owns the packet; TODO-1123 owns this separate
  cross-layer boundary.
- STREAM source draining, send counters and retransmission queue positions
  are still mutated before seal. Retained transmissions make payloads
  retryable, but exact FIFO and no phantom accounting require TODO-1122.
- The original work expanded beyond one transaction boundary. The split
  keeps this task on control/ACK/PTO/DATAGRAM and transport-local budget/
  PMTU/chaff staging. TODO-1122 owns STREAM state; TODO-1123 owns Core
  acceptance; TODO-1104 owns final trace/budget wire evidence.

## Verification

- Default transport connection tests: 166 passed; paired 1-RTT tests cover
  failed second output, failed AEAD/HP seal, successful peer-opened retry,
  eight-packet one-call seal, PMTU probe rollback and one due chaff slot.
- `zero_copy_dgram` plus `stream_ring_buffer` transport connection tests:
  169 passed. Full root library: 1,848 passed, one pre-existing ignored.
  `qf-stealth`: 145 passed. Strict library Clippy and formatting passed.
- The first full library run found an unrelated invalid test assumption in
  `recv_datagram_batch_tests`: loopback send completion does not guarantee
  all datagrams are already available in one nonblocking receive batch.
  The corrected test drains every ordered datagram within two seconds and
  checks slot reuse on each batch; its focused run and the repeated full
  library run passed. Production UDP receive logic was unchanged.
- TODO-1071 owns release-profile seal-batch throughput measurement. This
  task proves the one-call eight-packet seal shape, not a measured speedup.

## Deviations

- The original target included STREAM rollback and Core outgoing queue
  admission. Their independent mutation owners made that one task more than
  twice the planned boundary; TODO-1122/1123 retain exact acceptance and
  dependency contracts. No cross-layer completion is claimed here.

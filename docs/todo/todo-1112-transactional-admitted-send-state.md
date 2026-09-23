---
id: TODO-1112
title: Commit 1-RTT control and ACK state only after packet sealing
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1051]
---

# TODO-1112: Transactional admitted-send state

## Why and evidence

`src/transport/connection/send.rs::send_admitted_batch` calls
`send_with_datagram_overhead` repeatedly with `admitted_batch_defer=true`.
During this framing phase,
`src/transport/connection/recv.rs::flush_pending_control_frames` pops
control frames, `maybe_emit_application_ack_frame` commits Application ACK
state and observer side effects, and the send path removes a pending PTO
probe. The deferred packet has not yet passed
`seal_prepared_short_headers`. On a later framing or sealing error,
`abort_admitted_batch` restores held stream transmissions and resets batch
counters but never restores control, ACK, or PTO state. The caller receives
an error and no sealed packet. The normal production path reaches this
builder through `src/core/connection/send.rs::produce_admitted_batch` for
multi-DATAGRAM bursts; equal-size successful packets are covered by a test,
but a failed second frame or failed seal is not.

The same control/ACK commit-before-seal ordering exists in the ordinary
single-packet path; this task must address that shared ownership boundary
without making two parallel send implementations. TODO-1104 owns the
associated cover/trace ledger commit and is a coordinated dependency, not
a duplicate control-state task.

## Target contract

- Framing is speculative: no queued control frame, ACK obligation, PTO
  probe, or observer/telemetry effect is consumed until its sealed packet
  has been accepted by the caller's outgoing ownership path. A failed
  frame, buffer check, HP/AEAD seal, or batch accounting step leaves each
  obligation eligible for exactly one later send. Packet numbers may be
  skipped after an attempted seal, but must never be reused.
- Both single-packet and admitted-batch sends use the same stage/commit
  contract. A successfully sealed packet is committed once; a failed
  packet restores the exact FIFO/control and ACK/probe state without
  duplicating stream transmissions or DATAGRAM payloads. Terminal close
  priority and congestion-bypass rules remain intact.
- Wire cover, trace phase, PMTU and budget side effects follow TODO-1104's
  actual-emission boundary; no speculative debit or phantom send timestamp
  survives rollback. Avoid a full connection clone or a second transport
  state machine: stage only the small set of effects each packet owns.

## Implementation and proof

- [ ] Trace every mutation between `send_with_datagram_overhead` framing
      and `seal_prepared_short_headers`, including `pending_control`,
      `pkt_spaces[2]`, `pending_probe_spaces`, stream and DATAGRAM queues,
      PMTU, observer callbacks and the ledger. Record which effects are
      reversible and which must be deferred until commitment.
- [ ] Extend the existing `AdmittedShortHeader`/send result with the minimal
      staged effect metadata. Peek or skip queued controls/ACKs/probes while
      framing multiple packets, then commit only after each sealed output
      is handed to the caller. Use one commit path for batch and single
      sends; keep per-packet accounting exact.
- [ ] Add real transport tests: first deferred packet contains an ACK,
      control frame and PTO probe, then a second too-small output fails;
      separately force a seal error after framing. In both cases assert no
      output ownership, obligations preserved, and the next valid send
      emits each once. Cover a successful eight-packet batch and a
      single-packet seal failure to prevent divergent behavior.
- [ ] Run focused transport tests, root library tests and the TODO-1051
      batch/peer-open gate; remeasure its TODO-1071 seal-batch cell to prove
      the staging change does not erase the admitted-run benefit.

## Acceptance

- Every described failure returns no packet and preserves all unsent
  control/ACK/probe obligations; a subsequent valid send emits and the
  peer opens them exactly once. No duplicate DATAGRAM or stream payload.
- Successful admitted runs still use one `seal_batch` for eight compatible
  packets, and the single-packet path shares the same commit semantics.
- TODO-1104 verifies that the ledger and trace observe only outputs actually
  admitted to the wire queue.

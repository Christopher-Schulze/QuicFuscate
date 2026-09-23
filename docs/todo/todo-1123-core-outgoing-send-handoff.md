---
id: TODO-1123
title: Make sealed transport packets safe through Core outgoing admission
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1112, TODO-1122]
---

# TODO-1123: Core outgoing ownership after transport seal

## Why and evidence

`src/core/connection/send.rs::produce_admitted_batch` receives committed,
sealed 1-RTT packets and then calls `finish_produced_packet` for each. That
function can still return an error before `outgoing_fec_packets` owns the
systematic packet: framing-headroom bounds, `u16` length conversion,
`FecPacket::from_pooled_blocks`, repair ordinal/`write_symbol`,
`dgram_send_parts`, and QuicFrame `FecPacket::from_block` are fallible.
`produce_one_queued` and the direct raw send path have the same commitment
gap. An error on batch member N can also leave members 1..N-1 queued while
the API reports no produced batch. TODO-1112 closes only the transport-local
seal transaction; TODO-1122 closes pre-seal STREAM ownership.

## Target contract

- A sealed transport datagram is either owned by an outgoing Core queue or
  remains available to a later send with its control, STREAM and DATAGRAM
  obligations intact. No Core error may discard a committed systematic
  packet or leave a committed batch prefix invisible to its caller.
- Choose one boundary after proving the actual costs: either return an
  owned, uncommitted transport send token that Core commits after queue
  admission, or preflight all Core capacity/format constraints and make the
  post-seal materialization path infallible. Do not clone the connection,
  duplicate the transport pipeline, or silently downgrade a required FEC
  profile to raw output.
- Treat systematic output as mandatory and repairs as optional only under
  the established FEC policy. Repair rejection must never lose the source,
  debit an unqueued repair, or leave a partial repair side effect. Preserve
  exact `SendInfo.from/to`, path-control precedence, bulk bypass, packet
  sequence, paired-reorder bounds, Maybenot events, and TODO-1098's actual
  wire-byte budget contract.

## Implementation and proof

- [ ] Enumerate every `Result`/early return in `produce_admitted_batch`,
      `produce_one_queued`, `finish_produced_packet`, `send_with_info_raw`,
      `OutgoingFecPacket::write_to`, the FEC constructors and repair queue
      admission. Mark which operations can be proven by preflight and which
      require a commit/abort token; inspect actual API signatures first.
- [ ] Establish one ownership boundary shared by raw, framed, QuicFrame,
      single-packet and eight-packet admitted sends. Reserve destination
      blocks/queue capacity and validate profile, headroom, symbol sizes and
      packet lengths before transport commitment, or carry staged transport
      effects in an owned token. Do not mutate FEC encoder/window state
      before a failure can no longer strand the systematic packet.
- [ ] Stage all Core-produced queue entries locally and publish the whole
      admitted run only when every mandatory member can be retained. Handle
      optional repair failures with an explicit drop/error metric and exact
      ledger reconciliation; never return a generic error after a source
      packet has been committed to outgoing ownership.
- [ ] Exercise real source/repair paths under Zero, raw framed, and
      in-QUIC FEC; induce too-small headroom, queue-full repair admission,
      invalid/oversized symbol and batch-member failure through genuine
      interfaces. Check no source loss, no duplicate peer delivery, no
      invisible committed prefix, exact queue order, budget and telemetry.
      Include path-control and bulk-only bypass and direct raw emission.
- [ ] Run focused Core/transport/FEC tests, root library tests, strict
      Clippy and formatting, then a real client/server TUN packet pump with
      capture that reconciles produced, queued and emitted packet counts.

## Acceptance

- All mandatory systematic packets accepted by transport reach Core
  outgoing ownership exactly once, including every member of an admitted
  batch. Any failure before ownership leaves send obligations retryable.
- No Core error after transport commitment discards a source or reports an
  unreturned batch prefix; optional repair denial is observable and does
  not debit bytes that were never queued.
- Raw and both FEC framing modes preserve payload, routing and wire-budget
  semantics under the real peer/TUN proof.

## Deviations

- Split from TODO-1112 because Core owns FEC materialization and output
  queueing after transport seal; transport-local control staging alone
  cannot establish this cross-layer ownership guarantee.

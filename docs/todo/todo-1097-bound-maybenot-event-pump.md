---
id: TODO-1097
title: Bound Maybenot event and padding work
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1061]
---

# TODO-1097: Bound Maybenot event and padding work

## Why and evidence

`src/core/connection/maybenot.rs::pump` processes its `event_queue` until
empty, with no iteration or time budget. `apply_action(UpdateTimer)` queues
`TimerBegin` whenever `replace=true`, even when `now + duration` equals the
existing deadline. The pinned Maybenot 2.2.2 framework schedules an action
on a state self-transition; its `Machine::validate` checks state validity but
does not prohibit timer feedback cycles. A machine with a `TimerBegin` self
transition to `UpdateTimer(replace=true)` can therefore keep the same-time
event chain alive indefinitely. This is a code-level reachability finding;
the exact serialized reproducer and observed stop behavior still need a
bounded test. `pending_pad` and the core `maybenot_tick` drain are also
unbounded, so rapid valid events during an outgoing block can retain an
unbounded number of pad actions before they are charged to the wire budget.
The operator must opt in to a machine; stock presets load none.
The upstream `TriggerEvent` contract requires `TunnelRecv` before decrypt,
then `NormalRecv` only for a non-padding packet or `PaddingRecv` for padding;
`TunnelSent` is to follow the actual network write. The adapter's
`note_wire_recv` always emits `TunnelRecv` plus `NormalRecv` only after
`conn.recv` succeeds (`src/core/connection.rs::deliver_wire_payload`), even
for padding-only packets, and omits failed-decrypt receives. Core
`send_with_info` calls `note_wire_emit` before its caller attempts the socket
write. Machines that use these event classes therefore see a different
sequence/timing than the Maybenot contract.

## Target contract

- Queue `TimerBegin` only when a timer is newly created or its deadline
  actually changes. Preserve Maybenot `replace` semantics for a genuinely
  changed deadline; do not produce an event from an idempotent update.
- Give each external event/tick a finite work budget independent of machine
  content. A saturated cycle exits with a typed machine-fault outcome,
  disables or quarantines that connection's defense cleanly, and records a
  bounded diagnostic. The QUIC send/recv loop, pure ACKs, PTO and teardown
  continue. No silent infinite spin or event loss counted as success.
- Bound `event_queue`, action timers and `pending_pad` per connection in
  relation to the configured machine and current wire-budget window. Expire
  or coalesce excess pads according to an explicit, tested policy; never
  spend beyond the shared ledger. Use checked deadline arithmetic for any
  sampled duration that can reach `Instant` addition.
- Keep one Maybenot runtime and one shared wire budget. Do not add another
  shaping scheduler or an always-on framework for stock personas.
- Emit `TunnelRecv` at complete underlay-datagram receipt before decrypt,
  then exactly one of `NormalRecv` or `PaddingRecv` after packet-content
  classification. Emit `NormalSent`/`PaddingSent` when the packet is queued
  and `TunnelSent` at the closest owned point to a successful socket write.
  If the core cannot observe a kernel write, make its adapter return an
  emission event to the existing IO owner rather than pretending that
  `send_with_info` completed the write. Do not classify FEC/GSO aggregates
  as a single normal packet without first defining the wire-unit mapping.

## Implementation and proof

- [ ] Confirm the exact `Framework::trigger_events`, `Machine::validate`,
      `UpdateTimer` and self-transition signatures/behavior in pinned
      maybenot 2.2.2. Construct and serialize a valid `TimerBegin` feedback
      machine plus a high-rate padding machine in focused tests.
- [ ] Reproduce the current same-deadline feedback under a bounded test
      harness; use an external watchdog so the pre-fix test cannot hang the
      suite indefinitely. Record the precise transition trace.
- [ ] Fix unchanged-deadline detection and impose a per-pump work cap with
      explicit fault handling. Audit `tick`, `next_deadline`, and core
      `maybenot_tick` for the same feedback pattern and queue growth.
- [ ] Test normal timer replace/nonreplace, self-transition, zero-duration,
      high-rate padding during a block, budget rejection, malformed machine,
      PTO/pure-ACK progress, and cleanup. Run qf-core focused and relevant
      rust-tests plus the Maybenot simulator; measure overhead under benign
      machines so the cap does not truncate ordinary behavior.
- [ ] Trace the complete underlay send/receive call chain and run a local
      socket test that checks event sequence for a normal packet, padding-only
      packet, rejected ciphertext, failed socket send, and a GSO/GRO batch.
      Compare each trace with the pinned Maybenot event contract.
- [ ] Reconcile TODO-1061 and product docs with the actual bounded runtime
      contract and state that machines are opt-in.

## Acceptance

- Every accepted machine causes finite work and bounded retained state per
  external event/tick; the deterministic feedback reproducer exits through
  the typed fault path without hanging a send or receive call.
- Benign machines preserve their expected padding/blocking actions, with
  zero ledger overspend. ACK/PTO progress and connection teardown complete
  after the machine fault.
- The fault path is observable and does not claim a defense is active after
  it has been disabled.
- Each observed Maybenot event has the documented packet class and lifecycle
  timing; failed writes never count as `TunnelSent` and padding-only ingress
  never counts as `NormalRecv`.

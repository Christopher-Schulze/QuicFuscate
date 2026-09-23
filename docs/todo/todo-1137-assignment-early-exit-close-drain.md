---
id: TODO-1137
title: Reconcile queued QUIC closes on other assignment exits
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1134, TODO-1117, TODO-1135]
---

# TODO-1137: Reconcile queued closes on assignment early returns

## Why and evidence

`IoDriver::negotiate_assignment` now drains a physical-hop close after its
receive match. Several other paths still return early: the initial
`flush_outbound`, control-plane rejection, authenticated assignment finalization,
`begin_masque_control_tunnel`, and `poll_http3` errors. In particular,
`ClientDataPlane::poll_http3` first runs `drive()` and then Core H3 polling;
either can fail before the post-receive terminal check. It is not yet proven
which of these exits can leave a newly queued protected QUIC close. A socket
send failure cannot be repaired by another send on the same failed socket.

## Target contract

- Classify every assignment early return by whether a local or remote hop can
  be terminal with a pending close. Preserve the original error and do not
  attempt a second send after an already failed UDP send.
- For each physical-hop exit with a deliverable queued local close, reuse
  TODO-1134's bounded direct close drain before teardown. For a nested hop,
  use the authenticated relay path owned by TODO-1135 only when its preceding
  links are usable. Never flush unrelated application or cover traffic.
- If source inspection and focused tests prove an exit cannot queue a close,
  record that proof rather than adding a speculative branch.

## Source-verified exit inventory

| Exit | Current owner and effect | Close decision to prove |
| --- | --- | --- |
| Pre-receive `flush_outbound` | `ClientDataPlane::send` calls `CircuitRuntime::drive` before physical `send`; `drive` can fail during H3 polling, nested ingress, link activation, or inner output. Socket/sendmmsg failure occurs after packet serialization. | Inspect the first terminal hop and pending-close ownership before any retry. Never issue a second send on a failed socket. A nested close requires TODO-1135's authenticated relay. |
| `AssignmentReception::failure` | The capsule callback stores a control-plane rejection; the loop currently marks the data plane failed and returns after its next outbound flush. | A rejected assignment alone is not proof of a QUIC close. Test whether the same received packet also queued a transport/H3 close; drain only that already queued close. |
| `finalize_authenticated_assignment` | `CircuitRuntime` marks QKey transcript authentication on active hops, then calls `private_packet_protection_control_tick` on each. Its errors include private-negotiation and capsule-send failures. | Distinguish a local policy error from a transport already closed with a serializable close; identify the hop before draining. Do not fabricate a QUIC code from a textual `EngineError`. |
| `begin_masque_control_tunnel` | Core initializes H3 and creates the required CONNECT-UDP control stream; an error returns before the receive branch. | Verify whether H3/transport queued a close. Ordinary setup or backpressure failure has no implicit close and must retain its original error. |
| Post-receive `poll_http3` | `CircuitRuntime::poll_http3` runs `drive` and Core H3 polling. H3 `Connection::poll` can queue an application close for `IdError` or `StreamCreationError`, then return an error. Other peer H3 classes remain TODO-1117. | Once TODO-1117 maps all fatal H3 classes, dispatch the physical close directly or the nested close through TODO-1135. Preserve the H3 code and original cause; do not route cover or application data after terminal selection. |
| UDP receive error or deadline | A socket error returns immediately; the wait deadline returns timeout. Neither calls QUIC frame admission. | Do not send on an already failed socket or invent a protocol close. Only a separately observed, already queued close can justify a terminal drain. |

This matrix is a planning inventory, not completed wire proof. TODO-1117 and
TODO-1135 must establish H3 close coding and nested relay before this task can
claim every early exit is reconciled.

## Implementation and proof

- [x] Trace return sites in `negotiate_assignment` and signatures/side effects
      of `flush_outbound`, `AssignmentReception`,
      `finalize_authenticated_assignment`, `begin_masque_control_tunnel`,
      `ClientDataPlane::drive`, and Core H3 polling. Build the source-grounded
      exit/cause inventory above before editing code; confirm each queued-close
      outcome with focused tests during implementation.
- [ ] Add only the missing drain calls or error routing justified by that
      matrix, preserving one close attempt, 500 ms socket-send cap, original
      cause, and TODO-1135's nested-link preconditions.
- [ ] Exercise each newly reachable close exit through real Core and socket
      behavior. Assert one peer-opened close or an exact undeliverable outcome,
      and no second send on socket failure.
- [ ] Run focused assignment/H3 tests, default and feature root tests, strict
      library Clippy, formatting, and diff hygiene.

## Acceptance

- Every assignment early exit with a deliverable queued QUIC close has one
  bounded terminal path; exits unable to queue a close are documented with
  source and test evidence. Existing assignment behavior and gates pass.

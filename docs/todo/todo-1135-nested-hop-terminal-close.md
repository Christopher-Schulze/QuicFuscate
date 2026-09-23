---
id: TODO-1135
title: Carry a nested-hop terminal close through the circuit without cover leakage
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1134]
---

# TODO-1135: Deliver nested-hop closes through authenticated MASQUE links

## Why and evidence

`ClientDataPlane::is_closed()` becomes true when any hop closes. During
assignment, `negotiate_assignment` returns on that state before the next
outbound flush. `CircuitRuntime::send_physical` runs `drive()` first; its
`flush_inner_outbound` drains all deeper hops and pending inner egress in
reverse order. An inner close can therefore be stranded by an earlier drive
error, a missing/unconfirmed CONNECT-UDP link, full DATAGRAM queue, or unrelated
queued application output. Reusing the physical-hop drain from TODO-1134
would not prove that the inner peer sees its protected close.

## Target contract

- Identify the first terminal hop and retain its original typed local or
  remote cause. If its preceding CONNECT-UDP chain is authenticated, seal
  one close at that hop and carry the resulting datagram outward one link at
  a time to the physical UDP socket. Do not inject new application or cover
  payload into the terminal drain. Honor each link's flow ID, MTU, queue
  capacity, and packet-protection owner.
- If a required link is unavailable, the close cannot be delivered. Record
  that exact undeliverable outcome and terminate assignment without claiming
  a peer-visible close. A full queue or socket failure similarly reports
  the failed stage; avoid indefinite retries, duplicate closes and partial
  replay on the next circuit generation.
- Keep nonterminal packet production and normal multi-hop assignment
  unchanged. Reuse the existing `QuicFuscateConnection::send` and MASQUE
  carrier operations; one terminal policy owner should select the drain
  across both physical and nested hops.

## Implementation and proof

- [ ] Map `CircuitRuntime::drive`, `flush_inner_outbound`, pending inner
      egress, link establishment, `send_next_hop_masque_datagram`, physical
      output, and all assignment teardown paths. Define a bounded terminal
      drain budget and explicit outcome for every failing stage before edits.
- [ ] Implement the smallest shared terminal close owner, preserving
      TODO-1134's direct physical path while adding nested relay only when
      each required link is usable. Do not flush unrelated queued payloads
      merely to make a close appear successful.
- [ ] Run a real two-hop and three-hop UDP/CONNECT-UDP test: peer opens the
      exact nested QUIC close once, no cover or application datagram follows
      terminal decision, and no close is claimed for an unavailable link or
      failed socket send. Test queue pressure and a duplicate receive.
- [ ] Run focused circuit/client, default and feature root tests, strict
      Clippy and formatting. Record native wire and deployment limits.

## Acceptance

- A deliverable inner close reaches the intended remote hop exactly once
  through the authenticated carrier chain, while an undeliverable close is
  reported precisely. Normal circuit behavior and all required gates pass.

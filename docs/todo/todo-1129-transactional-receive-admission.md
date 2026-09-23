---
id: TODO-1129
title: Commit QUIC receive state only after stateful frame admission
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1127]
---

# TODO-1129: Make packet-number and frame effects atomic on receive

## Why and evidence

`src/transport/connection/recv.rs` performs stateless frame syntax preflight
around line 305 and calls `pkt_spaces[space_idx].on_packet_recv` around line
371 before dispatching frames. A CRYPTO frame reaches the stateful
`Connection::process_crypto_frame` around line 685; its bounded reassembly can
reject an authenticated but out-of-window or conflicting range after the
packet number was recorded. TLS-provider rejection after CRYPTO drain and
other fallible frame handlers after the same boundary require an inventory.
A rejected packet can therefore change
duplicate-detection, ACK, key, recovery or earlier-frame state despite the
receive call returning an error. TODO-1127 fixes the CRYPTO buffer itself;
it does not make a whole packet transactional.

## Target contract

- Every frame in an authenticated packet passes the stateful admission rules
  needed to avoid later expected validation errors before packet-number and
  frame-owned state is committed. A rejected packet changes no packet-number,
  ACK, recovery, TLS, stream, control, replay or connection state beyond
  explicitly documented rejection telemetry.
- Preserve QUIC duplicate/replay semantics and private-key epoch commits.
  Packet number is marked received once only after the packet is accepted;
  accepted multi-frame packets apply effects exactly once in wire order.
- Keep preflight bounded by packet size and encryption level. Do not clone
  whole connections, invoke TLS twice, or create a second frame parser with
  divergent semantics. Share parsed frame metadata or stage irreversible
  effects behind one commit boundary.

## Implementation and proof

- [ ] Inventory every `?`, early return and state mutation between frame
      preflight and final receive accounting in `recv.rs`, including CRYPTO,
      TLS-provider, STREAM, ACK, RESET_STREAM, CID, PATH and close frames.
      Identify which checks are pure and which effects require staging.
- [ ] Define and implement one per-packet admission/commit contract with
      bounded metadata. Connect TODO-1127 CRYPTO window/overlap validation
      before `on_packet_recv`, then stage or preflight the other fallible
      handlers without duplicating parser rules.
- [ ] Add failable tests for a valid leading frame followed by rejected
      CRYPTO, conflicting overlap, stream limit, malformed control and mixed
      packet-space frames. Assert exact PN/ACK/recovery/TLS/queue snapshots
      after rejection and one peer-visible effect after valid retry.
- [ ] Run default/feature library tests, targeted integration, strict Clippy,
      formatting and relevant native wire gates; document exact evidence.

## Acceptance

- No stateful rejection after stateless frame preflight leaves the rejected
  packet's PN or any earlier frame effect committed.
- Duplicate detection and recovery are unchanged for accepted packets; tests
  prove exact failure atomicity and successful single application.
- Required gates pass with counts and native limits recorded.

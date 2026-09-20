---
id: TODO-1015
title: ChameleonFlow-style bounded reorder window for bulk datagrams
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-20
depends_on: [TODO-1011]
---

# TODO-1015: Bounded reorder window on bulk datagrams

## Objective
Full ChameleonFlow (MLCIPR 2025) variant: instead of buying chaff bytes,
redistribute real packets across a small time window to destroy train
structure (burst lengths, direction alternation) that WF classifiers
extract. Reported literature numbers: WF accuracy 96.3% -> 35.8% at 8.7%
bandwidth / 11.2% latency overhead - far cheaper than padding defenses.

Density rule half already landed (padding rate halves under dense
ACK-clocked traffic). This TODO is the reorder-window remainder, scoped
by the design study in
`docs/todo/todo-1010-stealth-shaping-research-track.md`.

## Implementation plan

1. Window placement: in the send drain after packet compose
   (`src/transport/connection/send.rs` -> `src/core/connection/send.rs`).
   Packet numbers are allocated at compose time, so reordering composed
   packets is wire-legal (send order need not equal PN order).
2. Eligibility: only `DatagramClass::Bulk` entries (TODO-1011) enter the
   window - their inner protocol (TCP) tolerates reorder/delay. ACK,
   control, handshake, and `Protected` datagrams always bypass.
3. Mechanics: bounded delay queue (W ~ 5-15 ms max hold, k ~ 8 packets
   max depth). Flush triggers: window expiry, depth reached, or any
   bypass-class packet emitting (flush first to keep relative order of
   protected traffic). Emission order within a flush: seed-permuted
   (per-connection seed, NOT deployment seed - see TODO-1014 boundary).
4. Interactions to verify: io_uring multishot drain and the sendmmsg
   batch tail must not just move the burst signature one layer down -
   flush should ride the normal batch emit, not a separate syscall path.
5. Success metric: train-structure entropy gain at <= 2 ms median added
   latency on bulk packets; zero added latency on protected classes;
   bandwidth overhead ~0 (no new bytes).

## Risks
- Holding bulk packets interacts with inner-TCP RTT estimation; cap the
  hold below typical tunnel RTT contribution and never hold retransmits
  (inner TCP already numbers them - reordering adds nothing).
- A fixed window size is itself a signal; W should jitter per flush
  (reuse the per-connection seed).

## Acceptance
- Window only delays Bulk-classified traffic (asserted by unit test
  feeding mixed-class entries).
- Omega e2e: bulk TCP throughput within noise of baseline; protected
  ping RTT unchanged; wire capture shows reordered PN sequences on bulk
  bursts.

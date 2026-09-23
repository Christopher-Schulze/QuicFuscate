---
id: TODO-1128
title: Remove quadratic CRYPTO retransmission queue scans
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1126]
---

# TODO-1128: Keep CRYPTO retransmission offsets ordered without linear dedup scans

## Why and evidence

`crates/qf-transport-crypto-stream/src/lib.rs::requeue_all_unacked` walks every
retained CRYPTO range and calls `VecDeque::contains` before each insert, then
sorts offsets already ordered by `BTreeMap`. `requeue_crypto` likewise scans
the entire retransmission queue for each overlapping range, copies it into a
Vec and sorts after insertion. A PTO or broad loss batch with `n` retained
ranges therefore costs quadratic comparisons even though the wire byte
retention is bounded by TODO-1126. Small CRYPTO packet budgets and partial
ACKs can produce many ranges under that byte cap. This is a source-level
complexity finding; no native performance regression has yet been measured.

## Target contract

- Retransmission membership and ordered extraction cost at most `O(log n)`
  per distinct offset. Requeueing all `n` retained ranges costs `O(n log n)`
  with no duplicate sort or linear membership scan. Preserve ascending
  offset order and exact retransmission priority over fresh CRYPTO bytes.
- Keep the retained payload and retransmission index under one canonical
  owner. ACKed or reset ranges cannot replay; partial retransmission of a
  large range keeps the suffix queued exactly once. Avoid a parallel
  queue-plus-membership map unless measurement proves it necessary.
- Measure the current typical and high-range-count PTO path before choosing
  the data structure. `BTreeSet<u64>` is the initial candidate because it
  combines ordered `first`/`pop_first` with unique insertion; benchmark its
  allocation and latency cost against the current `VecDeque` at 1, 128,
  4,096 and 16,384 ranges. Retain the simpler queue if the measured product
  range count makes the replacement a net loss.

## Implementation and proof

- [ ] Inventory all `retx` reads/mutations, ACK/reset interactions and the
      actual range-count distribution from Initial/Handshake send paths.
- [ ] Add failable duplicate, full-PTO, partial-split, partial-ACK and reset
      regressions; preserve exact offsets and byte content.
- [ ] Benchmark both structures at the specified range counts, choose the
      lower end-to-end cost, and document the decision and native limits.
- [ ] Apply the smallest change that meets the target; run leaf, transport,
      default/feature library, strict Clippy and formatting gates.

## Acceptance

- No quadratic membership scan or redundant full sort remains on a bounded
  PTO/loss requeue path unless measurement explicitly justifies the existing
  queue at all specified product range counts.
- Duplicates, partial retransmissions, ACKed offsets and reset behave
  byte-exactly; benchmark and required gates pass with recorded results.

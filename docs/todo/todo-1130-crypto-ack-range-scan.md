---
id: TODO-1130
title: Bound high-offset CRYPTO ACK scans and full-ACK cloning
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1128]
---

# TODO-1130: Process only intersecting retained CRYPTO ACK ranges

## Why and evidence

`crates/qf-transport-crypto-stream/src/lib.rs::CryptoStream::ack_crypto`
collects all `unacked.range(..ack_end)` keys, including ranges entirely below
the ACK start, and clones every overlapping payload before distinguishing
full retirement from head/tail retention. The retransmission index is now
ordered and bounded by TODO-1128, but an ACK for a late CRYPTO fragment can
still incur a linear scan through unrelated prior ranges. Full ACKs need no
payload copy. This is a source-backed performance finding, not a measured
production regression.

## Target contract

- Find at most one preceding retained interval whose end crosses `offset`,
  then iterate only keys in `[offset, ack_end)`; complexity is `O(log n + k)`
  for `k` intersecting ranges, independent of unrelated earlier intervals.
- Preflight all range arithmetic and byte-accounting before mutation. Clone
  only the head and/or tail bytes that remain after a partial ACK; a full ACK
  retires its map entry and queued retry offset without cloning payload.
- Preserve exact retained byte count, ordered retry intent for both surviving
  fragments, duplicate ACK idempotence, and typed overflow failure atomicity.
  Do not create a second retained-payload ledger or alter wire offsets.

## Implementation and proof

- [ ] Inventory all `ack_crypto` callers and recovery ACK/loss ordering;
      capture a high-offset many-range baseline before changing the scan.
- [ ] Replace the broad range walk with predecessor plus intersecting range
      traversal, stage the minimal retained fragment copies, then commit the
      payload and retry-index changes once after validation.
- [ ] Add failable tests for late single-range ACK, full and partial ACK,
      multiple intersecting ranges, duplicate ACK, concurrent queued loss,
      overflow and reset. Compare exact offsets, bytes and accounting.
- [ ] Measure before/after latency and allocation at 1, 128, 4,096 and
      16,384 retained ranges; run leaf and default/feature root libraries,
      strict Clippy, formatting and diff hygiene. Record native limits.

## Acceptance

- A late ACK visits only its predecessor and intersecting entries; a full
  ACK makes no payload clone. Retry intent and byte accounting are exact.
- Failable regressions and all required gates pass with measured tradeoffs.

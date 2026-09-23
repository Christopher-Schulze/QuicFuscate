---
id: TODO-1130
title: Bound high-offset CRYPTO ACK scans and full-ACK cloning
severity: MEDIUM
phase: S
priority: P2
status: DONE
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

- [x] Inventory all `ack_crypto` callers and recovery ACK/loss ordering;
      capture a high-offset many-range baseline before changing the scan.
- [x] Replace the broad range walk with predecessor plus intersecting range
      traversal, stage the minimal retained fragment copies, then commit the
      payload and retry-index changes once after validation.
- [x] Add failable tests for late single-range ACK, full and partial ACK,
      multiple intersecting ranges, duplicate ACK, concurrent queued loss,
      overflow and reset. Compare exact offsets, bytes and accounting.
- [x] Measure before/after latency and allocation at 1, 128, 4,096 and
      16,384 retained ranges; run leaf and default/feature root libraries,
      strict Clippy, formatting and diff hygiene. Record native limits.

## Acceptance

- A late ACK visits only its predecessor and intersecting entries; a full
  ACK makes no payload clone. Retry intent and byte accounting are exact.
- Failable regressions and all required gates pass with measured tradeoffs.

## Native decision evidence

- ARM64 macOS, Rust 1.98 debug test profile, manual ignored benchmark using
  the test-only system allocator counter. Each case retains `n-1` earlier
  one-byte ranges plus one late 1,200-byte range; the timed operation fully
  ACKs the late range. Allocation counts and requested bytes are per ACK,
  excluding setup and reinsertion between iterations. Nanoseconds are
  approximate local measurements, not release or network latency:

  | Ranges | Before ns | After ns | Before allocations/bytes | After allocations/bytes | Iterations |
  | ---: | ---: | ---: | ---: | ---: | ---: |
  | 1 | 739 | 1,064 | 3 / 1,296 | 1 / 224 | 10,000 |
  | 128 | 40,583 | 2,398 | 135 / 11,535 | 1 / 224 | 1,000 |
  | 4,096 | 1,663,444 | 2,381 | 4,108 / 332,943 | 1 / 224 | 50 |
  | 16,384 | 7,356,679 | 4,154 | 16,398 / 1,328,271 | 1 / 224 | 10 |

- The original code cloned every earlier payload before testing overlap,
  which explains allocation counts proportional to all retained ranges.
  The optimized path inspects only the predecessor and intersecting range;
  the single remaining allocation holds the staged ACK plan. The one-range
  timing difference is measurement noise or tree/predecessor overhead at
  sub-microsecond scale; no end-to-end throughput claim is inferred.
- Final local verification: leaf `15 passed, 2 ignored` (both manual
  benchmarks passed when selected); default root library `1,865 passed,
  1 ignored`; feature root library (`rust-tests`, `stream_ring_buffer`,
  `zero_copy_dgram`) `1,870 passed, 1 ignored`; strict leaf-test and leaf/root
  library Clippy, formatting and diff hygiene pass. No peer/wire run was
  required for this in-memory ACK-retirement change.
- The first feature-suite compile failed before tests because `target/`
  disappeared during compilation while free disk space rose from 4.7 to
  13 GiB. The process responsible was not identified. Retrying with
  `CARGO_INCREMENTAL=0` completed the same feature suite. TODO-1131 owns the
  cleanup-race diagnosis; this is not evidence of a product test failure.

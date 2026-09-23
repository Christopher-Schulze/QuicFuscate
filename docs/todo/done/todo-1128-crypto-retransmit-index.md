---
id: TODO-1128
title: Remove quadratic CRYPTO retransmission queue scans
severity: MEDIUM
phase: S
priority: P2
status: DONE
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
complexity finding. The original `requeue_crypto` also walks every lower
range when only a high-offset range is lost. A separate correctness failure
occurs when a queued lost range is split by a later partial ACK: `ack_crypto`
replaces the retained key but leaves the old key in `retx`, so the surviving
bytes can be skipped instead of retransmitted. A focused test reproduced
`Ok(None)` where offset 2 and bytes `cdef` were required.

## Target contract

- Retransmission membership and ordered extraction cost at most `O(log n)`
  per distinct offset. Requeueing all `n` retained ranges costs `O(n log n)`
  with no duplicate sort or linear membership scan. Preserve ascending
  offset order and exact retransmission priority over fresh CRYPTO bytes.
- Keep the retained payload and retransmission index under one canonical
  owner. ACKed or reset ranges cannot replay; partial retransmission of a
  large range keeps the suffix queued exactly once. Avoid a parallel
  queue-plus-membership map unless measurement proves it necessary.
- A partial ACK of a queued range must transfer the retransmission intent
  exactly to each surviving head/tail range, remove fully ACKed offsets, and
  preserve increasing offset order. A high-offset loss scan must inspect
  only its predecessor and intersecting ranges.
- Measure the current typical and high-range-count PTO path before choosing
  the data structure. `BTreeSet<u64>` is the initial candidate because it
  combines ordered `first`/`pop_first` with unique insertion; benchmark its
  allocation and latency cost against the current `VecDeque` at 1, 128,
  4,096 and 16,384 ranges. Retain the simpler queue if the measured product
  range count makes the replacement a net loss.

## Implementation and proof

- [x] Inventory all `retx` reads/mutations, ACK/reset interactions and the
      source-defined range-count bounds from Initial/Handshake send paths;
      record the absence of a production range-count histogram.
- [x] Add failable duplicate, full-PTO, partial-split, partial-ACK and reset
      regressions; preserve exact offsets and byte content.
- [x] Benchmark both structures at the specified range counts, choose the
      lower end-to-end cost, and document the decision and native limits.
- [x] Apply the smallest change that meets the target; run leaf, transport,
      default/feature library, strict Clippy and formatting gates.

## Native decision evidence

- ARM64 macOS, Rust 1.98 debug test profile, one ignored manual benchmark with
  a test-only system-allocator counter. Each case begins with `n` retained
  one-byte ranges; the queue baseline reuses its VecDeque capacity across
  iterations while the ordered set releases and rebuilds its nodes. Values
  are approximate nanoseconds per PTO pass, not release or network latency:

  | Ranges | VecDeque ns | BTreeSet ns | Queue alloc calls/bytes total | Set alloc calls/bytes total | Iterations |
  | ---: | ---: | ---: | ---: | ---: | ---: |
  | 1 | 167 | 283 | 1 / 32 | 10,000 / 1,040,000 | 10,000 |
  | 128 | 61,418 | 43,793 | 6 / 2,016 | 21,000 / 2,472,000 | 1,000 |
  | 4,096 | 48,754,714 | 2,001,977 | 11 / 65,504 | 13,620 / 1,600,800 | 20 |
  | 16,384 | 806,187,625 | 8,682,597 | 13 / 262,112 | 8,184 / 962,880 | 3 |

- The set increases node allocation and a one-range pass by roughly 116 ns
  in this debug measurement. It wins at 128 ranges and removes the extreme
  high-range PTO cost, about 93x at 16,384. The 4 MiB retained-byte limit
  permits this high-range case when packet budgets are small; no production
  range-count histogram exists, so these cases are bounds, not a claim about
  normal traffic. The ordered set is chosen for bounded worst-case work and
  exact deduplication; its allocation cost is explicit.
- The benchmark counts allocator calls and requested bytes, not peak RSS or
  release-mode throughput. Root source reaches this leaf through QFTLS and
  transport-local Initial/Handshake CRYPTO ownership. There is no runtime
  histogram of retained range counts; the benchmark is an adversarial bound.
  The unrelated high-offset `ack_crypto` scan and avoidable full-ACK cloning
  are retained as TODO-1130, outside this retransmission-index change.
- Verification after the final high-offset loss-scan change: leaf `13 passed,
  1 ignored` (manual benchmark separately passed); default root library
  `1,865 passed, 1 ignored`; feature root library (`rust-tests`,
  `stream_ring_buffer`, `zero_copy_dgram`) `1,870 passed, 1 ignored`; strict
  leaf test and leaf/root library Clippy pass. Formatting and diff hygiene
  pass. The broader root `--tests` Clippy lane retains the pre-existing
  TODO-1079 diagnostics; no native peer/wire run was needed for this
  in-memory queue change.

## Acceptance

- No quadratic membership scan or redundant full sort remains on a bounded
  PTO/loss requeue path unless measurement explicitly justifies the existing
  queue at all specified product range counts.
- Duplicates, partial retransmissions, ACKed offsets and reset behave
  byte-exactly; benchmark and required gates pass with recorded results.

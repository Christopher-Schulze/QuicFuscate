---
id: TODO-475
title: ACK accounting extract-if hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-06-30
depends_on: [TODO-400, TODO-474]
---

# TODO-475: ACK accounting extract-if hotpath

## Goal
Reduce the measured ACK sent-byte accounting cost without changing QUIC RTT sampling, congestion ACK/loss accounting, PMTU probe confirmation, or packet-threshold loss behavior.

## Implemented State

- `src/transport/connection.rs` now drains ACKed and loss-threshold packet-number ranges from `sent_packets_by_pn` with `BTreeMap::extract_if`.
- The previous implementation collected matching BTreeMap entries into temporary `Vec`s and then removed the same packet numbers from the map in a second pass.
- The new path keeps the original semantics:
  - RTT sample is still derived only from the largest acknowledged packet number.
  - Acked bytes still feed recovery and `stats.acked_bytes`.
  - Packet-threshold losses still feed recovery and loss counters.
  - PMTU probe ACK/loss handling is unchanged.
- Added `sparse_ack_accounting_removes_acked_and_prunes_packet_threshold_losses` to pin sparse ACK and loss-pruning behavior.

## Broderick Evidence

All commands were run on `broderick` from `/root/QuicFuscate-git` after synchronizing the candidate change.

| Gate | Result | Evidence |
|---|---:|---|
| Sparse ACK regression test | PASS | `sparse_ack_accounting_removes_acked_and_prunes_packet_threshold_losses ... ok` |
| Criterion ACK bench | PASS | `cargo bench --bench ci_regression --features benches ack_sent_byte_accounting -- --sample-size 10 --warm-up-time 1 --measurement-time 2` |
| 10k ACK all | Improved | `1.0159 ms`, Criterion reports about `34.7%` faster than the prior candidate baseline |
| 10k ACK half | Improved | `877.09 us`, Criterion reports about `21.7%` faster than the prior candidate baseline |
| 10k ACK sparse | Improved | `1.3610 ms`, Criterion reports about `30.4%` faster than the prior candidate baseline and below the earlier observed `1.73 ms` production hotpath candidate |

## Notes

- A direct `range().next()` plus `remove_entry()` loop was tested and rejected because it regressed Broderick sparse and dense ACK benches.
- `BTreeMap::extract_if` is the current best fit because it drains the matching range in one pass and returns owned packet metadata without a temporary collection.
- This is still BTreeMap-backed accounting. A more radical future redesign would require changing the packet-number tracking container, not just the removal primitive.

## Acceptance

- [x] ACK/loss accounting no longer builds temporary `Vec`s for ACKed and lost packet ranges.
- [x] Sparse ACK behavior and packet-threshold loss pruning are covered by a real unit test.
- [x] Local `cargo check`, `cargo clippy -D warnings`, and `cargo test --lib` pass.
- [x] Broderick targeted ACK benchmark improves the measured 10k sparse accounting path.

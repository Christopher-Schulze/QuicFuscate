---
id: TODO-485
title: ACK accounting split-drain hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-400, TODO-475]
---

# TODO-485: ACK accounting split-drain hotpath

## Context

TODO-475 replaced collect-then-remove ACK/loss accounting with `BTreeMap::extract_if`, which removed an unnecessary temporary vector and improved sparse ACK accounting. Follow-up Criterion runs still showed ACK sent-byte accounting as the largest direct transport microbenchmark. The remaining cost came from large contiguous acknowledged ranges and packet-threshold loss prefixes, where a range split is a better fit than repeatedly visiting and removing individual entries.

## Desired Outcome

- Keep ACK accounting behavior identical: acknowledged bytes, packet-threshold loss, RTT sampling from the largest acknowledged packet, DPLPMTUD probe ACK/loss handling, and congestion window updates must not change.
- Use `BTreeMap::split_off` for large contiguous ACK ranges and for loss prefixes.
- Keep `BTreeMap::extract_if` for sparse/narrow ACK ranges, where split/append overhead is not worth it.
- Prove the behavior with regression tests and local plus Broderick Criterion measurements.

## Implementation

- Added `SENT_PACKET_SPLIT_DRAIN_THRESHOLD = 64` as the cutoff for large contiguous ACK range drains.
- Added `Connection::drain_sent_packet_range(start, end)` to drain `[start, end)` with `BTreeMap::split_off`, then append the preserved tail back into `sent_packets_by_pn`.
- Added `Connection::drain_sent_packets_through(end_inclusive)` to drain packet-threshold loss prefixes with one split.
- Updated `account_sent_bytes_for_ack_ranges_with_delay()`:
  - ranges with span `>= 64` use the split-drain helper;
  - smaller ranges keep `extract_if`;
  - loss prefix drains use split-drain unconditionally because the prefix is contiguous by definition.
- Added regression tests for large contiguous ACK range draining and large loss prefix draining while preserving unacked/unlost tail entries.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests ack_` pass, 39 tests.
- Local: `cargo test --lib --features rust-tests large_loss_prefix_uses_split_drain_and_preserves_unlost_tail` pass.
- Local: `cargo bench --bench ci_regression --features benches ack_sent_byte_accounting -- --sample-size 10 --warm-up-time 1 --measurement-time 2` pass.
- Broderick: `cargo test --lib --features rust-tests ack_` pass, 39 tests.
- Broderick: `cargo test --lib --features rust-tests large_loss_prefix_uses_split_drain_and_preserves_unlost_tail` pass.
- Broderick: `cargo bench --bench ci_regression --features benches ack_sent_byte_accounting -- --sample-size 10 --warm-up-time 1 --measurement-time 2` pass.

## Broderick Criterion Evidence

| Case | Previous median | TODO-485 median | Result |
|------|-----------------|-----------------|--------|
| `10240_inflight_ack_all` | `1.0277 ms` | `0.8368 ms` | about 18.6% faster |
| `10240_inflight_ack_half` | `899.0 us` | `828.6 us` | about 7.8% faster |
| `10240_inflight_ack_sparse` | `1.3867 ms` | `1.2201 ms` | about 12.0% faster |
| `2048_inflight_ack_all` | `197.8 us` | `159.8 us` | about 19.2% faster |
| `2048_inflight_ack_sparse` | `262.8 us` | `234.1 us` | about 10.9% faster |
| `512_inflight_ack_all` | `58.3 us` | `48.2 us` | about 17.3% faster |

Small 32-packet cases remain effectively unchanged, which is the intended threshold behavior: narrow ranges avoid split-drain overhead and continue using `extract_if`.

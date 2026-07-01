---
id: TODO-487
title: ACK sparse prefix classification hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-400, TODO-475, TODO-485]
---

# TODO-487: ACK sparse prefix classification hotpath

## Context

TODO-475 moved ACK accounting from collect-then-remove to `BTreeMap::extract_if`.
TODO-485 then added split-drain helpers for large contiguous ACK ranges and
packet-threshold loss prefixes. That hybrid path made ACK-all and ACK-half
large-window cases fast, but ACK frames with many sparse ranges still performed
two logically adjacent operations:

- remove each sparse acked range from `sent_packets_by_pn`;
- drain the packet-threshold prefix afterward to mark old unacked packets lost.

For many sparse ranges, the loss prefix is the dominant shape. The map already
needs to walk the ordered prefix; classifying each drained PN as either acked or
lost in that single pass avoids re-walking the same packet-number region.

## Desired Outcome

- Classify many sparse ACK ranges and packet-threshold losses in one ordered
  prefix drain.
- Keep normal contiguous ACK-all and ACK-half cases on the previous split-drain
  path so their hot path stays neutral.
- Preserve largest-ACK RTT sampling, recovery `on_ack()`, loss accounting,
  DPLPMTUD ACK/loss hooks, and the unacked/unlost tail.
- Add a focused regression test that proves sparse ACK/loss/tail semantics.

## Implementation

- Added `ACK_PREFIX_CLASSIFY_RANGE_THRESHOLD = 8`.
- Updated `Connection::account_sent_bytes_for_ack_ranges_with_delay()`:
  - if an ACK frame has at least 8 ranges and a packet-threshold loss prefix,
    drain the prefix once via `drain_sent_packets_through()`;
  - classify each drained packet number against the sorted ACK ranges;
  - count matching packet numbers as acked and non-matching packet numbers as
    lost;
  - process any ACK range tail beyond the loss prefix with the existing range
    drain logic;
  - keep the old TODO-485 split-drain branch unchanged for fewer than 8 ranges.
- Added `sparse_ack_prefix_classification_preserves_ack_loss_and_tail`.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo clippy --lib --features rust-tests -- -D warnings` pass.
- Local: `cargo test --lib --features rust-tests sparse_ack_prefix_classification_preserves_ack_loss_and_tail` pass.
- Local: `cargo test --lib --features rust-tests ack_` pass, 40 tests.
- Local: `cargo bench --bench ci_regression --features benches ack_sent_byte_accounting -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.
- Broderick: `cargo test --lib --features rust-tests sparse_ack_prefix_classification_preserves_ack_loss_and_tail` pass.
- Broderick: `cargo bench --bench ci_regression --features benches ack_sent_byte_accounting -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.

## Criterion Evidence

Broderick measurements after the branch-split fix:

| Case | Result |
|------|--------|
| `32_inflight_ack_all` | within noise (`+0.19%`) |
| `32_inflight_ack_half` | no change |
| `128_inflight_ack_all` | within noise (`+0.12%`) |
| `128_inflight_ack_half` | within noise (`-0.52%`) |
| `512_inflight_ack_all` | improved (`-2.41%`) |
| `512_inflight_ack_half` | improved (`-1.52%`) |
| `1024_inflight_ack_all` | improved (`-2.69%`) |
| `1024_inflight_ack_half` | improved (`-2.71%`) |
| `2048_inflight_ack_all` | improved (`-1.21%`) |
| `2048_inflight_ack_half` | improved (`-1.38%`) |
| `10240_inflight_ack_all` | no change |
| `10240_inflight_ack_half` | no change |
| `512_inflight_ack_sparse` | improved from `59.07 us` to `58.12 us` |
| `2048_inflight_ack_sparse` | within noise around `199.63 us` |
| `10240_inflight_ack_sparse` | within noise around `1.045 ms` |

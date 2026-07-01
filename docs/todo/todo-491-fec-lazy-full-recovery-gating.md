---
id: TODO-491
title: FEC lazy full-recovery gating
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-476, TODO-484, TODO-490]
---

# TODO-491: FEC lazy full-recovery gating

## Context

TODO-490 made `fec_decode_pipeline` truthful enough to expose the real Strong
mode 10% loss cost. Broderick showed `17.5-18.5 ms` per 128-packet decode batch.
That cost was not caused by useful recovery work on every packet. After a source
sequence gap, `LazyDecoder::recovery_needed()` stayed true, so
`AdaptiveFec::on_receive_into()` called `get_result()` on each later systematic
packet. `get_result()` flushes pending repairs and runs the heavy decoder, so
the hot path repeatedly attempted full Gaussian/Wiedemann recovery even when no
new repair packet had arrived.

## Desired Outcome

- Keep clean-link lazy receive behavior allocation-light and recovery-free.
- Preserve tail-loss repair recovery.
- Preserve partial recovery emission when a gap may have peeled existing
  equations.
- Trigger full recovery only when fresh repair data was flushed or a tail-loss
  repair is available.
- Keep systematic packets forwarded immediately to QUIC even while recovery is
  pending.
- Prove correctness with tests that fail if full recovery is skipped when it is
  actually required.

## Implementation

- `LazyDecoder` now tracks separate `full_recovery_pending` and
  `partial_recovery_pending` flags.
- `flush_to_decoder()` returns whether a repair packet was actually flushed.
- Gap-only systematic arrivals mark partial recovery pending without forcing
  full recovery when no repair data was flushed.
- Repair packets after a known gap still flush immediately and mark full
  recovery pending.
- Tail-loss repairs mark full recovery pending while preserving the buffered
  repair until the next full poll.
- `InterleavedDecoder` exposes `full_recovery_needed()` across its lazy blocks.
- `AdaptiveFec::on_receive_into()` now calls:
  - `get_result()` only when full recovery is pending;
  - `get_partial_result()` when only partial drain work is pending.
- Added focused lazy decoder tests for gap-only partial drain and repair-driven
  full recovery.
- Added Strong-mode `on_receive_into()` recovery coverage for a dropped source
  packet.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests lazy_decoder` pass, 7 passed.
- Local: `cargo test --lib --features rust-tests test_strong_receive_into_recovers_single_source_loss` pass.
- Local: `cargo test --lib --features rust-tests fec::` pass, 175 passed.
- Local: `cargo clippy --lib --features rust-tests -- -D warnings` pass.
- Local: `cargo test --lib --features rust-tests` pass, 1633 passed.
- Local: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Broderick: `cargo test --lib --features rust-tests fec::` pass, 175 passed.
- Broderick: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Broderick: focused `fec_decode_pipeline` clean and 10% loss runs pass for
  Normal, Strong, and Streaming.

## Criterion Evidence

Broderick ARM/AArch64 measurements after lazy full-recovery gating:

| Case | Median |
|------|--------|
| `fec_decode_pipeline/normal/batch128_no_loss_reuse` | `279 us` |
| `fec_decode_pipeline/normal/batch128_10pct_reuse` | `506 us` |
| `fec_decode_pipeline/strong/batch128_no_loss_reuse` | `200 us` |
| `fec_decode_pipeline/strong/batch128_10pct_reuse` | `195 us` |
| `fec_decode_pipeline/streaming/batch128_no_loss_reuse` | `447 us` |
| `fec_decode_pipeline/streaming/batch128_10pct_reuse` | `474 us` |

## Notes

The optimization does not weaken recovery semantics. It removes repeated full
recovery polls that had no new repair data to consume. Full recovery still runs
when repair data is available, while partial drain remains available after gaps
for already-peeled decoder output.

---
id: TODO-501
title: FEC streaming lazy tail-loss gating
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-490, TODO-491, TODO-498, TODO-499]
---

# TODO-501: FEC Streaming Lazy Tail-Loss Gating

## Context

Broderick Criterion runs after TODO-500 showed the retained send, stealth, and
connection hot paths were stable, but `fec_decode_pipeline/streaming` remained
an outlier: clean 128-packet streaming decode cost about `26.7 ms`, and the
deterministic 10% loss case cost about `15.1 ms`.

The root cause was in `LazyDecoder`: streaming repair packets were treated like
block-FEC tail-loss evidence as soon as a repair arrived before the current
decoder block was complete. That is correct for block FEC, where a late repair
after an incomplete source block may be the only tail-loss signal. It is wrong
for streaming FEC, because streaming mode intentionally emits repairs before a
block is complete. The old behavior woke the heavy GF(2^8) decoder and full
elimination path during clean streaming traffic.

## Desired Outcome

- Keep block-FEC tail-loss recovery behavior intact.
- Keep streaming Tetrys-style single, multi, and burst-loss recovery intact.
- Keep clean streaming early repairs on the lazy path until a real gap exists,
  enough tail repairs accumulate, or the pending-repair safety cap is reached.
- Prove the clean streaming decode batch no longer pays millisecond-scale full
  recovery cost.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added `streaming_mode` to `LazyDecoder`, derived from the retained FEC backend
  family at construction time.
- Split tail-loss detection:
  - Block FEC preserves the existing behavior: any incomplete block plus repair
    requests full recovery.
  - Streaming FEC requests full recovery for an incomplete tail only after the
    number of pending repairs is at least the number of missing tail sources.
- Added `test_lazy_decoder_streaming_repair_before_block_end_stays_lazy`.
- Kept existing streaming recovery tests green:
  - `test_streaming_tetrys_style_recovery_single_loss`
  - `test_streaming_tetrys_multi_loss_uniform_recovery`
  - `test_streaming_tetrys_burst_loss_recovery`
  - `test_streaming_rank_progression_monotonic`

## Broderick Criterion Evidence

Broderick ARM/AArch64 `fec_decode_pipeline/streaming` after TODO-501:

| Group | Before | After | Criterion change |
|-------|--------|-------|------------------|
| clean 128-packet batch | `26.738 ms` | `211.75 us` | `-99.213%` time |
| deterministic 10% loss batch | `15.111 ms` | `307.97 us` | `-97.963%` time |

`fec_lazy_fast_path` stayed neutral except for small nanosecond-scale
measurement noise in zero-mode reuse. Normal-mode lazy receive remained stable:
`normal_mode_no_loss_reuse` measured `1.2455 us`.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --features rust-tests --lib test_lazy_decoder_streaming_repair_before_block_end_stays_lazy` pass.
- Local: `cargo test --features rust-tests --lib test_lazy_decoder_tail_loss_replays_buffered_sources_on_recovery` pass.
- Local: `cargo test --features rust-tests --lib fec::` pass (`177 passed`).
- Local: `cargo test --features rust-tests` pass.
- Local: `cargo clippy --workspace --all-targets -- -D warnings` pass.
- Broderick: `cargo test --features rust-tests --lib fec::` pass (`177 passed`).
- Broderick: `cargo bench --bench fec_pipeline --features benches -- "fec_decode_pipeline/streaming|fec_lazy_fast_path" --sample-size 10 --measurement-time 1` pass.

## Notes

This keeps Streaming FEC aggressive when loss is real, but prevents clean
streaming cover/repair cadence from looking like constant tail loss. The change
is deliberately inside the lazy decoder trigger policy rather than the GF(2^8)
solver, because the heavy decoder was waking too early, not computing the wrong
answer.

---
id: TODO-482
title: FEC lazy clean sequence tracker
severity: MEDIUM
phase: "R"
priority: P2
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-476, TODO-481]
---

# TODO-482: FEC lazy clean sequence tracker

## Status

DONE

## Context

`LazyDecoder` used a `BTreeSet<u64>` to track every seen systematic source
sequence. That was exact, but it also allocated and touched tree nodes for the
normal no-loss receive path where packets arrive in order and no sparse lookup
is needed.

TODO-481 fixed false gap detection for interleaved streams by normalizing source
sequences by depth. This task tightens the remaining clean-path tracker itself:
keep the exact semantics, but avoid per-source tree work when the stream is
clean.

## Desired Outcome

Replace per-source tree tracking with a cleaner hot-path representation:

- clean in-order sources are tracked as one contiguous range without heap use;
- duplicate source packets do not inflate the seen-source count;
- real gaps still enable recovery polling;
- out-of-order gaps can be filled and return to the lazy clean path;
- sparse interval tracking is allocated only after a real non-contiguous source
  sequence arrives;
- local documentation is honest about benchmark evidence.

## Implementation

- `src/fec/internal.rs`: added private `LazySequenceTracker`.
- `src/fec/internal.rs`: clean source tracking now stores `Option<(start, end)>`
  plus a unique source count.
- `src/fec/internal.rs`: sparse fallback uses sorted non-overlapping intervals
  only after out-of-order/gap input appears.
- `src/fec/internal.rs`: `LazyDecoder::has_gaps()` now delegates to the tracker.
- `src/fec/internal.rs`: clean complete block pruning now uses the tracker count.
- `src/fec/internal.rs`: added duplicate-source and gap-fill regression tests.

## Verification

- `cargo fmt --all -- --check`
- `cargo test --lib -- test_lazy_decoder_buffers_repairs_until_loss test_lazy_decoder_flushes_on_gap test_lazy_decoder_prunes_clean_complete_blocks test_lazy_decoder_depth_normalizes_interleaved_clean_sources test_lazy_decoder_duplicate_source_does_not_inflate_clean_block test_lazy_decoder_gap_can_be_filled_before_recovery_poll`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib`
- `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 0.5 --measurement-time 1`
- Local A/B: stashed the patch, ran `cargo bench --features benches --bench fec_pipeline -- 'fec_lazy_fast_path/normal_mode_no_loss' --sample-size 30 --warm-up-time 1 --measurement-time 2`, then restored the patch.

Local benchmark result:

- Patched `normal_mode_no_loss`: `4.6702 us` median in the 30-sample focused
  run.
- Baseline `normal_mode_no_loss` from the immediate stash A/B run: `4.7170 us`
  median.
- Criterion reported no statistically significant latency change.

Interpretation: this task is accepted as a clean-path allocation/resource
improvement, not as a proven latency improvement.

## Completion Criteria

- [x] Clean in-order source tracking uses no heap allocation.
- [x] Duplicate sources do not inflate clean block accounting.
- [x] Real gaps still trigger recovery polling.
- [x] Filled gaps can return to the lazy clean path.
- [x] Full lib tests, focused lazy decoder tests, clippy, fmt, and local FEC
      benchmark pass.

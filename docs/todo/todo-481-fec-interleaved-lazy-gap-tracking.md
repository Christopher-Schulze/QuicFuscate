---
id: TODO-481
title: FEC interleaved lazy gap tracking
severity: HIGH
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-433, TODO-476]
---

# TODO-481: FEC interleaved lazy gap tracking

## Status

DONE

## Context

`InterleavedDecoder` routes systematic packets to lazy decoder blocks by
`seq % depth`. With depth `4`, one lazy block receives clean source sequences
such as `0,4,8,12`. `LazyDecoder` previously tracked gaps as if every block saw
step-1 source sequences, so clean interleaved streams looked like loss gaps.

That defeated the lazy no-loss fast path for interleaved modes:

- clean blocks could trigger recovery polling even though no packet was lost;
- normal no-loss decode cost stayed in the multi-microsecond range;
- repair packets after a clean interleaved block were less likely to stay lazy.

## Desired Outcome

Make lazy FEC gap tracking aware of interleave depth:

- preserve the existing behavior for depth `1`;
- normalize source sequence numbers for each lazy block when depth is greater
  than `1`;
- keep real gap detection intact;
- keep tail-loss recovery behavior intact;
- add a regression test for clean interleaved source sequences.

## Implementation

- `src/fec/internal.rs`: added `depth` to `LazyDecoder`.
- `src/fec/internal.rs`: source sequence tracking now uses `seq / depth` before
  inserting into `seen_seqs`.
- `src/fec/internal.rs`: `expected_seq` is updated with the normalized block
  sequence.
- `src/fec/internal.rs`: added
  `test_lazy_decoder_depth_normalizes_interleaved_clean_sources`, covering
  `0,4,8,12` at depth `4`.

## Verification

- `cargo fmt --all -- --check`
- `cargo test --lib -- test_lazy_decoder_depth_normalizes_interleaved_clean_sources test_lazy_decoder_flushes_on_gap test_lazy_decoder_prunes_clean_complete_blocks`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib`
- `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 0.5 --measurement-time 1`

Local benchmark result:

- `fec_lazy_fast_path/normal_mode_no_loss`: `2.8028 us` median, about `78.8%`
  faster than the previous Criterion baseline.
- `fec_lazy_fast_path/zero_mode_passthrough_reuse`: `196.02 ns` median, no
  statistically significant change.
- `fec_lazy_fast_path/zero_mode_passthrough`: `202.78 ns` median, a small
  Criterion baseline regression unrelated to the normal/interleaved path.

## Completion Criteria

- [x] Clean interleaved systematic sequences do not look like loss gaps.
- [x] Depth-1 lazy decoder behavior remains unchanged.
- [x] Real gap detection still enables recovery polling.
- [x] Full lib tests, focused lazy decoder tests, clippy, fmt, and FEC benchmark pass.

---
id: TODO-504
title: FEC interleaved recovery isolation
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-490, TODO-491, TODO-501]
---

# TODO-504: FEC Interleaved Recovery Isolation

## Context

Broderick Criterion measurements showed the FEC persistent send hot paths were
stable, but streaming decode regressed after the previous lazy tail-loss gating
work:

| Benchmark | Before |
|-----------|--------|
| `fec_decode_pipeline/streaming/batch128_no_loss_reuse` | `220.83 us` |
| `fec_decode_pipeline/streaming/batch128_10pct_reuse` | `499.58 us` |

The root cause was not GF math. `InterleavedDecoder::get_result()` called
`LazyDecoder::get_result()` on every interleave block whenever any block needed
full recovery. `LazyDecoder::get_result()` flushes pending source and repair
buffers into the heavy decoder. That meant one lossy interleave lane forced
unrelated clean lanes to flush their buffered repairs and run unnecessary heavy
decode work.

## Desired Outcome

- Keep clean interleave lanes lazy while a different lane performs full
  recovery.
- Preserve full recovery for lanes that actually have repair-backed recovery
  work.
- Preserve partial peeled-result draining for lanes with partial recovery
  pending.
- Add a regression test proving a clean-lane pending repair buffer survives a
  full recovery attempt in another lane.
- Avoid frontend, UI, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Updated `InterleavedDecoder::get_result()` to call `LazyDecoder::get_result()`
  only for blocks where `full_recovery_needed()` is true.
- Updated the same method to call `get_partial_result()` only for blocks where
  `recovery_needed()` is true but full recovery is not needed.
- Added a test-only `block_pending_repairs_len()` accessor.
- Added
  `test_interleaved_decoder_get_result_skips_idle_lazy_blocks`, which builds a
  two-lane streaming decoder, leaves one clean lane with a pending repair,
  triggers full recovery on the other lane, calls `get_result()`, and verifies
  the clean lane's pending repair is still buffered.

## Verification

| Command | Result |
|---------|--------|
| Local: `cargo fmt --all -- --check` | PASS |
| Local: `cargo test --lib test_interleaved_decoder_get_result_skips_idle_lazy_blocks -- --nocapture` | PASS |
| Local: `cargo test --lib fec::` | PASS, 178 tests |
| Broderick: `cargo test --lib test_interleaved_decoder_get_result_skips_idle_lazy_blocks -- --nocapture` | PASS |
| Broderick: `cargo bench --bench fec_pipeline --features benches -- "fec_decode_pipeline/streaming/batch128" --sample-size 10 --measurement-time 1` | PASS |

## Broderick Performance Evidence

| Benchmark | After | Change |
|-----------|-------|--------|
| `fec_decode_pipeline/streaming/batch128_no_loss_reuse` | `180.48 us` | `-17.871%` |
| `fec_decode_pipeline/streaming/batch128_10pct_reuse` | `256.97 us` | `-55.358%` |

## Notes

This change narrows work to the recovery-active interleave lane instead of
making full recovery a decoder-wide event. It improves streaming decode latency
without changing FEC wire format, mode selection, repair cadence, or recovery
semantics for blocks that actually need decoding.

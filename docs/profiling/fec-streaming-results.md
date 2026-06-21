# FEC Streaming Adaptive Loop — Validation Results (TODO-414)

## Status: Code Complete, Server Validation Pending

The streaming-FEC adaptive loop (TODO-414) is implemented and unit-tested.
Server-side profiling validation against the TODO-418 tc-netem scenarios is
pending the next broderick profiling run.

## Implemented Changes

### 1. StreamingAdaptive Selection (5-15% burst loss)

`continuous_fec_target()` now selects the `Streaming` FEC family for moderate
burst-loss (5-15%) when `burst_variance > 0.3`, indicating bursty rather than
uniform loss patterns.

- Falls back to `LowCostBlock` for uniform loss (low variance).
- Escalates to `HeavyBlock` above 15%.
- New `burst_variance()` method on `LossEstimator` computes run-length
  variance from the burst window.

### 2. RTT-coupled `stream_every`

`stream_every` scales with RTT: high RTT → larger interval (less overhead,
recovery is RTT-bound); low RTT → smaller interval (faster recovery,
overhead is cheap).

- Formula: `scale = clamp(rtt_ms / 100ms, 0.5, 3.0)`, clamped to `[1, 18]`.
- RTT fed from transport via `set_rtt_hint()` method.
- Wired in `core.rs` update loop.

### 3. Fountain Cross-fade Configurability

- `cross_fade_window` field on `AdaptiveFec` (env:
  `QUICFUSCATE_FEC_CROSS_FADE_WINDOW`, default: 32).
- `compute_cross_fade_target_len_capped()` applies configurable maximum.
- Fountain transitions emit both repair types during cross-fade.

## Pending Server Validation

The following validation scenarios need to be run on broderick with tc-netem:

| Scenario | Loss | Burst | Expected Family | Metric |
|----------|------|-------|-----------------|--------|
| 5% uniform | 5% | low var | LowCostBlock | baseline recovery |
| 5% burst | 5% | high var | Streaming | lower recovery latency |
| 10% burst | 10% | high var | Streaming | lower recovery latency |
| 15% burst | 15% | high var | HeavyBlock | baseline recovery |
| 0% loss | 0% | n/a | Zero | no throughput regression |

## stream_ring_buffer Evaluation

The `stream_ring_buffer` feature was evaluated against the profiling baseline
(flamegraph-a.svg, flamegraph-udp-fastpath.svg). The baseline shows that
kernel UDP send/receive dominates (97% kernel time) and the user-space
`to_vec()` in `maybe_flush_one_writable_stream` does not appear in the Top-10
hotspots.

**Decision**: `stream_ring_buffer` is NOT enabled by default. The profiling
evidence does not justify the complexity. If future profiling on higher-core
systems or with different workloads shows `to_vec()` as a hotspot, this
decision can be revisited.

## Unit Tests

- `burst_variance()` computes correct variance for bursty vs uniform patterns.
- `stream_every` scales correctly with RTT (low/medium/high).
- `continuous_fec_target` selects `Streaming` for 5-15% burst loss with high variance.
- `continuous_fec_target` selects `LowCostBlock` for uniform loss.
- Cross-fade window config is respected.

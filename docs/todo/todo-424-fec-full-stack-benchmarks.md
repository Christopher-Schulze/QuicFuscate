---
id: TODO-424
title: FEC full-stack performance benchmarks (encode/decode pipeline, mode switch, streaming)
severity: HIGH
phase: "F"
priority: P1
status: DONE
created: 2026-06-29
depends_on: ["TODO-423"]
---

# TODO-424: FEC Full-Stack Performance Benchmarks

## Problem

The only existing Criterion benchmark for FEC is `bench_fec_matrix_mul` (GF(256) 4x4/8x8/16x16
matrix multiply). This benchmarks a single micro-operation but not the real FEC pipeline.

Missing benchmarks:
- Full `AdaptiveFec::on_send()` pipeline (packet ingest → window fill → repair generation → output)
- Full `AdaptiveFec::on_receive()` pipeline (packet ingest → decoder → recovery → output)
- Mode transition overhead (cross-fade cost during mode switch)
- Streaming repair emission overhead
- Lazy decoder skip cost (zero-loss fast path)
- Memory pool allocation/recycling under FEC load
- SIMD dispatch overhead per mode (GF4 vs GF8 vs GF16 vs Fountain)

## Goal

Build Criterion benchmarks that measure the **real FEC hot paths** — not just matrix multiply,
but the full encode/decode pipeline including memory management, locking, and mode dispatch.

## Implementation Plan

### 1. Criterion benchmark: FEC encode pipeline (`benches/fec_pipeline.rs`)

```
bench_fec_encode_pipeline/{mode}/{packet_size}
  - modes: Zero, Light, Normal, Medium, Strong, Extreme, Streaming, Fountain
  - packet_sizes: 64B, 256B, 1400B, 4096B, 16384B
  - measures: on_send() latency per packet, repair generation time, total output packets
```

### 2. Criterion benchmark: FEC decode pipeline

```
bench_fec_decode_pipeline/{mode}/{loss_pattern}
  - modes: Normal, Strong, Extreme, Fountain
  - loss_patterns: no_loss, single_drop, burst3, random10pct, random25pct
  - measures: on_receive() latency, recovery time, recovered packet count
```

### 3. Criterion benchmark: Mode transition overhead

```
bench_fec_mode_transition/{from_mode}/{to_mode}
  - measures: cross-fade cost, transition_encoder setup, transition_left countdown
  - verifies: no allocation spike during transition
```

### 4. Criterion benchmark: Streaming repair emission

```
bench_fec_streaming_repair/{stream_every}/{packet_size}
  - stream_every: 4, 8, 16, 32
  - measures: repair emission interval cost, scratch queue reuse
```

### 5. Criterion benchmark: Lazy decoder fast path

```
bench_fec_lazy_fast_path/{packet_count}
  - measures: on_receive() with zero loss (lazy skip cost)
  - verifies: <10ns per packet overhead in lazy mode
```

### 6. CI regression thresholds

Wire into `scripts/benchmarks/suites/bench-fec.sh` and `ci.yml` benchmarks job:
- 15% warn / 30% error regression thresholds (matching existing CI pattern)
- critcmp baseline comparison

## Files to Create
- `benches/fec_pipeline.rs` — Criterion benchmarks for FEC hot paths
- Update `scripts/benchmarks/suites/bench-fec.sh` — wire new benchmarks
- Update `Cargo.toml` — add bench target if needed

## Acceptance Criteria
- All 5 benchmark groups run under `cargo bench --features benches -- fec_`
- Zero mode: <5ns per packet (passthrough fast path)
- Lazy decoder: <10ns per packet overhead (zero-loss skip)
- Normal mode encode: <500ns per packet (1400B, GF8)
- Mode transition: <2us per packet during cross-fade
- CI regression thresholds configured
- No allocations in steady-state hot paths (verified via benchmark custom measurement)

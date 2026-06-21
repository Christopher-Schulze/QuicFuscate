---
id: TODO-414
title: Streaming-FEC in adaptiven Loop integrieren (supersedes TODO-409)
severity: HIGH
phase: "2"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: [TODO-418]
supersedes: [TODO-409]
---

# TODO-414: Streaming-FEC in Adaptiven Loop

## Problem

QuicFuscate's FEC subsystem has the building blocks for sliding-window streaming FEC but they are **not integrated into the adaptive control loop**:

1. **`InterleavedEncoder`/`InterleavedDecoder`** (`src/fec/internal.rs`): Burst-loss protection via interleaving depth (default 4). Exists but only used in explicit `Streaming` mode, not selected by the adaptive controller.

2. **`continuous_fec_target()`** (`src/fec/mod.rs:282-366`): Selects FEC family based on loss + disturbance, but only chooses between `Zero`, `LowCostBlock`, `HeavyBlock`, and `Fountain`. The `Streaming` family is **never selected adaptively**.

3. **`stream_every` parameter** (`src/fec/mod.rs:351-364`): Controls repair emission interval, is "adaptive per pressure" but **not coupled to RTT**. High RTT should mean larger intervals (less overhead); low RTT should mean smaller intervals (faster recovery).

4. **Fountain codes** (`src/fec/fountain_codes.rs`): LT fountain with Robust Soliton distribution exists but is isolated to `Fountain` mode. The transition from block codes to fountain at high loss (>40%) is a hard jump, not a gradual cross-fade.

5. **Cross-fade transitions** (`src/fec/mod.rs:3021`): Defined in code but **no evidence of active use** in mode switches.

### SOTA Context

IETF QUIC-FEC framework (RFC 8681 RLC, RFC 9407) and Tetrys demonstrate that **sliding-window codes have lower recovery latency than block codes** for burst-loss scenarios. QuicFuscate has the components (InterleavedEncoder, stream_every, LazyDecoder) but lacks the wiring to make the adaptive controller choose streaming when appropriate.

**RLNC (Random Linear Network Coding) is explicitly NOT pursued** — Robust Soliton fountain is sufficient for single-path QUIC, and RLNC brings coefficient-management complexity without a clear win.

## Acceptance

1. **`continuous_fec_target()` extended**: New family `StreamingAdaptive` is selectable as an option between `LowCostBlock` and `HeavyBlock` for moderate burst-loss (5-15%).
   - Selection criteria: burst-loss detected (variance > threshold) + moderate loss rate (5-15%).
   - Falls back to `LowCostBlock` for uniform loss (low variance).
   - Escalates to `HeavyBlock` for high loss (>15%).

2. **`stream_every` RTT-coupled**:
   - High RTT (>200ms): larger `stream_every` (less overhead, recovery is RTT-bound anyway).
   - Low RTT (<50ms): smaller `stream_every` (faster recovery, overhead is cheap).
   - Formula: `stream_every = clamp(base * (rtt / reference_rtt), min, max)`.
   - RTT sourced from transport telemetry (existing `TransportObserver` / `StealthBrain` sensor).

3. **Fountain transition cross-fade**:
   - At >40% loss, transition from block → fountain is gradual (not hard jump).
   - Cross-fade mechanism (`mod.rs:3021`) activated: redundancy ramps up over N packets during transition.
   - No throughput cliff at mode boundary.

4. **`stream_ring_buffer` evaluation** (from TODO-409):
   - Profile with and without `stream_ring_buffer` feature (TODO-418 scenarios).
   - If flamegraph shows `to_vec()` in `maybe_flush_one_writable_stream` as Top-10 hotspot, enable feature by default for throughput builds.
   - Decision documented in `docs/profiling/fec-streaming-results.md`.

5. **Profiling validation** (from TODO-418):
   - tc-netem scenarios with 5%, 10%, 15% burst loss show lower recovery latency with `StreamingAdaptive` vs `LowCostBlock`.
   - No throughput regression for 0% loss (FEC off / Zero mode unaffected).
   - Results in `docs/profiling/fec-streaming-results.md`.

6. **Tests**:
   - Unit test: `continuous_fec_target` selects `StreamingAdaptive` for burst-loss 5-15%.
   - Unit test: `stream_every` scales with RTT.
   - Integration test: tc-netem 10% burst-loss scenario, recovery latency measured.
   - `cargo test --lib` green.

## Fix Plan

### Step 1: Extend `continuous_fec_target()` (src/fec/mod.rs)
1. Add `StreamingAdaptive` to the `FecBackendFamily` enum (or reuse `Streaming` with adaptive parameters).
2. In `continuous_fec_target()`, add selection logic:
   ```rust
   if loss_rate >= 0.05 && loss_rate <= 0.15 && burst_variance > BURST_THRESHOLD {
       return FecTarget { family: StreamingAdaptive, ... };
   }
   ```
3. Wire `StreamingAdaptive` to use `InterleavedEncoder`/`InterleavedDecoder` with adaptive interleave depth.

### Step 2: RTT-coupled `stream_every`
1. Add RTT input to FEC controller (from `TransportObserver` or `StealthBrain`).
2. Implement scaling formula in `continuous_fec_target()` or `FecRuntimePolicy`.
3. Add env override: `QUICFUSCATE_FEC_STREAM_EVERY_RTT_SCALE` (default: enabled).

### Step 3: Fountain cross-fade
1. In mode-switching logic (`mod.rs:176-200` or `mod.rs:3021`), implement gradual transition:
   - When switching from `HeavyBlock` to `Fountain`: emit both block repairs AND fountain symbols for N packets (cross-fade window).
   - N = `CROSS_FADE_WINDOW` (default 32 packets).
   - After N packets, block repairs cease, only fountain symbols remain.
2. Same for reverse transition (Fountain → HeavyBlock).

### Step 4: `stream_ring_buffer` evaluation
1. Run TODO-418 scenario (a) with `--features stream_ring_buffer` and without.
2. Compare flamegraphs.
3. If `to_vec()` in `maybe_flush_one_writable_stream` is Top-10 hotspot without feature:
   - Enable `stream_ring_buffer` by default in `Cargo.toml` for `throughput` feature.
   - Document decision.
4. If not a hotspot: leave feature off, document "not justified by profiling".

### Step 5: Validation
1. Re-run TODO-418 scenarios (b) and (c) with new `StreamingAdaptive` family.
2. Compare recovery latency (time from loss event to decoded packet) vs baseline.
3. Document in `docs/profiling/fec-streaming-results.md`.

## Files

- `src/fec/mod.rs` (continuous_fec_target, mode-switching, stream_every RTT coupling)
- `src/fec/internal.rs` (StreamingAdaptive wiring if new variant needed)
- `src/brain.rs` (RTT feed to FEC controller, if not already wired)
- `Cargo.toml` (stream_ring_buffer default if justified)
- `docs/profiling/fec-streaming-results.md` (new — validation results)

## SOTA References

- RFC 8681: Sliding Window Random Linear Code (RLC) FEC for QUIC
- RFC 9407: FEC Framework for QUIC
- Tetrys: Online FEC coding with sliding window (Lacan et al.)
- QuicFuscate existing: `fountain_codes.rs` (Robust Soliton LT), `internal.rs` (InterleavedEncoder)

## Notes

- **No RLNC** — deliberately excluded. Robust Soliton fountain + interleaved streaming is sufficient.
- No UI changes.
- Precondition: TODO-418 (profiling baseline) for "before" state comparison.
- TODO-409 is superseded by this task — `stream_ring_buffer` evaluation is integrated as Step 4.
- The `FecRuntimePolicy` env vars (`QUICFUSCATE_FEC_*`) should be extended, not replaced, for backward compat.

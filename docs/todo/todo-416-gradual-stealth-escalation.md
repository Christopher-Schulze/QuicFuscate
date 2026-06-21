---
id: TODO-416
title: Graduelle Stealth-Eskalation (3-Stufen-Rampe mit Hysterese)
severity: HIGH
phase: "2"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: [TODO-418]
supersedes: []
---

# TODO-416: Graduelle Stealth-Eskalation

## Problem

QuicFuscate's Intelligent stealth mode escalates **binarily** from Performance → AntiDpi on first probe detection:

- `escalate_to_anti_dpi_features()` (`src/stealth/mod.rs:5264`) activates all runtime overrides on **any** probe detection.
- No hysteresis: a single false-positive probe → immediate full overhead (padding + jitter + rotation).
- No de-escalation path: once escalated, the connection stays at AntiDpi level.
- No intermediate level: Performance (zero overhead) → AntiDpi (full overhead) with nothing in between.

The existing `INTELLIGENT_STEALTH_LEVEL_HINT` (`src/brain.rs:30`) already defines levels 0/1/2 but the escalation logic doesn't use them — it's a binary flip of `runtime_padding_forced`, `runtime_timing_forced`, `runtime_rotation_enabled` (all `AtomicBool`).

## Acceptance

1. **Three-level ramp** implemented:
   - **Level 0 (Performance)**: No padding, no jitter, no rotation. Near-zero overhead.
   - **Level 1 (Stealth)**: Padding active (configurable rate), no jitter, no rotation. Moderate overhead.
   - **Level 2 (AntiDpi)**: Padding + jitter + fingerprint rotation. Full overhead.
   - `INTELLIGENT_STEALTH_LEVEL_HINT` atomically set to 0/1/2 by `StealthBrain`.

2. **Hysteresis for escalation**:
   - Escalation 0→1: requires ≥3 probe detections within 60 seconds.
   - Escalation 1→2: requires ≥5 additional probe detections within 60 seconds (cumulative 8 in 120s).
   - Single probe detection does NOT trigger escalation — logged but no mode change.

3. **De-escalation path**:
   - De-escalation 2→1: 5 minutes with zero probe detections.
   - De-escalation 1→0: additional 5 minutes with zero probe detections (10 min total from Level 2).
   - De-escalation is conservative (long timeout) to avoid oscillation.

4. **Gradual intensity** (not binary):
   - `runtime_padding_forced` changed from `AtomicBool` to `AtomicU8` (0-100, representing percentage).
   - Level 0: padding = 0%.
   - Level 1: padding = 50% (configurable via `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1`).
   - Level 2: padding = 100%.
   - Jitter range scales similarly: Level 1 = 50% of `jitter_max_us`, Level 2 = 100%.
   - Rotation interval: Level 1 = no rotation, Level 2 = `fingerprint_rotation_interval` (default 120s).

5. **Brain-driven level calculation**:
   - `StealthBrain` computes escalation level from: probe count, probe recency, loss rate, RTT spikes.
   - Not just probe count — sustained bad network conditions can also justify Level 1.
   - Level hint published to `INTELLIGENT_STEALTH_LEVEL_HINT` atomic.

6. **Profiling validation** (from TODO-418):
   - Scenario (f): synthetic probe injection, measure escalation latency (time from probes to level change).
   - Measure throughput at each level: Level 0 vs Level 1 vs Level 2.
   - Document stealth tax per level in `docs/profiling/stealth-escalation-results.md`.

7. **Tests**:
   - Unit test: 1 probe → no escalation (stays Level 0).
   - Unit test: 3 probes in 60s → escalation to Level 1.
   - Unit test: 8 probes in 120s → escalation to Level 2.
   - Unit test: 5 min no probes from Level 2 → de-escalation to Level 1.
   - Unit test: `AtomicU8` padding rate scales correctly per level.
   - `cargo test --lib` green.

## Fix Plan

### Step 1: Change AtomicBool → AtomicU8 for intensity
1. In `src/stealth/mod.rs`, replace:
   - `runtime_padding_forced: AtomicBool` → `runtime_padding_rate: AtomicU8` (0-100).
   - `runtime_timing_forced: AtomicBool` → `runtime_timing_rate: AtomicU8` (0-100).
   - `runtime_rotation_enabled: AtomicBool` → `runtime_rotation_rate: AtomicU8` (0-100, threshold at >50 = active).
2. Update all read sites: `if flag.load()` → `if rate.load() > 0` (or threshold-based).
3. Update all write sites: `flag.store(true)` → `rate.store(percentage)`.

### Step 2: Implement escalation state machine
1. New struct `EscalationState` in `src/stealth/mod.rs` or `src/brain.rs`:
   ```rust
   struct EscalationState {
       current_level: AtomicU8,  // 0, 1, 2
       probe_count_window: SlidingWindowCounter,  // 60s window
       last_probe_time: AtomicU64,  // epoch ms
       last_escalation_time: AtomicU64,
   }
   ```
2. `on_probe_detected()`: increment counter, check thresholds, escalate if met.
3. `check_de_escalation()`: called periodically (every ACK or timer), de-escalates if quiet period exceeded.

### Step 3: Wire StealthBrain level calculation
1. In `src/brain.rs`, `StealthBrain::apply_policy`:
   - Read `EscalationState::current_level`.
   - Set `INTELLIGENT_STEALTH_LEVEL_HINT` to current level.
   - Adjust padding/jitter/rotation rates based on level.
2. Consider network conditions: if loss > 10% or RTT spike > 4x baseline, bump to at least Level 1 even without probes.

### Step 4: Update `escalate_to_anti_dpi_features()`
1. Replace binary escalation with level-based:
   - `escalate_to_level(1)` and `escalate_to_level(2)` methods.
   - Each level sets the appropriate rates (not all to 100%).
2. Remove the old `escalate_to_anti_dpi_features()` or make it call `escalate_to_level(2)`.

### Step 5: Config knobs
1. Add env overrides:
   - `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1` (default: 3)
   - `QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2` (default: 8)
   - `QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC` (default: 300)
   - `QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1` (default: 50)
2. Document in `DOCUMENTATION.md` stealth section.

### Step 6: Validation
1. Run TODO-418 scenario (f) with new escalation logic.
2. Measure: escalation latency, throughput per level, de-escalation behavior.
3. Document in `docs/profiling/stealth-escalation-results.md`.

## Files

- `src/stealth/mod.rs` (AtomicBool→AtomicU8, EscalationState, level-based methods)
- `src/brain.rs` (level calculation, INTELLIGENT_STEALTH_LEVEL_HINT wiring)
- `src/DOCUMENTATION.md` (config knobs, escalation behavior)
- `docs/profiling/stealth-escalation-results.md` (new — validation results)

## Risks

- **AtomicBool → AtomicU8**: All consumers must be updated. Missing a read site could cause padding to never activate (if checking `== true`) or always activate (if checking `!= 0`).
- **De-escalation**: Conservative timeout (5 min) prevents oscillation but means a brief probe burst causes 10 min of elevated overhead. Acceptable tradeoff.
- **Backward compat**: `Performance` and `Stealth` and `AntiDpi` explicit modes should NOT use the escalation state machine — only `Intelligent`/`Auto` mode. Explicit modes set their level directly.

## Notes

- No UI changes.
- Precondition: TODO-418 for "before" profiling and scenario (f) validation.
- This task makes the `Intelligent` mode actually intelligent — currently it's a binary tripwire.
- The `FingerprintRotationConfig` (`stealth/mod.rs:3314`) stays as-is — rotation is enabled/disabled by level, not restructured.
- `ActiveProbeDetector` patterns (GFW_TLS_Probe, DPI_QUIC_Scan) are NOT changed — only the response to detection changes.

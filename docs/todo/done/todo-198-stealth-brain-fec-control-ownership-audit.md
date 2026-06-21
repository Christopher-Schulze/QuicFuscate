# TODO-198: Stealth, Brain, and FEC Control Ownership Audit

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The adaptive runtime currently has three overlapping policy layers:

- `stealth.rs` configures default timing, padding, pacing, and mode behavior
- `brain.rs` reads transport/network signals, owns ACK adaptation and sensor fusion, and now hands Intelligent-mode stealth steering through a narrow runtime-policy delta instead of scattering raw actuator mapping logic across the observer
- `fec.rs` owns adaptive loss handling and still exposes transport-facing FEC sync through `FecTransportObserver`

The current design contains useful guardrails, but it does not yet prove clean ownership. Multiple layers can still touch the same knobs, which increases audit cost and the risk of subtle self-interference.

## Current Observed State
- `AdaptiveFec` owns loss-driven FEC mode and stream interval adaptation.
- `core.rs` feeds transport loss telemetry into `AdaptiveFec`.
- `FecTransportObserver` now owns only FEC-side cadence/redundancy observation and sync, not generic transport actuators.
- `StealthBrain` reads ECN, reorder, RTT, size/IAT divergence, keeps transport ACK adaptation live, and now limits Intelligent-mode stealth steering to a narrow runtime-policy delta that is derived through `stealth.rs` and applied centrally by `Connection`.
- `StealthManager` still sets default timing/padding/pacing baselines from mode/config.

## Progress Update (2026-03-17)
- The first ownership cut is now partially implemented:
  - `FecTransportObserver` no longer writes `ack_threshold` or `external_pacing`
  - `core.rs` no longer calls the FEC observer's generic policy hook every update tick
  - FEC observer integration now syncs only FEC-owned redundancy/cadence hints into transport/core
- The second ownership cut is now also partially implemented:
  - `Connection` now carries an explicit Intelligent-runtime gate for Brain-owned stealth actuator rewrites
  - `StealthBrain` no longer rewrites external pacing, timing, padding, mimic bias, granularity, or CC stealth profile on non-Intelligent connections
  - transport timing jitter now ignores Brain global timing hints unless the connection is flagged as Intelligent runtime
  - explicit transport overrides now lock the corresponding Brain actuator instead of being silently re-overridden at runtime
- The third ownership cut is now landed:
  - `stealth.rs` now owns the concrete Intelligent-mode runtime policy derivation for pacing, timing, padding, mimic bias, granularity, and CC profile
  - `brain.rs` now diff-checks and emits a narrow `StealthRuntimeDelta` instead of embedding the raw per-actuator mapping logic inline
  - `transport/connection.rs` now applies that delta through one central method instead of multiple scattered setter calls from the Brain observer
  - deterministic tests now cover clean-path and hostile-path Intelligent runtime policy derivation directly
- Deterministic regression coverage now proves:
  - FEC hint sync leaves ACK threshold and external pacing unchanged
  - `QuicFuscateConnection::update_state()` no longer rewrites ACK/pacing through the FEC path when the Brain is disabled
  - non-Intelligent connections preserve their preset timing/padding baselines even when the Brain observer runs
  - Intelligent connections still receive live Brain steering for pacing, padding, and timing hints
  - explicit transport overrides freeze the corresponding Brain actuator path
- Final forensic closeout on 2026-03-17 confirmed:
  - `stealth.rs` still writes only preset/config baselines during transport configuration construction
  - `fec.rs` no longer owns generic transport actuators in live runtime paths; the remaining actuator writes there are test-only assertions
  - the removed `TIMING_JITTER_HINT_US` path was the last redundant Intelligent-mode timing side channel; timing now flows only through the live `StealthRuntimeDelta` and connection runtime config
  - the retained hint channels are now limited to FEC cadence/redundancy and Intelligent stealth-level escalation, which are advisory and single-owner rather than competing actuator writers

## Concrete Ownership Map to Resolve
- `ack_threshold`: baseline in `stealth.rs`, live transport adaptation in `brain.rs`, but explicit ACK overrides now lock Brain writes
- `external_pacing`: baseline in `stealth.rs`, live Intelligent-only overrides from `brain.rs`, but explicit pacing/jitter overrides now lock Brain writes
- `stealth padding strategy` / `max padding`: baseline in `stealth.rs`, live overrides from `brain.rs`, but explicit padding-family overrides now lock Brain writes
- `timing jitter / mimic bias / granularity`: baseline in `stealth.rs`, live overrides from `brain.rs`, but explicit timing/padding-family overrides now lock Brain writes
- `FEC cadence / redundancy`: native owner is `AdaptiveFec`, but hints still arrive from `brain.rs` and transport observer glue

## First Surgical Cut
1. Remove `ack_threshold` and `external_pacing` writes from `FecTransportObserver`. Completed on 2026-03-17.
2. Keep FEC ownership inside `fec.rs` for interval/redundancy decisions and expose only a narrow telemetry surface upward. Partially completed on 2026-03-17 through FEC-only hint sync.
3. Replace direct multi-knob writes from `brain.rs` with a smaller stealth policy handoff so `stealth.rs` becomes the sole runtime policy owner for stealth actuators. Completed on 2026-03-17 through a `StealthRuntimePolicy` + `StealthRuntimeDelta` handoff.
4. Add deterministic scenario tests proving that timing, padding, pacing, and FEC no longer have parallel writers.

## Recommended Target Model
1. **FEC owns FEC.**
   - mode, redundancy, stream interval, and decoder/encoder family decisions stay in `fec.rs`
   - Brain may consume FEC telemetry, but it should not micromanage FEC actuators
2. **Stealth owns stealth capability wiring and default mode policy.**
   - presets, feature enablement, compatibility surfaces, and base policies stay in `stealth.rs`
3. **Brain owns sensor fusion and high-level adaptive coordination only.**
   - it should emit a narrow policy object or escalation level, not directly twiddle many raw knobs across subsystems
4. **One owner per actuator.**
   - timing
   - padding
   - external pacing
   - FEC cadence
   - fronting/mimic bias

## Fix Plan
1. Inventory every actuator and every writer.
2. Define a single owner for each one.
3. Convert direct writes into a narrower policy handoff where needed.
4. Add deterministic tests and trace outputs proving that layers do not fight or cancel each other.
5. Remove any feature that is redundant, dominated, or mathematically counterproductive.

## Acceptance Criteria
- [x] Every adaptive actuator has one canonical owner.
- [x] Brain no longer contains hidden parallel logic for FEC decisions if FEC already owns them.
- [x] No retained stealth feature remains without a clear, measurable role.
- [x] Tests demonstrate non-destructive interaction between timing, padding, pacing, and FEC adaptation.

## Dependencies
- TODO-197 for validation surfaces
- TODO-195 for final documentation wording

## Affected Files
- `src/brain.rs`
- `src/fec.rs`
- `src/stealth.rs`
- `src/core.rs`
- `src/transport/config.rs`
- `src/transport/connection.rs`
- `docs/DOCUMENTATION.md`

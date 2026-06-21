# TODO 88: Continuous FEC Auto Controller and Internal Mode Collapse

## Scope
- `src/fec.rs`
- FEC-facing telemetry and controller hints
- FEC runtime control and transition logic
- FEC tests, docs, and runtime validation

## Problem Statement
- The public FEC contract is already correct: `Off` / `Auto`.
- Internally, the control model still thinks primarily in a coarse explicit mode ladder.
- That ladder works, but it is not yet the cleanest architecture for the actual product goal:
  - essentially zero FEC cost on clean paths
  - graceful continuous strengthening under loss, burstiness, or disturbance
  - maximum stability under severe conditions, even at higher CPU cost

## Desired End State
- Public FEC contract remains exactly:
  - `Off`
  - `Auto`
- Internal FEC control becomes continuous and policy-driven:
  - one protection-pressure model
  - one cost/stability controller
  - backend-family escalation only when justified
- Stable links stay on a real near-zero-overhead path.
- Disturbed links climb continuously through stronger protection behavior.
- Streaming and Fountain remain retained canonical capability, but as internal escalation families rather than the primary user-visible mental model.

## Current Truth Snapshot
- `src/fec.rs` still encodes the internal primary control story as a discrete `FecMode` ladder:
  - `Zero`
  - `Light`
  - `Normal`
  - `Streaming`
  - `Medium`
  - `Strong`
  - `Extreme`
  - `Ultra`
  - `Fountain`
- `internal::ModeManager` still owns the main ladder logic through:
  - `target_mode_for_loss(...)`
  - `mode_rank(...)`
  - `params_for(...)`
  - `overhead_for(...)`
  - `update(...)`
- `AdaptiveFec::update_mode(...)` still consumes that discrete result and then layers policy overrides:
  - `force_on`
  - extreme-loss -> `Fountain`
  - disturbance -> `Streaming`
- Clean-link efficiency is already partially right:
  - `AdaptiveFec::on_send(...)` has a real `Zero` fast path with immediate pass-through.
- The missing piece is therefore not capability.
- The missing piece is a cleaner continuous controller architecture.

## Target Architecture

### External Contract
- Keep exactly:
  - `Off`
  - `Auto`
- No additional user-visible mode story returns.

### Internal Split
- Introduce one primary controller model that reasons in terms of:
  - path pressure
  - recovery urgency
  - cost budget
  - backend family
- The control path should produce a structured target, not primarily a coarse named mode.

### Proposed Internal Owner Model
- `FecProtectionInputs`
  - smoothed loss
  - instantaneous loss
  - disturbance/burst signal
  - clean-link stability
  - brain hints where still justified
  - compute profile / hardware profile
- `FecProtectionPressure`
  - normalized protection demand, monotonic and bounded
- `FecProtectionTarget`
  - target redundancy
  - target cadence
  - target effective window
  - target interleave depth
  - target backend family
- `FecBackendFamily`
  - `Zero`
  - low-cost block recovery
  - heavy block recovery
  - `Streaming`
  - `Fountain`
- `FecTransitionPlan`
  - bounded transition length
  - escalation priority
  - de-escalation hysteresis

### Internal Family Mapping Rule
- Discrete internals may still exist as machine-room backend labels for implementation reuse.
- They must stop being the primary control abstraction.
- The controller should decide pressure and target behavior first, then map to backend family second.

### Efficiency Rule
- When the path is effectively clean:
  - no repair generation
  - no unnecessary encoder/decoder churn
  - no avoidable periodic work
  - maintain the existing practical `Zero` fast path
- As pressure rises:
  - scale protection continuously before jumping families
  - spend additional CPU only when it actually buys stability

### Stability Rule
- Disturbance and burst-loss conditions should escalate earlier into low-latency recovery paths.
- Sustained extreme loss should still escalate into `Fountain`.
- If CPU must rise to keep the link alive, stability wins.

## Non-Negotiables
- Stable links must keep a real zero-cost or near-zero-cost path.
- Severe conditions must prefer stability over CPU thrift.
- Streaming and Fountain must remain available.
- No weakening of existing recovery capability is allowed.
- External product contract must stay `Off` / `Auto`.
- No UI/CLI story expansion is allowed.

## Work Breakdown
- [x] Inventory the current ladder-driven control logic and separate:
  - pressure estimation
  - redundancy/cadence policy
  - backend-family selection
  - transition policy
- [x] Design a continuous internal protection controller with explicit owner types and bounded transitions.
- [x] Rework `AdaptiveFec` and `ModeManager` ownership so controller state is primary and discrete families are secondary implementation detail.
- [x] Preserve or improve the current zero-overhead fast path.
- [x] Preserve or improve disturbance and extreme-loss escalation to Streaming/Fountain.
- [x] Rework tests to validate continuous escalation/de-escalation behavior, stability retention, and no-regression clean-link cost.
- [x] Update canonical docs after implementation.

## Detailed Execution Plan

### Phase 1: Control-Plane Separation
- Extract controller logic from the current ladder-first flow in:
  - `internal::ModeManager`
  - `AdaptiveFec::update_mode(...)`
- Keep existing runtime behavior compiling while introducing a new internal target structure.

### Phase 2: Continuous Target Model
- Compute target behavior from normalized inputs instead of direct named-mode thresholds.
- Explicitly derive:
  - redundancy target
  - stream cadence target
  - effective block/window target
  - escalation family

### Phase 3: Family Mapping and Transition Cleanup
- Keep the retained machine-room families.
- Map controller targets into those families through one owner.
- Retune cross-fade / transition lengths so they follow controller urgency rather than coarse hardcoded ladder jumps where possible.

### Phase 4: Regression Hardening
- Add focused controller-behavior tests.
- Keep the existing recovery/capability tests.
- Add clean-link efficiency assertions so the zero-overhead promise is actually guarded.

## Acceptance Criteria
- [x] External FEC product contract is still exactly `Off` / `Auto`.
- [x] Clean-link behavior keeps effectively zero FEC overhead and minimal CPU work.
- [x] Internal control no longer reads like a coarse visible mode ladder as the primary design.
- [x] Strong-loss and burst-loss cases still escalate into robust retained backend families, including Streaming/Fountain where appropriate.
- [x] Transition behavior remains seamless and does not tear or thrash.
- [x] Validation proves no regression in retained recovery capability.

## Current Progress
- [x] The first controller-side owner types now exist in `src/fec.rs`:
  - `FecBackendFamily`
  - `FecProtectionPressure`
  - `FecProtectionTarget`
  - helper family-mapping functions
  - `continuous_fec_target(...)`
- [x] `ModeManager::target_mode_for_loss(...)` no longer hardcodes the old threshold ladder directly; it now consumes the new controller target as the first internal convergence step.
- [x] `AdaptiveFec::update_mode(...)` now consumes the new controller target for backend-family transitions, window targeting, and streaming-cadence steering.
- [x] `ModeManager` now owns a target-first parameter seam:
  - `target_for_loss(...)`
  - `params_for_target(...)`
  - family-stability-based switching
  - same-family window retargeting
- [x] The retained mode-compatibility helpers (`params_for(...)`, mode mapping, overhead mapping) now derive from one target mapping instead of carrying a separate primary ladder truth.
- [x] Cross-fade sizing now has a target/family-aware owner:
  - `compute_cross_fade_target_len(...)`
- [x] Streaming cadence and forced transitions now also route through the controller target:
  - `stream_interval_target(...)`
  - `transition_to_target(...)`
  - `force_streaming_mode(...)` now resolves through target mapping instead of a direct mode-first path
- [x] Encoder/decoder backend construction now routes through controller-family truth instead of the old direct mode-zoo switch:
  - low-cost block -> GF4 or GF8 via target mapping
  - heavy block -> AdaptiveRS or GF16 via target mapping
- [x] Switch escalation/de-escalation ranking now routes through `target_rank(...)` instead of the old standalone mode-rank ladder.
- [x] Runtime-plan initialization now also resolves through target mapping:
  - initial mode/window selection
  - force-on promotion from zero
  - initial cross-fade sizing
  - initial streaming-family flag
- [x] The retained AdaptiveRS machine-room path now also resolves its GF8/GF16 choice from target truth instead of a direct old mode bucket.
- [x] Focused controller regression coverage now exists for:
  - clean-link zero family
  - disturbance -> streaming family
  - extreme loss -> fountain family
  - target-parameter mapping
- [x] Additional controller coverage now exists for stream-cadence targeting.
- [x] Additional controller coverage now exists for:
  - backend-family construction mapping
  - target-rank monotonicity
  - runtime-plan force-on promotion
  - AdaptiveRS GF16 selection from target truth
- [x] The old machine-room `FecMode` ladder now survives only as a compatibility/backend label set and no longer acts as the active control owner.

## Validation Matrix
- Rust unit/integration coverage in `src/fec.rs` must prove:
  - zero-loss path stays on the true near-zero-cost path
  - low-but-real loss raises protection smoothly without over-escalation
  - disturbance prefers lower-latency recovery before full rateless escalation
  - sustained severe loss reaches `Fountain`
  - recovery/de-escalation does not flap
- Required validation commands before closure:
  - `cargo check`
  - `cargo test --features rust-tests fec`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`

## Notes
- The goal is not to make FEC simpler by removing power.
- The goal is to make the internal control model more disciplined, more continuous, and more faithful to the actual product requirement:
  - spend as little as possible
  - survive as much as possible
  - never drop stability when the path turns hostile
- March 9, 2026:
  - first controller-side convergence step is implemented and validated
  - the old ladder has not been fully removed yet, but control decisions are no longer purely threshold-hardcoded at the top seam
  - second convergence step is now implemented and validated:
    - `ModeManager` switches on controller-family/target truth rather than a standalone hardcoded mode ladder
    - same-family window retargeting is now possible without inventing a fake mode jump
    - target-to-params and target-aware cross-fade sizing are now explicit owners
  - final closure:
    - the productive auto-FEC path is now target-first across target derivation, params, cadence, transitions, backend-family mapping, runtime-plan initialization, switch ranking, and AdaptiveRS GF-width selection
    - retained `FecMode` names remain only as machine-room compatibility/backend labels and no longer own the active control architecture
    - validation is green:
      - `cargo check`
      - `cargo test --features rust-tests continuous_target --lib`
      - `cargo test --features rust-tests mode_manager_ --lib`
      - `cargo test --features rust-tests backend_family_mapping_preserves_ --lib`
      - `cargo test --features rust-tests stream_interval_target_tracks_controller_target --lib`
      - `cargo test --features rust-tests target_rank_monotonic_from_clean_to_extreme --lib`
      - `cargo test --features rust-tests runtime_plan_force_on_promotes_zero_target --lib`
      - `cargo test --features rust-tests adaptive_rs_gf16_selection_comes_from_target_truth --lib`
      - `cargo clippy --all-targets --all-features -- -W clippy::all`

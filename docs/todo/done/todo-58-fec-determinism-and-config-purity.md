# TODO 58: FEC Determinism and Config Purity

## Scope
- Adaptive FEC construction and policy logic across:
  - `src/fec.rs`
  - related runtime wiring in `src/core.rs`
  - supporting telemetry/config touchpoints

## Problem Statement (Audit Evidence, 2026-03-05)
- `AdaptiveFec::new()` currently mixes explicit config with:
  - env overrides
  - global thread-pool decisions
  - CPU-profile heuristics
  - global memory-pool side effects
  - Evidence: `src/fec.rs:4698`, `:4700`, `:4708`, `:4711`, `:4751`, `:4763`
- This makes FEC behavior less reproducible and harder to reason about or benchmark from `FecConfig` alone.
- Some enum variants are preserved primarily for compatibility rather than clear runtime policy.

## Objectives
- Make FEC behavior primarily config-driven and deterministic.
- Isolate ambient process state from core FEC construction where possible.
- Keep effectiveness tuning explicit rather than hidden in global/environment behavior.

## Work Breakdown
### A. Evidence and Classification
- [x] Inventory all ambient inputs that influence FEC behavior during construction and mode management.
- [x] Classify which inputs are truly required and which are legacy/ambient debt.

### B. Constructor Refactor Plan
- [x] Separate pure config/policy derivation from global resource initialization.
- [x] Reduce or eliminate env-driven side effects in constructor paths.
- [x] Clarify which CPU-profile heuristics are canonical policy versus optional tuning.

### C. Runtime Contract
- [x] Ensure FEC behavior can be explained from config plus a small, explicit set of runtime capabilities.
- [x] Revisit compatibility-only mode variants and their place in the real automatic policy.

### D. Validation
- [x] Add deterministic tests around allowed ambient inputs.
- [x] Add benchmarkability/reproducibility notes and checks where relevant.

## Acceptance Criteria
- [x] `AdaptiveFec` behavior is predictable from explicit inputs.
- [x] Constructor no longer hides large policy changes behind env/global state.
- [x] FEC auto-selection and resource behavior are testable and explainable.

## Deliverables
- [x] FEC constructor policy map.
- [x] Refactor plan and implementation tracking for ambient-state reduction.
- [x] Deterministic tests for remaining allowed runtime heuristics.

## Progress Notes
- 2026-03-05: Created from deep review after adaptive FEC runtime wiring work highlighted remaining constructor-level ambient complexity.
- 2026-03-08: Continued constructor/resource isolation in `src/fec.rs` by turning the remaining Rayon setup into an explicit `FecRayonGlobalPolicy` (`Default` vs `ThreadCap(n)`) owned by `FecGlobalResources` instead of an ad hoc optional env parse embedded directly in the initialization side effect. Validation remains green with `cargo check` and `cargo clippy --all-targets --all-features -- -W clippy::all`.
- 2026-03-08: Closed the remaining retained observer heuristic seam by modeling `FecObserverProfilePolicy` explicitly (`Explicit(profile)` vs `Ambient(profile)`) inside `FecObserverAmbientInputs`. This keeps the allowed transport-profile heuristic as a named snapshot policy instead of a loose mix of env, platform, and container checks. With constructor/runtime policy snapshots, explicit global-resource policy, and deterministic regression coverage in place, TODO 58 is complete.

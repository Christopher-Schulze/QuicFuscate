---
id: TODO-483
title: Brain policy target cache hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-468, TODO-479, TODO-482]
---

# TODO-483: Brain policy target cache hotpath

## Status

DONE

## Context

The StealthBrain policy loop is a real runtime hot path: transport observers can
call `apply_policy()` while a connection is active, and the policy output owns
ACK, pacing, timing, padding, cover, and FEC hints. The previous code already
reused histogram scratch buffers, but still rebuilt the JS-divergence target
distributions on every policy tick.

Those target distributions depend only on the configured histogram bin counts,
so per-tick allocation and recomputation were unnecessary.

## Desired Outcome

- Measure the real `StealthBrain::apply_policy()` observer path in Criterion.
- Cover clean observer, intelligent clean, and pressure/actuating cases.
- Remove per-policy-tick target-vector allocation without changing stealth
  semantics.
- Preserve existing Brain ownership rules: no mid-session persona mutation,
  only runtime actuators.
- Avoid product UI, frontend, Docker, Kubernetes, Helm, or deployment changes.

## Implementation

- `src/brain.rs`: cached `size_profile_target` and `iat_profile_target` inside
  `StealthBrainState` during construction.
- `src/brain.rs`: `apply_policy()` now reuses those cached target
  distributions when computing JS divergence.
- `src/transport/connection.rs`: added a bench-only
  `bench_set_brain_runtime()` helper under `feature = "benches"`.
- `scripts/benchmarks/ci_regression.rs`: added `brain_apply_policy` benchmark
  cases for clean observer, intelligent clean, and pressure/actuating runtime
  policy application.

## Verification

- Local: `cargo fmt --all -- --check`
- Local: `cargo clippy --lib --features rust-tests -- -D warnings`
- Local: `cargo test --lib --features rust-tests brain_can_steer_stealth_runtime_when_connection_is_intelligent`
- Local: `cargo test --lib --features rust-tests brain_preserves_non_intelligent_preset_stealth_knobs`
- Local: `cargo test --lib --features rust-tests`
- Local: `cargo bench --bench ci_regression --features benches brain_apply_policy -- --sample-size 10 --warm-up-time 1 --measurement-time 2`
- Broderick: `cargo test --lib --features rust-tests brain_can_steer_stealth_runtime_when_connection_is_intelligent`
- Broderick: `cargo test --lib --features rust-tests brain_preserves_non_intelligent_preset_stealth_knobs`
- Broderick: `cargo bench --bench ci_regression --features benches brain_apply_policy -- --sample-size 10 --warm-up-time 1 --measurement-time 2`

Local Criterion A/B result:

- `clean_observer`: `496.68 ns` baseline to `316.84 ns` optimized.
- `intelligent_clean`: `503.93 ns` baseline to `353.00 ns` optimized.
- `intelligent_pressure_actuating`: `474.92 ns` baseline to `346.41 ns`
  optimized.

Broderick Criterion A/B result:

- `clean_observer`: `1.1617 us` baseline to `640.99 ns` optimized.
- `intelligent_clean`: `1.1688 us` baseline to `642.56 ns` optimized.
- `intelligent_pressure_actuating`: `1.1321 us` baseline to `599.49 ns`
  optimized.

## Completion Criteria

- [x] Brain policy application has a dedicated Criterion benchmark.
- [x] Per-tick JS-divergence target-vector allocation is removed.
- [x] Brain runtime actuator semantics stay unchanged.
- [x] Local fmt, clippy, targeted tests, full lib tests, and benchmark pass.
- [x] Broderick targeted tests and benchmark pass with A/B improvement proof.

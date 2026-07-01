---
id: TODO-482
title: Transport stealth padding decision fastpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-401, TODO-416, TODO-479]
---

# TODO-482: Transport stealth padding decision fastpath

## Status

DONE

## Context

TODO-479 moved non-security stealth padding and jitter decisions from secure OS
randomness to a secure-seeded fast RNG. The next audit found that the real QUIC
transport padding decision path was not directly measured by the Criterion
suite: `padding_gen` covered TLS record padding in `optimize::stealth`, not
`Connection::compute_stealth_padding()`.

The same pass found a clean zero-rate inefficiency: when
`stealth_padding_rate == 0`, the legacy probabilistic path still sampled a
random roll before returning `0`.

## Desired Outcome

- Add a Criterion benchmark for the real transport stealth-padding decision
  path.
- Cover disabled, zero-rate, adaptive, browser-mimic, and probabilistic random
  cases.
- Preserve FullPadding and ConstantRate behavior, where traffic-analysis defense
  modes intentionally ignore `stealth_padding_rate`.
- Avoid changing product UI, frontend, Docker, Kubernetes, Helm, or deployment
  manifests.

## Implementation

- `src/transport/connection.rs`: added bench-only helpers for configuring and
  invoking transport stealth-padding decisions under `feature = "benches"`.
- `src/transport/connection.rs`: added a direct `stealth_padding_rate == 0`
  exit in `compute_stealth_padding()` after traffic-analysis defense precedence
  and before any RNG sampling.
- `scripts/benchmarks/ci_regression.rs`: added
  `transport_stealth_padding_decision` with disabled, `adaptive_0pct`,
  `adaptive_100pct`, `browser_mimic_100pct`, and `random_50pct` cases.

## Verification

- Local: `cargo fmt --all -- --check`
- Local: `cargo test --lib --features rust-tests test_off_mode_preserves_probabilistic_padding`
- Local: `cargo test --lib --features rust-tests test_stealth_padding_configuration`
- Local: `cargo clippy --lib --features rust-tests -- -D warnings`
- Local: `cargo test --lib --features rust-tests`
- Local: `cargo bench --bench ci_regression --features benches transport_stealth_padding_decision -- --sample-size 10 --warm-up-time 1 --measurement-time 2`
- Broderick: `cargo test --lib --features rust-tests test_off_mode_preserves_probabilistic_padding`
- Broderick: `cargo test --lib --features rust-tests test_stealth_padding_configuration`
- Broderick: `cargo bench --bench ci_regression --features benches transport_stealth_padding_decision -- --sample-size 10 --warm-up-time 1 --measurement-time 2`

Broderick benchmark result:

- `disabled`: `4.2623 ns` median.
- `adaptive_0pct`: `4.3014 ns` median.
- `adaptive_100pct`: `5.3976 ns` median, normal mode change within Criterion
  noise threshold.
- `browser_mimic_100pct`: `16.109 ns` median, normal mode change within
  Criterion noise threshold.
- `random_50pct`: `15.150 ns` median, normal mode change within Criterion
  noise threshold.

An attempted replacement of `fast_rand_u64_uniform()` with a Lemire
multiply-high mapper was rejected before commit because local A/B measurements
regressed adaptive and random padding cases. It is intentionally not shipped.

## Completion Criteria

- [x] Transport padding decision path has a dedicated Criterion benchmark.
- [x] Zero-rate padding exits without RNG sampling.
- [x] Traffic-analysis defense modes still ignore the probabilistic rate gate.
- [x] Local fmt, clippy, full lib tests, targeted tests, and benchmark pass.
- [x] Broderick targeted tests and benchmark pass.

---
id: TODO-492
title: Transport adaptive padding power-of-two fastpath
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-482, TODO-489]
---

# TODO-492: Transport adaptive padding power-of-two fastpath

## Context

Broderick CI-hotpath measurements after TODO-491 showed the transport and Brain
groups stable or faster, with one small regression in
`transport_stealth_padding_decision/adaptive_100pct`: `5.62 ns`, about `3.9%`
slower than its previous Criterion baseline. The absolute cost was tiny, but
the function is a per-packet decision point when adaptive stealth padding is
enabled.

Adaptive padding uses `stealth_adaptive_granularity`, defaulting to `64`. Before
this task, the hot path always used `%` to compute the boundary remainder even
when the granularity was a power of two.

## Desired Outcome

- Keep adaptive padding behavior identical for all configured granularities.
- Optimize the default and common power-of-two granularities without changing
  stealth policy.
- Preserve non-power-of-two custom granularity behavior with a regression test.
- Avoid touching UI, frontend, Docker, deployment manifests, or unrelated transport
  behavior.

## Implementation

- `Connection::compute_stealth_padding()` now computes the adaptive remainder
  with `cur_pt_len & (granularity - 1)` when `granularity.is_power_of_two()`.
- Non-power-of-two granularities still use `cur_pt_len % granularity`.
- The `min()` cap is replaced with a direct branch in the adaptive path to keep
  the hot branch compact.
- Added a regression test for `stealth_adaptive_granularity = 30`, including
  aligned and budget-capped cases.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests test_padding_adaptive_non_power_of_two_granularity` pass.
- Local: `cargo clippy --workspace --all-targets -- -D warnings` pass.
- Broderick: `cargo test --lib --features rust-tests test_padding_adaptive_non_power_of_two_granularity` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- 'transport_stealth_padding_decision' --sample-size 10 --measurement-time 1` pass.

## Criterion Evidence

Broderick ARM/AArch64 `transport_stealth_padding_decision` after the fastpath:

| Case | Median | Result |
|------|--------|--------|
| `disabled` | `4.26 ns` | noise |
| `adaptive_0pct` | `4.31 ns` | noise |
| `adaptive_100pct` | `5.23 ns` | improved from `5.62 ns` |
| `browser_mimic_100pct` | `16.10 ns` | slightly improved |
| `random_50pct` | `15.29 ns` | noise |

## Notes

This is intentionally a small hotpath change. It does not change which packets
receive padding, how much padding they receive, or how stealth modes escalate.
It only removes division from the common adaptive boundary calculation.

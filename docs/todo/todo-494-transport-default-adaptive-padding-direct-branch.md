---
id: TODO-494
title: Transport default adaptive padding direct branch
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-492]
---

# TODO-494: Transport default adaptive padding direct branch

## Context

Broderick CI-regression runs after TODO-493 showed the transport padding
decision group stable overall, but the product-default adaptive path still sat
around `5.49 ns` for `adaptive_100pct`. TODO-492 removed division for
power-of-two adaptive granularities, but the default `64` path still paid the
generic custom-granularity dispatch cost (`max(1)` plus `is_power_of_two()`).

## Desired Outcome

- Keep adaptive padding behavior identical.
- Optimize the default 64-byte adaptive padding path without adding config
  state or broad refactoring.
- Preserve custom power-of-two and non-power-of-two granularity behavior.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- `Connection::compute_stealth_padding()` now special-cases
  `stealth_adaptive_granularity == 64`.
- The default branch computes `rem = cur_pt_len & 63` and `pad = 64 - rem`
  directly.
- Custom granularities keep the existing normalized generic branch:
  `granularity.max(1)`, bit-mask for power-of-two values, modulo for
  non-power-of-two values.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Local: `cargo clippy --workspace --all-targets -- -D warnings` pass.
- Broderick: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- 'transport_stealth_padding_decision' --sample-size 30 --measurement-time 2` pass.

## Criterion Evidence

Broderick ARM/AArch64 `transport_stealth_padding_decision` after the direct
default branch:

| Case | Median | Result |
|------|--------|--------|
| `disabled` | `4.26 ns` | noise |
| `adaptive_0pct` | `4.30 ns` | noise |
| `adaptive_100pct` | `5.27 ns` | improved from about `5.49 ns` |
| `browser_mimic_100pct` | `16.20 ns` | slightly improved |
| `random_50pct` | `15.22 ns` | noise |

## Notes

This keeps TODO-492's semantic guarantees. It only removes generic dispatch from
the overwhelmingly common product default.

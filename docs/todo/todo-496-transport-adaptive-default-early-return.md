---
id: TODO-496
title: Transport adaptive default early return
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-492, TODO-494, TODO-495]
---

# TODO-496: Transport adaptive default early return

## Context

Broderick rescreening after TODO-495 found that the TODO-494 `5.27 ns`
`adaptive_100pct` measurement was not stable. A focused 40-sample rerun on
`0add68c` measured the product-default adaptive padding decision at about
`5.505 ns`. The direct 64-byte branch was present, but it still lived behind the
generic max/match strategy dispatch.

## Desired Outcome

- Keep adaptive padding behavior identical.
- Move the product-default adaptive branch (`strategy=3`, `granularity=64`) out
  of the generic strategy dispatch.
- Preserve custom power-of-two and non-power-of-two granularity behavior.
- Improve the `transport_stealth_padding_decision` default adaptive path on
  Broderick with a stable focused benchmark.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- `Connection::compute_stealth_padding()` now caches the strategy byte once.
- The default adaptive branch returns before generic `max`/`match` dispatch:
  `rem = cur_pt_len & 63`, `max = stealth_padding_max_size.min(budget)`, and
  `(64 - rem).min(max)`.
- The generic adaptive branch now handles custom granularities only, keeping
  `granularity.max(1)`, bit-mask for power-of-two values, and modulo for
  non-power-of-two values.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Broderick: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- 'transport_stealth_padding_decision' --sample-size 40 --measurement-time 2` pass.

## Criterion Evidence

Broderick ARM/AArch64 `transport_stealth_padding_decision` after the early
return:

| Case | Median | Result |
|------|--------|--------|
| `disabled` | `3.68 ns` | about 13.5% faster |
| `adaptive_0pct` | `3.82 ns` | about 11.3% faster |
| `adaptive_100pct` | `4.67 ns` | about 15.1% faster |
| `browser_mimic_100pct` | `16.19 ns` | about 1.2% faster |
| `random_50pct` | `15.03 ns` | about 1.7% faster |

## Notes

This also corrects the TODO-494 evidence trail: the earlier `5.27 ns` result
was an unstable sample. The durable improvement is this early-return branch,
measured against the stable `0add68c` baseline around `5.505 ns`.

---
id: TODO-499
title: FEC send reuse hotpath benchmark truth
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-480, TODO-488, TODO-498]
---

# TODO-499: FEC Send Reuse Hotpath Benchmark Truth

## Context

Broderick screening after TODO-498 showed `fec_systematic_hot_path/zero/*`
around `1.08 us`, which contradicted the clean Zero-mode send path and the
`fec_encode_pipeline/zero/*` results around `219-351 ns`.

The benchmark name was misleading: `fec_systematic_hot_path` uses
`iter_batched()` to create a fresh `AdaptiveFec` and output buffer for each
sample. That is a useful cold-start guard, but it is not the production send
hot path. The production path keeps a long-lived `AdaptiveFec` instance and
reuses caller-owned output scratch via `on_send_into()`.

## Desired Outcome

- Keep the existing cold-start benchmark for setup-cost visibility.
- Add a production-send benchmark with persistent FEC state and reusable output.
- Make benchmark comments distinguish cold-start from hot-path measurement.
- Capture Broderick evidence for all FEC modes and realistic packet sizes.
- Avoid runtime behavior changes unless the new measurement exposes a real bug.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Renamed the `bench_fec_systematic_hot_path` comment from hot-path semantics to
  cold-start semantics without changing the existing benchmark group name.
- Added `bench_fec_send_reuse_hot_path`.
- The new benchmark keeps one `AdaptiveFec` instance per mode/size, reuses one
  output `Vec`, advances packet IDs, and calls `AdaptiveFec::on_send_into()`.
- Registered the new benchmark in `criterion_group!(fec_pipeline_benches, ...)`.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Broderick: `cargo bench --bench fec_pipeline --features benches --
  fec_send_reuse_hot_path` pass.

## Criterion Evidence

Broderick ARM/AArch64 `fec_send_reuse_hot_path`:

| Mode | 64B | 256B | 1400B | 4KB |
|------|-----|------|-------|-----|
| Zero | `195.78 ns` | `198.97 ns` | `233.37 ns` | `328.44 ns` |
| Light | `492.98 ns` | `618.86 ns` | `1.7190 us` | `4.1414 us` |
| Normal | `709.81 ns` | `762.10 ns` | `1.1081 us` | `1.8691 us` |
| Medium | `382.16 ns` | `375.03 ns` | `402.38 ns` | `506.61 ns` |
| Strong | `385.99 ns` | `380.38 ns` | `408.48 ns` | `506.25 ns` |
| Streaming | `342.58 ns` | `343.78 ns` | `380.88 ns` | `484.88 ns` |

## Notes

The new benchmark did not expose a runtime regression. It exposed a measurement
truth issue: the cold-start guard was being interpreted as a hot-path send
benchmark. Medium, Strong, and Streaming are cheaper on average than Light and
Normal in this measurement because their product windows and emission cadence
amortize repair work differently.

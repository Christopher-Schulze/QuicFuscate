---
id: TODO-488
title: FEC benchmark product-window calibration
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-480, TODO-484]
---

# TODO-488: FEC benchmark product-window calibration

## Context

The `fec_encode_pipeline` benchmark previously constructed mode-specific
configs from `FecConfig::default()`. That library default uses large synthetic
mode windows such as Strong k512, while production paths build FEC config from
the Engine section (`FecConfig::from_engine_section()` / `product_default()`)
with product defaults:

- `window_good = 10`
- `window_fair = 30`
- `window_poor = 50`

This made Criterion output easy to misread: a synthetic Strong k512 repair burst
looked like a product hotpath stall, even though production Strong uses k50 by
default.

## Desired Outcome

- Make FEC Criterion mode variants use product-default FEC windows.
- Separate reusable-output systematic-send cost from block repair-burst cost.
- Measure repair bursts across Light, Normal, Medium, and Strong product
  windows instead of only Normal k64.
- Preserve the existing compatibility `fec_encode_pipeline` group.

## Implementation

- Updated `config_with_mode()` in `benches/fec_pipeline.rs` to start from
  `FecConfig::product_default()` and override only `initial_mode`.
- Added `window_size_for_mode()` so burst benchmarks label the actual product
  window (`k10`, `k30`, `k50`, etc.).
- Added `fec_systematic_hot_path`:
  - uses `AdaptiveFec::on_send_into()`;
  - reuses output allocation;
  - creates a fresh FEC instance per measured packet via Criterion setup so the
    measured packet never completes a repair window.
- Expanded `fec_window_fill_burst`:
  - Light k16;
  - Normal k10;
  - Medium k30;
  - Strong k50.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Local: `cargo bench --bench fec_pipeline --features benches fec_systematic_hot_path/strong/1400B -- --sample-size 10 --warm-up-time 1 --measurement-time 1` pass.
- Local: `cargo bench --bench fec_pipeline --features benches fec_window_fill_burst -- --sample-size 10 --warm-up-time 1 --measurement-time 1` pass.
- Broderick: `cargo bench --bench fec_pipeline --features benches fec_systematic_hot_path/strong/1400B -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.
- Broderick: `cargo bench --bench fec_pipeline --features benches fec_window_fill_burst -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.

## Criterion Evidence

Broderick ARM/AArch64 product-window measurements after the calibration:

| Case | Result |
|------|--------|
| `fec_systematic_hot_path/strong/1400B` | `4.37 us` median |
| `fec_window_fill_burst/light/k16_repair_burst` | `32.7 us` median |
| `fec_window_fill_burst/normal/k10_repair_burst` | `14.9 us` median |
| `fec_window_fill_burst/medium/k30_repair_burst` | `23.7 us` median |
| `fec_window_fill_burst/strong/k50_repair_burst` | `37.7 us` median |

The previous synthetic Strong k512 result was a benchmark-truth artifact, not a
production FEC hotpath regression.

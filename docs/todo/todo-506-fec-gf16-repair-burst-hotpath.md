---
id: TODO-506
title: FEC GF16 repair-burst hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-488, TODO-505]
---

# TODO-506: FEC GF16 Repair-Burst Hotpath

## Context

Broderick Criterion measurements showed `fec_window_fill_burst/strong/k50_repair_burst`
as the next FEC hot spot after TODO-505. Strong mode uses the GF16-heavy
AdaptiveRS path and emits many repair packets when a product-sized FEC window
fills. Each repair packet previously recomputed its GF16 Cauchy coefficient row
with repeated `gf16_inv()` exponentiation, even though those coefficients depend
only on `k` and the repair index, not on packet payload data.

The output vector also started small and could grow during the repair burst.
That was a smaller cost than GF16 math, but it happened exactly on the burst
path.

## Desired Outcome

- Preserve GF16 wire coefficients exactly.
- Avoid repeated GF16 inverse/exponentiation work for repair rows that are fixed
  for the encoder parameters.
- Reserve repair-burst output capacity once before pushing repairs.
- Keep clean systematic-only send paths unchanged.
- Add a regression test proving generated GF16 coefficients still match the
  expected Cauchy formula.
- Avoid frontend, UI, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Replaced the `Encoder16 = Encoder<GF16>` type alias with a thin `Encoder16`
  wrapper.
- `Encoder16` owns the original `Encoder<GF16>` plus precomputed coefficient
  rows. Rows are built from the same formula used previously:
  `gf16_inv(j ^ (k + repair_idx))`.
- `generate_repair_packet()` copies the cached row into each packet's coefficient
  buffer, preserving decoder and wire semantics.
- `AdaptiveFec::on_send_into()` now reserves the caller output vector once before
  normal and transition repair bursts.
- Added `test_gf16_encoder_uses_expected_cauchy_coefficients`.

## Verification

| Command | Result |
|---------|--------|
| Local: `cargo fmt --all -- --check` | PASS |
| Local: `cargo test --lib test_gf16_encoder_uses_expected_cauchy_coefficients -- --nocapture` | PASS |
| Local: `cargo test --lib test_on_send_into -- --nocapture` | PASS |
| Broderick: `cargo test --lib test_gf16_encoder_uses_expected_cauchy_coefficients -- --nocapture` | PASS |
| Broderick: `cargo bench --bench fec_pipeline --features benches -- "fec_window_fill_burst/(normal|strong)/k(10|50)_repair_burst" --sample-size 10 --measurement-time 1` | PASS |

## Broderick Performance Evidence

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| `fec_window_fill_burst/normal/k10_repair_burst` | `14.35 us` | `14.25 us` | neutral |
| `fec_window_fill_burst/strong/k50_repair_burst` | `40.99-43.73 us` | `24.73 us` | `-38.568%` time, `+62.782%` throughput |

## Notes

The optimization only removes repeated coefficient-row construction and output
growth from repair bursts. It does not alter FEC mode selection, payload math,
repair count, packet IDs, coefficient values, or decoder behavior.

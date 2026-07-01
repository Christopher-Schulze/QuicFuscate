---
id: TODO-497
title: FEC active-mode lock bypass
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-476, TODO-480, TODO-484, TODO-490, TODO-491]
---

# TODO-497: FEC Active-Mode Lock Bypass

## Context

Focused Broderick screening of `fec_lazy_fast_path` after TODO-496 showed that
the production-style `_into` receive path was already allocation-free, but the
send and receive fast paths still read the active FEC mode through
`ModeManager::current_mode()` on every packet. That meant taking the
`ModeManager` mutex just to decide whether the packet is on the Zero,
Streaming, or generic path.

The `ModeManager` still owns hysteresis and target-window policy. Packet
send/receive only needs the current resolved `FecMode`.

## Desired Outcome

- Preserve all FEC mode-switching and transition behavior.
- Keep `ModeManager` as the policy/window state owner.
- Avoid `ModeManager` mutex reads in `AdaptiveFec::on_send_into()`,
  `AdaptiveFec::on_receive()`, `AdaptiveFec::on_receive_into()`, and
  `AdaptiveFec::current_mode()`.
- Improve Broderick `fec_lazy_fast_path` clean-link timings.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added `AdaptiveFec::active_mode: FecMode`.
- Initialized `active_mode` from the resolved runtime plan.
- Updated `active_mode` at every mode mutation point:
  - `transition_to_target()`
  - `force_mode_for_test()`
  - `update_mode()` when a switch is applied
  - `force_streaming_mode()`
- Changed packet fast paths to read `self.active_mode` directly instead of
  calling `self.current_mode()`.
- Changed `current_mode()` to return the cached field.
- Coalesced `transition_to_target()` mode/window reads into one
  `ModeManager` lock.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests receive -- --nocapture` pass
  (`7 passed`).
- Local: `cargo test --lib --features rust-tests transition -- --nocapture`
  pass (`11 passed`).
- Broderick: `cargo bench --bench fec_pipeline --features benches --
  fec_lazy_fast_path --sample-size 40 --measurement-time 2` pass.

## Criterion Evidence

Broderick ARM/AArch64 `fec_lazy_fast_path`, old `9c762a0` baseline versus
TODO-497 patch:

| Case | Baseline | TODO-497 | Result |
|------|----------|----------|--------|
| `zero_mode_passthrough` | `307.95 ns` | `283.49 ns` | about 8.1% faster |
| `zero_mode_passthrough_reuse` | `284.96 ns` | `266.13 ns` | about 6.7% faster |
| `normal_mode_no_loss` | `2.0940 us` | `1.9873 us` | about 4.8% faster |
| `normal_mode_no_loss_reuse` | `1.9671 us` | `1.9145 us` | about 3.2% faster |

## Notes

The broad FEC matrix run was intentionally stopped after it kept running for
about 10 minutes and consumed about half of Broderick RAM. The broad run had
already produced noisy partial estimates and was less useful than the focused
lazy-fast-path measurement. The narrowed bench isolates the changed code path
without conflating product-window setup or recovery-burst costs.

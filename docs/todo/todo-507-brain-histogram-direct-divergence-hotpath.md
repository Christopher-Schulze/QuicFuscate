---
id: TODO-507
title: Brain histogram direct divergence hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-483, TODO-468]
---

# TODO-507: Brain Histogram Direct Divergence Hotpath

## Context

Broderick Criterion measurements after TODO-506 showed `brain_apply_policy` as
the next meaningful hot path outside FEC. TODO-483 had already removed per-tick
target-distribution allocation, but `StealthBrain::apply_policy()` still copied
both size and inter-arrival histograms into scratch vectors before summing and
running Jensen-Shannon divergence.

That made every policy tick do extra memory traffic after histogram decay. It
also left `Hist::total` stale after decay, because the bins were decayed but the
cached total was not updated.

## Desired Outcome

- Preserve Brain policy semantics, actuator ownership, and Intelligent-mode
  gating.
- Avoid per-tick histogram scratch copies.
- Keep `Hist::total` synchronized with decayed bins.
- Preserve existing SIMD/scalar histogram decay and Jensen-Shannon kernels.
- Add a regression test for histogram total consistency after decay.
- Avoid frontend, UI, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added `decay_histogram_and_divergence(...)` in `src/brain.rs`.
- The helper calls the existing accelerated `decay_histogram(...)` directly on
  `VecDeque::make_contiguous()` storage, recomputes `Hist::total`, and feeds the
  same contiguous slice into `jensen_shannon_divergence(...)`.
- Removed the `size_hist_snap` and `iat_hist_snap` scratch vectors from
  `StealthBrainState`.
- Replaced the copy-then-sum blocks in `StealthBrain::apply_policy()` with
  direct `size_divergence(...)` and `iat_divergence(...)` calls.
- Added `histogram_divergence_keeps_total_synchronized_after_decay`.

## Verification

| Command | Result |
|---------|--------|
| Local: `cargo fmt --all -- --check` | PASS |
| Local: `cargo test --lib histogram_divergence_keeps_total_synchronized_after_decay -- --nocapture` | PASS |
| Local: `cargo test --lib brain:: -- --nocapture` | PASS |
| Local: `cargo clippy --lib -- -D warnings` | PASS |
| Broderick: `cargo test --lib histogram_divergence_keeps_total_synchronized_after_decay -- --nocapture` | PASS |
| Broderick: `cargo bench --bench ci_regression --features benches -- "brain_apply_policy" --sample-size 10 --measurement-time 1` | PASS |

## Broderick Performance Evidence

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| `brain_apply_policy/clean_observer` | `647.86 ns` | `600.01 ns` | `-7.3343%` time, `+7.9148%` throughput |
| `brain_apply_policy/intelligent_clean` | `647.74 ns` | `599.07 ns` | `-7.5346%` time, `+8.1486%` throughput |
| `brain_apply_policy/intelligent_pressure_actuating` | `601.92 ns` | `550.67 ns` | `-8.3871%` time, `+9.1549%` throughput |

## Notes

This optimization only removes redundant scratch-copy work and fixes the
histogram total bookkeeping after decay. It does not change Brain pressure
calculation, ACK bandit behavior, FEC hints, MASQUE hints, persona handling, or
runtime stealth actuator permissions.

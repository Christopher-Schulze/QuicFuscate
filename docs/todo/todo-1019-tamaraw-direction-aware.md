---
id: TODO-1019
title: Adaptive-Tamaraw direction-aware parameters - split the phase table by direction
severity: MEDIUM
phase: M
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1010]
---

# TODO-1019: Adaptive-Tamaraw direction-aware parameters

## Context

TODO-1010 candidate 2 (Adaptive Tamaraw, arXiv 2509.01046) is partially
adapted: `intelligent_policy.rs` classifies traffic into `TrafficPhase`
(Dense/Sparse/BurstEdge on smoothed `ack_us`) and scales jitter per
phase. What stays open (written in TODO-1010): a literal per-cluster
(rho, gamma) row with **disjoint upload vs download weights** - the
policy is symmetric today, so the table has one axis. Splitting it
needs direction-aware signal plumbing (up/down ACK density measured
separately).

## Objective

Give the Tamaraw-style parameter table a direction axis: upstream and
downstream traffic each get their own density estimate and their own
shaping parameters, matching the paper's asymmetric (rho_up, gamma_up)
vs (rho_down, gamma_down) parameterization.

## Implementation sketch

1. **Signal plumbing** (`crates/qf-stealth` + brain inputs): today the
   brain's EMA exposes a single `ack_us` (send-side ACK cadence). Add a
   receive-side density estimate - e.g. `rx_us` / `down_iat_us` - fed
   from inbound datagram inter-arrival on the same EMA/hysteresis path
   the send side already uses (`IntelligentStealthInputs` extension;
   check where `ack_us` is sampled in `src/brain/` and mirror it for
   the receive direction).
2. **Direction-aware phase table** (`intelligent_policy.rs`): extend
   `classify_phase`/`derive_intelligent_runtime_policy` so each
   direction resolves its own `TrafficPhase` and parameter row
   {jitter_scale, padding_rate, chaff_rate}; downstream rows primarily
   steer padding/chaff (we do not delay inbound packets), upstream
   rows steer jitter + pacing as today.
3. **Cluster match gating**: keep conservative global parameters as
   fallback until the per-direction estimate is confident (existing
   hysteresis pattern - reuse it, do not add a second mechanism).

## Constraints

- The density-halving rule under dense traffic (candidate 1's landed
  half) must compose correctly with direction splits - dense upstream
  must not halve downstream padding and vice versa.
- Direction estimation must be cheap (EMA on existing timestamps); no
  new syscalls, no allocation per packet.
- Symmetric behavior stays the default when a direction has no signal
  yet (cold start / one-way phases like handshake or idle download).

## Acceptance

- Unit tests with `ManualTimeSource`-style determinism: independent
  up/down phases resolve independently (dense-up + sparse-down picks
  the split row, not the symmetric one); cold-start falls back to the
  global row; hysteresis prevents flapping at thresholds.
- Omega e2e (iperf3 TCP through tunnel): asymmetric load (uplink-heavy
  vs downlink-heavy runs) shows the expected parameter split in stats/
  telemetry without throughput regression vs the symmetric baseline.
- TODO-1010's Tamaraw entry updated to reflect the direction axis
  landing.

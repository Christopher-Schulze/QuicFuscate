---
id: TODO-1019
title: Adaptive-Tamaraw direction-aware parameters - split the phase table by direction
severity: MEDIUM
phase: M
priority: P2
status: DONE
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

## Implementation (landed)

The split needed no new signal plumbing: `ack_us` was already the
**downstream** density (our emitted ACK delay tracks inbound packet
inter-arrival), and the brain already reads `conn.delivery_rate()` for
its bandit. `src/brain.rs` now folds the delivery rate into a packet
inter-arrival estimate (`up_us = 1200 B * 1e6 / dr`) so both directions
classify on the same microsecond axis; `up_us <= 0` (no estimate yet -
handshake/cold start) falls back to the symmetric row.

`intelligent_policy.rs` evaluates the phase table per direction:

- **Upstream row** (`up_phase`) steers `timing_max_jitter_us` - the only
  timing we actually reshape is outbound.
- **Downstream row** (`down_phase`) steers the `padding_rate` density
  halving - a dense upload alone no longer shrinks the padding row and
  vice versa, satisfying the disjoint-weights requirement.
- `external_pacing`, `mimic_bias`, anomaly overrides unchanged.

Unit tests (qf-stealth, 139 green incl. 4 new):
`direction_split_uses_upstream_density_for_jitter`,
`direction_split_keeps_downstream_density_for_padding`,
`dense_upload_alone_does_not_halve_padding`,
`missing_upstream_signal_falls_back_to_symmetric_row`.
TODO-1010's Tamaraw entry records the direction axis.

## Acceptance

- [x] Unit tests: independent up/down phases resolve independently;
  cold-start falls back to the symmetric row.
- [x] Omega e2e 2026-09-21 (`tcp-1019d`, `JITTER_US=0`, pacing_rate_bps
  for `up_us` only; bandit still reads the unused `stats.delivery_rate`):
  uplink 88.625 Mbit/s 0 retrans, hot `up_us` 37-63 / `ack_us` 2-743 /
  `stealth_jitter_us` 1800-2140; `-R` 142.163 Mbit/s 1 retrans, hot
  `up_us` 827-1379 / `ack_us` 2-1058 / `stealth_jitter_us` 1900-2200.
  Direction inputs split; both stay Dense (`up_us` < 3000) so the jitter
  row correctly does not diverge. `stealth_pad=0` at Intelligent level 0.
  Feeding pacing into `Connection::delivery_rate()` was tried and
  reverted: it collapsed `-R` to 9.3 Mbit via the bandit.
- [x] TODO-1010's Tamaraw entry updated to reflect the direction axis
  landing.

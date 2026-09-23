---
id: TODO-1053
title: One send clock under the PTO threshold
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1052]
---

# TODO-1053: One send clock under the PTO threshold

## Why

Two rate limiters (congestion control and the choke) produce a spacing that matches no browser. Jitter on ack-eliciting packets inflates RTT and trips PTO. That self-inflicted loss is what lifts FEC out of Zero, which today stamps the cleartext FEC prefix (TODO-1046). Pure ACKs are already exempt. Data packets are not.

## Current code

- `src/stealth/manager.rs` `process_outgoing_packet`: if `enable_realtime_choke`, `RateChoker::shape`. Else if mode is `StealthMax` and the packet is not ack-only, `FlowShaper` jitter plus flight pacing.
- `src/core/connection/send.rs` merges that delay with `transport_stealth_jitter_delay` via `compute_outbound_stealth_release`. A comment already records that holding packets inflates the in-flight clock toward a spurious PTO (TODO-1016).
- BBR / CUBIC / Reno still run as the congestion controller. The choke is a second limiter (`choke_target_mbps`, `choke_burst_ms`).

## Target

One clock.

- The congestion controller is the only continuous rate limiter.
- Extra delay is allowed only as a short block whose duration is strictly below the current PTO / 4, and only when the wire budget (TODO-1052) still has room. Pure ACKs stay at delay zero.
- `enable_realtime_choke` is removed from stealth modes. A manual bandwidth cap, if kept at all, replaces the congestion controller's pacing rate for that connection. It does not sit beside it.
- `StealthMax`-only jitter that ignores the PTO bound is deleted.

## Non-goals

- No Maybenot integration here (TODO-1061). This task only removes the unsafe delay. Maybenot may later spend the same bounded slot.
- No change to loss detection math in `qf-transport-recovery` beyond consuming the existing PTO value.

## Design

1. `process_outgoing_packet` reads the recovery timer's current PTO and clamps any shaping delay to `min(requested, pto/4)`. If `pto` is zero or unknown, delay is zero.
2. Delete the choke branch from stealth presets. `performance()` and `stealth_max()` must not set `enable_realtime_choke`.
3. If a manual cap remains, it sets the pacer's rate. `RateChoker::shape` must not run on top of CC delay.
4. Metric: `choke_delay_clamped_total` so a regression is visible.

## Sub-Tasks

- [x] Clamp helper with a unit test: requested 50 ms, PTO 20 ms, result 5 ms.
- [x] ACK-only path still returns zero when choke used to be on.
- [x] Presets: `stealth_max` and `dynamic` do not enable a second limiter.
- [x] The only release site (`bounded_stealth_release`) clamps both delays before they become an instant. A paired lossless-socket PTO comparison was not added; there is no second schedule site.

## Result

`RateChoker::shape` is gone from `StealthManager`. Manual `enable_realtime_choke` writes `max_pacing_rate` in bytes per second (`mbps * 125_000`). `clamp_shaping_delay` is `min(requested, pto/4)`, and a PTO below 4 ns yields zero. `CHOKE_DELAY_CLAMPED_TOTAL` counts reductions. Tests: `shaping_delay_clamps_to_one_quarter_of_pto`, `ack_only_stays_undelayed_when_manual_choke_is_enabled`, `ack_only_packets_bypass_jitter_but_feed_history`, `canonical_stealth_modes_keep_padding_ssot`.

## Acceptance

- No stealth preset enables `RateChoker` and a congestion controller together.
- Every non-zero data delay is `< pto/4` at the moment it is scheduled.
- Existing "do not delay pure ACKs" tests still pass.

## Risks

- Clamping toward zero makes timing defense weaker. That is correct until TODO-1061 has a measured machine. An unmeasured delay that causes loss is not a defense.

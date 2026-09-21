---
id: TODO-981
title: Adaptive FEC: single lossy batch escalates to Fountain; Kalman freeze pins stale estimate
status: OPEN
created: 2026-09-19
---

# TODO-981 - Adaptive FEC: single lossy batch escalates to Fountain; Kalman freeze pins stale estimate

## Symptom

On Omega (`tun-e2e-fec-transition-netns.sh`, "moderate" scenario: 20% netem
loss, 150 lossy pings, 10s settle, 250 recovery pings):

- Phase 2 adapted correctly `zero -> streaming`, tunnel loss 5-8% under 20%
  injection (protection works).
- Phase 3 returned to 0% tunnel loss, `fec_clean_ack_streak` reached 231,
  `fec_estimated_loss_ppm` reached 0 — yet the client ended in
  `mode=fountain` with `mode_switches_total=3` and 852 repair packets
  (~209% wire overhead).
- The transition test failed: `Auto policy did not return to Zero within the
  bounded recovery phase` (recovery ~36s).

## Root cause (three defects)

1. **Fountain rescue tier armed by a single lossy batch.**
   `LossEstimator::fountain_ready` required `total_seen >= 32` — a cumulative
   lifetime counter that is permanently satisfied after warmup, leaving only
   `ema >= 0.25 && recent >= 0.25`. Both were spikable by one report: a large
   loss batch (in-flight packets declared lost after the 10s settle gap)
   carried `smoothed_loss` ~1.0 into `report_rate`, which projected up to
   `min(total, burst_capacity)` = 16 slots — flooding the entire recent window
   — while CUSUM detection boosted lambda to 0.85, lifting `ema` past the
   threshold in one step. `policy_loss_estimate` was designed to clamp such
   spikes below the fountain threshold, but its `fountain_ready` gate was
   latched open, so `update_mode` forced `FecMode::Fountain` with
   `ExtremeLossPolicy` on a recovered link.

2. **Kalman process noise starves to the floor, freezing the estimate.**
   After >128 stable reports the estimator repeatedly multiplies `q` by 0.9
   down to `1e-8`. At that floor the Kalman gain collapses (~1e-3), so a
   high-loss estimate stays pinned even while the measurement stream reports
   zero. `clean_link_confirmed` masked this (`smoothed_loss` reports 0 while
   the clean streak holds), but any late loss reset the streak and unmasked
   the stale ~0.3-0.4 estimate, feeding fresh escalations long after the link
   recovered.

3. **Zero downshift gated by sample counts on sparse feedback.**
   `ModeManager::update` requires the last-10 average plus four consecutive
   samples mapping to the target rank before any downshift. On
   datagram-dominated links (MASQUE DATAGRAMs are not ACK-tracked), feedback
   reports arrive at roughly 0.3-1/s, so draining those sample windows took
   longer than the test's bounded recovery (~36s) even though the transport
   had already proven the link clean (clean_ack_streak=193, estimate=0 at the
   snapshot). The commit layer already encoded the "clean proof -> Zero now"
   principle via `clean_zero_transition`; the decision layer did not.

## Fix

`crates/qf-fec/src/loss.rs`:

- `fountain_ready` now requires `fountain_streak >= 3` — three consecutive
  reports where both `ema` and `recent` are at or above the fountain threshold —
  plus a saturated recent window (`burst_window.len() >= burst_capacity`)
  and the original warmup guard. A single lossy batch can no longer qualify.
- Per-report burst-window injection is capped at `burst_capacity / 8` slots so
  one smoothed sample cannot dominate the recent window; a fractional carry
  (`projected_carry`) keeps the projection unbiased at small slot counts
  (25% of 2 slots averages to one lost slot every other report, not 50%).

`crates/qf-fec/src/kalman.rs`:

- The filter now tracks an innovation EMA (`|z - x|`). While the innovation
  stays above 0.05 the process noise `q` is boosted 1.5x per update (bounded
  at 0.25), so a real level shift restores responsiveness instead of staying
  frozen at the `q` floor.

`crates/qf-fec/src/manager.rs` + `adaptive_controller/gf16_and_config.rs`:

- `ModeManager::update_with_clean_proof(loss_rate, clean_proof)` feeds the
  estimator's `clean_link_confirmed` signal into the mode decision. While the
  proof holds (32+ consecutive ACKs, zero loss), the Zero target is selected
  immediately and the downshift stability gate is satisfied by the proof
  itself — stronger evidence than 4 smoothed samples. Hysteresis for every
  non-Zero target and every escalation path is unchanged; `update()` keeps
  the old behaviour for non-transport callers.

## Tests

- `loss::tests::single_loss_batch_does_not_arm_fountain` — clean-confirmed
  estimator + one `rate=1.0` batch + clean flow: `fountain_ready` never true.
- `loss::tests::sustained_loss_arms_fountain` — sustained 40% loss still arms
  the rescue tier within bounded reports.
- `loss::tests::frozen_kalman_does_not_reemerge_after_late_loss` — 20k stable
  reports starve `q` to the floor; clean phase converges via the innovation
  path; a late loss cannot unmask a stale >=0.25 estimate.
- `loss::tests::projected_slots_track_fractional_loss` — 25% smoothed loss
  converges the recent window near 25% (carry prevents quantization bias).
- `fec::adaptive_tests::test_pending_transition_commits_at_block_boundary` —
  pending transitions commit once the current block completes.
- `fec::adaptive_tests::test_single_lossy_batch_never_reaches_fountain` —
  controller-level: one `report_loss(48,48)` batch never enters Fountain.
- `fec::e2e_tests::test_transport_feedback_mode_trajectory_recovers` — the real
  `report_transport_loss` path at production cadence with the 10s settle gap:
  never reaches Fountain, returns to Zero within the 40s budget.
- `fec::adaptive_tests::test_clean_proof_deescalates_on_sparse_feedback` —
  batched clean ACKs (40/report) de-escalate to Zero within 8 reports; fails
  without the clean-proof bypass (sample-window gates need ~14+ reports).

## Verification

- `cargo test -p qf-fec`: 89/89 green.
- `cargo test --lib fec::`: 217/217 green.
- Workspace lib suite: 1728/1728 green; fmt/clippy clean.
- Omega `tun-e2e-fec-transition-netns.sh` (moderate profile) on `4433a48`:
  **PASS**. Phase 1: 0% tunnel loss (mode zero, no overhead). Phase 2: 2%
  tunnel loss under 20% injection (streaming active, protection effective).
  Phase 3: 0% tunnel loss, `streaming -> zero` committed mid-phase
  (live telemetry: `clean_ack_streak=95`, `estimated_loss_ppm=0`,
  `pending_transition=0`, `mode_switches_total=3`). No fountain at any point;
  the recovered snapshot shows `mode="zero"` inside the bounded window.
- Omega severe profile (40% netem, fountain permitted): **PASS**. 0%/33%/0%
  tunnel loss across the phases, `mode_switches_total=4`, mode back to `zero`
  with `clean_ack_streak` still growing when the recovery snapshot ran.

## Notes

- The earlier hypothesis that the fountain encoder window never drains was
  wrong: `on_send_into` calls `encoder.clear_window()` after emitting repairs
  once `packets_in_window() >= k`, so every source block is covered, not just
  the first k. The 30s `pending_transition` seen in live telemetry was bounded
  block-boundary latency (fountain k=128 at ~10pps), not a deadlock.
- Diagnosis was enabled by the three new adaptation gauges added in this
  session: `fec_estimated_loss_ppm`, `fec_clean_ack_streak`,
  `fec_pending_transition` (published from `report_transport_loss_inner`).

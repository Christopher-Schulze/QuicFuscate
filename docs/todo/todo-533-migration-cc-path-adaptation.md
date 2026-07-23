---
id: TODO-533
title: Complete configurable migration and CC path adaptation
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-450, TODO-544]
---

# TODO-533: Complete Configurable Migration and CC Path Adaptation

## Why

Validated migration preserves in-flight bytes and halves cwnd, but the factor and cooldown are hard-coded. PATH_CHALLENGE RTT is discarded, congestion controllers receive only a generic window setter, and active-transfer recovery bounds are unproven.

## Acceptance

- Load validated migration reduction, cooldown, and probe-target policy from operator configuration with safe bounds and explicit zero/one-factor behavior.
- Capture validation RTT and pass a typed path-change event into every congestion controller so path-specific RTT, epoch, pacing, and slow-start state are correct.
- Preserve bytes in flight, reset PTO/loss timers deliberately, set the canonical congestion-avoidance boundary, and prove exact 100000-byte window vectors for factors 0.5, 0.25, and 1.0.
- Prove challenge/response validation remains mandatory and migration during active transfer loses less than 50% throughput and recovers to 90% within two seconds.
- Pass local Rust gates, native CI, Omega live migration proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Policy gate: bounds, precedence, disabled behavior, zero/one-factor behavior, cooldown, and probe targets pass typed configuration and negative tests.
- Controller gate: exact 100000-byte vectors plus every congestion-controller path prove validation RTT, epoch, pacing, slow start, bytes-in-flight, loss/PTO, and avoidance-boundary transitions.
- Migration gate: active authenticated traffic cannot migrate before challenge/response validation and the controlled path-switch matrix loses under 50% throughput and returns to 90% within two seconds.
- Release gate: local Rust gates, native CI, exact-artifact Omega migration proof, SHA-256, cleanup, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map configuration, validation timing, recovery, and every CC implementation.
- [ ] Define the typed migration policy and CC path-change contract.
- [ ] Implement configuration, state transition, and exact units.
- [ ] Execute active-transfer local/native/Omega proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-450 reconciliation. Avoid a second Reno-only reduction after the shared migration policy.

## Deviations

None.

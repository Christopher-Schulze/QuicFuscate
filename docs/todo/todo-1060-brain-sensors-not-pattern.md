---
id: TODO-1060
title: Brain sensors may switch repairs and Reality, not the packet shape
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1059]
---

# TODO-1060: Brain sensors may switch repairs and Reality, not the packet shape

## Why

The brain optimizes a local score (Kalman on congestion, JS divergence, epsilon-greedy). "More random than last tick" is not a browser. A bandit that converges is a stable pattern, which is a fingerprint. There is no evaluation against DF, Tik-Tok, or Var-CNN. The sensors are still useful. The pattern generator is not.

## Current code

- `src/brain.rs`: StealthBrain, Kalman CE ratio, histogram JS divergence, epsilon-greedy bandit for ACK threshold. Outputs include ACK threshold, pacing, timing jitter, padding strategy, CC profile, MASQUE hint.
- `crates/qf-stealth/src/intelligent_policy.rs` `derive_intelligent_runtime_policy` turns those inputs into stealth deltas.
- `FecTransportObserver.apply_policy` runs from `core` update and from transport send. Both have cooldown guards.
- TODO-1059 already forbids distribution changes during `dynamic`. This task removes the generator that produced those changes.

## Target

Keep:

- loss, CE, RTT, probe bit
- a repair-ratio hint inside the TODO-1052 cap
- a boolean that arms the Reality relay

Delete as behavior:

- epsilon-greedy selection of padding strategy
- jitter amplitude chosen by the bandit
- any output that changes the length set or the FEC framing

The packet shape comes from the frozen image (TODO-1059) or, later, from a Maybenot machine (TODO-1061). Not from the bandit.

## Non-goals

- Do not delete the Kalman filter if repair-ratio still uses a smoothed loss estimate. Delete only the policy outputs that change shape.
- No frontend visual change.
- No new score function.

## Design

1. List every field `StealthBrain` writes into transport or stealth config. Mark each keep or drop in Notes before editing.
2. `derive_intelligent_runtime_policy` returns only `repair_ratio` and `reality_armed`.
3. Call sites that applied padding strategy or jitter from the brain get the frozen image instead.
4. Tests that expected the bandit to change padding are rewritten to expect a constant strategy.

## Sub-Tasks

- [ ] Output inventory in Notes.
- [ ] Narrow the policy struct.
- [ ] Disconnect padding and jitter writers.
- [ ] Test: 1000 brain ticks under shifting loss do not change `PaddingStrategy` or framing.

## Acceptance

- No production call applies a bandit-chosen padding strategy.
- Repair ratio still moves when loss moves, and it cannot exceed the byte cap.
- `cargo test` brain and stealth policy tests pass with the narrower struct.

## Risks

- ACK-threshold control might be a congestion feature, not a stealth feature. If it only affects when ACKs are sent, keep it under the PTO clamp from TODO-1053. Do not let it add a second spacing pattern. Note the decision in this file if ACK threshold stays.

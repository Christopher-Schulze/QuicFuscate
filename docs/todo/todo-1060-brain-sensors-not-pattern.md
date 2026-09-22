---
id: TODO-1060
title: Brain sensors may switch repairs and Reality, not the packet shape
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
completed: 2026-09-21
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

- [x] Output inventory in Notes.
- [x] Narrow the policy struct.
- [x] Disconnect padding and jitter writers.
- [x] Test: 1000 brain ticks under shifting loss do not change `PaddingStrategy` or framing.

## Acceptance

- No production call applies a bandit-chosen padding strategy.
- Repair ratio still moves when loss moves, and it cannot exceed the byte cap.
- `cargo test` brain and stealth policy tests pass with the narrower struct.

## Risks

- ACK-threshold control might be a congestion feature, not a stealth feature. If it only affects when ACKs are sent, keep it under the PTO clamp from TODO-1053. Do not let it add a second spacing pattern. Note the decision in this file if ACK threshold stays.

## Notes

### Output inventory (what `StealthBrain` used to write)

| Old output | Verdict |
| --- | --- |
| ACK-eliciting threshold (bandit arms {2,3,4,8}) | KEEP as pure congestion feature — no bandit, CE/ACK-cadence driven, step-limited, operator-lockable |
| `StealthRuntimeDelta` { timing, padding, bias, granularity, cc_profile, external_pacing } | DROP — all shape fields |
| `StealthRuntimePolicy` via `derive_intelligent_runtime_policy` | DROP — replaced by `derive_intelligent_actuators` |
| Tamaraw direction table + `tamaraw_runtime_snapshot` stats | DROP |
| epsilon-greedy explore roll (`explore_prob`, `pad_max_*`, `jitter_dither_pct`, `PADDING_RATE_LEVEL1` env) | DROP |
| `BrainFecHints` repair-ratio + interval | KEEP — inside the TODO-1052 shared byte cap |
| `IntelligentLevelHints` -> Reality/MASQUE armed bit | KEEP — probe escalation may still arm |
| `intelligent_stealth_runtime` config gate + `apply_brain_stealth_runtime_delta` | DROP — no runtime delta path remains |
| `TransportPolicyError`, `delivery_rate`/`pacing_rate_bps`/`intelligent_stealth_runtime_enabled` trait methods | DROP — `TransportPolicyTarget` exposes only `brain_runtime_permissions()` + `set_ack_eliciting_threshold()` |

### Decisions

- **ACK threshold stays.** It changes *when* ACKs are emitted, never the packet length set or framing — a congestion function, not a shape actuator. The bandit arms are gone; the threshold is now derived from CE pressure and ACK cadence, step-limited by one per policy tick, clamped to `[ack_min, ack_max]`, and locked out when the operator sets `QUICFUSCATE_ACK_THRESHOLD`/`QUICFUSCATE_ACK_MAX_DELAY_MS` (`BrainRuntimePermissions { ack_threshold }`).
- **`BrainRuntimePermissions` is reduced to `deny_all()`/`ack_threshold`** — `dynamic` (TODO-1059) installs `deny_all()`, so the Brain cannot reach even the threshold there.
- **`StealthBrainConfig` keeps only sensor/cooldown knobs**: ACK bounds, histogram bins, probe budget, `hist_decay`, `jitter_max_us` (feeds jitter-pressure sensing only — it is never emitted as timing).
- **`environment` field deleted** (supersedes TODO-894): the actuator derivation takes no `EnvSnapshot`; `apply_policy` performs zero environment reads.
- Connect-time `config.set_stealth_*` stays — it defines the frozen image, not a runtime mutation surface.

### Acceptance evidence

- `thousand_ticks_under_shifting_loss_never_change_shape` (`src/brain.rs`): 1000 `apply_policy` ticks under varying packet sizes, reordering, ACK delays and ECN — timing config, padding enable, `PaddingStrategy` and the (absent) stealth-CC wrapper are byte-identical afterwards.
- `brain_never_touches_the_frozen_wire_shape`, `brain_writes_repair_hints_and_ack_threshold_only`, `brain_respects_ack_threshold_lock` cover the narrowed surface.
- qf-stealth `143/143`, qf-transport-types `41/41`, root lib `1775/1775`; workspace `--all-targets` clean.

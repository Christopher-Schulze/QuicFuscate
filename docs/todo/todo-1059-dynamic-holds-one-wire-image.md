---
id: TODO-1059
title: dynamic keeps one wire image for the whole connection
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1052, TODO-1046]
---

# TODO-1059: dynamic keeps one wire image for the whole connection

## Why

`dynamic` is the shipped default. It starts near the performance preset and then turns stealth features on. The change in packet sizes is a feature for a classifier. The cipher stays AES-GCM the whole time, which is correct. The distribution must also stay one shape.

## Current code

- `StealthMode::Dynamic` and `dynamic_enabled`.
- `src/stealth/manager.rs` allows escalation when `dynamic_enabled` is set (probe detector, flow shaper, reality proxy).
- `crates/qf-stealth/src/escalation.rs` `EscalationState` moves padding, timing, and related flags during the connection.
- Engine pin: `dynamic` does not use libaegis. Payload stays AES-GCM. Do not change that.

## Target

At connect, `dynamic` chooses one image and stores it:

- `PerformanceImage`: no stealth padding, no cover, FEC wrapper allowed, AES-GCM. This is not `performance` mode's AEGIS pin.
- `StealthImage`: TODO-1052 persona trace, in-QUIC FEC (TODO-1046), no second choke (TODO-1053), AES-GCM.

Default when the operator sets no preference: `StealthImage`. Do not start thin and thicken. Say so in `config/quicfuscate.toml`.

Escalation may still change repair count inside the byte cap, and whether the Reality relay is armed.

Escalation must not change padding length set, cover schedule shape, FEC framing, or AEAD.

## Non-goals

- No bandit (TODO-1060).
- No frontend visual change. The mode name stays `dynamic`.

## Design

1. `EscalationState` loses setters for padding, timing amplitude, and framing.
2. It keeps a repair-ratio hint and a reality-armed bit.
3. A test drives high loss and a probe and asserts the length-set id and framing enum are unchanged, while `reality_armed` may flip.

## Sub-Tasks

- [ ] Freeze image at connect.
- [ ] Strip distribution fields from escalation.
- [ ] Test the allowed deltas and the forbidden ones.
- [ ] Toml comment: default image is the stealth image, cipher remains AES-GCM.

## Acceptance

- A `dynamic` connection's framing and length-set id are constant from the first 1-RTT packet to close.
- Payload AEAD remains AES-GCM for both images.

## Risks

- Operators who wanted a ramp from fast to careful lose it. The ramp is the bug. Explicit `performance` remains the speed mode, and that mode still uses libaegis.

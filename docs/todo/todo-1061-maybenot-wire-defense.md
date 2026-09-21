---
id: TODO-1061
title: Maybenot as the measured wire defense
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1052, TODO-1053, TODO-1060]
---

# TODO-1061: Maybenot as the measured wire defense

## Why

Maybenot (WPES 2023, crate 2.2.2 as of 2025-09-12) is a Rust runtime for traffic-analysis defenses. Machines take wire events and emit `SendPadding` or `BlockOutgoing` with hard limits. Upstream ships machines for FRONT and RegulaTor, plus a simulator. That is the replacement for the bandit, not a fifth padding strategy. It is not a cipher.

## Current code

- No `maybenot` dependency.
- Padding and delay are the presets plus the brain. TODO-1060 removes the brain's shape outputs.

## Target

- After seal, report sent and received ciphertext lengths into one Maybenot instance on the connection.
- `SendPadding` becomes QUIC PADDING before the next seal, charged to TODO-1052. If the cap is hit, drop the action.
- `BlockOutgoing` becomes a send block clamped by TODO-1053 (`< pto/4`). Pure ACKs are not blocked.
- Machine bytes are the TODO-1052 cap. No private overhead.
- Do not ship a machine as the default until the simulator reports overhead and accuracy against at least one published classifier (DF or a documented successor). `Stealth MAX` may select that machine only after the number is written in this file.
- Until then, `stealth` and `Stealth MAX` stay on the persona trace.

## Non-goals

- Do not run Maybenot beside the bandit.
- Do not vendor a fork. Pin crates.io `maybenot`.
- No frontend visual change.
- No claim of beating a classifier before the simulator runs.

## Design

1. Add the dependency on the crate that owns the connection send loop. Keep it out of `qf-crypto`.
2. Integration point: `src/core/connection/send.rs` after a datagram is sealed and its wire length is known, and the receive path after a datagram is accepted. Events are lengths and direction only.
3. Actions queue on the connection and are consumed by the existing padder and the clamped delay. One machine per connection.
4. The simulator is a feature-gated example or a script under `scripts/benchmarks/`. It reads a trace and writes overhead and accuracy into this file. No network.

## Sub-Tasks

- [ ] Pin `maybenot` and compile the adapter behind stealth modes.
- [ ] Unit tests: padding dropped at the cap, block clamped at `pto/4`.
- [ ] Simulator run for one upstream machine. Record overhead and accuracy here.
- [ ] Do not flip `Stealth MAX` onto that machine in the same change as the adapter.

## Acceptance

- Adapter tests pass.
- Default config does not load a Maybenot machine.
- This file contains either simulator numbers or an explicit "not run" plus the command that will run them.
- No bandit-chosen padding remains (TODO-1060).

## Risks

- Blocking still causes PTO if the clamp is skipped. The clamp is mandatory.
- A machine trained on Tor cells will not fit a Chrome length set. Do not enable a Tor machine on `stealth`.

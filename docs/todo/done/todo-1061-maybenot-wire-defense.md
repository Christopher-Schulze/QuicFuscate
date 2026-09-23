---
id: TODO-1061
title: Maybenot as the measured wire defense
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-21
depends_on: [TODO-1052, TODO-1053, TODO-1060]
---

# TODO-1061: Maybenot as the measured wire defense

## Why

Maybenot (WPES 2023, crate 2.2.2 as of 2025-09-12) is a Rust runtime for traffic-analysis defenses. Machines take wire events and emit `SendPadding` or `BlockOutgoing` with hard limits. Upstream ships machines for FRONT and RegulaTor, plus a simulator. That is the replacement for the bandit, not a fifth padding strategy. It is not a cipher.

## Current code (post-change)

- `maybenot = "2.2.2"` pinned on the crate that owns the connection send
  loop (root `quicfuscate`, not `qf-crypto`). `maybenot-simulator = "2.2.1"`
  rides the `benches` feature only.
- `src/core/connection/maybenot.rs`: per-connection `MaybenotRuntime`
  wrapping `maybenot::Framework<Vec<Machine>, SmallRng, Instant>` with the
  integrator-owned state the upstream contract requires (action timers,
  internal timers, blocking window, bypass tracking).
- Config path: `stealth.maybenot_machine = "<serialized machine>"` (TOML
  key in `qf-stealth` + `qf-engine-types`). `StealthManager::maybenot_machine()`
  returns it only on stealth-family modes; `off`/`performance` ignore the
  key. No preset ships one. An invalid string disables the adapter with a
  warning (fail closed).
- Send path: `NormalSent` after `conn.send` produced a datagram,
  `TunnelSent` at the final emit point (`emit_queued_packet` and the raw
  emit tail), `PaddingSent` when a machine pad is queued. FEC repairs and
  repair-ACK reports that bypass `conn.send` report `NormalSent` when they
  enter the wire queue.
- Recv path: `TunnelRecv` + `NormalRecv` after `conn.recv` accepts a
  datagram (`deliver_wire_payload`). Upstream `TriggerEvent` carries no
  length field — direction-only per-datagram events are the honest
  fulfillment of "lengths and direction only"; no payload, address or
  timing metadata crosses the boundary.
- `SendPadding` matures into a QUIC `PADDING` frame of
  `effective_path_mtu - 48` queued before the next seal and charged to
  `try_spend_wire_cover` (TODO-1052). A denied spend drops the action and
  bumps `MAYBENOT_PADDING_BUDGET_DROPPED` — no private overhead channel.
- `BlockOutgoing` opens a send block clamped to `pto / 4` (same bound as
  TODO-1053); a zero/unknown PTO yields no block. `maybenot_blocks_send`
  returns false when the only sendable is the ACK queue — pure ACKs flow.
  Pads during a non-bypassable block are held (upstream "queue padding"),
  bypass pads on bypassable blocks ride the next allowed packet.
- `next_send_deadline()` folds in armed actions, internal timers and the
  blocking-window end so the runtime wakes exactly when the machine needs
  it.

## Simulator

- Harness: `scripts/benchmarks/maybenot_sim.rs` (`[[bench]] maybenot_sim`,
  `benches` feature, `maybenot-simulator` 2.2.1). It parses an upstream
  `nanos,{s,r}` trace, runs `sim()` with the operator's machine on the
  client, prints padding share vs sent and vs input plus blocked time,
  and can write the defended trace for an external classifier run.
- Smoke run (proves the harness works end-to-end, NOT a WF evaluation):
  upstream docs.rs example machine over the 10-packet example trace →
  1 padding packet on 6 normal sends, padding share of sent 14.29%,
  padding vs input 10.00%, blocked 0us.
- Real WF evaluation: **not run**. There is no website-fingerprinting
  trace and no published classifier (DF/deepcoffin) in this repo. The
  command that runs the overhead half is:

      cargo bench --bench maybenot_sim --features benches -- \
          --machine <serialized-machine-file> \
          --trace <input.trace> [--delay-ms 10] [--out defended.trace]

  Accuracy then requires scoring `defended.trace` with a published WF
  classifier — deliberately not claimed here.

## Sub-Tasks (final)

Recorded above under Simulator — all boxes checked except the deferred
WF evaluation, which stays open until a trace and classifier exist.

## Acceptance (final)

Recorded above — all adapter acceptance items verified; classifier
accuracy explicitly not claimed.

## Risks

- Blocking still causes PTO if the clamp is skipped. The clamp is mandatory.
- A machine trained on Tor cells will not fit a Chrome length set. Do not enable a Tor machine on `stealth`.

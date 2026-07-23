---
id: TODO-560
title: Make active-connection FEC policy changes truthful
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-558, TODO-559]
---

# TODO-560: Make Active-Connection FEC Policy Changes Truthful

## Why

`QuicFuscateEngine::set_fec_mode()` claims that FEC can change without restarting the engine, but it currently updates only `EngineConfig` and the exported engine statistic. The active client connection retains its original `AdaptiveFec` policy. Standalone server reload updates shared FEC configuration for later connection construction without a proven policy transition for already-active sessions. A successful control-plane response can therefore report Off while live connections continue Auto repair behavior.

## Acceptance

- Define one typed active-policy transition contract for `Off` and `Auto`, including command acknowledgement, effective-policy observation, connection scope, transition timing, queued source/repair ownership, and failure semantics.
- Make the Engine client setter update the active connection or fail explicitly without mutating reported state. A successful response must mean the active policy is effective and observable.
- Give standalone server reload one explicit contract: atomically update every active session or explicitly report next-connection-only scope. Do not present future-connection configuration as an active-session change.
- On Auto-to-Off, cancel pending adaptive transitions, stop new repairs, retire or safely discard queued repair-only datagrams, preserve source datagrams, clear recovery-only state, and reach Zero without packet corruption, duplication, or stale process gauges.
- On Off-to-Auto, restore a validated adaptive bootstrap and allow the controller to select the cheapest sufficient mode without reusing stale loss, encoder, decoder, or repair-retention state.
- Serialize concurrent policy commands with connection lifecycle, shutdown, reconnect, config reload, Brain hints, loss feedback, and send/receive processing. Last accepted command wins deterministically.
- Expose configured and effective policy separately where a boundary cannot apply immediately. Never update `fec_mode` statistics before the effective transition succeeds.
- Preserve the current Svelte web-admin and Svelte/Tauri desktop UI byte- and pixel-identically; this task changes Rust control/runtime behavior and tests only.

## Completion Gates

- Contract gate: public methods, command results, telemetry, documentation, and admin/engine responses distinguish requested, configured, effective, pending, rejected, and next-connection-only state.
- Transition gate: failable tests cover Auto-to-Off and Off-to-Auto at idle, mid-source-window, with queued repairs, under loss, during backpressure, concurrent with disconnect/reconnect, and under repeated commands.
- Integrity gate: source delivery is byte-exact with zero duplicates; Off produces no repair after acknowledgement; process and connection-local gauges remain balanced through transition and drop.
- Runtime gate: real Engine client and standalone server control/reload tests prove the declared active-session scope and negative failure behavior.
- Performance gate: steady-state Off and Auto hot paths remain within TODO-558 baselines; a policy command does not add packet-path locking or per-packet allocation.
- Release gate: formatting, strict Clippy, full `rust-tests`, native CI/Clippy/Release jobs, artifact SHA-256, protected UI diff, and isolated Omega live transitions pass.
- Truth gate: `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, control-plane help, runtime comments, and Dioxus backend dependencies agree before closure.

## Sub-Tasks

- [ ] Map Engine, client runtime, standalone server reload, active connection, queue, observer, telemetry, and shutdown ownership.
- [ ] Design the typed requested/configured/effective policy transition and acknowledgement model.
- [ ] Implement active client and declared server-session policy propagation without packet-path contention.
- [ ] Add deterministic transition, concurrency, integrity, telemetry, and performance regressions.
- [ ] Run local, native, exact-artifact Omega, teardown, protection, and documentation gates.

## Notes

- Primary paths: `src/engine/engine.rs`, `src/implementations/client/`, `src/implementations/server/mod.rs`, `src/core.rs`, and `src/fec/mod.rs`.
- TODO-558 owns immutable lifetime policy after connection construction plus truthful telemetry producers. This task owns policy changes after a connection is already active.
- TODO-559 must settle queued TUN/MASQUE and outbound datagram ownership before this task decides how an active Auto-to-Off command retires queued repair-only output.
- TODO-550 and TODO-551 depend on this task because their real configuration and direct Rust service flows must consume truthful effective-policy state.

## Deviations

None.

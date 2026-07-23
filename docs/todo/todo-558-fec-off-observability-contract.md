---
id: TODO-558
title: Make FEC-off control and live observability truthful
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-424, TODO-547, TODO-555]
---

# TODO-558: Make FEC-Off Control and Live Observability Truthful

## Why

The production `--fec-mode off` path currently selects `FecMode::Zero` only as the initial mode while every `AdaptiveFec` instance retains automatic control. Loss reports can therefore escalate an explicitly disabled client into repair modes. The exact TODO-555 ARM64 artifact reproduced this under 20% netem loss: the control reached Streaming mode with 75 switches. Runtime FEC acceptance also lacks trustworthy producer ownership for loss, encoded/decoded/recovered packet counts, and an exact exported mode mapping. TODO-557 cannot compare Auto against a controlled baseline or fail closed on live FEC behavior until these contracts are real.

## Acceptance

- Represent operator policy independently from the active codec mode: Off is a stable no-repair policy, Auto owns adaptation, and future explicit policies cannot be silently collapsed into initial-state hints.
- Make `--fec-mode off` remain Zero for the full connection lifetime under loss reports, ECN, ACK feedback, disturbance detection, observer updates, transition requests, and streaming hints.
- In Off mode, emit no repair symbols, create no recovery-only retention, perform no automatic mode switches, and preserve the allocation-free or minimal-overhead Zero fast path.
- Keep Auto behavior adaptive, including bounded escalation and de-escalation, without changing Fountain's recovery-first role under catastrophic loss.
- Define one exact public mapping from exported numeric mode values to `Zero`, `Light`, `Normal`, `Medium`, `Strong`, `Extreme`, `Ultra`, `Fountain`, and `Streaming`; remove stale aliases and comments.
- Give every required FEC acceptance metric one real producer and one declared scope. At minimum, expose active mode, mode transitions by reason, effective window, observed loss, source/repair packet counts, decoded/recovered packet counts, and wire-byte overhead.
- Keep process-global telemetry only where the aggregate scope is explicit. Add connection-local evidence or identifiers where a client/server aggregate could otherwise make a scenario ambiguous.
- Remove or explicitly mark metrics that cannot be produced truthfully. A zero-valued dead counter must never satisfy an acceptance gate.
- Add failable deterministic tests for Off immutability, zero repair output, Auto adaptation, metric producer ownership, exact mode mapping, transition accounting, and concurrent client/server telemetry isolation.
- Preserve the specialized harness ownership contract from TODO-555 and leave every protected Svelte/Tauri UI path byte-identical.

## Completion Gates

- Policy gate: typed tests exercise every control input and prove Off stays Zero with zero repairs and zero switches while Auto still escalates and de-escalates.
- Fast-path gate: Zero/Off allocation, CPU, and throughput measurements meet an explicit baseline and show no recovery-state growth during a long clean or lossy run.
- Telemetry gate: every required metric changes under a deterministic positive producer test, remains unchanged under its negative control, documents its scope and unit, and exports a stable name plus exact mode mapping.
- Isolation gate: simultaneous isolated client and server runtimes expose distinguishable, scenario-owned evidence without port collision or cross-process inference.
- Live gate: the exact ARM64 artifact passes repeated Off and Auto Omega matrices at clean, moderate, severe, and recovery phases; Off emits zero repairs/switches and Auto exhibits bounded expected adaptation.
- Release gate: local formatting, strict Clippy, full `rust-tests`, telemetry regressions, native CI/Clippy/Release jobs, artifact SHA-256, teardown inspection, and protected UI diff pass.
- Truth gate: CLI help, `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, telemetry comments, and the specialized harness consumers agree before closure.

## Sub-Tasks

- [x] Map engine policy, active mode, observers, transition requests, repair emission, and every exported FEC metric producer.
- [x] Design the typed operator-policy and per-runtime observability contract.
- [x] Implement immutable Off semantics and preserve adaptive Auto behavior.
- [x] Wire or retire every required FEC telemetry producer and publish exact units, scope, and mode mapping.
- [x] Add deterministic policy, telemetry, concurrency, and performance regressions.
- [x] Run local Rust and telemetry gates.
- [~] Run exact-commit native CI/Clippy/Release gates and repeated exact-artifact Omega Off/Auto matrices.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Primary policy paths: `src/main.rs`, `src/implementations/server/mod.rs`, and `src/fec/mod.rs`.
- Pre-implementation probe: `FecConfig::apply_engine_mode(Off)` set only `initial_mode=Zero` and `force_on=false`; `AdaptiveFec::new()` still installed automatic control.
- Pre-implementation probe: telemetry exported an undocumented numeric `quicfuscate_fec_mode`, incomplete loss state, and dead packet counters.
- The implementation contract separates `FecControlPolicy::{Off, Auto}` from the nine codec modes. Off rejects every non-Zero transition request; Auto retains the current adaptive cascade.
- Process telemetry owns only explicit aggregates: active-connection counts for every stable mode ID, active-window sum, cumulative lost/observed samples, committed transitions by reason, and actual source/repair/decoded/recovered wire counters. `AdaptiveFec` additionally owns a connection-local snapshot.
- Send metrics are produced only after `OutgoingFecPacket::write_to()` serializes the complete datagram into the network-facing output buffer. Receive metrics are produced only after `WireFecReceiver` accepts a framed datagram and reports original versus recovered output. Generated, queued, dropped, malformed, and duplicate symbols cannot masquerade as serialized or recovered work.
- The native performance matrix now has an explicit `fec_off_policy_fast_path` Criterion group comparing lossy hard-Off against the clean Auto/Zero baseline with persistent state and reusable output. The 4,096-packet regression separately proves zero repairs, zero encoder window state, and zero repair-retention growth under sustained total loss.
- Local evidence is green: `cargo fmt --all`, `git diff --check`, strict all-target Clippy with `rust-tests` and warnings denied, the complete `cargo test --features rust-tests` suite with 1,805 library tests plus every binary/integration/runtime/doc target, 216 FEC tests, 18 wire tests, 12 telemetry tests, 4 server-metric tests, ShellCheck and Bash syntax for the specialized harness, TODO consistency across 196 detail files with zero violations, and runtime guardrails with zero critical findings and zero warnings.
- The specialized transition harness now exposes canonical moderate (20%) and severe (40%) loss profiles and can retain a collision-safe manifest plus six client/server phase telemetry snapshots in an explicitly new `QF_E2E_ARTIFACT_DIR`. This closes TODO-558's live policy-evidence path without taking over TODO-557's comparative or statistical acceptance scope.
- `Engine::set_fec_mode()` and server runtime reload still do not prove policy changes on already-active connections. That separate active-control contract is registered as TODO-560 and does not weaken this task's connection-construction and lifetime-Off scope.
- Exact probe source commit: `222ebdc0c91a887e480dc6697f82e45e4c9d417c`; ARM64 binary SHA-256: `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`.
- This task owns control and observability correctness. Scenario thresholds and comparative acceptance remain TODO-557.

## Deviations

None.

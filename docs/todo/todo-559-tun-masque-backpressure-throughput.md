---
id: TODO-559
title: Make TUN/MASQUE sustained throughput backpressure-safe
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-422, TODO-534, TODO-544, TODO-555]
---

# TODO-559: Make TUN/MASQUE Sustained Throughput Backpressure-Safe

## Why

The exact TODO-555 ARM64 artifact establishes and pings through the authenticated tunnel, but sustained valid IPv6 traffic can fill the fixed QUIC DATAGRAM queue. `send_masque_datagram()` currently maps every enqueue failure to `InternalError`; `send_tunnel_packet()` then falls back immediately to framed H3, and the client loop consumes the TUN frame before either carrier has accepted it. The current live probe produced repeated MASQUE and H3 `InternalError` messages, TUN packet failures, a heartbeat timeout, and roughly 0.13 Mbit/s where the earlier TODO-535 artifact proved about 3 Mbit/s. Liveness and FEC benefit cannot be evaluated truthfully while expected backpressure is misclassified or consumed packets can disappear.

## Acceptance

- Preserve one explicit ownership state for every TUN packet from read through carrier acceptance, transport acknowledgement or declared terminal failure. A packet must never disappear because a bounded queue is temporarily full.
- Distinguish retryable DATAGRAM capacity/backpressure from protocol, negotiation, connection, and internal failures without erasing the original transport error.
- Apply bounded backpressure to TUN intake and retry accepted work fairly. Define queue capacity, byte bound, wake-up condition, timeout, overload behavior, and shutdown ownership.
- Keep QUIC DATAGRAM as the low-latency path for eligible packets. Use framed H3 only for packets or negotiated states where it is semantically valid, not as an unconditional reaction to transient DATAGRAM pressure.
- Integrate with canonical ACK/loss/PTO and writable-deadline ownership from TODO-544 instead of creating a parallel retransmission or timer system.
- Maintain heartbeat and control-plane progress during sustained uplink and bidirectional load. No select-branch starvation, busy loop, unbounded retry, log flood, or control-frame starvation is allowed.
- Prove byte-exact IPv4 and IPv6 TCP/UDP transfer through the real authenticated TUN/MASQUE path at clean link, random loss, reordering, jitter, and configured bottleneck pressure.
- Define current-artifact throughput, CPU, allocation, queue-depth, latency, and loss baselines. Regressions must fail on zero receiver bytes, unit/parser errors, application-level truncation, internal-error floods, or heartbeat timeout.
- Emit bounded backpressure/drop/error telemetry with exact cause ownership. An intentional overload rejection must be explicit and measurable, never a silent green.
- Preserve TODO-555 runtime isolation and leave every protected Svelte/Tauri UI path byte-identical.

## Completion Gates

- Ownership gate: deterministic state-machine tests prove each frame is queued, retried, accepted exactly once, or terminates with one observable error across capacity pressure, carrier fallback, disconnect, and shutdown.
- Failability gate: injected DATAGRAM full, H3 blocked, socket blocked, peer close, and heartbeat starvation cases reject silent loss, duplicate delivery, unbounded memory, generic error erasure, and false-green summaries.
- Integrity gate: repeated valid TCP and UDP payloads arrive byte-identical with explicit sender/receiver byte equality and no application-level loss below the configured admitted-load ceiling.
- Performance gate: clean and impaired throughput, p50/p95 latency, CPU, allocations, queue depth, and retained-throughput ratios meet recorded architecture-specific bounds against the TODO-534/TODO-535 evidence.
- Liveness gate: sustained bidirectional load completes without MASQUE/H3 internal-error floods, TUN send failures, heartbeat timeout, control-plane starvation, or stuck teardown.
- Release gate: local formatting, strict Clippy, full `rust-tests`, focused transport regressions, native CI/Clippy/Release jobs, exact ARM64 artifact SHA-256, repeated Omega matrices, zero residue, and protected UI diff pass.
- Truth gate: runtime telemetry, harness parsers, `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, and this detail file report the same ownership and measured thresholds.

## Sub-Tasks

- [ ] Map TUN reader, channel, event-loop, DATAGRAM queue, framed H3, socket flush, heartbeat, and shutdown ownership.
- [ ] Design the minimal bounded packet state machine and integrate TODO-544 writable/loss deadlines.
- [ ] Preserve transport error classes and implement fair backpressure without duplicate carrier ownership.
- [ ] Add exact delivery, overload, starvation, shutdown, telemetry, and parser regressions.
- [ ] Establish clean and impaired local/native performance baselines.
- [ ] Run exact-commit native CI/Clippy/Release gates and repeated exact-artifact Omega TCP/UDP matrices.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Primary paths: `src/main.rs`, `src/core.rs::send_tunnel_packet()`, `src/transport/h3.rs::send_masque_datagram()`, QUIC DATAGRAM queue ownership in `src/transport/connection.rs`, and the TUN E2E harnesses.
- `send_masque_datagram()` currently converts every `dgram_send()` error into `Error::InternalError`, preventing the caller from distinguishing queue pressure from terminal failure.
- The client loop currently removes a frame from its channel before `send_client_tun_packet()` proves carrier acceptance.
- The exact TODO-555 artifact emitted repeated `MASQUE datagram send failed, using framed H3 fallback: InternalError` and `TUN packet send failed: Transport("H3 error: InternalError")` messages during the TODO-557 inventory probe.
- TODO-535 previously proved 3.001 Mbit/s clean median and 2.862 Mbit/s at 5% loss on its exact artifact. Those historical values are comparison evidence, not a passing threshold for a different artifact.
- This task owns sustained data-plane delivery and pressure semantics. TODO-544 owns canonical QUIC loss/PTO timers; TODO-557 owns final FEC scenario acceptance.

## Deviations

None.

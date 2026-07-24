---
id: TODO-531
title: Wire production logging configuration and lifecycle proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-446, TODO-527]
---

# TODO-531: Wire Production Logging Configuration and Lifecycle Proof

## Why

The production logger has compact JSON/text formatting, size rotation, retention, per-module filters, file/stderr sinks, RFC 5424 UDP, and the admin buffer adapter. Startup initializes it from `LoggingConfig::default()` before reading the operator configuration, so configured behavior is not active. Shutdown flush and enabled-path cost are unproven.

## Acceptance

- Load and validate the effective logging configuration before the single global logger initialization; CLI/runtime level changes may narrow filters but must not replace sink ownership.
- Keep the documented stable NDJSON schema (`ts`, `level`, `target`, `msg`) valid and add process-level schema proof.
- Prove configured file-only, stderr-only, dual-output, size rotation, retention, per-module filters, RFC 5424 delivery, and admin-buffer delivery.
- Explicitly flush all owned sinks during clean shutdown and prove final-record durability.
- Define bounded behavior for file and syslog errors without recursion or process failure.
- Benchmark enabled `info` logging and either meet the retained 1us producer budget or replace synchronous sinks with a bounded worker that does.
- Keep deterministic size rotation as the only application-owned rotation policy; daily rotation remains outside scope.
- Pass full local Rust gates, native CI, Omega process proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Configuration gate: process tests prove file-only, stderr-only, dual-output, per-module filters, admin buffer, RFC 5424 delivery, invalid configuration, and single logger ownership.
- Durability gate: rotation, retention, file/syslog failure, recursion prevention, and clean shutdown prove bounded behavior and final-record persistence with the stable NDJSON schema.
- Performance gate: measured `info` producer cost meets 1 microsecond or the implementation uses one proven bounded worker with explicit saturation behavior.
- Release gate: full Rust gates, native CI, exact-artifact Omega sink/rotation/restart proof, SHA-256, cleanup, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Resolve startup ordering and single logger ownership before editing.
- [ ] Wire effective configuration and explicit shutdown flush.
- [ ] Add process-level sink, schema, rotation, failure, and performance tests.
- [ ] Execute local, native, and Omega gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-446 reconciliation. Existing formatter/appender units remain useful but insufficient.
- Primary surfaces: `src/logging.rs`, `src/engine/config.rs`, `src/main.rs`, `src/implementations/server/mod.rs`, `config/quicfuscate.toml`, and `config/server-linux.default.toml`.
- Scope lock: preserve one global application logger and the stable NDJSON schema. Audit logging remains TODO-525, daily rotation remains external, and no second async runtime, collector, or UI log surface may be introduced.
- Evidence bundle: record effective configuration precedence, sink matrix, schema samples, rotation/retention state, failure injection, final-record flush, producer-latency distribution, queue/drop bounds if asynchronous, artifact hash, and Omega file/socket cleanup.

## Deviations

None.

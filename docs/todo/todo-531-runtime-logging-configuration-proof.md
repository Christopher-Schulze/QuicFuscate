---
id: TODO-531
title: Wire production logging configuration and lifecycle proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-446, TODO-521]
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

## Sub-Tasks

- [ ] Resolve startup ordering and single logger ownership before editing.
- [ ] Wire effective configuration and explicit shutdown flush.
- [ ] Add process-level sink, schema, rotation, failure, and performance tests.
- [ ] Execute local, native, and Omega gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-446 reconciliation. Existing formatter/appender units remain useful but insufficient.

## Deviations

None.

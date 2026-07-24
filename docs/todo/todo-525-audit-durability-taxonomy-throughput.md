---
id: TODO-525
title: Complete audit durability, taxonomy, and throughput contract
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-439, TODO-515, TODO-527, TODO-531]
---

# TODO-525: Complete Audit Durability, Taxonomy, and Throughput Contract

## Why

The retained audit log is append-only NDJSON with file permissions, a hash chain, a production verification CLI, and real authentication, connection, admin, and firewall events. Its caller still performs synchronous mutex-protected write plus flush, the file grows without bound, tail deletion cannot be proven without an external checkpoint, and the event taxonomy omits required security outcomes.

## Acceptance

- Move serialization, hash chaining, file I/O, and durability flushes behind one bounded worker with non-blocking producers and an explicit dropped-event counter.
- Preserve total event order and chain integrity under concurrent producers, shutdown, I/O failure, queue saturation, and process restart.
- Add configurable bounded rotation and retention with verifiable chain continuity across every retained segment; do not silently delete the only proof anchor.
- Extend verification to ordered segment sets, mutation, interior deletion, reordering, truncation, and tail-deletion detection through a durable checkpoint contract.
- Complete typed auth, QKey, connection, admin, config, firewall/routing, privilege, and system event coverage with actor, target, outcome, and reason fields where applicable.
- Sustain 10,000 accepted events per second without producer-side file I/O or unbounded memory growth, with deterministic saturation and shutdown tests.
- Keep RFC 5424 and CEF transport outside the process; document canonical NDJSON collector integration instead.
- Pass full local Rust gates, relevant native CI, live Omega lifecycle proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Integrity gate: mutation, deletion, reordering, truncation, tail loss, rotation, restart, and checkpoint tests all fail on invalid chains and pass on valid ordered segment sets.
- Load gate: a measured 10,000 accepted events per second produces no producer-side file I/O, unbounded queue growth, order loss, or silent loss; any dropped event is counted and observable.
- Lifecycle gate: I/O failure, saturation, rotation, retention, and shutdown preserve the declared durability contract and final accepted records.
- Release gate: full Rust gates, relevant native CI, exact-artifact SHA-256, Omega process/restart/collector proof, clean teardown, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Define the ordered queue, flush, failure, checkpoint, and shutdown contracts before editing.
- [ ] Implement bounded asynchronous persistence and rotation without parallel audit owners.
- [ ] Complete event taxonomy and runtime call sites.
- [ ] Add integrity, saturation, failure, restart, rotation, and throughput gates.
- [ ] Execute local, native, and Omega evidence and flush documentation.

## Notes

- Created from TODO-439 reconciliation. Syslog and CEF conversion remain external collector responsibilities.
- Primary surfaces: `src/audit/mod.rs`, `src/main.rs`, `src/implementations/server/mod.rs`, `src/implementations/server/admin_http.rs`, `src/implementations/server/qkey_registry.rs`, and `src/implementations/server/routing.rs`.
- Scope lock: preserve the existing global audit owner and NDJSON/hash-chain contract; do not create a second logger, collector, database, or network exporter. Start by tracing every current producer and shutdown path into one ordered event map.
- Evidence bundle: record queue and segment bounds, checkpoint format, injected failure points, accepted/dropped counts, throughput distribution, restart/rotation manifests, verifier output, artifact SHA-256, and final Omega residue state.

## Deviations

None.

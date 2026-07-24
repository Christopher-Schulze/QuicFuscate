---
id: TODO-529
title: Wire per-client bandwidth, quota, and fairness enforcement
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-445, TODO-523]
---

# TODO-529: Wire Per-Client Bandwidth, Quota, and Fairness Enforcement

## Why

Token-bucket, quota, statistics, and client-map helpers exist with unit tests but have no production caller. Sessions, TUN/MASQUE forwarding, QKey policy, and admin routes do not own or enforce them, and no fair scheduler exists.

## Acceptance

- Define one per-session owner for bidirectional byte-rate, burst, and quota state, created after authentication and removed on every close/expiry path.
- Enforce configured limits at the real uplink and downlink boundaries without unbounded queues, silent cross-client coupling, or packet-order corruption.
- Define deterministic UTC daily and monthly quota periods plus typed block, throttle, or disconnect outcomes with audit and metrics coverage.
- Add bounded deficit-round-robin scheduling for competing downlink clients with explicit weights and no starvation.
- Extend QKey policy and authenticated admin routes for read, update, and reset operations with exact precedence over global defaults.
- Prove unlimited, 10 Mbit/s, burst, quota, equal-weight, and 1:2:1 cases with three real clients and measured throughput on Omega.
- Pass full local Rust gates, native CI, Omega proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Ownership gate: authenticated session creation, update, expiry, disconnect, and cleanup tests prove exactly one independent rate/quota owner per client.
- Correctness gate: byte accounting, UTC period rollover, burst, quota outcomes, precedence, admin mutation, and audit/metric assertions pass without cross-client leakage or packet reordering.
- Fairness gate: controlled three-client unlimited, 10 Mbit/s, equal-weight, and 1:2:1 matrices meet documented tolerance with no starvation or unbounded queue.
- Release gate: full Rust gates, native CI, exact-artifact Omega throughput proof, SHA-256, cleanup/residue checks, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map session, QKey, admin, and forwarding ownership before editing.
- [ ] Wire typed rate/quota state and cleanup into authenticated sessions.
- [ ] Add fair scheduling and control-plane operations.
- [ ] Add unit, integration, and three-client throughput gates.
- [ ] Execute local, native, and Omega evidence and flush documentation.

## Notes

- Created from TODO-445 reconciliation. Existing helper units are evidence only, not runtime enforcement.
- Primary surfaces: `src/implementations/server/bandwidth.rs`, `src/implementations/server/session.rs`, `src/implementations/server/mod.rs`, `src/implementations/server/admin_http.rs`, `src/implementations/server/qkey_registry.rs`, and `src/implementations/server/metrics.rs`.
- Scope lock: one authenticated-session policy owner must consume the existing helpers or replace them in place. Do not create a second scheduler, billing service, durable accounting database, or UI control surface; exact admin/API behavior belongs to the existing typed control boundary.
- Evidence bundle: retain configured/effective policy, byte-accounting ledgers, rollover clock inputs, scheduler decisions, per-client queue bounds, throughput/fairness distributions, audit/metric output, artifact SHA-256, and cleanup proof.

## Deviations

None.

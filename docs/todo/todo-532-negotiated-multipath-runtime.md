---
id: TODO-532
title: Complete negotiated multipath wire and data-plane runtime
severity: CRITICAL
phase: S
priority: P0
status: SCRAPPED
created: 2026-07-22
scrapped: 2026-07-24
depends_on: [TODO-449, TODO-533, TODO-544]
---

# TODO-532: Complete Negotiated Multipath Wire and Data-Plane Runtime

**SCRAPPED (2026-07-24):** Owner decision - multipath (WiFi+LTE bonding) is explicitly excluded from the product roadmap. Existing `PathManager`/`PathScheduler` helper code in `src/transport/path.rs` and `src/transport/path_scheduler.rs` is retained as dead code but will not be wired into the production runtime. All dependent tasks have had their `depends_on` updated to remove this reference.

## Why

`PathState`, `PathManager`, and `PathScheduler` model isolated multipath behavior, but `Connection` never owns or invokes them. There is no negotiated multipath wire contract, per-path packet-number/recovery state, production scheduler, standby failover, or bonded runtime evidence.

## Acceptance

- Define and implement one standards-tracked negotiated multipath contract, including transport parameters, path lifecycle frames, peer validation, and downgrade behavior.
- Give each active path independent packet-number, AEAD nonce, RTT, recovery, congestion, loss, byte-counter, and anti-amplification state without nonce reuse.
- Wire selectable lowest-RTT, configured-weight, redundant, and primary-with-standby strategies into the production send path; keep disabled mode byte-for-byte behaviorally compatible.
- Prove simultaneous dual-path transfer, per-path accounting, loss isolation, no-disconnect failover under 100 ms, and at least 1.5x aggregate throughput on controlled WiFi/LTE-like paths.
- Add exhaustive failable units for frame codecs, negotiation, all strategies, state transitions, manager operations, nonce vectors, and failure handling.
- Pass local Rust gates, native CI, privileged Omega dual-interface proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Standards gate: the exact current primary multipath draft, versioned wire choices, negotiation, downgrade, frame codecs, and peer-validation rules are recorded and covered by vectors.
- Isolation gate: deterministic tests prove independent per-path packet number, nonce, RTT, recovery, congestion, anti-amplification, and byte state with no reuse or cross-path corruption.
- Network gate: controlled dual-interface matrices prove all schedulers, simultaneous transfer, loss isolation, failover under 100 ms, and at least 1.5x aggregate throughput while disabled mode remains compatible.
- Release gate: local Rust gates, native CI, exact-artifact Omega proof, SHA-256, teardown/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Verify the current IETF multipath draft and select the exact wire contract before editing.
- [ ] Design per-path state ownership and connection integration.
- [ ] Implement negotiation, codecs, scheduling, recovery, and failover atomically.
- [ ] Add unit, integration, performance, and privileged network proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-449 reconciliation. Existing path and scheduler helpers may be retained only where they match the selected wire/runtime contract.
- Primary surfaces: `src/transport/path.rs`, `src/transport/path_scheduler.rs`, `src/transport/config.rs`, `src/transport/connection.rs`, `src/core.rs`, and `src/engine/`.
- Scope lock: select one current standards-tracked wire version from primary sources before coding. Do not ship private unversioned frames, reuse packet numbers/nonces across paths, or let existing helper APIs dictate a non-compliant protocol.
- Evidence bundle: retain the cited draft/version, vectors, negotiated parameters, per-path state snapshots, scheduler decisions, packet-number/nonce traces, failover timing, throughput distributions, artifact hash, interface teardown, and route/qdisc residue.

## Deviations

None.

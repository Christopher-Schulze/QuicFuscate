---
id: TODO-521
title: Reconcile legacy DONE acceptance contracts with production truth
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-448, TODO-520]
supersedes: []
---

# TODO-521: Reconcile Legacy DONE Acceptance Contracts with Production Truth

## Why

The post-TODO-448 exhaustive backlog audit found 31 detail files marked `DONE` while 441 acceptance checkboxes remain unchecked. Some are stale documentation only, some describe architecture explicitly superseded by later tasks, and some appear to be real unimplemented production contracts. The existing consistency audit validates frontmatter and index parity but cannot detect a false `DONE` claim.

Two direct contradictions prove this is blocking rather than cosmetic:

- TODO-457 requires runtime QKey challenge-response, TLS exporter binding, replay protection, and optional client-certificate mutual TLS. `AuthFrame` and `verify_auth_frame()` have no non-test runtime caller. TODO-520 instead intentionally establishes the current canonical contract as a post-TLS encrypted HTTP/3 bearer.
- TODO-449 requires live multipath transport, wire frames, failover, and throughput evidence. `PathManager` and `PathScheduler` exist with unit tests, but no production `Connection` caller owns or invokes them.

Global production-readiness cannot remain closed until every affected acceptance item is either proven, implemented, or explicitly superseded by a named current contract.

## Acceptance

- Classify all 441 unchecked items in the 31 `DONE` detail files as verified, superseded, non-goal, or genuine gap, with code/test/runtime evidence.
- Reopen every genuine gap and split implementation work into bounded follow-up TODOs before changing product code.
- Replace every superseded criterion with a named successor contract; never silently mark stale architecture as implemented.
- Close or explicitly justify all nine `DEFERRED` detail files, including TODO-447's historical unchecked Docker criteria.
- Extend the TODO consistency audit so `DONE` files cannot retain unclassified unchecked acceptance criteria.
- Keep `docs/todo.md`, `docs/DOCUMENTATION.md`, and affected detail files aligned with the verified result.
- Run the relevant local, native CI, and live Omega evidence required by each reopened production contract.
- Preserve all protected Svelte/Tauri UI files byte-for-byte.

## Sub-Tasks

- [x] Build the complete acceptance-item inventory and assign evidence-backed classifications.
- [x] Reconcile superseded identity, authentication, cryptography, and security contracts.
- [x] Reconcile data-plane, multipath, migration, IPv6, firewall, and TUN contracts.
- [x] Reconcile cross-platform Windows, installation, logging, and lifecycle contracts.
- [x] Reconcile congestion control, PMTUD, traffic-analysis, fingerprinting, and performance contracts.
- [x] Resolve or explicitly retire every deferred task under current product scope.
- [x] Add the DONE-acceptance CI guard and prove it fails on an unclassified item.
- [ ] Execute all follow-up implementation tasks and their required local/native/live gates.
- [ ] Flush final documentation truth and restore the production-readiness closure only after zero gaps remain.

## Notes

- Reconciliation markers are authoritative: `VERIFIED` names current code/test/runtime evidence; `SUPERSEDED` names the current successor contract; `NON-GOAL` removes an obsolete product obligation with explicit scope; `GAP -> TODO-NNN` transfers an unmet production obligation to an open successor task. A checked legacy item means classified, not automatically implemented.
- Initial inventory: 166 detail files total; 139 `DONE`, 18 `SCRAP`, 9 `DEFERRED`; 31 `DONE` files contain 441 unchecked items; TODO-447 adds 12 unchecked historical Docker items.
- The discovery occurred after TODO-448 closure commit `90db0835c7ad5f0a29541e04dbfcfdc7227dac17` and invalidates only the global closure claim, not TODO-448's verified lifecycle result.
- Current architecture contracts are canonical. Historical criteria must be marked with an explicit successor when superseded; otherwise they remain binding evidence requirements.
- First classified gaps: TODO-515 was reopened, gained authentication-timeout, connection-lifecycle, firewall-mutation, production CLI chain verification, and real auth-plus-admin integration coverage, passed full local gates, and is closed again. TODO-516 was reopened, gained a production-boundary test plus native ARM64 `VmLck` proof, passed full local gates, and is closed again.
- TODO-437 through TODO-441 reconciliation transferred kill-switch DNS/IPv6 proof to TODO-522, production client isolation to TODO-523, audit durability/taxonomy to TODO-525, retained secret erasure to TODO-526, and irreversible privilege reduction plus post-drop runtime proof to TODO-527. Syslog/CEF formatting, application-owned chroot, and deprecated macOS sandbox profiles are explicit non-goals with external collector or service-manager successors.
- TODO-442 and TODO-444 through TODO-446 reconciliation transferred native Wintun data-plane proof to TODO-528, per-client bandwidth enforcement to TODO-529, firewall-backend configuration plus privileged nftables proof to TODO-530, and effective runtime logging configuration to TODO-531. Daily application log rotation is superseded by the canonical bounded size-retention policy.
- TODO-449 through TODO-453 reconciliation transferred complete multipath wiring to TODO-532, configurable CC-aware migration to TODO-533, 1500-byte DPLPMTUD plus TUN/runtime proof to TODO-534, CUBIC conformance and live fairness/loss proof to TODO-535, and standards-based QUIC v2/version negotiation to TODO-536. Private custom QUIC versions and a parallel common-MTU table are explicit non-goals.
- TODO-455 through TODO-463 reconciliation transferred timer-owned traffic-analysis defense to TODO-537, complete QKey auth blocking to TODO-538, fail-closed QKey registry encryption to TODO-539, sustained DDoS policy to TODO-540, clean-distro installer proof to TODO-541, owned cleanup lifecycle to TODO-542, complete TCP/ICMP fingerprint runtime proof to TODO-543, and RFC loss detection to TODO-544. TODO-457's challenge-response and mutual-client-PKI design is superseded by TODO-520's single encrypted HTTP/3 bearer contract.
- All nine deferred files are resolved: TODO-356, TODO-378, TODO-396 through TODO-398, and TODO-409 are scrapped with explicit successors or non-contract rationale; TODO-358 and TODO-447 are closed against current evidence/scope; TODO-362 is reopened for the live FEC suppression audit; cipher reinstallation safety moved to TODO-545. No `DEFERRED` detail remains.
- `audit-todo-consistency.sh` now rejects unchecked checklist items inside `Acceptance`, `Acceptance Criteria`, or `Completion Criteria` sections of every `DONE` detail file. The 191-file repository audit passes with zero violations; an isolated DONE fixture with one unchecked acceptance item fails with exactly one violation and exit code 1. The existing `todo-consistency` CI job invokes this guard.

## Deviations

None.

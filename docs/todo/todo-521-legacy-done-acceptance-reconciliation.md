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

- [~] Build the complete acceptance-item inventory and assign evidence-backed classifications.
- [ ] Reconcile superseded identity, authentication, cryptography, and security contracts.
- [ ] Reconcile data-plane, multipath, migration, IPv6, firewall, and TUN contracts.
- [ ] Reconcile cross-platform Windows, installation, logging, and lifecycle contracts.
- [ ] Reconcile congestion control, PMTUD, traffic-analysis, fingerprinting, and performance contracts.
- [ ] Resolve or explicitly retire every deferred task under current product scope.
- [ ] Add the DONE-acceptance CI guard and prove it fails on an unclassified item.
- [ ] Execute all follow-up implementation tasks and their required local/native/live gates.
- [ ] Flush final documentation truth and restore the production-readiness closure only after zero gaps remain.

## Notes

- Initial inventory: 166 detail files total; 139 `DONE`, 18 `SCRAP`, 9 `DEFERRED`; 31 `DONE` files contain 441 unchecked items; TODO-447 adds 12 unchecked historical Docker items.
- The discovery occurred after TODO-448 closure commit `90db0835c7ad5f0a29541e04dbfcfdc7227dac17` and invalidates only the global closure claim, not TODO-448's verified lifecycle result.
- This is a scope expansion larger than the completed graceful-shutdown task. Product code changes are paused until the canonical treatment of superseded historical criteria is confirmed.

## Deviations

None.

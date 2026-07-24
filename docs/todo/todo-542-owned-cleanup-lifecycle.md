---
id: TODO-542
title: Complete owned TUN and firewall cleanup lifecycle
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-461, TODO-530]
---

# TODO-542: Complete Owned TUN and Firewall Cleanup Lifecycle

## Why

Server startup invokes routing cleanup and server shutdown retries routing teardown, but backend failures can be debug-only and successful-looking. There is no postcondition verification, client symmetry, owned TUN fallback, injected failure coverage, or crash/restart proof.

## Acceptance

- Give Linux, macOS, and Windows routing backends typed command outcomes and exact ownership identifiers for every rule/table/anchor/NAT object.
- Retry bounded transient failures, verify every cleanup postcondition, and invoke only target-specific owned fallback deletion.
- Never flush shared firewall chains or delete an interface whose ownership cannot be proven.
- Run startup cleanup before setup on server and client; make teardown idempotent under partial setup, repeated shutdown, and crash residue.
- Prove first-failure recovery, persistent failure reporting, preseeded residue cleanup, crash/restart success, and zero unrelated firewall changes.
- Pass local Rust gates, native platform CI, privileged Omega proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Ownership gate: every created interface, route, rule, table, anchor, NAT object, and process resource has a typed identity, creator, cleanup owner, and verified postcondition.
- Failure gate: injected transient, permanent, partial-setup, repeated-shutdown, and command-output failures prove bounded retry, exact reporting, idempotence, and target-only fallback.
- Native lifecycle gate: Linux, macOS, and Windows tests prove stale startup cleanup, crash/restart recovery, client/server symmetry, zero owned residue, and zero unrelated firewall or route delta.
- Release gate: local Rust gates, native platform CI, exact-artifact privileged Omega proof, SHA-256, residue manifest, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map every platform setup/teardown/startup caller and command signature.
- [ ] Design owned resource identities, typed outcomes, retries, and postconditions.
- [ ] Implement injectable runners and exhaustive failure tests.
- [ ] Execute native and privileged residue/crash proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-461 reconciliation. Shared-chain flushes are explicitly forbidden.
- Primary surfaces: `src/implementations/server/routing.rs`, `src/implementations/client/killswitch.rs`, `src/firewall/mod.rs`, `src/interface.rs`, `src/main.rs`, and the TUN/kill-switch harnesses under `scripts/tests/`.
- Scope lock: every fallback requires a proven QuicFuscate ownership identity and target-specific postcondition. Never infer ownership from a generic interface name, flush shared state, kill unrelated processes, or hide permanent cleanup failure behind debug logging.
- Evidence bundle: record the resource ownership ledger, injected command results, retry timing, preseeded/crash state, pre/post native firewall and route snapshots, unrelated-resource fingerprints, artifact SHA-256, and final zero-owned-residue manifest.

## Deviations

None.

---
id: TODO-804
title: Make Omega proof checkout ownership singular and inspectable
severity: HIGH
phase: S
priority: P2
status: OPEN
created: 2026-08-03
depends_on: []
---

# TODO-804: Make Omega Proof Checkout Ownership Singular and Inspectable

## Current execution gate (2026-09-23)

The two-checkout/PID inventory below is historical, not the current remote
layout. `docs/todo.md` records the user's 2026-08-20 Omega-only cleanup:
the owned service and TUN were stopped, bounded candidate/runtime/archive
paths removed, and one clean `~/TESTING/QuicFuscate` checkout created at
`2afac5ca`. Do not repeat that cleanup or select the retired SOFTWARE/CODE
roots from this old snapshot. The remaining gate is a **fresh read-only**
`verify-omega-proof-ownership` run against the selected TESTING root. Verify
its current Git object/diff readability, HEAD/dirty state, running process
ownership, and evidence-root collision policy; record the exact run manifest.
Then run one explicitly scoped exact-revision proof and join source, build,
artifact hash, runtime PID, result, and cleanup identity. If the host has
drifted, report `UNAVAILABLE` with the observed state and obtain an exact
new cleanup scope before changing anything remote. This task is OPEN for the
read-only preflight now; a non-pass root or missing proof authorization blocks
the subsequent runtime cell and final closure. TODO-730's local audit-runner
reporting is independent and is not a prerequisite for proof-root inspection.

## Why

Exact Omega proof requires one attributable source revision, one artifact boundary, and one owned runtime. The current host exposes two QuicFuscate checkouts with unrelated state, a large untracked candidate corpus, a live server process, and incomplete Git diff readability. Protected remote state must be reconciled before any new exact-commit proof is claimed.

## Findings

### 1. The remote proof surface is split across two non-clean states

- `omega:/home/ubuntu/SOFTWARE/QuicFuscate` is on `main` at `9b57474197f9f3e14d4b81bc61850c0f85ce6c52`, has 97 untracked status paths and 43,722 untracked files, and contains a running server from `runtime-todo528-dc72c84`.
- `omega:/home/ubuntu/CODE/QuicFuscate` is on `main` at `d36652d887c287353f1f953c2c82a58a3ddafcb3`, has 20 modified tracked files, and its `git diff --name-only` command reports a missing object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1`.
- Read-only inspection did not mutate either checkout, remove candidate data, reset Git state, or stop the live server.

## Acceptance

- One user-approved Omega proof checkout or immutable isolated runtime is selected and documented.
- The selected checkout passes Git object/readability and clean-state checks before a proof begins.
- Source revision, bundle revision, binary hashes, runtime PID, and evidence root are recorded together for every exact proof.
- Protected dirty checkouts, unrelated live processes, and unresolved Git-object failures produce `UNAVAILABLE`, not a green proof.
- Candidate and evidence cleanup is bounded to explicitly owned paths and does not touch the persistent checkout without approval.

## Sub-Tasks

- [x] Obtain ownership/cleanup direction for the historical two-checkout
      state; the user authorized Omega-only cleanup on 2026-08-20.
- [ ] Revalidate the selected `~/TESTING/QuicFuscate` proof root and its Git
      object database read-only before building; do not reuse the old report.
- [x] Add a fail-closed preflight that rejects ambiguous checkout selection, dirty state, unreadable diffs, and unrelated live processes.
- [!] Re-run one exact-commit Omega proof with source, artifact, runtime, and cleanup provenance joined in one evidence manifest.

## Notes

- This task was created from the read-only comprehensive audit on 2026-08-03.
- No remote mutation is authorized by this audit record.

## Current Reconciliation (2026-08-07)

- The protected Omega environment still has multiple or dirty QuicFuscate checkouts and no safe exact-commit attribution. Local audit evidence cannot be promoted to authenticated remote proof, and this audit performed no remote mutation. The task remains externally bounded.

## Current Reconciliation (2026-08-08)

- `scripts/audits/verify-omega-proof-ownership.sh` runs the new read-only preflight and emits `quicfuscate.omega-proof-ownership.v1` JSON with create-new output semantics and explicit mutation policy fields.
- Local implementation is committed as `47905c3` (`TASK 804: Add fail-closed Omega proof ownership preflight`).
- Live preflight report `scripts/out/audits/omega-proof-ownership-20260808T195315Z/ownership.json` is `UNAVAILABLE`: discovery finds both `/home/ubuntu/SOFTWARE/QuicFuscate` and `/home/ubuntu/CODE/QuicFuscate`; SOFTWARE has 43,722 untracked paths; CODE has 20 tracked modifications, an unreadable Git object `c7831a90bd47c77be57fb345fdf4a47a6022d3e1`, and an unreadable working-tree diff; PID `1363976` is a running server not declared as proof-owned.
- No SSH operation performed by the preflight writes files, resets Git, removes candidates, or controls processes. Exact Omega proof remains blocked until the user explicitly selects/authorizes one isolated proof root and resolves the existing dirty checkout/runtime state.

## Deviations

None.

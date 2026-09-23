---
id: TODO-1140
title: Reconcile ten legacy module coverage findings against current behavior
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-24
depends_on: []
---

# TODO-1140: Reconcile Current Behavior Coverage

## Why

TODO-379 through TODO-388 named ten real behavioral risk areas but were marked
SCRAP because a single cargo-tarpaulin baseline was expected. A coverage
summary cannot prove the named paths' behavior, and the old source sizes,
module boundaries, test counts, and proposed fixed numbers of tests are stale.
The old tasks remain historical; this task owns all ten findings on current
source without reintroducing duplicate per-file task plans.

## Target contract

At one source revision, record one row for each old ID with the current
production owner, active caller or an explicit dead-code finding, registered
unit/integration/native tests, the behavioral claim each test actually proves,
remaining gap, and disposition. A green test count or line coverage percentage
alone is insufficient. For a genuine gap, add a minimal failable real-path
test in the owning test family or create a linked focused implementation task
when a source bug prevents proof. Keep platform-only evidence explicitly
unavailable until executed on its native target. Do not set arbitrary tests
per 1,000 lines or duplicate tests just to increase inventory.

| Legacy ID | Current starting point | Behavior to reconcile |
|---|---|---|
| TODO-379 | `src/stealth/`, `crates/qf-stealth/`, stealth integration tests | Persona/TLS cover, padding and flow shaping, probe handling, mode transition, lifecycle, and fail-closed config paths. |
| TODO-380 | `src/simd.rs`, `src/optimize/simd/`, `crates/qf-cpu/`, `crates/qf-simd/`, `crates/qf-fec/` | Runtime dispatch, scalar/native parity, GF/CRC/encoding edge cases, and feature-gated fallbacks. |
| TODO-381 | `src/transport/connection/`, `scripts/tests/rust/rt-transport-connection.rs` | Handshake/state, stream/flow control, protected receive, 0-RTT, migration, recovery, and idle/keepalive transitions. |
| TODO-382 | `src/transport/h3/`, `scripts/tests/rust/rt-transport-h3.rs` | QPACK, H3 frame/control-stream placement, SETTINGS, request lifecycle, MASQUE/WebTransport admission, malformed/error paths. |
| TODO-383 | `src/implementations/server/` and its owned test modules | Session/auth admission, multi-client isolation, limits, shutdown/cleanup, metrics, and certificate failure. |
| TODO-384 | `src/optimize/iter.rs`, `crates/qf-cpu/src/iter.rs`, iterator integration tests | Empty/single/unaligned input, reduction parity, scalar/native dispatch, overflow and remainder behavior. |
| TODO-385 | `src/optimize/unsafe.rs`, `src/optimize/unsafe/tests.rs`, memory-pool/zero-copy owners | Pointer bounds, alignment, allocation failure, zeroization/lifecycle, native-only paths, and Miri feasibility. |
| TODO-386 | `src/implementations/server/fsutil.rs` | Existing happy-path, overwrite, nested directory, empty content, failed commit, destination preservation, permission tests; check any remaining atomicity/concurrency gap before adding tests. |
| TODO-387 | `src/transport/batch.rs`, `crates/qf-transport-batch/`, batch integration tests | Batch size bounds, iovec/packet lifetime, fallback parity, partial sends/receives, and Linux-native boundaries. |
| TODO-388 | `src/implementations/client/subsystems.rs` and client lifecycle tests | Existing construction/lookup tests versus actual init, ownership, teardown, and failure propagation. |

## Execution

- [ ] Read each current owner, direct caller, test registration, and existing
      failable assertion before classifying any of the ten findings.
- [ ] Build a ten-row evidence table in this task with exact paths, test names,
      revision, coverage verdict (`COVERED`, `GAP`, `DEAD`, or `NATIVE-UNAVAILABLE`),
      and the reason. Do not infer coverage from file existence or a report total.
- [ ] For each `GAP`, write the smallest direct behavior regression in the
      owning test family or open a linked implementation task with a reproducer,
      exact target state, and acceptance gates if source correction is needed.
- [ ] Run each changed test family, the relevant feature and platform matrix,
      formatting/Clippy, and the canonical coverage summary only where it
      adds measured information. Respect the Rust disk floor before builds.
- [ ] Reconcile `docs/todo.md`, each affected historical detail, and current
      documentation/MAP claims; retain native or external non-pass results as
      explicit gates rather than calling the aggregate green.

## Acceptance

- All ten legacy IDs have a current-source verdict and a cited real test or
  linked actionable child task; zero findings disappear under `SCRAP`.
- Confirmed behavior gaps have failable assertions or an owned task with a
  concrete implementation and proof contract. No tests are added solely to
  hit a numerical coverage target.
- Every touched test/build gate passes at the exact revision, with native-only
  limitations recorded as such. The task closes only when its ten-row register
  and all linked dispositions are consistent in the board.

## Notes

The source paths above are starting points, not claims that the old modules
still own the entire behavior. `fsutil.rs` already has direct tests and
`subsystems.rs` already has a test module; the old zero-test claims are stale.

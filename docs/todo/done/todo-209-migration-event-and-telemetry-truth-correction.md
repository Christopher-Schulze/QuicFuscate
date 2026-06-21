# TODO-209: Migration Event and Telemetry Truth Correction

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
Path events and telemetry currently overstate migration success by treating optimistic internal transitions as successful validated migration outcomes.

## Objective
Make migration events, counters, and runtime reporting describe only real validated outcomes.

## Scope
- `PathEvent` semantics.
- Migration-related telemetry counters and internal accounting.
- Runtime/server migration bookkeeping that depends on those events.
- Any examples or diagnostics that imply success too early.

## Detailed Work Plan
1. Audit all path event producers and consumers.
2. Separate tentative path discovery from validated migration success.
3. Update counters so they increment only on real completed migration.
4. Adjust any dependent server/runtime bookkeeping.
5. Align docs and examples after the semantics are corrected.

## Tracking Checklist
- [x] Event producers audited.
- [x] Event model corrected.
- [x] Telemetry counters corrected.
- [x] Dependent bookkeeping rechecked.
- [x] Docs/examples aligned to the new truth.

## Completion Notes
- `Validated` and `PeerMigrated` are no longer emitted optimistically from `migrate`.
- `PATH_MIGRATIONS` now increments only on validated path promotion, not on migration request start and not twice for the same transition.
- Core runtime bookkeeping now updates the active path on `Validated` and treats `PeerMigrated` as an informational old-peer/new-peer signal.

## Acceptance Criteria
- Migration telemetry reflects real validated migrations only.
- Path events no longer report success before validation completes.
- Runtime/server migration observers consume semantically correct signals.

## Dependencies
- TODO-207
- TODO-208
- TODO-210
- TODO-212

## Affected Files
- `src/transport/connection.rs`
- `src/metrics.rs`
- `src/implementations/server/accept.rs`
- `src/implementations/server/mod.rs`
- `docs/DOCUMENTATION.md`

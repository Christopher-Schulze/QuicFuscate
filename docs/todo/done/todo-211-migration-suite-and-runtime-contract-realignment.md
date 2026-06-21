# TODO-211: Migration Suite and Runtime Contract Realignment

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
Migration currently lives in a gray zone between partial implementation, optimistic tests, config exposure, and product-facing claims. Once the state machine is implemented, the runtime contract and validation suite must be rewritten around the completed truth.

## Objective
Make runtime config, suite naming, suite scope, and product contract language all match the completed migration implementation exactly.

## Scope
- Config and runtime comments.
- Transport and E2E suite descriptions.
- Runtime examples and operator-facing guidance.
- The meaning of `enable_migration` across code and docs.

## Detailed Work Plan
1. Audit every active migration-facing contract surface.
2. Define the exact finished migration contract.
3. Update suite names and runtime comments to that contract.
4. Remove any remaining “optimistic migration” wording from active code/tests.
5. Revalidate the final contract against the completed state machine.

## Tracking Checklist
- [x] Contract surfaces inventoried.
- [x] Final migration contract written down.
- [x] Suite naming updated.
- [x] Runtime comments updated.
- [x] Contract revalidated against code/tests.

## Completion Notes
- Wired `config.connection.enable_migration` into the transport runtime by driving `disable_active_migration`.
- Updated transport/core comments and suite naming so the active contract is explicitly validated migration, not optimistic path switching.
- Added an engine-level regression test proving the config flag now changes transport behavior.

## Acceptance Criteria
- The config surface, runtime code comments, and test suite names all describe the same finished migration behavior.
- No active contract surface overstates or understates migration capabilities.

## Dependencies
- TODO-207
- TODO-208
- TODO-209
- TODO-210
- TODO-212

## Affected Files
- `config/quicfuscate.toml`
- `src/engine/config.rs`
- `scripts/tests/suites/test-e2e.sh`
- `scripts/tests/suites/test-transport.sh`
- `docs/DOCUMENTATION.md`

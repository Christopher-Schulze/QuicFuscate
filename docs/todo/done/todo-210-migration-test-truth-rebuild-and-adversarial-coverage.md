# TODO-210: Migration Test Truth Rebuild and Adversarial Coverage

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
The current migration tests encode optimistic behavior as if it were true validation, which gives false confidence and actively protects the wrong contract.

## Objective
Replace optimistic migration tests with truth-preserving coverage and add adversarial cases that prove the real state machine.

## Scope
- Unit tests for the transport connection migration path.
- Integration and suite-level migration coverage.
- Negative-path and abuse-path tests.
- Test naming and assertions that currently overclaim migration completion.

## Detailed Work Plan
1. Audit all migration-related tests and suite names.
2. Rewrite optimistic event-order assertions.
3. Add success-path validation tests for the real state machine.
4. Add timeout, spoofed response, invalid response, abuse, and cooldown tests.
5. Make the suites and names describe the real behavior.

## Tracking Checklist
- [x] Migration test inventory completed.
- [x] Optimistic assertions removed.
- [x] Success-path tests added.
- [x] Negative/adversarial tests added.
- [x] Suite labels and names aligned.

## Completion Notes
- Rewrote `scripts/tests/rust/rt-transport-connection.rs` so migration no longer passes by asserting fake immediate validation.
- Added explicit mismatch, timeout, and cooldown coverage.
- Updated `scripts/tests/rust/rt-core-connection-basics.rs` and the release-suite migration selector so they validate the new contract instead of the old optimistic one.

## Acceptance Criteria
- No migration test passes by asserting fake validation.
- Adversarial and failure paths are explicitly covered.
- Test names and expectations reflect the real runtime contract.

## Dependencies
- TODO-207
- TODO-208
- TODO-209

## Affected Files
- `scripts/tests/rust/rt-transport-connection.rs`
- `scripts/tests/rust/rt-core-connection-basics.rs`
- `scripts/tests/suites/test-e2e.sh`
- related migration and transport tests

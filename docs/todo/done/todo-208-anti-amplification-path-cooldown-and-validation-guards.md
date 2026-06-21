# TODO-208: Anti-Amplification, Path Cooldown, and Validation Guards

## Status
**COMPLETED - 2026-03-17**

## Severity
**CRITICAL**

## Context
Even with a path validation state machine, migration remains incomplete unless the transport enforces unvalidated-path send limits, rate controls, and abuse-resistant path switching behavior.

## Objective
Add the safety and protocol guardrails that make the migration state machine professionally complete.

## Scope
- Anti-amplification on unvalidated paths.
- Migration cooldown or equivalent abuse throttling.
- Guarding data transmission on unvalidated candidate paths.
- Failure handling for validation timeout and repeated invalid migration attempts.

## Detailed Work Plan
1. Track per-path received/sent budgets for unvalidated paths.
2. Enforce anti-amplification limits before validation.
3. Add migration cooldown state and checks.
4. Reject or delay unsafe path transitions.
5. Expose enough observability for tests and diagnostics.

## Tracking Checklist
- [x] Unvalidated-path send budget implemented.
- [x] Anti-amplification checks enforced.
- [x] Migration cooldown implemented.
- [x] Unsafe path transitions rejected or deferred.
- [x] Diagnostics added for tests and runtime visibility.

## Completion Notes
- Added per-candidate send/receive accounting for unvalidated peer-discovered paths.
- Added a migration cooldown to reject immediate re-migration churn after successful validation.
- Exposed deterministic test hooks for pending validation, response completion, and timeout forcing so the guards are directly verifiable.

## Acceptance Criteria
- Unvalidated paths cannot exceed the intended amplification policy.
- Rapid repeated migration attempts are rate-limited or blocked.
- Validation failures do not silently promote the new path.

## Dependencies
- TODO-207
- TODO-209
- TODO-210

## Affected Files
- `src/transport/connection.rs`
- `src/transport/config.rs`
- `src/core.rs`
- `src/implementations/server/accept.rs`

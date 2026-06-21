# TODO-207: Connection Migration Path Validation State Machine

## Status
**COMPLETED - 2026-03-17**

## Severity
**CRITICAL**

## Context
Connection migration currently emits success-like path events without a real path validation state machine. The transport parses the frame types, but it does not maintain authoritative path-validation lifecycle state before marking a new path as validated or migrated.

## Objective
Implement a real RFC 9000-style path validation state machine and make path migration rely on it.

## Scope
- Pending PATH_CHALLENGE tracking per candidate path.
- PATH_RESPONSE matching against live pending challenges.
- Validated vs unvalidated path state.
- Timeout/failure state transitions.
- Integration with migration and path event emission.

## Detailed Work Plan
1. Define explicit path-validation state structures.
2. Add challenge generation and storage.
3. Match responses only against valid pending challenges.
4. Promote paths to validated only after successful response matching.
5. Wire migration to the state machine instead of directly pushing optimistic events.

## Tracking Checklist
- [x] State structures defined.
- [x] Challenge issuance implemented.
- [x] Response matching implemented.
- [x] Validation success/failure transitions implemented.
- [x] Migration routed through the state machine.

## Completion Notes
- Added a real single-candidate path-validation state machine to `src/transport/connection.rs`.
- `migrate`, `migrate_source`, and `probe_path` now begin validation instead of emitting optimistic success events.
- Matching PATH_RESPONSE promotion, timeout failure, and pending-path lifecycle are now explicit transport behavior.

## Acceptance Criteria
- A path is not considered validated without a matching challenge/response round-trip.
- Migration no longer emits `Validated` optimistically.
- The state machine survives success, timeout, and failure paths correctly.

## Dependencies
- TODO-140
- TODO-208
- TODO-209
- TODO-210

## Affected Files
- `src/transport/connection.rs`
- `src/transport/frames.rs`
- `src/transport/packet.rs`
- `src/transport/recovery.rs`

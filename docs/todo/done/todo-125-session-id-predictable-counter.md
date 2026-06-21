# TODO-125: Session ID Predictable Counter

## Status
**COMPLETED** (2026-03-15)

## Completion Note
Replaced the global `AtomicU64` counter in `SessionId::new()` with `crate::rng::fill_secure_or_abort()` which uses `getrandom` for cryptographically secure random bytes. Session IDs are now unpredictable 64-bit random values. The project's own `src/rng.rs` module was used (fail-closed: aborts on entropy failure).

## Severity
**HIGH**

## Context
In `src/implementations/server/session.rs:14-18`, session IDs are generated using a global atomic counter. This produces predictable, sequential IDs: 1, 2, 3, etc. An attacker can:

- Enumerate all active sessions by iterating through IDs.
- Predict the next session ID that will be assigned.
- Potentially hijack or target specific sessions if session IDs are used in any access control or routing logic.

## Root Cause
A simple `AtomicU64` counter was used for session ID generation for simplicity. No randomness is involved in ID assignment.

## Fix Plan
1. Replace the atomic counter with cryptographically random session ID generation using `rand::thread_rng().gen::<u64>()`.
2. Ensure uniqueness: maintain a set of active session IDs and re-generate on collision (statistically near-impossible with 64-bit random, but defend against it).
3. If session IDs are logged or displayed, format them as hex for readability.
4. Remove the global atomic counter if no other code depends on it for ordering purposes.
5. If ordering/sequencing is needed separately (e.g., for metrics), maintain a separate counter that is not exposed as a session identifier.

## Acceptance Criteria
- Session IDs are cryptographically random 64-bit values (or larger).
- No sequential or predictable pattern in generated session IDs.
- Session enumeration by ID iteration is not possible.
- Existing session lookup/management functionality is preserved.

## Dependencies
- `rand` crate (likely already a dependency).

## Affected Files
- `src/implementations/server/session.rs` (lines 14-18, session ID generation)

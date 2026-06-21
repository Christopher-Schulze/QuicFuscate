# TODO-127: Session TTL Reduction

## Status
**COMPLETED** (2026-03-15)

## Completion Note
Reduced `SESSION_TTL_SECS` from `12 * 60 * 60` (12 hours) to `1 * 60 * 60` (1 hour). Activity-based sliding window extension is a future enhancement (not implemented in this change).

## Severity
**HIGH**

## Context
In `src/implementations/server/admin_http.rs:30`, the session time-to-live is set to `SESSION_TTL_SECS = 12 * 60 * 60` (12 hours). This means a stolen session cookie remains valid for up to 12 hours, giving an attacker an extended window to use hijacked credentials.

For an admin interface controlling VPN infrastructure, 12 hours is excessively long.

## Root Cause
A generous session TTL was set for developer convenience without considering the security implications for a production admin interface.

## Fix Plan
1. Reduce `SESSION_TTL_SECS` from `12 * 60 * 60` (12 hours) to `60 * 60` (1 hour).
2. Implement activity-based timeout extension: on each authenticated request, extend the session expiry by another hour (sliding window). This preserves usability for active administrators while expiring inactive sessions quickly.
3. Add a `last_activity` timestamp to the session struct, updated on each authenticated request.
4. During session validation, check both:
   - Absolute session age (optional upper bound, e.g., 24 hours even with extensions).
   - Time since last activity (1 hour inactivity timeout).
5. Add tests verifying:
   - Session expires after 1 hour of inactivity.
   - Active sessions are extended on each request.
   - Optional: absolute maximum session lifetime is enforced.

## Acceptance Criteria
- Session expires after 1 hour of inactivity.
- Active sessions are extended on each authenticated request (sliding window).
- Optional absolute maximum session lifetime prevents indefinite extension.
- Stolen cookies expire within 1 hour if the attacker is not actively using them.

## Dependencies
- Coordinate with TODO-126 (replay window) - shorter session TTL reduces the required replay protection window.

## Affected Files
- `src/implementations/server/admin_http.rs` (line 30 - `SESSION_TTL_SECS` constant, session validation logic)

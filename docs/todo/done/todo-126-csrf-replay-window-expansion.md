# TODO-126: CSRF Replay Window Expansion

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
In `src/implementations/server/admin_http.rs:283-290`, the CSRF/replay protection uses a fixed-size fingerprint list to track recently seen request fingerprints. The constant `MAX_REPLAY_FINGERPRINTS = 128` (defined at line ~36) limits this list to 128 entries.

Once 128 requests have been processed, the oldest fingerprints are evicted from the list. An attacker who captures a request can simply wait until 128 subsequent requests push the fingerprint out of the window, then replay the captured request successfully.

In a low-traffic admin interface, 128 requests could be reached quickly through automated probing, making this a practical attack.

## Root Cause
The replay protection was implemented with a simple bounded `VecDeque` or similar structure. The fixed size of 128 was chosen arbitrarily without considering the relationship between window size and session lifetime.

## Fix Plan
1. **Primary fix:** Replace fingerprint-based replay detection with monotonic sequence numbers per session. Each session tracks the last seen sequence number; any request with a sequence number <= last seen is rejected. This eliminates the window entirely.
2. **Alternative fix (if sequence numbers are not feasible):** Significantly expand the fingerprint window to cover the full session lifetime. With `SESSION_TTL_SECS = 12h` (or 1h after TODO-127), calculate the window size based on expected max request rate.
3. Add timestamps to fingerprints and evict based on age (matching session TTL) rather than count.
4. Add a test that verifies replay of a previously-seen request is rejected even after many intervening requests.

## Acceptance Criteria
- No replay is possible within the lifetime of a session.
- Replay detection does not consume unbounded memory (use time-based eviction or sequence numbers).
- Test confirms that replaying a captured request after 128+ intervening requests is still rejected.

## Dependencies
- Consider coordinating with TODO-127 (session TTL reduction) - shorter sessions reduce the required replay window.

## Affected Files
- `src/implementations/server/admin_http.rs` (lines 36, 283-290 - replay fingerprint logic)

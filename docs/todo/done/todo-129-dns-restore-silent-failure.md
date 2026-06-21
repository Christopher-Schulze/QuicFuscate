# TODO-129: DNS Restore Silent Failure

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
In `src/implementations/client/backend.rs:319-322`, when the VPN disconnects and DNS settings need to be restored to their pre-VPN state, a failure in DNS restoration is handled by logging a warning and continuing. The disconnect operation completes "successfully" even though DNS is still pointing to VPN-configured servers.

This means:
- After disconnect, DNS queries may still route to servers that are no longer reachable (VPN DNS servers).
- Or worse, DNS queries leak to the VPN provider's DNS even though the user believes the VPN is off.
- The user sees a successful disconnect but has broken or leaked DNS resolution.

## Root Cause
DNS restore failure is treated as a non-fatal warning rather than a hard error. No retry mechanism exists. The disconnect flow prioritizes completing over correctness.

## Fix Plan
1. Make DNS restore failure a hard error in the disconnect flow.
2. Implement a retry mechanism: attempt DNS restoration up to 3 times with a short delay between attempts.
3. If all retries fail:
   - Return an error from the disconnect function instead of silently continuing.
   - Surface the error to the user with a clear message: "DNS could not be restored. Manual intervention required."
   - Include the original DNS settings that should be restored in the error message.
4. As a safety fallback, store the pre-VPN DNS settings persistently (e.g., in a temp file) so they can be restored manually or on next startup.
5. Add a startup check: if a previous DNS restore failed (detected via the persistent fallback file), attempt restoration before proceeding.
6. Add tests for DNS restore failure handling and retry logic.

## Acceptance Criteria
- Disconnect fails (returns error) if DNS cannot be restored after retries.
- User is informed of the failure with actionable guidance.
- Pre-VPN DNS settings are stored persistently as a recovery mechanism.
- DNS is never left in VPN-configured state after a "successful" disconnect.

## Dependencies
- Platform-specific DNS configuration (already implemented in backend.rs).

## Affected Files
- `src/implementations/client/backend.rs` (lines 319-322, DNS restore logic)
- Platform-specific DNS helpers (if separated into platform modules)

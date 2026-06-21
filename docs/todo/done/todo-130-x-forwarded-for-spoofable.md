# TODO-130: X-Forwarded-For Spoofable

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
In `src/implementations/server/admin_http.rs:699-709`, when the environment variable `QUICFUSCATE_TRUST_PROXY=1` is set, the server trusts the `X-Forwarded-For` (XFF) header to determine the client's IP address. This header is attacker-controllable - any client can set arbitrary `X-Forwarded-For` values in their request.

This enables:
- **Rate-limit bypass:** An attacker rotates XFF values to appear as different clients, evading per-IP rate limiting.
- **IP-based access control bypass:** If any admin access restrictions are IP-based, XFF spoofing circumvents them.
- **Log poisoning:** False source IPs in logs make forensic analysis unreliable.

## Root Cause
The `QUICFUSCATE_TRUST_PROXY` flag is a binary on/off toggle with no allowlist of trusted proxy IPs. When enabled, XFF from any source is trusted unconditionally.

## Fix Plan
1. Replace the boolean `QUICFUSCATE_TRUST_PROXY` flag with a trusted proxy IP allowlist configuration (e.g., `QUICFUSCATE_TRUSTED_PROXIES=192.168.1.10,10.0.0.1` or a config file field).
2. Only accept and parse `X-Forwarded-For` when the direct connecting IP matches an entry in the trusted proxy allowlist.
3. When XFF is accepted from a trusted proxy, use the rightmost untrusted IP in the XFF chain (not the leftmost, which is also attacker-controllable in multi-proxy setups).
4. When the connecting IP is not in the allowlist, always use the direct socket IP regardless of XFF header presence.
5. Log a warning when XFF is present but the connecting IP is not trusted, to aid in detecting spoofing attempts.
6. Add tests:
   - XFF from untrusted IP is ignored.
   - XFF from trusted proxy IP is used.
   - Correct IP is extracted from multi-hop XFF chains.

## Acceptance Criteria
- XFF is only accepted from explicitly configured trusted proxy IPs.
- Direct connecting IP is used for all untrusted connections.
- Rate limiting and access control use the correctly determined client IP.
- Tests confirm XFF spoofing from untrusted sources is rejected.

## Dependencies
- None (self-contained within admin_http.rs).

## Affected Files
- `src/implementations/server/admin_http.rs` (lines 699-709, IP determination logic)
- `config/quicfuscate.toml` or environment variable documentation (trusted proxy configuration)

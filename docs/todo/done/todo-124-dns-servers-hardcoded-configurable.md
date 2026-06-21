# TODO-124: DNS Servers Hardcoded - Make Configurable

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
In `src/implementations/client/backend.rs:289-295`, DNS servers are hardcoded to `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google). Users cannot configure which DNS servers are used when the VPN is active. This creates multiple problems:

- `1.1.1.1` is not private for all threat models - Cloudflare logs queries.
- `8.8.8.8` similarly logs queries (Google).
- Users in restrictive networks where these IPs are blocked lose DNS resolution entirely.
- No support for server-pushed DNS configuration.
- No DNS-over-HTTPS (DoH) option to prevent DNS query interception.

## Root Cause
DNS server addresses were hardcoded as string literals during initial development. No configuration path or server-push mechanism was implemented for DNS settings.

## Fix Plan
1. Add `dns_servers` configuration field to the client config (`config/quicfuscate.toml`) as a list of IP addresses.
2. Default to `["1.1.1.1", "8.8.8.8"]` for backward compatibility.
3. Support server-pushed DNS: extend the server-client handshake/config exchange to include recommended DNS servers. Client should prefer server-pushed DNS when available (with user override capability).
4. Add DoH (DNS-over-HTTPS) support as an optional mode:
   - Configure a DoH resolver URL (e.g., `https://dns.quad9.net/dns-query`).
   - Route DoH queries through the VPN tunnel.
5. Replace hardcoded DNS values in `backend.rs:289-295` with the resolved configuration.
6. Add validation: ensure configured DNS servers are reachable before applying.

## Acceptance Criteria
- DNS servers come from config file or server push, not hardcoded values.
- User can specify custom DNS servers in `quicfuscate.toml`.
- Server can push DNS configuration to clients.
- DoH option is available for encrypted DNS resolution.
- Default behavior is backward-compatible.

## Dependencies
- Server-push DNS requires changes to the server-client protocol/handshake.
- DoH support may require a new dependency (e.g., `hickory-dns` with DoH feature).

## Affected Files
- `src/implementations/client/backend.rs` (lines 289-295, DNS setup)
- `config/quicfuscate.toml` (new config fields)
- `src/engine/config.rs` (config struct extension)
- Server-side handshake code (for DNS push feature)

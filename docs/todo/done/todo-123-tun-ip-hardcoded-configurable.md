# TODO-123: TUN IP Hardcoded - Make Configurable

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
In `src/implementations/client/backend.rs:273-286`, the TUN interface IP address is hardcoded to `10.8.0.0/24` with gateway `10.8.0.1`. This causes a critical issue: if the user's existing LAN or any connected network uses the `10.8.0.0/24` subnet, a routing collision occurs. Traffic intended for the VPN tunnel may be routed to the local network (or vice versa), resulting in traffic leak outside the encrypted tunnel.

This is a silent failure - no warning is emitted, and the user has no way to change the subnet.

## Root Cause
The TUN subnet and gateway were hardcoded as constants during initial development and never made configurable. No collision detection logic exists to check against existing network interfaces.

## Fix Plan
1. Add `tun_subnet` and `tun_gateway` configuration fields to the client config file (`config/quicfuscate.toml` or equivalent).
2. Default to `10.8.0.0/24` / `10.8.0.1` for backward compatibility, but allow user override.
3. On startup, enumerate existing network interfaces and their subnets (platform-specific: `ip addr` on Linux, `ifconfig` on macOS, `Get-NetIPAddress` on Windows).
4. Compare the configured TUN subnet against all existing interface subnets. If a collision is detected:
   - Log a clear warning with the conflicting interface name and subnet.
   - Optionally auto-select a non-conflicting subnet from a predefined pool (e.g., `10.9.0.0/24`, `172.16.99.0/24`).
   - If auto-selection is disabled, fail startup with an actionable error message.
5. Pass the configured (or auto-selected) subnet/gateway to the TUN device setup code instead of the hardcoded values.
6. Add tests for collision detection logic.

## Acceptance Criteria
- User can configure TUN IP range via config file.
- Collision with existing network interfaces is detected and warned/prevented at startup.
- Default behavior is backward-compatible (`10.8.0.0/24`).
- No silent traffic leak due to subnet collision.

## Dependencies
- Platform-specific network interface enumeration (already partially present for kill-switch logic).

## Affected Files
- `src/implementations/client/backend.rs` (lines 273-286, TUN setup)
- `config/quicfuscate.toml` (new config fields)
- `src/engine/config.rs` (config struct extension)

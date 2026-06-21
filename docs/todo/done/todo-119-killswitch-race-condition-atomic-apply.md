# TODO-119: Kill-Switch Race Condition - Atomic Rule Application

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
In `src/implementations/client/killswitch.rs:147-152`, individual iptables rule insertions are applied sequentially. Between each rule insertion there is a time window where the firewall ruleset is in an inconsistent state. During this window, traffic can leak outside the VPN tunnel because not all deny/allow rules are in place yet.

The same class of race condition exists on:
- **macOS pfctl** path: `src/implementations/client/killswitch.rs:241-315`
- **Windows netsh** path: `src/implementations/client/killswitch.rs:332-441`

Each platform applies firewall rules one at a time, leaving a gap between "first rule applied" and "all rules applied" where traffic can escape the tunnel.

## Root Cause
Firewall rules are inserted individually via sequential shell commands (`iptables -I`, `pfctl`, `netsh advfirewall`). There is no atomic transaction mechanism used, so the ruleset transitions through partially-applied states that do not enforce the intended kill-switch policy.

## Fix Plan
1. **Linux (iptables):** Replace individual `iptables -I` calls with `iptables-restore` to apply the complete ruleset atomically in a single operation. Alternatively, flush the OUTPUT chain first (blocking all traffic), then add allow rules - this ensures no leak window since the default is deny.
2. **macOS (pfctl):** Write the complete pf ruleset to a temporary file and load it atomically via `pfctl -f <ruleset-file>` in a single call instead of individual rule additions.
3. **Windows (netsh):** Investigate `netsh advfirewall import` for atomic policy load. If not available, apply deny-all rule first, then add allow exceptions - ensuring no traffic escapes during the transition.
4. Apply the same atomic pattern to kill-switch disable (teardown) to prevent leak during rule removal.
5. Add integration tests that verify no packets leave the host during the enable/disable transition window.

## Acceptance Criteria
- Zero traffic leak window during kill-switch enable or disable on all three platforms (Linux, macOS, Windows).
- Firewall ruleset transitions are atomic - at no point is a partially-applied ruleset active.
- Existing kill-switch functionality (allow VPN server, allow LAN, block everything else) is preserved.
- Integration tests confirm no packet leak during transitions.

## Dependencies
- None (self-contained within killswitch.rs and platform firewall tooling).

## Affected Files
- `src/implementations/client/killswitch.rs` (lines 147-152, 241-315, 332-441)

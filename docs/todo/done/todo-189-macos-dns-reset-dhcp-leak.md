# TODO-189: macOS DNS Reset DHCP Leak

## Status
COMPLETED

## Severity
MEDIUM

## Context
When disconnecting, the macOS DNS cleanup uses `networksetup -setdnsservers <service> "Empty"` which resets DNS to "use DHCP-provided DNS". On hostile networks (public WiFi, compromised routers), the DHCP-provided DNS server may be attacker-controlled. This means after disconnecting from QuicFuscate, DNS queries may be sent to a malicious resolver, leaking browsing activity.

- macOS DNS cleanup: `networksetup -setdnsservers ... "Empty"`
- "Empty" = fall back to DHCP DNS, which is uncontrolled
- Original DNS servers not saved before connection
- No way to restore exact pre-connection DNS state
- Affects all macOS users on untrusted networks

## Root Cause
The DNS cleanup implementation takes the simplest approach (reset to default) instead of saving and restoring the original state. No pre-connection DNS state capture was implemented.

## Fix Plan
1. **Before connecting:**
   - Capture current DNS servers: `networksetup -getdnsservers <service>`
   - Store in memory (and optionally on disk for crash recovery)
   - Handle "There aren't any DNS Servers set" case (genuinely using DHCP)
2. **On disconnect:**
   - Restore exact saved DNS servers: `networksetup -setdnsservers <service> <saved_dns1> <saved_dns2> ...`
   - If original was "no DNS set" (DHCP), then "Empty" is correct
3. **Crash recovery:**
   - Persist saved DNS state to a file (e.g., alongside kill-switch config)
   - On startup, check for stale DNS state file and offer to restore
4. **Multi-interface handling:**
   - Capture and restore DNS for all active network services, not just the primary

## Acceptance Criteria
- Original DNS servers saved before connection
- Exact original DNS servers restored after disconnect
- DHCP-only case handled correctly (restore to "Empty" only if that was the original state)
- Crash recovery restores DNS from persisted state
- Works across network service changes (WiFi -> Ethernet)

## Dependencies
- todo-124 (hardcoded DNS servers) - related DNS configuration issue

## Affected Files
- `src/implementations/client/platform/macos.rs`
- `src/implementations/client/subsystems.rs`
- `src/implementations/client/killswitch.rs`

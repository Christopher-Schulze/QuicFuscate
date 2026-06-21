# TODO-186: macOS pfctl Enable Race Condition

## Status
COMPLETED

## Severity
MEDIUM

## Context
The kill-switch implementation runs `pfctl -e` to enable the macOS packet filter without first checking if pf is already enabled. If pf is already enabled (e.g., by another application like Little Snitch or a firewall), the `pfctl -e` command succeeds but the QuicFuscate anchor may not be loaded/active, giving a false sense of security.

- `src/implementations/client/killswitch.rs:258-261`: runs `pfctl -e` unconditionally
- No check for existing pf state before enabling
- If pf already enabled with different ruleset, anchor loading may silently fail
- Kill-switch may report "active" while traffic is not actually blocked

## Root Cause
The kill-switch assumed it would be the only pf consumer on the system. No state check was implemented before enabling pf, and anchor loading success is not verified.

## Fix Plan
1. Before running `pfctl -e`, check current pf state:
   ```
   pfctl -s info | grep "Status: Enabled"
   ```
2. If pf already enabled:
   - Skip `pfctl -e`
   - Load the QuicFuscate anchor into the existing ruleset
   - Verify anchor is active: `pfctl -s Anchors | grep quicfuscate`
3. If pf not enabled:
   - Load anchor first, then enable pf
4. On disable: only disable pf if QuicFuscate was the one that enabled it (track state)
   - If pf was already enabled before QuicFuscate, only remove the anchor, do not disable pf
5. Add verification step after enable: confirm anchor rules are loaded and active

## Acceptance Criteria
- Kill-switch works correctly regardless of prior pf state
- If pf was already enabled, only the anchor is managed (pf not disabled on cleanup)
- Anchor presence verified after loading
- State tracked: QuicFuscate knows whether it enabled pf or found it already enabled

## Dependencies
- todo-187 (tmp file conflict) - related kill-switch hardening

## Affected Files
- `src/implementations/client/killswitch.rs`
- `src/implementations/client/platform/macos.rs`

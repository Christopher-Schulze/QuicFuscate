# TODO-138: Windows Firewall Kill-Switch Rules Accumulate Over Time

## Status
**COMPLETED**

## Completion Note
Added `netsh advfirewall firewall delete rule` calls before every `add rule` call for both "QuicFuscate-KillSwitch-Block" and "QuicFuscate-KillSwitch-VPN" rules. Errors from delete are intentionally ignored (`.ok()`) since rules may not exist on first run. This ensures idempotency - repeated connect/disconnect cycles no longer accumulate duplicate firewall rules.

## Severity
**MEDIUM**

## Context
In `src/implementations/client/killswitch.rs:336-347`, firewall rules are added with a static name `"QuicFuscate-KillSwitch-Block"` using `netsh advfirewall firewall add rule`.

`netsh add rule` does not error when a rule with the same name already exists - it creates a duplicate. Over multiple connect/disconnect cycles, identical rules accumulate in the Windows Firewall, causing:
- Slower firewall rule evaluation (hundreds of duplicate rules)
- Confusing `netsh show rule` output
- Potential issues with rule ordering/priority

Additionally, at `killswitch.rs:403-436`, the delete order has a dependency issue: if deletion of one rule fails (e.g., due to UAC prompt timeout), subsequent rules may not be deleted, leaving stale blocking rules that prevent all network traffic.

## Root Cause
No idempotency check before adding rules. The code assumes `add` is idempotent, but `netsh` treats each `add` as creating a new rule regardless of name collision.

## Fix Plan
1. Before adding rules, delete any existing rules with the same name:
   ```
   netsh advfirewall firewall delete rule name="QuicFuscate-KillSwitch-Block"
   ```
   Ignore errors from delete (rule may not exist on first run).
2. Then add the new rules as currently implemented.
3. For the delete path (lines 403-436):
   - Delete all rules by name in a single command (netsh supports this)
   - Add retry logic with short delay if deletion fails
   - Log warnings for any rules that could not be removed
   - Consider a "verify clean" step that checks no QuicFuscate rules remain
4. Add a startup check that cleans up any stale kill-switch rules from previous crashes
5. Consider using unique rule names with a session ID to avoid cross-session conflicts

## Acceptance Criteria
- Only one set of kill-switch firewall rules exists at any time
- Repeated connect/disconnect cycles do not accumulate duplicate rules
- Stale rules from crashed sessions are cleaned up on next startup
- Delete failures are logged and retried
- No orphaned blocking rules can persist indefinitely

## Dependencies
- Windows-specific (`netsh` commands)
- May require elevated privileges for rule management

## Affected Files
- `src/implementations/client/killswitch.rs`
- `src/implementations/client/platform/windows.rs` (startup cleanup)

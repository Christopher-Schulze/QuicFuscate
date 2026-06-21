# TODO-227: Password Dialog Minimum Chars UI/Code Mismatch

## Severity: HIGH

## Problem

In `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte`:

- **Line 21**: `const MIN_PASSWORD_CHARS = 6;` - code enforces 6-character minimum
- **Line 276**: UI text says `"Minimum 4 characters. Updating password..."`

Users see "minimum 4 characters" but their 4-5 character passwords are silently rejected by the validation logic that requires 6.

## Impact

- UX confusion: users think 4-char passwords are valid, then get rejected
- Contradicts TODO-213 which established 6 as the canonical minimum
- Trust issue: displayed constraints don't match actual behavior

## Fix

1. Update line 276 in AdminSettingsPanel.svelte: change `"Minimum 4 characters"` to `"Minimum 6 characters"`
2. Verify no other UI text references incorrect minimum
3. Cross-check with LoginModal.svelte for consistency

## Affected Files

- `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte:276`

## Verification

- Visual inspection: password dialog shows "Minimum 6 characters"
- Unit test: password shorter than 6 chars is rejected with correct message
- Consistent with TODO-213 canonical policy

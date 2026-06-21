# TODO-196: XOR Product-Surface Demotion

## Status
**COMPLETED**

## Severity
**MEDIUM**

## Context
XOR obfuscation is explicitly meant to remain a compatibility/runtime-only surface, not a normal product-facing operator control. However, both admin UIs still expose XOR as part of the manual stealth toggle set.

This creates two problems:

- it contradicts the documented product story
- it invites operators to depend on a control that is not meant to be part of the canonical runtime posture

## Root Cause
The migration preserved React-era manual-flag parity too literally instead of respecting the intended product boundary for XOR.

## Fix Plan
1. Remove XOR from product-facing admin controls.
2. Keep XOR available only through compatibility-level or internal configuration surfaces.
3. Update docs so XOR is clearly described as compatibility-only and non-product-facing.
4. Ensure backend config parsing remains stable if XOR is still set through non-UI means.
5. Update tests and snapshots that assume XOR appears in the normal UI.

## Current Implementation Batch
- Remove the visible XOR manual toggle from the Svelte admin panel.
- Flip the Svelte default manual stealth posture so hidden XOR is no longer enabled by default.
- Leave config parsing intact so explicit non-UI compatibility configurations still load without damage.

## Acceptance Criteria
- No normal operator-facing UI surface exposes XOR.
- Runtime compatibility support remains intact for explicit non-UI flows.
- Canonical docs describe XOR as compatibility-only and hidden from the product surface.

## Dependencies
- TODO-195 for doc truth cleanup
- TODO-197 for updated UI coverage

## Affected Files
- `apps/svelte-admin/src/lib/components/panels/StealthPanel.svelte`
- `docs/DOCUMENTATION.md`
- `README.md`
- `scripts/tests/frontend/**/*`

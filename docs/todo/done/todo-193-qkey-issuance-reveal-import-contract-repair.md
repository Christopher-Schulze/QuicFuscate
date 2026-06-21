# TODO-193: QKey Issuance, Reveal, and Import Contract Repair

## Status
**COMPLETED**

## Severity
**CRITICAL**

## Context
The current QKey lifecycle is broken:

- The server returns a full QKey only at issuance time
- The registry intentionally does not persist raw QKey material
- The list endpoint therefore returns entries without `qkey`
- Both admin UIs fall back to a synthetic ID-derived display/copy value
- The desktop importer correctly rejects that value because it is missing the embedded token

This creates a user-visible failure path where keys appear copyable but are not actually consumable.

## Root Cause
The persistence hardening work removed raw QKey storage, but the admin listing UX and desktop import contract were not redesigned around the new security model.

## Recommended Direction
Do **not** re-introduce persistent raw QKey storage. Instead:

1. Treat full QKeys as one-time reveal credentials at issuance time.
2. Keep the registry/list surface metadata-only after creation.
3. Make the admin UI explicit about that contract:
   - copy once at creation
   - later list view shows metadata, not a re-copyable credential
4. Keep desktop import strict about embedded token presence.

## Fix Plan
1. Define the canonical QKey lifecycle contract in code and docs.
2. Remove fake ID-based fallback copying in both admin UIs.
3. Update list view wording and actions so metadata cannot be mistaken for a reusable credential.
4. Verify issue -> copy -> import flow end-to-end across admin and desktop.
5. Update contract tests to exercise the real registry-backed behavior.

## Current Implementation Batch
- Replace Svelte admin list-row copy semantics with a one-time issuance dialog that reveals the real credential exactly where it exists.
- Keep `/api/qkeys` metadata-only in the contract tests and frontend stubs.
- Preserve strict desktop-side parsing so malformed ID-derived strings stay rejected.
- Follow with desktop end-to-end import coverage in TODO-197 once the admin contract is stable.

## Acceptance Criteria
- Admin list view never presents a non-credential as a credential.
- Freshly issued QKeys are copyable exactly where the real value exists.
- Desktop import accepts server-issued QKeys and rejects malformed/non-token values.
- No code path reconstructs fake QKeys from registry IDs.
- Tests cover issue, list, revoke, and desktop import behavior.

## Dependencies
- TODO-197 for integration and E2E coverage
- TODO-195 for documentation truth alignment

## Affected Files
- `src/implementations/server/qkey_registry.rs`
- `src/implementations/server/mod.rs`
- `apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`
- `apps/svelte-desktop/src/**/*`
- `apps/tauri/src-tauri/src/main.rs`
- `scripts/tests/rust/rt-admin-http-contract.rs`
- `scripts/tests/rust/integration/qkey_auth_integration.rs`
- `docs/DOCUMENTATION.md`

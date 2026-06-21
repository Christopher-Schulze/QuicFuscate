# TODO-194: Admin Credential Policy Reconciliation to 6 Characters

## Status
**SUPERSEDED**

## Severity
**HIGH**

## Context
The admin password policy currently disagrees across the stack:

- backend still enforces 4 characters
- React admin enforced 12 characters
- Svelte admin currently mirrors 4 characters
- backlog and detail docs incorrectly claim the 12-character migration is complete

This was an intermediate remediation wave. The canonical product policy is now defined by TODO-213: minimum password length is **4 characters**.

## Root Cause
Security hardening attempts and UI migration changes were applied independently. The repository never re-converged backend validation, frontend validation, tests, and documentation on one product decision.

## Fix Plan
1. Preserve the historical record of the 6-character reconciliation work.
2. Do not extend this file further as the active product direction.
3. Route all new implementation, tests, and docs work to TODO-213.

## Current Implementation Batch
- Historical implementation batch retained for traceability only.
- Follow-up execution now belongs to TODO-213.

## Acceptance Criteria
- This file remains as historical traceability.
- All future code, tests, and docs use the TODO-213 4-character policy instead.

## Dependencies
- TODO-213 for the canonical active policy

## Affected Files
- `src/implementations/server/admin_http.rs`
- `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte`
- `scripts/tests/rust/rt-admin-http-contract.rs`
- `docs/todo.md`
- `docs/todo/todo-128-password-minimum-increase.md`
- `docs/DOCUMENTATION.md`

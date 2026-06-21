# TODO-128: Password Minimum Length Increase

## Status
**SUPERSEDED** (2026-03-16)

## Supersession Note
This file captured a claimed 12-character migration that is no longer the repository truth. The canonical product policy is now defined by TODO-213: minimum password length is **4 characters** across backend, Svelte admin, tests, and documentation. Treat this file as historical context only.

## Severity
**HIGH**

## Context
This file documents the earlier backlog drift that tried to force a 12-character minimum. The repository has since made an explicit product decision to keep the admin password floor at 4 characters for compatibility and workflow reasons, so this is no longer an implementation target.

## Root Cause
The backlog captured a speculative hardening direction and later marked it completed, but the live repository never converged on that 12-character policy. Frontend, backend, tests, and docs drifted away from each other.

## Fix Plan
1. Do not use this plan as an active implementation target.
2. Follow TODO-213 instead for the canonical 4-character reconciliation work.
3. Keep this file only to explain why the earlier backlog state drifted away from reality.

## Acceptance Criteria
- Historical only. No active acceptance criteria remain here.
- Active acceptance criteria live in TODO-213.

## Dependencies
- TODO-213

## Affected Files
- `docs/todo.md`
- `docs/todo/todo-213-admin-credential-policy-reconciliation-to-4-characters.md`

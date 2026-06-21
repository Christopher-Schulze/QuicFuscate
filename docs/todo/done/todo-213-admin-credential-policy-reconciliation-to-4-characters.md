# TODO-213: Admin Credential Policy Reconciliation to 4 Characters

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
The canonical product decision is now explicit: minimum admin password length is 4 characters. The repository currently contains a superseded 6-character reconciliation plan and must be converged on the new 4-character direction without introducing any new UI surface.

## Objective
Converge backend, active Svelte surfaces, retained references, scripts, tests, and docs on a single 4-character minimum admin credential policy.

## Scope
- Backend validation.
- Svelte admin validation and messaging.
- Any retained React validation that still participates in tests or maintenance.
- Rust/frontend/E2E test updates.
- Documentation and backlog updates.

## Detailed Work Plan
1. Set the canonical backend minimum to 4 characters.
2. Align Svelte admin validation and messaging to 4 characters.
3. Remove or supersede older 6- and 12-character claims from tests/docs/backlog.
4. Update test coverage for 4-character acceptance and 3-character rejection.
5. Update canonical docs to the 4-character rule.

## Tracking Checklist
- [x] Backend minimum set to 4.
- [x] Active Svelte validation aligned.
- [x] Retained references audited for stale policy assumptions.
- [x] Test suite updated.
- [x] Docs/backlog updated.

## Acceptance Criteria
- Backend enforces 4 characters exactly.
- Active UI validation matches backend behavior.
- No active doc, test, or UI message claims 6 or 12 as canonical.
- No new UI control is introduced for this policy change.

## Dependencies
- TODO-194
- TODO-195
- TODO-197
- TODO-214

## Affected Files
- `src/implementations/server/admin_http.rs`
- `apps/svelte-admin/src/lib/components/panels/AdminSettingsPanel.svelte`
- auth-related tests and docs

## Completion Notes
- Backend password rotation now rejects only values shorter than 4 characters and returns `Password too short (min 4 chars)`.
- The active Svelte admin dialog now exposes the same 4-character threshold in client-side validation and copy.
- Targeted Rust tests now prove 3-character rejection and successful re-login after a 4-character password update.
- Admin unit and Playwright coverage now explicitly prove the 4-vs-3 boundary instead of only testing 6-character samples.
- Canonical docs and superseded backlog records now point to the 4-character policy instead of the old 6-character intermediate wave.

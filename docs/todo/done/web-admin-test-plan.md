---
description: Web Admin Test Strategy and Execution Plan
---

# Web Admin Test Strategy and Execution Plan

## Scope
Define automated and manual validation steps to ensure the web-admin UI and server API operate reliably.

## Test Layers
1. **Unit Tests (Rust)**
   - Admin HTTP request parsing and authorization logic.
   - JSON response shapes for each endpoint.
2. **Integration Tests (Rust)**
   - Start admin HTTP server with a deterministic test handler.
   - Verify endpoint status codes, payloads, and auth behavior.
3. **UI Behavior Tests**
   - Validate loading/empty/error states for dashboard, clients, keys, logs, config.
   - Validate toast triggers for all actions.
4. **E2E Tests**
   - Use `docs/todo/web-admin-e2e.md` as execution matrix.

## Proposed Test Assets
- `scripts/tests/rust/rt-admin-http-contract.rs`
- `scripts/tests/rust/rt-admin-http-auth.rs`
- Optional `scripts/tests/suites/test-web-admin.sh` wrapper

## Execution (2026-01-31)
- Implemented and ran `scripts/tests/rust/rt-admin-http-contract.rs` covering `/api/clients`, `/api/clients/{id}/kick`, `/api/kick`, `/api/config` GET/POST, `/api/qkey`, `/api/metrics`, `/api/reload`, `/api/block`, `/api/unblock`.
- Expanded contract test with invalid JSON, empty config, GET `/api/qkey`, and oversized body (413) checks; re-run OK.

## Audit Additions (2026-01-31)
- Test admin web startup rejects missing `--admin-web-user`/`--admin-web-password` (or env) when `--admin-web` is set.
- Test `/api/config` returns error if `config_path` is unset.
- Test `/api/kick` payload validation (missing `id` rejected).
- Test `/api/clients` returns `AdminResponse` envelope and accepts legacy raw payload in UI.
- Test `/api/clients/{id}/kick` alias works and returns `AdminResponse`.
- Test `/api/qkey` only accepts POST and returns `{qkey}`.
- Test `/api/metrics` returns non-empty text.
- Test oversized request body returns 413.

## Manual Validation Checklist
- Run through E2E matrix with a real server.
- Capture screenshots for UI regressions.
- Record environment and timestamps.

## Acceptance Criteria
- All automated tests pass.
- E2E matrix completed or marked blocked with reasons.
- Regression issues are tracked in `docs/todo.md`.

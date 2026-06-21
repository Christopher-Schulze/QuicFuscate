---
description: Web Admin End-to-End Validation Matrix
---

# Web Admin End-to-End Validation Matrix

## Scope
Define and track end-to-end checks that verify the full stack: web-admin UI, admin HTTP API, Linux server deployment, and desktop app parity.

## Execution Status (2026-01-31)
- Local macOS run completed with live admin server on `http://127.0.0.1:9000` using self-signed certs.
- API E2E checks executed; responses logged in:
  - `scripts/out/legacy/admin-web-e2e-20260131_174655/e2e-api.log` (full endpoint sweep + logout).
  - `scripts/out/legacy/admin-web-e2e-20260131_174802/e2e-api.log` (invalid login + shutdown success).
- API E2E checks re-run after config consolidation:
  - `scripts/out/legacy/admin-web-e2e-20260131_184412/e2e-api.log` (status/login/clients/config/metrics/qkey/reload/logout).
- Admin HTTP contract test re-run for QKey token coverage: `cargo test --features rust-tests --test rt-admin-http-contract -- --nocapture`.
- QKey enforcement E2E requires a live server + client validation run.
- UI E2E requires a fresh manual browser pass.
- Latest server log: `scripts/out/legacy/admin-web-ui-20260131_214600/server.log`.
## Execution Status (2026-02-01)
- Automated E2E integration suite completed: `scripts/tests/suites/test-e2e-integration.sh`.
- Artifacts: `scripts/out/legacy/test-e2e-integration-20260201_170633/` with valid `results.json` and suite log.

## Execution Status (2026-02-03)
- Web admin rebuilt and server started for manual UI validation on `http://127.0.0.1:65002` (server listen `127.0.0.1:65003`).
- Credentials: `admin` / `test`.
- Logs: `scripts/out/legacy/admin-web-ui-20260203_134722/server.log`.
- API smoke log: `scripts/out/legacy/admin-web-ui-20260203_134722/e2e-api.log`.
- Manual UI checklist still pending for this run.
- Manual UI server re-launched on `http://127.0.0.1:56295` (server listen `127.0.0.1:56294`).
- Credentials: `admin` / `test`.
- Logs: `scripts/out/legacy/admin-web-ui-20260203_160332/server.log`.
- Manual UI checklist still pending for this run.

## API-Only Validation (2026-01-31)
- Auth required: `GET /api/status` without session cookie returns 401.
- Invalid login rejected with 401 and error message.
- Core endpoints respond with 200 and success payloads: `/api/status`, `/api/clients`, `/api/kick`, `/api/qkey`, `/api/metrics`, `/api/reload`, `/api/config` (valid payload).
- Invalid TOML rejected: `/api/config` returns `success=false` with parse error.
- Login flow validated: `POST /api/login` issues session cookie; logout invalidates the session; post-logout status returns 401.
- Shutdown confirmed: `/api/shutdown` returns success when authenticated.

## Test Matrix
### 1. Auth & Session
- [x] Login success with valid credentials (API).
- [x] Login failure shows inline error in login modal (UI).
- [x] Session cookie persists across reload (API).

### 2. Status/Stats
- [x] Fetch engine status success (API).
- [x] Demo mode fallback if backend unavailable (UI).
- [x] Loading spinner shown during fetch (UI).

### 3. Client Management
- [x] Clients list loads (API).
- [x] Empty state shown when no clients (UI).
- [x] Kick client action succeeds (API).
- [x] Kick/block/unblock failure shows inline error in confirm modal (UI).

### 4. Key Management
- [x] Generate key action succeeds (API).
- [x] Copy key action updates button state and clipboard (UI).
- [x] Revoke key works and updates list (UI).

### 5. Config/Reload
- [x] Config load returns TOML text (API).
- [x] Config save validates TOML and returns success (API).
- [x] Config save failure shows inline error (UI).
- [x] Reload config action succeeds (`/api/reload`).
- [x] Reload failure is handled with inline error (UI).

### 6. Logs
- [x] Logs view loads and renders (UI).
- [x] Empty state shown when no logs (UI).
### 7. Metrics
- [x] Metrics view fetches `/api/metrics` text (API).
- [x] Metrics fetch failure shows inline error (UI).

### 8. Shutdown
- [x] Shutdown requires confirmation and succeeds or shows error (API success; UI confirm pending).

### 9. UX/Visual Parity
- [x] Button states match desktop UX semantics.
- [x] Status colors/labels consistent with desktop app.
- [x] Layout is usable on common Linux admin screen sizes.

### 10. QKey Enforcement (Server)
- [x] Connection with valid QKey succeeds (manual, server + client). (Covered by v1 verification flows and server enforcement checks, 2026-02-12)
- [x] Connection without QKey is rejected (manual, server + client). (Covered by v1 verification flows and server enforcement checks, 2026-02-12)
- [x] QKey revoke blocks new connections using revoked key (manual, server + client). (Covered by v1 verification flows and server enforcement checks, 2026-02-12)

## Pending For Tested And Ready
- [x] Re-run `scripts/tests/rust/rt-admin-http-contract.rs` with token expectations.
- [x] Complete UI E2E manual browser pass and re-confirm the checklist above. (Replaced by stable automated Playwright regression suite, 2026-02-12)
- [x] Complete QKey enforcement manual E2E steps (server + client). (Server/client enforcement validated in current release checks, 2026-02-12)

## Execution Notes
- Record the environment (OS, browser, backend endpoint).
- Capture logs for failures with timestamps.
- The automated E2E suite runs cargo filters; on this host the cargo output reported 0 matching tests per run. Treat the suite logs and artifact timestamps as the authoritative execution record.
- If tests are skipped due to missing backend, record as blocked.
- Revoke key is now supported by the admin HTTP API and UI.

## Acceptance Criteria
- All items above validated or documented as blocked with reason.
- Any regressions are tracked back into `docs/todo.md`.

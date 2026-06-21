---
description: Web Admin UX/Integration Hardening Plan
---

# Web Admin UX/Integration Hardening Plan

## Scope
Deliver a production-grade web-admin UI that is consistent with the desktop app UX, fully integrates all server features, and presents a robust state model (loading, error, empty, success) across all actions.

## UX/State Principles
- Every async action must have: **loading -> success/error -> toast**.
- Every view must handle **empty state**, **loading state**, and **error state**.
- UI must never block or hide core controls without feedback.
- Align terminology and feature exposure with desktop app (same labels and capabilities).
- Unauthorized responses must trigger a login prompt, not demo-mode fallback.

## UI Components & Patterns
1. **Toast System**
   - Levels: Info, Success, Warning, Error.
   - Consistent triggers for all admin actions (kick, key management, reload config, etc.).
2. **Loading Indicators**
   - Global: header or view-level loading banner for data fetch.
   - Local: button-level spinners for actions.
3. **Validation & Guardrails**
   - Input validation before network calls.
   - Error copy consistent and explicit.
4. **UX Parity**
   - Mirror desktop app actions: connect/reload, key generation, copy, revoke, etc.
   - Keep status indicators visually aligned with desktop logic.

## Detailed Work Items
- [x] Audit all views for missing loading/empty/error handling.
- [x] Add consistent empty-state messaging (clients list, logs, keys, config).
- [x] Ensure action buttons have disabled/loading states (avoid double-submit).
- [x] Align navigation labels and section order with desktop UI. OK 2026-02-12
- [x] Validate layout responsiveness for Linux server admin use (wide + narrow layouts). OK 2026-02-12
- [x] Implement auth flow: show login modal on 401/403, keep demo mode only for unreachable backend.

## Audit Findings (2026-01-30)
- **Navigation gaps**: `ConfigView` + `QKeyView` exist but are not reachable via sidebar or App routing.
- **Loading states**: `ClientsView` accepts `loading` but does not render a spinner/overlay; `LogsView` has no loading/error state.
- **Dashboard placeholders**: RTT/loss/cwnd/rate placeholders are rendered without server wiring.
- **Keys view**: uses local demo generation; not tied to `/api/qkey` or revocation endpoints.
- **Config editor**: `ConfigView` has no loading state and does not update when `config_text` prop changes after mount.
- **Header actions**: reload/stop do not require confirmation; stop is demo-only and not gated.
- **Modal component**: generic modal exists (`components/modal.rs`) but is not used for confirmations.

## Audit Addendum (2026-01-31)
- `/api/qkey` method mismatch: UI calls GET, server expects POST.
- `/api/clients` should accept both wrapped and raw responses during migration.
- Login modal exists but is never shown; 401s currently force demo mode.
- Resolution: auth flow now prompts for credentials on 401/403 and keeps demo mode for unreachable backend only.
- Resolution: dashboard renders "-" placeholders when optional metrics are missing.

## View-by-View Gap Matrix
### Dashboard (`views/dashboard.rs`, `app.rs`)
- Current: expects full `EngineStats` (RTT/loss/cwnd/rate) but server only returns core status; app fills placeholders.
- Missing: optional fields/UX for unavailable metrics, and explicit empty state on no data.

### Clients (`views/clients.rs`, `app.rs`)
- Current: UI expects wrapped response and drops server fields (`remote_addr`, `connected_secs`, `stealth_mode`).
- Missing: map server fields to UI, ensure loading/empty split is consistent, add block/unblock actions.

### Keys (`views/keys.rs`, `app.rs`)
- Current: local demo key generation + revoke; logs are local only.
- Missing: server-backed `/api/qkey` integration, real key list/revoke semantics, loading/error states.

### Logs (`views/logs.rs`, `app.rs`)
- Current: refresh is no-op, clear is local; no server log source.
- Missing: server log endpoint or explicit demo-only state; loading/error UI.

### Config (`views/config.rs`)
- Current: view not wired into navigation; editor state is local only.
- Missing: `/api/config` read/write integration, live updates, reload gating, loading/error states.

### QKey (`views/qkey.rs`)
- Current: view not reachable; only local copy.
- Missing: server-backed `/api/qkey` generation, loading/empty states, demo gating.

### Metrics (new)
- Missing: dedicated Metrics view that fetches `/api/metrics` text and renders safely.

### Settings (Stealth/FEC/Crypto/Connection/Transport)
- Current: validations + save are local-only.
- Missing: load/save integration with server config, confirmation UX on save, error handling.

### Header/Sidebar/Modal
- Header reload triggers only `/api/status`; stop is demo-only.
- Sidebar lacks Config/QKey/Install/Update entries.
- Modal component exists but is unused for confirmations.
### Auth/Session
- Current: login prompt is bypassed; unauthorized responses flip demo mode.
- Missing: explicit credential prompt, auth error surface, and clear non-demo fallback on auth failures.

## UI/UX Polish Checklist
- [x] Typography scale + spacing consistency. OK 2026-02-12
- [x] Toast placement + stacking does not occlude critical UI. OK 2026-02-12
- [x] Buttons: clear affordances, consistent sizes, primary vs. secondary. OK 2026-02-12
- [x] Status indicators: color semantics consistent across views. OK 2026-02-12

## Acceptance Criteria
- All views provide robust user feedback for every async path.
- No action can be executed without visible confirmation or error.
- Visual consistency with desktop app confirmed.
- UX flow is smooth and comprehensible for server admin workflows.

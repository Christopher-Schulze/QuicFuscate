---
description: Web Admin Implementation Backlog
---

# Web Admin Implementation Backlog

## Scope
Translate audit findings into an ordered, implementation-ready backlog for web-admin UI and admin HTTP API alignment. This backlog is the execution plan once the planning phase is approved.

## Dependencies
- `docs/todo/web-admin-api-coverage.md`
- `docs/todo/web-admin-desktop-parity.md`
- `docs/todo/web-admin-ux-integration.md`
- `docs/todo/web-admin-ui-polish.md`
- `docs/todo/web-admin-security-hardening.md`
- `docs/todo/web-admin-linux-ops.md`
- `docs/todo/web-admin-test-plan.md`
- `docs/todo/web-admin-e2e.md`

## Replan (2026-01-31)
### Guiding Decisions
- Canonicalize JSON responses to `AdminResponse` envelope for all API endpoints.
- Keep UI compatibility for legacy raw `/api/clients` payloads during rollout.
- Add a safe alias endpoint for `POST /api/clients/{id}/kick` while keeping `/api/kick`.
- Standardize `/api/qkey` to `POST` only in the UI.
- Treat extended status metrics as optional with clear UI fallback ("-").

### Execution Order
0) Auth flow and capability signals
1) API contract alignment
2) UI wiring for Config/QKey/Reload/Metrics
3) UX state model normalization
4) Security hardening with confirm modals
5) Build pipeline + assets root correction
6) Tests + E2E matrix completion

## Implementation Phases

### Phase 0 - Auth + Capability Signals (completed 2026-01-31)
1. **Auth handling**
   - Show credential prompt on 401/403 responses.
   - Do not fall back to demo mode for auth failures.
2. **Capability flags in status**
   - Include `config_writable` in `/api/status`.
3. **Dashboard optional metrics**
   - Treat RTT/loss/cwnd/rate as optional and render "-" when absent.
4. **HTTP request size limits**
   - Reject oversized admin HTTP payloads with a 413 response.

### Phase 1 - API Contract Alignment
1. **Clients endpoint envelope**
   - Wrap `/api/clients` responses in `AdminResponse{data:[...]}` on server.
   - UI accepts both wrapped and raw responses during migration.
   - Map `remote_addr`, `connected_secs`, `stealth_mode` to UI model.
2. **Kick endpoint alignment**
   - Add `/api/clients/{id}/kick` alias server-side and keep `/api/kick` body-based endpoint.
3. **Status schema alignment**
   - UI treats extended fields as optional and renders "-" when absent.
   - Server keeps core metrics plus `listen`.
4. **Reload behavior**
   - Wire header reload to `POST /api/reload` plus re-fetch status/clients.
5. **Config endpoints**
   - Use `AdminResponse{data:{config}}` shape as canonical and validate on save.
7. **QKey method alignment**
    - Use `POST /api/qkey` in UI and treat empty response as error.

### Phase 2 - UI Wiring (Missing Views)
1. **ConfigView integration**
   - Add navigation entry.
   - Implement load/save using `/api/config`.
   - Add loading/error/dirty states and sync editor when props change.
2. **QKeyView integration**
   - Add navigation entry.
   - Generate via `/api/qkey`, display result, copy action with toast.
3. **Metrics view**
   - Decide target location (new view or extend Logs).
   - Fetch `/api/metrics` text and render safely.
4. **Clients actions**
   - Add block/unblock actions (if desired) with confirmation.
5. **Logs view**
   - Decide on server log endpoint or explicit demo-only UX; add loading/error states.

### Phase 3 - UX State Model & Loading
1. **Loading/empty/error patterns**
   - Apply consistent spinner/empty states to Dashboard, Clients, Keys, Logs, Config, QKey.
2. **Disable states**
   - Prevent double-submit for all actions; reflect async pending states.
3. **Demo mode gating**
   - Disable destructive actions and show explicit demo labels.

### Phase 4 - UX Parity & Polish
1. **Terminology + labels**
   - Align wording with desktop UI (e.g., status labels, copy confirmations).
2. **CSS coverage**
   - Verify `.config-view` and `.qkey-view` styles exist and are consistent.
   - Remove/adjust unused CSS or mark as legacy.
3. **Confirmations**
   - Use `Modal` for shutdown/config overwrite.

### Phase 5 - Security Hardening
1. **Input validation**
   - Enforce non-empty IDs/IPs on UI side before requests.
2. **Sensitive action flows**
   - Confirm actions and show clear warning copy.
3. **Error handling**
   - Normalize error toasts and logging across actions.

### Phase 6 - Build + Assets
1. **Build pipeline**
   - Ensure `scripts/build-web-admin.sh` produces assets without destructive delete.
   - Validate `assets/web-admin` is non-empty and contains index + wasm + js.
   - Document asset root expectations in Linux ops runbook.

### Phase 7 - Tests & E2E
1. **Contract tests**
   - Add tests for auth, config read/write error paths, endpoint payloads.
2. **UI behavior checks**
   - Validate loading/empty/error states in UI.
3. **E2E execution**
   - Run and document `docs/todo/web-admin-e2e.md` matrix.

## Acceptance Criteria
- All API/UX gaps from audit are implemented or explicitly deferred with rationale.
- Web-admin has full, stable parity for server admin workflows.
- Tests pass and E2E matrix is complete or explicitly blocked.

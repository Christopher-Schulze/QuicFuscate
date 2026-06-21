---
description: Web Admin API Coverage and Contract Mapping
---

# Web Admin API Coverage and Contract Mapping

> Status: Historical. This document maps the legacy Dioxus web admin client.
> The current admin UI is React: `archive/apps/web-admin-ui/`.
> Legacy Dioxus sources live at `archive/unused code/apps-web-admin-dioxus/`.

## Scope
Define the canonical JSON contract for the admin HTTP server and map each endpoint to the web-admin UI usage. Identify gaps, mismatches, and required wiring.

## Sources of Truth
- Server: `src/implementations/server/admin_http.rs`, `src/implementations/server/admin.rs`
- Client (legacy): `archive/unused code/apps-web-admin-dioxus/src/api.rs`, `archive/unused code/apps-web-admin-dioxus/src/app.rs`

## Endpoint Inventory (Server)
| Endpoint | Method | Auth | Request Body | Response Shape | Notes |
| --- | --- | --- | --- | --- | --- |
| `/api/login` | POST | none | `{username,password}` | `AdminResponse{data:{user}}` | Sets session cookie `qf_admin_session` (HttpOnly).
| `/api/logout` | POST | Session cookie | none | `AdminResponse` | Clears session cookie.
| `/api/status` | GET | Session cookie | none | `AdminResponse{data:{version,uptime_secs,clients_active,clients_total,bytes_in,bytes_out,listen}}` | No RTT, loss, cwnd, delivery rate fields today.
| `/api/clients` | GET | Session cookie | none | `AdminResponse{data:Vec<ClientInfo>}` | Wrapped in `AdminResponse`.
| `/api/kick` | POST | Session cookie | `{id}` | `AdminResponse` | Alias exists at `/api/clients/{id}/kick`.
| `/api/block` | POST | Session cookie | `{ip}` | `AdminResponse` | UI missing action.
| `/api/unblock` | POST | Session cookie | `{ip}` | `AdminResponse` | UI missing action.
| `/api/reload` | POST | Session cookie | none | `AdminResponse` | UI uses for reload.
| `/api/qkey` | POST | Session cookie | none | `AdminResponse{data:{qkey}}` | UI uses POST.
| `/api/shutdown` | POST | Session cookie | none | `AdminResponse` | UI missing gated action.
| `/api/config` | GET | Session cookie | none | `AdminResponse` | Needs defined `data` payload for config string.
| `/api/config` | POST | Session cookie | `{config}` | `AdminResponse` | UI wiring missing.
| `/api/metrics` | GET | Session cookie | none | `text/plain` | UI missing view.

## Current UI Usage (Client)
- `/api/status` via `get_json<AdminResponse<ApiStatusData>>`.
- `/api/clients` via `get_text` and accepts AdminResponse wrapper or raw legacy array.
- `/api/clients/{id}/kick` via `post_json` (alias supported by server).
- `/api/login` via `post_json` to set the session cookie.
- `/api/qkey` via POST.
- Config editor wired to `/api/config` GET/POST.
- Metrics view wired to `/api/metrics`.
- Logs remain local-only; no server log endpoint used.

## UI Route Mapping (Call Sites)
- `fetch_stats` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): GET `/api/status` -> expects `AdminResponse<ApiStatusData>` with `listen`.
- `fetch_clients` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): GET `/api/clients` -> expects `AdminResponse<Vec<ApiClientInfo>>`.
- `handle_kick` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): POST `/api/clients/{id}/kick` with empty body.
- `handle_reload` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): re-fetches `/api/status`, does **not** call `/api/reload`.
- `handle_generate_key` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): local demo generation only.
- `handle_save_*` (`archive/unused code/apps-web-admin-dioxus/src/app.rs`): local-only saves, no `/api/config` writes.

## Contract Gaps (Must Resolve)
1. **Status data mismatch**: UI expects RTT/loss/cwnd/delivery rate fields; server only supplies core metrics plus `listen`.
2. **Logs endpoint**: no server log endpoint, UI should be explicit about demo-only logs.

## Audit Findings (2026-01-30)
- **UI status schema mismatch**: `archive/unused code/apps-web-admin-dioxus/src/app.rs` expects RTT/loss/cwnd/delivery rate; server only exposes core metrics plus `listen`.
- **Client list mismatch**: resolved by wrapping `/api/clients` in `AdminResponse` and adding UI legacy parsing.
- **Kick path mismatch**: resolved by adding alias `/api/clients/{id}/kick`.
- **Config/QKey/metrics actions missing**: resolved by wiring in UI.
- **Shutdown absent**: endpoint exists server-side, no UI confirmation/gating flows.

## Server Behavior Notes (2026-01-31)
- `--admin-web` requires `--admin-web-user` and `--admin-web-password` (or env); server refuses to start otherwise.
- `/api/login` issues a `qf_admin_session` HttpOnly cookie with SameSite=Strict; `/api/logout` clears it.
- `/api/config` returns error when `config_path` is unset; writes validate TOML before saving.
- `/api/reload` exists but UI never calls it (only re-fetches `/api/status`).
- `/api/status` includes `config_writable` for UI gating.
- Admin HTTP server enforces body size limits with a 413 response.

## Replan Decisions (2026-01-31)
### Canonical Contract (v2)
Adopt a single JSON envelope for all API responses:
```json
{ "success": true|false, "message": "string?", "data": { ... }? }
```

### Compatibility Strategy
1. **Server**: Wrap `/api/clients` in `AdminResponse{data:[...]}` and add a backward-compatible alias for `/api/clients/{id}/kick`.
2. **UI**: Accept both wrapped and raw `Vec<ClientInfo>` for `/api/clients` until server alignment is deployed everywhere.
3. **Method Alignment**: Standardize `/api/qkey` as `POST` in the UI, keep server `POST` only.
4. **Capabilities**: expose `config_writable` in `/api/status` for UI gating.

### Canonical Payloads
#### Status
```json
{
  "version": "semver",
  "uptime_secs": 0,
  "clients_active": 0,
  "clients_total": 0,
  "bytes_in": 0,
  "bytes_out": 0,
  "listen": "0.0.0.0:4433",
  "rtt_ms": null,
  "loss_percent": null,
  "cwnd": null,
  "delivery_rate_bps": null,
  "bytes_in_flight": null
}
```
Optional fields are `null` when not supported.

#### Clients
```json
[
  {
    "id": "string",
    "ip": "string",
    "remote_addr": "string",
    "connected_secs": 0,
    "bytes_in": 0,
    "bytes_out": 0,
    "stealth_mode": "string"
  }
]
```

#### Config
```json
{ "config": "toml string" }
```

#### QKey
```json
{ "qkey": "QKey-..." }
```

## Alignment Plan
1. **Response Envelope Standardization**
   - Option A: wrap all endpoints in `AdminResponse` (recommended for consistent parsing).
   - Option B: allow mixed payloads and add API-specific parsing in UI.
2. **Status Schema Alignment**
   - Define minimal status fields in UI to match server output.
   - Add optional fields (`listen`, RTT, loss) as nullable in UI if server cannot supply.
3. **Clients Schema Mapping**
   - Map server `ClientInfo` to UI `ClientInfo`:
     - `ip` <- server `ip`
     - `connected_at` <- server `connected_secs`
     - `country` <- future optional enrichment
     - `bytes_in/out` <- server values
     - `id` <- server `id`
4. **Kick Flow**
   - Switch UI to `POST /api/kick` with `{id}` payload, or extend server to accept `/api/clients/{id}/kick`.
5. **QKey Flow**
   - Implement server-backed key generation using `/api/qkey` and show the result in Keys or QKey view.
6. **Config + Metrics**
   - Wire `ConfigView` to `/api/config` GET/POST.
   - Add metrics view or embed in Logs with parsing boundaries.
7. **Shutdown**
   - Add gated UI actions with confirmation and safe states (disabled in demo mode).

## Validation & Tests
- Add contract tests for each endpoint shape in `scripts/tests/rust/`.
- Add smoke checks for response envelopes and missing fields.
- Update E2E matrix to cover every endpoint.

## Acceptance Criteria
- UI and server API contracts are aligned and documented.
- No endpoint is called with a mismatched path or payload.
- All admin endpoints have a corresponding UI workflow or explicit exclusion rationale.

# TODO #36: Desktop Client (Tauri + React) Productionization

> Status: Completed. This document predates the current Tauri + React implementation.
> The current desktop app lives in `apps/tauri/` and is wired to the real engine (no simulated connect/stats).
> Keep this doc only as a record of the original productionization plan.

**Status**: Historical
**Priority**: High
**Effort**: High (5-10 days)
**Depends On**:
- Core engine APIs: `src/engine/*`
- QKey format: `src/engine/qkey.rs`
- Server admin HTTP (for end-to-end): `src/main.rs`, `src/implementations/server/admin_http.rs`

## Goal

Deliver a production-ready cross-platform desktop client (macOS, Windows, Linux) that:
- Imports and stores server connection entries (QKeys).
- Connects and disconnects using the real QuicFuscate engine (no simulations).
- Displays live status, stats, and logs from the engine.
- Uses a consistent design language with the server web-admin UI.

## Current State (Code Reality)

Desktop (Tauri + React):
- App: `apps/tauri/`
- Frontend stack: Vite + React 19 + TypeScript + Tailwind v4 + Radix UI + Framer Motion + Jotai.
- Backend: `apps/tauri/src-tauri/src/main.rs` implements Tauri commands, but:
  - `engine_connect` and `engine_disconnect` use the real engine and are fail-safe (see unit tests in `apps/tauri/src-tauri/src/main.rs`).
  - `engine_stats` and `engine_logs_since` return real data from the running engine state (or `null`/empty when disconnected).
  - QKey parsing and validation are enforced in Rust (rejects empty QKey, invalid remotes, missing tokens when required).
  - Frontend uses IPC (`invoke`) for status, stats, logs, connect/disconnect.
- UI model mismatch:
  - `TunnelConfig` in `archive/apps/desktop/src/stores/types.ts` is QKey-based (remote + SNI + `qkey` canonical credential).
  - QuicFuscate uses `QKey-...` plus token auth; the desktop model treats the QKey as the canonical credential.

Server web-admin:
- App: `archive/apps/web-admin-ui/` (React web)
- Admin API and QKey TTL enforcement are implemented in `src/main.rs`:
  - QKeys are stored and can expire; expired keys are rejected.
  - When QKey registry has entries, server requires token in QUIC Initial.

Legacy Dioxus desktop:
- App (archived): `archive/unused code/apps-gui-dioxus/` wires the real engine in-process.
- It is a reference implementation for behavior, but the target client is `apps/tauri/`.

## Architectural Decision (Client vs Server Responsibilities)

Desktop client responsibilities:
- Manage "Tunnels" as QKey-based connection entries:
  - Store the full QKey string as the canonical credential.
  - Derive display metadata from the decoded QKey (remote host:port, sni, optional tags).
- Provide only client-side UX options that are real and implemented.
  - Do not expose toggles that have no working implementation.

Server web-admin responsibilities:
- Configure server behavior and generate/manage QKeys with expiry.
- Optional: provide "recommended client defaults" as copyable snippets, but do not require client settings to mirror server internals.

## Required Output Surface (Desktop)

### Tunnels
- List of saved tunnels (name, endpoint, optional flag/location).
- Add tunnel flows:
  - Import QKey (paste).
  - Import QKey file (optional).
  - Manual entry (advanced):
    - Either paste QKey, or provide remote + sni + token (if supported).
    - Without token, connection must be refused if the server requires QKeys.

### Connection
- Connect / Disconnect to the selected tunnel using the real engine.
- Show connection state: disconnected, connecting, connected, disconnecting.

### Live Status
- Stats: RTT, loss, bytes in/out, packets in/out, uptime, stealth/fec mode.
- Logs: engine logs (live append; selectable and copyable).

### Settings (Client-Only)
- Only include settings that are implemented end-to-end.
- If a feature is not implemented (for example, a true OS kill switch), it must not be surfaced as a toggle.

## Implementation Plan (Concrete)

### 1. Replace Tauri Backend Stubs with Real Engine State
- Add `quicfuscate` as a dependency in `apps/tauri/src-tauri/Cargo.toml`.
- Create a single backend state container:
  - `Arc<Mutex<Option<QuicFuscateEngine>>>`
  - plus log sink buffer and current connection state.
- Implement Tauri commands (minimum):
  - `qkey_parse(qkey: String) -> ParsedQKey` (remote, sni, has_token, stealth, fec)
  - `engine_connect(qkey: String, settings: ClientSettings) -> Result<()>`
  - `engine_disconnect() -> Result<()>`
  - `engine_status() -> EngineStatusSnapshot` (state + last_error)
  - `engine_stats() -> Option<StatsSnapshot>`
  - `engine_logs_since(cursor: u64) -> (cursor, Vec<LogLine>)`
- Ensure all commands are deterministic and reflect real engine outcomes.

Reference logic:
- Port the working pieces from `archive/unused code/apps-gui-dioxus/src/state.rs` (connect/disconnect/stats/log capture) into the Tauri backend.

### 2. Make Frontend Use IPC, Remove All Simulation
- Replace `startStatsSimulation` and related timers in:
  - `archive/apps/desktop/src/components/tunnel/tunnel-detail.tsx`
- Replace tunnel activation state machine with:
  - `invoke("engine_connect", ...)` and `invoke("engine_disconnect", ...)`
  - Poll `engine_status` and `engine_stats` while connected.
- Populate `logsAtom` by polling `engine_logs_since`.

### 3. Fix Data Model: Replace WireGuard-like Fields
- Replace `TunnelConfig` fields to match the QuicFuscate reality:
  - `id`, `name`, `qkey`, `remote`, `sni`, `createdAt`, optional `notes`, optional `countryCode/location`.
- Update:
  - `archive/apps/desktop/src/stores/types.ts`
  - `archive/apps/desktop/src/components/tunnel/*`
  - `archive/apps/desktop/src/views/*`

### 4. QKey Import Must Be Canonical
- Parsing and validation must happen in Rust using `quicfuscate::engine::qkey::parse`.
- Frontend may do a lightweight pre-check for UX, but it must not be the source of truth.

### 5. Persistence (No Data Loss, Versioned)
- Store state in OS-appropriate app config directory, not `$HOME/.quicfuscate`.
- Persist:
  - tunnel list
  - selected tunnel
  - minimal settings
- Add schema versioning in the persisted JSON.

### 6. End-to-End Validation
- Run against local server (`quicfuscate server --admin-web ...`) using a real generated QKey.
- Add one E2E script (shell) that:
  - generates a QKey via admin API
  - launches desktop backend in headless test mode (or invokes backend commands)
  - connects, checks status/stats, disconnects

## Acceptance Criteria
- Desktop client has zero simulated stats and zero simulated connect flow.
- A pasted QKey connects successfully to a running server that requires QKeys.
- Stats and logs reflect real engine data.
- Persistence survives restart and keeps tunnels intact.
- UI contains only functional settings and flows.

## Risks / Notes
- A real OS-level kill switch is non-trivial; do not expose it until it is implemented per platform.
- QKeys are bearer credentials; treat them like passwords. They are base64-encoded JSON, not encrypted.
- Optional future: add an encrypted QKey variant, but do not block production readiness on it.

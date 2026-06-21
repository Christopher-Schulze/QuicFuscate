---
description: Web Admin vs Desktop App Parity Mapping
---

# Web Admin vs Desktop App Parity Mapping

> Status: Needs refresh for the current React UIs.
> Active UIs are `apps/tauri/` (Tauri + React) and `archive/apps/web-admin-ui/` (React web admin).
> Legacy Dioxus sources are referenced only as historical context.

## Scope
Ensure the web-admin UI exposes a feature set consistent with the desktop app, and that terminology, workflows, and state models match. Document any intentional divergence.

## Sources
- Desktop app (current): `archive/apps/desktop/src/`, `apps/tauri/src-tauri/src/main.rs`
- Web admin (current): `archive/apps/web-admin-ui/src/` (views/components), `archive/apps/web-admin-ui/src/api.ts`
- Desktop app (legacy, historical): prior Dioxus implementation notes
- Web admin (legacy, historical): prior Dioxus implementation notes

## Parity Dimensions
1. **Connection Lifecycle**
   - Desktop: connect/disconnect, auto-reconnect, last QKey use.
   - Web-admin: server status/reload/stop.
   - Parity action: align status labels, display connection/uptime consistently.
2. **QKey Management**
   - Desktop: import/export QKey, clipboard copy.
   - Web-admin: generate/revoke/copy (currently demo-only).
   - Parity action: align copy feedback, warnings, and key lifecycle semantics.
3. **Settings Coverage**
   - Desktop: Stealth/FEC/Crypto/Transport/Connection settings with validation.
   - Web-admin: views exist but are not server-wired.
   - Parity action: same labels, option lists, defaults, and validation.
4. **Clients & Sessions**
   - Desktop: typically client-side only.
   - Web-admin: server-side client list and kick/block.
   - Parity action: ensure UI clarity that actions are server-side only.
5. **Logs & Diagnostics**
   - Desktop: log stream view and error surface.
   - Web-admin: logs view (local only).
   - Parity action: align severity colors, timestamp formatting, and empty/error states.
6. **Status Metrics**
   - Desktop: engine stats and telemetry indicators.
   - Web-admin: dashboard stats (demo placeholders).
   - Parity action: unify metric labels and formatting (bytes, rates, RTT, loss).

## Audit Work Items
- [x] Extract desktop app action list (connect, disconnect, export, import, reload, etc.). (Parity baseline completed in current React UIs, 2026-02-12)
- [x] Map each action to web-admin equivalent or justify a server-only variant. (Parity baseline completed in current React UIs, 2026-02-12)
- [x] Align label naming, button verbs, and status wording. (Parity baseline completed in current React UIs, 2026-02-12)
- [x] Normalize formats: bytes, durations, timestamps, rates. (Parity baseline completed in current React UIs, 2026-02-12)
- [x] Ensure error/empty/loading states match UX expectations in both apps. (Parity baseline completed in current React UIs, 2026-02-12)

## Known Gaps to Address
- Web-admin uses demo-only key generation; server-backed QKey not wired.
- Web-admin dashboard uses placeholders for RTT/loss/cwnd/cc algorithm.
- Config editor and reload are not wired to server API.
- Logs view is local-only (no server log endpoint).

## Audit Findings (2026-01-30)
### Desktop App (legacy Dioxus, historical) Feature Summary
- Connection lifecycle: connect/disconnect with busy states + error surfacing.
- Config management: list, select, import, delete, export QKey to clipboard.
- Settings: General (kill switch, auto-reconnect, launch at login, log level) plus full stealth/fec/crypto/transport sections.
- Logs: log levels rendered, refresh + clear actions.

### Web-Admin (legacy Dioxus, historical) Feature Summary
- Navigation: Status, Clients, Stealth, FEC, Crypto, Connection, Transport, Keys, Logs.
- Config and QKey views exist in codebase but are not wired to nav or app routing.
- Keys view currently uses local demo generation and local logs only.
- Header actions: reload triggers local fetch; stop shows demo-only toast.

### Parity Gaps (Must Resolve)
1. **Config/QKey workflows**: Desktop supports import/export; web-admin does not expose config list/import/export or server-backed QKey generation.
2. **General settings**: Desktop supports general options (kill switch, auto-reconnect, log level); web-admin lacks a comparable section or equivalent controls.
3. **Status/metrics**: Desktop shows live stats from engine; web-admin shows placeholders for several fields without server wiring.
4. **Logs**: Desktop logs reflect engine state; web-admin logs are local-only and not bound to server logs.
5. **Action gating**: Desktop warns on error; web-admin lacks consistent confirmation flows for dangerous server actions (shutdown).
6. **Terminology**: Desktop uses "Connect/Disconnect" while web-admin is server-side; labels need clarified to avoid user confusion.

## Audit Addendum (2026-01-31)
- Desktop UI historical note: legacy Dioxus build referenced CSS variables `--fg-muted` and `--primary` without matching definitions.

## Acceptance Criteria
- Desktop and web-admin share consistent terminology and UX patterns.
- Feature differences are explicitly documented and justified.
- All parity gaps have a tracked implementation item.

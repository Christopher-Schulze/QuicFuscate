# TODO-231: Desktop Polish - Favicon, Poll Redundancy, Updater Config

## Severity: MEDIUM

## Problem

Three distinct issues in the desktop app:

### 1. Favicon is Svelte Logo
`apps/svelte-desktop/src/lib/assets/favicon.svg` contains the Svelte framework logo (`<title>svelte-logo</title>`, fill `#ff3e00`). Browser tabs show the Svelte logo instead of the QuicFuscate brand.

### 2. Redundant engine_status Polling (~3.1 calls/sec)
In `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`:
- **statusInterval** (line 159, 500ms = 2/sec): calls `invoke("engine_status")`
- **statsInterval** (line 182, 900ms = 1.1/sec): calls `invoke("engine_status")` AND `invoke("engine_stats")`

Both intervals independently call `engine_status`, resulting in ~3.1 calls/sec. The statsInterval only needs `engine_status` to get `activeTunnelId`, which statusInterval already computes.

### 3. Tauri Updater Plugin Unconfigured
`apps/tauri/src-tauri/tauri.conf.json:43` has `"plugins": {}` (empty). The updater plugin is referenced in Cargo.toml dependencies but has no configuration (no endpoint URLs, no public key, no update check interval).

## Fix

### Favicon
1. Replace `apps/svelte-desktop/src/lib/assets/favicon.svg` with QuicFuscate brand icon
2. Source from `assets/logo/` or create a simplified SVG version

### Poll Consolidation
3. Remove `engine_status` call from statsInterval
4. Have statsInterval read the status from the already-polled state (set by statusInterval)
5. Or: merge both intervals into one 500ms poll that fetches both status and stats

### Updater Config
6. Either configure the updater plugin properly in tauri.conf.json (endpoint, pubkey) or remove the plugin dependency from Cargo.toml if auto-update is not yet supported

## Affected Files

- `apps/svelte-desktop/src/lib/assets/favicon.svg`
- `apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte.ts`
- `apps/tauri/src-tauri/tauri.conf.json`
- Potentially `apps/tauri/src-tauri/Cargo.toml` (if removing updater plugin)

## Verification

- Visual: browser tab shows correct icon
- Performance: only ~2 IPC calls/sec instead of ~3.1
- Build: Tauri compiles without updater warnings

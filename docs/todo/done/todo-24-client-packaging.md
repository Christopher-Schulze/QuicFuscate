# TODO #24: Cross-Platform Client Packaging

**Status**: Planned
**Priority**: Medium
**Effort**: Medium (5-7 days)
**Depends On**: TODO #22 (Engine Wiring)

---

## Goal

Create distributable VPN client packages for:
1. **macOS** - DMG with app bundle
2. **Windows** - MSI/NSIS installer with Wintun driver
3. **Linux** - DEB/RPM packages + AppImage

---

## Architecture Overview

```
QuicFuscate Client

  UI (Tauri frontend, React/TypeScript)
  - server list
  - connect button
  - status display
  - settings

  Core (QuicFuscateEngine, Rust)
  - EngineConfig
  - lifecycle API
  - callbacks -> UI events

  Platform integration
  - TUN driver
  - system tray integration
```

---

## Platform-Specific Details

### macOS

**TUN Driver**: utun (built-in, no driver needed)

**Packaging**:
```
QuicFuscate.app/
  Contents/
    Info.plist
    MacOS/
      quicfuscate-client (universal binary)
    Resources/
      icon.icns
      config/
    Frameworks/
```

**Code Signing**: Required for TUN access

**Work Items**:
- [x] Universal binary (x86_64 + arm64) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] App bundle with proper Info.plist (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Code signing with Developer ID (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] DMG creation with background image (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Notarization for macOS 10.15+ (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] System extension for TUN (if needed) (Deferred to post-v1 packaging phase, 2026-02-12)

---

### Windows

**TUN Driver**: Wintun (bundled)

**Integration**:
```rust
// src/interface.rs - already has TunFactory

fn setup_windows_tun() -> Result<(), Error> {
    // Register Wintun driver
    let wintun = wintun::Adapter::open_or_create(
        "QuicFuscate",
        "QuicFuscate Tunnel",
        None
    )?;
    
    // Register with TunFactory
    TunFactory::register(WintunProvider::new(wintun));
    
    Ok(())
}
```

**Packaging**:
```
QuicFuscate-Setup.exe  (NSIS or WiX)
  quicfuscate-client.exe
  wintun.dll (bundled driver)
  config/
  resources/
```

**Work Items**:
- [x] Integrate wintun crate (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Implement WintunProvider for TunFactory (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] NSIS or WiX installer (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Driver installation on first run (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Windows Service mode (optional) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Firewall exception (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Start menu shortcuts (Deferred to post-v1 packaging phase, 2026-02-12)

---

### Linux

**TUN Driver**: /dev/net/tun (built-in)

**Packaging**:
```
# DEB package
quicfuscate_1.0.0_amd64.deb
  DEBIAN/
    control
    postinst
    postrm
  usr/bin/quicfuscate-client
  usr/share/applications/quicfuscate.desktop
  etc/quicfuscate/

# AppImage (distro-independent)
QuicFuscate-1.0.0-x86_64.AppImage
```

**Work Items**:
- [x] DEB package (Debian/Ubuntu) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] RPM package (Fedora/RHEL) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] AppImage (universal) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Desktop file and icon (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] PolicyKit rules for TUN access (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Man page (Deferred to post-v1 packaging phase, 2026-02-12)

---

## Tauri App Structure

```
frontend/quicfuscate-app/
  src-tauri/
    Cargo.toml         # Depends on quicfuscate
    tauri.conf.json
    src/
      main.rs          # Tauri entry point
      lib.rs           # IPC commands + engine state
    icons/
  src/
    app/               # Next.js app router
    components/
      ConnectionPanel.tsx
      ConfigList.tsx
      TabNavigation.tsx
      ImportDialog.tsx
      SettingsPanel.tsx
      LogsPanel.tsx
      AboutPanel.tsx
    stores/
      appStore.ts      # Engine/UI state management
  package.json
  vite.config.ts
```

**Tauri Commands**:
```rust
// src-tauri/src/commands.rs

use quicfuscate::engine::{QuicFuscateEngine, EngineConfig, EngineState};
use tauri::State;
use std::sync::Mutex;

#[tauri::command]
async fn connect(
    engine: State<'_, Mutex<QuicFuscateEngine>>,
    server: String,
) -> Result<(), String> {
    let mut engine = engine.lock().unwrap();
    engine.config_mut().connection.remote = server;
    engine.connect().map_err(|e| e.to_string())
}

#[tauri::command]
async fn disconnect(engine: State<'_, Mutex<QuicFuscateEngine>>) -> Result<(), String> {
    engine.lock().unwrap().disconnect().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_state(engine: State<'_, Mutex<QuicFuscateEngine>>) -> EngineState {
    engine.lock().unwrap().state()
}

#[tauri::command]
fn get_stats(engine: State<'_, Mutex<QuicFuscateEngine>>) -> StatsSnapshot {
    engine.lock().unwrap().stats()
}
```

**Work Items**:
- [x] Create Tauri app skeleton. OK 2026-01-23
- [x] Integrate QuicFuscateEngine as Tauri state. OK 2026-01-23
- [x] Implement IPC commands for core engine operations (status/connect/disconnect). OK 2026-01-23
- [x] Create initial UI components (React). OK 2026-01-23
- [x] System tray integration (Completed in current desktop client, 2026-02-12)
- [x] Auto-start on login option (Completed as persisted preference in current desktop client, 2026-02-12)
- [x] Server profiles management (Closed as superseded by current tunnel model and QKey workflow, 2026-02-12)

---

## Build Pipelines

```yaml
# .github/workflows/release.yml

name: Release

on:
  push:
    tags: ['v*']

jobs:
  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build universal binary
        run: |
          rustup target add aarch64-apple-darwin
          cargo build --release --target x86_64-apple-darwin
          cargo build --release --target aarch64-apple-darwin
          lipo -create -output target/release/quicfuscate-client \
            target/x86_64-apple-darwin/release/quicfuscate-client \
            target/aarch64-apple-darwin/release/quicfuscate-client
      - name: Build Tauri app
        run: pnpm tauri build
      - name: Sign and notarize
        run: ./scripts/sign-macos.sh
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: macos
          path: target/release/bundle/dmg/*.dmg

  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build --release
      - name: Build Tauri app
        run: pnpm tauri build
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: windows
          path: target/release/bundle/nsis/*.exe

  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build --release
      - name: Build Tauri app
        run: pnpm tauri build
      - name: Build AppImage
        run: ./scripts/build-appimage.sh
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: linux
          path: |
            target/release/bundle/deb/*.deb
            target/release/bundle/appimage/*.AppImage
```

**Work Items**:
- [x] GitHub Actions workflow for all platforms (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Code signing for macOS (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Code signing for Windows (optional) (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] AppImage bundling script (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Release automation (Deferred to post-v1 packaging phase, 2026-02-12)

---

## File Structure (After Implementation)

```
quicfuscate/
  src/                    # Core library
    engine/               # Engine API
  apps/
    desktop/              # Tauri desktop client (React)
      src-tauri/          # Rust backend (Tauri commands)
      src/                # Frontend (React/TypeScript)
      package.json
  deploy/
    macos/
      QuicFuscate.app/
    windows/
      installer.nsi
    linux/
      quicfuscate.deb
      quicfuscate.desktop
  .github/
    workflows/
      release.yml
```

---

## Success Criteria

- [x] macOS: DMG installs cleanly, app runs with utun (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Windows: Installer works, Wintun loads correctly (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] Linux: DEB/AppImage work on major distros (Deferred to post-v1 packaging phase, 2026-02-12)
- [x] GUI connects to server and shows status (Covered by current desktop runtime verification, 2026-02-12)
- [x] System tray minimizes properly (Covered by current desktop tray behavior, 2026-02-12)
- [x] Auto-updates work (optional) (Deferred to signed-binary phase, 2026-02-12)

---

## Estimated Effort

| Platform | Days | Risk |
|----------|------|------|
| macOS | 1.5 | Low |
| Windows | 2 | Medium (Wintun) |
| Linux | 1 | Low |
| Tauri App | 2 | Medium |
| CI/CD | 0.5 | Low |
| **Total** | **7 days** | |

---

## Notes

- Frontend GUI implementation is out of scope for this TODO
- Focus is on packaging and platform integration
- Tauri skeleton provides structure for future GUI development

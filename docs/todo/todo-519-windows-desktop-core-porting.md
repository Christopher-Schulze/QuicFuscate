---
id: TODO-519
title: "Windows desktop build: cfg-gate Unix-specific core library code for Windows compilation"
severity: HIGH
phase: "I"
priority: P2
status: OPEN
created: 2026-07-07
depends_on: []
---

# TODO-519: Windows Desktop Build — Core Library Windows Porting

## Goal

Enable the Tauri desktop app to compile and build on Windows (MSI bundle) by cfg-gating or porting Unix-specific code in the core QUIC library.

## Current State (verified against CI)

The `desktop-windows` job was removed from `release.yml` because the core library does not compile on Windows. CI run `28859507062` (job `85594291717`) produced the following errors:

- `error[E0433]: cannot find module or crate 'windows_sys' in this scope` — `windows_sys` is an optional dependency (`tun-windows` feature) not enabled by default in the Tauri app.
- `error[E0433]: cannot find 'unix' in 'os'` — `std::os::unix` used on Windows without cfg gate.
- `error[E0432]: unresolved imports 'libc::iovec', 'libc::msghdr', 'libc::sockaddr_storage', 'libc::socklen_t'` — `libc` Unix types used in `transport/batch.rs` without cfg gate.
- `error[E0425]: cannot find function 'current_node' in module 'numa'` — `numa` module not available on Windows.
- `error[E0432]: unresolved import 'admin::AdminServer'` — admin server module not available on Windows.

## Problem Analysis

The core QUIC library (`quicfuscate` crate) was designed for Linux/macOS servers. Several modules use Unix-specific syscalls without `cfg(unix)` gates:

1. **`src/transport/batch.rs`** — uses `libc::iovec`, `libc::msghdr`, `libc::sockaddr_storage`, `libc::socklen_t` for `recvmmsg`/`sendmmsg` batch I/O. These types don't exist in `libc` on Windows.
2. **`src/transport/udpfast.rs`** — references `windows_sys::Win32::Networking::WinSock` but only when the `tun-windows` feature is enabled.
3. **`src/optimize/mod.rs`** — references `windows_sys::Win32::Networking::WinSock` for WSARecvMsg/WSASendMsg.
4. **`src/interface/wintun.rs`** — Windows TUN backend (TODO-442, DONE) uses `windows_sys` but is feature-gated.
5. **Admin server** — `admin::AdminServer` is not available on Windows (Unix socket or TCP binding assumptions).

The Tauri desktop app (`apps/tauri/src-tauri/Cargo.toml`) depends on `quicfuscate` without the `tun-windows` feature, so `windows_sys` is not in scope.

## Proposed Approach

1. **Audit all Unix-specific code paths** in `src/` that are not cfg-gated:
   - `grep -rn "libc::iovec\|libc::msghdr\|libc::sockaddr_storage\|libc::socklen_t\|std::os::unix\|nix::" src/`
   - `grep -rn "recvmmsg\|sendmmsg\|mmsghdr" src/`

2. **cfg-gate Unix-only modules** behind `#[cfg(unix)]` or provide Windows alternatives:
   - `transport/batch.rs`: gate `recvmmsg`/`sendmmsg` batch path behind `cfg(unix)`, provide a Windows fallback using WSARecvFrom/WSASendTo or a simple loop.
   - `numa` module: gate behind `cfg(target_os = "linux")`.
   - Admin server: gate behind `cfg(unix)` or provide a Windows-compatible TCP listener.

3. **Add a Windows CI check** to `ci.yml`:
   ```yaml
   windows-check:
     runs-on: windows-latest
     steps:
       - uses: actions/checkout@v4
       - uses: dtolnay/rust-toolchain@stable
       - run: cargo check --lib
       - run: cargo clippy --lib -- -D warnings
   ```

4. **Re-add the `desktop-windows` job** to `release.yml` once the core library compiles on Windows.

## Completion Criteria

- [ ] `cargo check --lib --target x86_64-pc-windows-msvc` succeeds on Windows
- [ ] `cargo clippy --lib --target x86_64-pc-windows-msvc -- -D warnings` is clean
- [ ] `cargo tauri build` succeeds on `windows-latest` CI runner
- [ ] Windows MSI bundle is uploaded as a release artifact
- [ ] `latest.json` includes `windows-x86_64` platform entry with valid signature
- [ ] No regressions on Linux/macOS builds

## Notes

- TODO-442 (Windows TUN via Wintun) is DONE and provides the Wintun TUN backend, but the rest of the core library still needs Windows porting.
- The desktop app on Windows may not need TUN functionality (it could be client-only without VPN routing). Consider feature-gating TUN-dependent code behind a `tun` feature that is disabled for the Windows desktop build.
- No UI changes required — this is purely a backend/CI porting task.

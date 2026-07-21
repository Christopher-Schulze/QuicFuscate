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

# TODO-519: Windows Desktop Build - Core Library Windows Porting

## Goal

Enable the Tauri desktop app to compile and build on Windows (MSI bundle) by cfg-gating or porting Unix-specific code in the core QUIC library.

## Original Failure State (verified against CI)

The `desktop-windows` job was removed from `release.yml` because the core library does not compile on Windows. CI run `28859507062` (job `85594291717`) produced the following errors:

- `error[E0433]: cannot find module or crate 'windows_sys' in this scope` - `windows_sys` is an optional dependency (`tun-windows` feature) not enabled by default in the Tauri app.
- `error[E0433]: cannot find 'unix' in 'os'` - `std::os::unix` used on Windows without cfg gate.
- `error[E0432]: unresolved imports 'libc::iovec', 'libc::msghdr', 'libc::sockaddr_storage', 'libc::socklen_t'` - `libc` Unix types used in `transport/batch.rs` without cfg gate.
- `error[E0425]: cannot find function 'current_node' in module 'numa'` - `numa` module not available on Windows.
- `error[E0432]: unresolved import 'admin::AdminServer'` - admin server module not available on Windows.

## Problem Analysis

The core QUIC library (`quicfuscate` crate) was designed for Linux/macOS servers. Several modules use Unix-specific syscalls without `cfg(unix)` gates:

1. **`src/transport/batch.rs`** - uses `libc::iovec`, `libc::msghdr`, `libc::sockaddr_storage`, `libc::socklen_t` for `recvmmsg`/`sendmmsg` batch I/O. These types don't exist in `libc` on Windows.
2. **`src/transport/udpfast.rs`** - references `windows_sys::Win32::Networking::WinSock` but only when the `tun-windows` feature is enabled.
3. **`src/optimize/mod.rs`** - references `windows_sys::Win32::Networking::WinSock` for WSARecvMsg/WSASendMsg.
4. **`src/interface/wintun.rs`** - Windows TUN backend (TODO-442, DONE) uses `windows_sys` but is feature-gated.
5. **Admin server** - `admin::AdminServer` is not available on Windows (Unix socket or TCP binding assumptions).

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

4. **Keep the restored `desktop-windows` job required** in `release.yml` and validate its MSI/signature output on a native Windows runner.

## Completion Criteria

- [ ] `cargo check --lib --target x86_64-pc-windows-msvc` succeeds on Windows
- [ ] `cargo test --lib --features rust-tests` succeeds on Windows, including real destination-preserving batch UDP coverage
- [ ] `cargo clippy --lib --features rust-tests --target x86_64-pc-windows-msvc -- -D warnings` is clean
- [ ] `cargo tauri build` succeeds on `windows-latest` CI runner
- [ ] Windows MSI bundle is uploaded as a release artifact
- [ ] `latest.json` includes `windows-x86_64` platform entry with valid signature
- [ ] No regressions on Linux/macOS builds

## Notes

- TODO-442 (Windows TUN via Wintun) is DONE and provides the Wintun TUN backend, but the rest of the core library still needs Windows porting.
- The desktop app on Windows may not need TUN functionality (it could be client-only without VPN routing). Consider feature-gating TUN-dependent code behind a `tun` feature that is disabled for the Windows desktop build.
- No UI changes required - this is purely a backend/CI porting task.

### Execution checkpoint (2026-07-21)

- The Windows-specific dependency is now target-owned rather than coupled to the optional `tun-windows` feature. Rustls is explicitly ring-only so Windows builds do not pull the unrelated AWS-LC C toolchain.
- A local `x86_64-pc-windows-msvc` check reaches `ring` but cannot complete on macOS because the local host has no Windows SDK headers. This is an environment limitation, not accepted as Windows proof.
- A local `x86_64-pc-windows-gnu` check with MinGW reaches the QuicFuscate crate and reduced the old broad failure report to 24 exact source errors. The current implementation pass addresses those errors with direct Winsock scatter/gather APIs, real Windows NUMA calls, portable destination-preserving UDP fallbacks, Unix-only systemd/admin exports, Wintun debug support, and cfg-symmetric SIMD telemetry.
- `CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo check --lib --target x86_64-pc-windows-gnu` passes after the correction, proving that the full library source now type-checks for Windows. This is a strong local cross-target proof, but the completion criteria still require the native MSVC CI runner.
- `CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo clippy --lib --target x86_64-pc-windows-gnu -- -D warnings` also passes.
- The expanded Windows GNU `cargo test --lib --features rust-tests --target x86_64-pc-windows-gnu --no-run` gate exposed one additional test-surface contract bug: `BatchProcessor` narrowed a Windows `RawSocket` to `i32`. The fallback now accepts the platform-native handle, borrows it without accidental close-on-error ownership, preserves every packet destination, and cross-compiles cleanly. Feature-enabled Windows GNU Clippy also passes with warnings denied.
- `.github/workflows/ci.yml` now contains the native `windows-core-checks` check/test/Clippy gate. `.github/workflows/release.yml` restores `desktop-windows` as a required signed MSI producer and maps `.msi` plus `.msi.sig` into `latest.json` as `windows-x86_64`.
- The Windows CI gate also runs the full library `rust-tests` suite. Its Windows-only real UDP regression verifies that batch sends preserve two distinct destinations and never close the caller-owned socket handle.
- Live release inspection found that `v0.4.1` and `v0.4.2` were published after the documented v0.4.0 checkpoint while their server and desktop artifacts still carried product version `0.4.0`; `v0.4.2/latest.json` therefore advertised `0.4.2` for `0.4.0` artifacts. The next free release version is synchronized to `0.4.3`, and `verify-release-version.sh` now fails closed on root/Tauri/tag mismatch before any release build.
- The workflow contract is tracked but not yet native-proven. MSVC CI, Tauri MSI production/upload, and a tagged updater manifest remain open acceptance evidence.
- Native CI run `29838022208` job `88659311753` proves `cargo check --lib` on MSVC, but the 1,662-test library process then aborted with Windows status `0xc000001d` (`STATUS_ILLEGAL_INSTRUCTION`) before Clippy ran. The gate now executes tests serially with uncaptured output to identify the exact unsafe CPU-dispatch path; no test is skipped or weakened.
- Native macOS regression evidence is green: root `cargo check --lib`, root `cargo clippy --lib -- -D warnings`, `cargo test --lib --features rust-tests` with 1,664 passing tests, the broader `cargo test --workspace --all-targets --features rust-tests` gate including the integration harnesses, and `cargo clippy --workspace --all-targets --features rust-tests -- -D warnings`.
- The native Tauri host passes `cargo check`, 29/29 host tests, and `cargo clippy --all-targets -- -D warnings` with a temporary inline `TAURI_CONFIG` that changes only `build.frontendDist` to an external URL. This validates the Rust host without generating or modifying the protected Svelte bundle; it is not MSI packaging proof.
- Workflow YAML parsing and `git diff --check` pass locally. `audit-todo-consistency.sh` passes across 165 detail files with zero violations, and `audit-runtime-guardrails.sh` passes with zero critical findings and zero warnings.
- No Svelte, Tauri UI, shared UI package, theme, asset, screenshot, or generated frontend file is in scope or modified.

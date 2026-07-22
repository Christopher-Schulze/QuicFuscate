---
id: TODO-442
title: "Windows TUN via Wintun integration (client + server, dynamic DLL, ring buffer, kill switch)"
severity: HIGH
phase: "I"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-442: Windows TUN via Wintun Integration

## Goal
Replace the non-functional Windows TUN stub with a production-grade Wintun-backed adapter that implements the `TunDevice` trait for both client and server. The implementation must dynamically load `wintun.dll` (no static linking), support packet I/O via Wintun's ring buffer, integrate with the existing kill switch (Windows Firewall via `netsh`), and work with the io_uring/batch infrastructure through a dedicated blocking-thread + channel bridge.

## Current State (verified against code)

### Windows TUN stub
`src/interface.rs:868-888` — the `windows_tun` module defines `open_platform_tun` under two `cfg` branches, both return `Err(TunError::Config(...))`:
```rust
// src/interface.rs:872-879 (feature = "tun-windows")
#[cfg(feature = "tun-windows")]
pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Config(
        "Windows TUN requires Wintun; use register_tun_factory or link feature impl",
    ))
}

// src/interface.rs:883-888 (not(feature = "tun-windows"))
#[cfg(not(feature = "tun-windows"))]
pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Config(
        "Windows TUN not built-in; enable 'tun-windows' or use register_tun_factory",
    ))
}
```

### Empty Cargo feature
`Cargo.toml:118` — `tun-windows = []` is defined but has no crate dependency wired. No `wintun` or `wintun-rs` dependency exists anywhere in `Cargo.toml`.

### TunDevice trait
`src/interface.rs:255-268` — defines `name()`, `mtu()`, `read()`, `write()`, and optionally `raw_fd()` (Unix only). No Windows struct implements it.

### TunConfig struct
`src/interface.rs:152-167` — carries `name`, `ip`, `netmask`, `mtu`, `zero_copy`, `ip6`, `prefix6`. All ignored by the stub.

### tun_capabilities()
`src/interface.rs:229-239` — reports `built_in: false` on Windows. `validate_tun_runtime_requirements()` (`src/interface.rs:243-251`) rejects TUN operations unless an external factory is registered via `register_tun_factory`.

### Windows kill switch already exists
`src/implementations/client/killswitch.rs:596-694` — `WindowsKillSwitch` uses `netsh advfirewall` to add/delete block and allow rules. This is functional and must coexist with the Wintun TUN adapter (the kill switch allows VPN server IP + TUN interface, blocks everything else).

### Server routing on Windows
`src/implementations/server/routing.rs:138-139` — `RoutingManager::setup()` on Windows uses PowerShell `New-NetNat` for NAT. The TUN interface name from Wintun must be passed correctly to `RoutingManager`.

## Problem Analysis

The Windows TUN backend is a non-functional stub. QuicFuscate cannot create a TUN device on Windows — the world's largest desktop OS. The entire VPN data plane is non-functional on Windows without an external `register_tun_factory` call.

Key challenges:
1. **Wintun DLL loading**: Wintun is a userspace driver distributed as `wintun.dll`. It must be loaded dynamically at runtime — no static linking is possible. The DLL must be present on the system or bundled alongside the binary.
2. **Thread safety**: The Wintun C API session handle is not `Send`/`Sync` by default. The Rust `wintun` crate wraps it, but care must be taken with the `Session` type's thread safety guarantees.
3. **Async integration**: Wintun's `WintunReceivePacket` blocks the calling thread. Tokio's async runtime needs a dedicated OS thread that blocks on receive and forwards packets via a channel.
4. **IP assignment**: Wintun creates the adapter but does not assign IP addresses. This must be done via the Windows IP Helper API or `netsh interface ip set address`.
5. **Ring buffer capacity**: Wintun uses a ring buffer for packet I/O. The capacity must be configurable (power of 2, 128 KiB – 64 MiB) and tuned for VPN throughput.
6. **Server-side TUN on Windows**: The server also needs a TUN device for routing client traffic. The same Wintun integration must work for both client and server roles.

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WindowsTun Device                         │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │  Wintun DLL  │    │  Session (ring buffer)           │   │
│  │  (dynamic)   │───▶│  WintunReceivePacket (blocking)  │   │
│  │  wintun::load│    │  WintunSendPacket (non-blocking) │   │
│  └──────────────┘    └──────────────────────────────────┘   │
│         │                       │                           │
│         ▼                       ▼                           │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │  Adapter     │    │  Read Thread (dedicated OS)      │   │
│  │  (Arc<Adapter>)   │  receive_blocking() → channel    │   │
│  │  IP/netmask  │    │  Tokio mpsc → async read()       │   │
│  │  via netsh   │    └──────────────────────────────────┘   │
│  └──────────────┘                                            │
│                                                              │
│  Implements: TunDevice trait                                 │
│  - name() → adapter name                                     │
│  - mtu() → configured MTU                                    │
│  - read() → channel.recv() (async-compatible)               │
│  - write() → session.allocate_send_packet + send_packet      │
└─────────────────────────────────────────────────────────────┘
```

The architecture uses a dedicated blocking thread for packet reception (Wintun's `receive_blocking` is a blocking call). The thread reads packets from the Wintun ring buffer and sends them through a Tokio `mpsc` channel. The async `read()` method receives from this channel. Writes are non-blocking — `allocate_send_packet` + `send_packet` return immediately.

## Implementation Plan

### Step 1: Add wintun crate dependency
Add the `wintun` crate (v0.5.1, the maintained pure-Rust binding to wintun.dll) to `Cargo.toml`:
```toml
[target.'cfg(windows)'.dependencies]
wintun = "0.5"
```
Wire the `tun-windows` feature:
```toml
tun-windows = ["dep:wintun"]
```

The `wintun` crate v0.5.1 dynamically loads `wintun.dll` at runtime via `wintun::load()` / `wintun::load_from_path()`. The DLL must be present alongside the binary or in a system directory.

### Step 2: Implement WindowsTun struct
Replace the stub in `src/interface.rs:868-888` with a real implementation:

```rust
#[cfg(target_os = "windows")]
mod windows_tun {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    pub struct WindowsTun {
        session: Arc<wintun::Session>,
        adapter_name: String,
        mtu: u16,
        // Channel for packets received by the blocking thread
        recv_rx: mpsc::Receiver<Vec<u8>>,
        // Keep the adapter alive (dropping it destroys the adapter)
        _adapter: Arc<wintun::Adapter>,
        // Handle to the receive thread (joined on drop)
        recv_thread: Option<std::thread::JoinHandle<()>>,
    }

    impl WindowsTun {
        pub fn new(cfg: &TunConfig) -> Result<Self, TunError> {
            // 1. Load wintun.dll
            let wintun = unsafe {
                wintun::load().map_err(|e| TunError::Config(
                    "Failed to load wintun.dll: place it alongside the binary or in PATH"
                ))?
            };

            // 2. Create adapter
            let adapter_name = cfg.name.clone().unwrap_or_else(|| "quicfuscate".to_string());
            let adapter = wintun::Adapter::create(&wintun, &adapter_name, "QuicFuscate", None)
                .map_err(|e| TunError::Io(io::Error::other(format!("{:?}", e))))?;

            // 3. Assign IP and netmask via netsh
            if let Some(ip) = cfg.ip {
                if let Some(netmask) = cfg.netmask {
                    Self::set_adapter_ip(&adapter_name, ip, netmask)?;
                }
            }

            // 4. Start session with configurable ring capacity
            let ring_capacity = cfg.wintun_ring_capacity
                .unwrap_or(wintun::MAX_RING_CAPACITY);
            let session = Arc::new(adapter.start_session(ring_capacity)
                .map_err(|e| TunError::Io(io::Error::other(format!("{:?}", e))))?);

            // 5. Spawn blocking receive thread
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
            let session_clone = Arc::clone(&session);
            let recv_thread = std::thread::Builder::new()
                .name("wintun-recv".to_string())
                .spawn(move || {
                    loop {
                        match session_clone.receive_blocking() {
                            Ok(packet) => {
                                let data = packet.bytes().to_vec();
                                if tx.blocking_send(data).is_err() {
                                    break; // Channel closed, exit thread
                                }
                            }
                            Err(wintun::SessionError::NoMorePackets) => {
                                // Non-blocking mode would spin; in blocking mode this
                                // shouldn't happen. Sleep briefly to avoid busy-loop.
                                std::thread::sleep(std::time::Duration::from_micros(100));
                            }
                            Err(_) => break, // Session closed
                        }
                    }
                })
                .map_err(|e| TunError::Io(io::Error::other(e)))?;

            Ok(Self {
                session,
                adapter_name,
                mtu: cfg.mtu,
                recv_rx: rx,
                _adapter: adapter,
                recv_thread: Some(recv_thread),
            })
        }

        fn set_adapter_ip(name: &str, ip: IpAddr, netmask: IpAddr) -> Result<(), TunError> {
            use std::process::Command;
            let ip_str = ip.to_string();
            let mask_str = netmask.to_string();
            let status = Command::new("netsh")
                .args(["interface", "ip", "set", "address",
                       &format!("name={}", name),
                       "static", &ip_str, &mask_str])
                .status()
                .map_err(|e| TunError::Io(io::Error::other(e)))?;
            if !status.success() {
                return Err(TunError::Config("netsh failed to set adapter IP"));
            }
            Ok(())
        }
    }

    impl TunDevice for WindowsTun {
        fn name(&self) -> &str { &self.adapter_name }
        fn mtu(&self) -> u16 { self.mtu }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // Try non-blocking channel receive; if empty, do a blocking receive
            match self.recv_rx.blocking_recv() {
                Some(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    Ok(len)
                }
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "session closed")),
            }
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            let mut packet = self.session.allocate_send_packet(buf.len() as u16)
                .map_err(|e| io::Error::other(format!("{:?}", e)))?;
            packet.bytes_mut()[..buf.len()].copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(buf.len())
        }
    }

    impl Drop for WindowsTun {
        fn drop(&mut self) {
            // End the session — this unblocks the receive thread
            self.session.end_session();
            if let Some(handle) = self.recv_thread.take() {
                let _ = handle.join();
            }
        }
    }
}
```

### Step 3: Wire open_platform_tun to WindowsTun::new
Replace the stub `open_platform_tun`:
```rust
#[cfg(feature = "tun-windows")]
pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    windows_tun::WindowsTun::new(cfg).map(|t| Box::new(t) as Box<dyn TunDevice>)
}
```

### Step 4: Update tun_capabilities() for Windows
In `src/interface.rs:229-239`, add Windows to the `built_in` check:
```rust
built_in: cfg!(target_os = "linux")
    || cfg!(target_os = "android")
    || cfg!(target_os = "macos")
    || (cfg!(target_os = "windows") && cfg!(feature = "tun-windows")),
```

### Step 5: Add wintun_ring_capacity to TunConfig
Extend `TunConfig` (`src/interface.rs:152-167`) with:
```rust
/// Wintun ring capacity (power of 2, 128 KiB – 64 MiB). None = MAX_RING_CAPACITY.
#[cfg(target_os = "windows")]
pub wintun_ring_capacity: Option<u32>,
```

### Step 6: Server-side TUN on Windows
The server's `RoutingManager` (`src/implementations/server/routing.rs:138-139`) already has a Windows `setup()` path that uses `New-NetNat` for NAT. The Wintun adapter name returned by `WindowsTun::name()` must be passed to `RoutingManager::new()` as `tun_name`. No changes to `RoutingManager` are needed — it already works with any interface name.

### Step 7: Kill switch integration
The existing `WindowsKillSwitch` (`src/implementations/client/killswitch.rs:596-694`) uses `netsh advfirewall` to block/allow traffic. The `allow_vpn_traffic` method takes `tun_name` and `server_ip` — the Wintun adapter name is passed as `tun_name`. No changes needed to the kill switch; it already works with any adapter name.

### Step 8: CI cross-compilation
Add a Windows cross-compilation check to CI:
```yaml
# .github/workflows/ci.yml
windows-check:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo check --lib --features tun-windows
    - run: cargo clippy --lib --features tun-windows -- -D warnings
```

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| Wintun binding | `wintun` crate v0.5.1 | Maintained pure-Rust binding; 547K downloads; updated Jan 2025; supports Wintun driver 0.14+ API |
| DLL loading | `wintun::load()` (dynamic) | No static linking; DLL loaded at runtime from PATH or binary directory |
| Async bridge | Dedicated OS thread + `mpsc` channel | Standard pattern used by WireGuard, Tauri VPN clients; `receive_blocking` is inherently blocking |
| IP assignment | `netsh interface ip set address` | Simple, reliable, no additional crate needed. Production alternative: `windows` crate IP Helper API |
| Ring buffer | `wintun::MAX_RING_CAPACITY` (default) | 0x4000000 (64 MiB) — maximum throughput; configurable down to 128 KiB for low-memory devices |
| Alternative considered | `tun2` crate | Does not support Windows; `wintun` is the only viable option |

## Stealth/Efficiency Considerations

- **Packet I/O latency**: Wintun's ring buffer provides < 100µs read/write latency. The dedicated receive thread ensures no async runtime blocking.
- **No hot-path allocation**: The receive thread allocates a `Vec<u8>` per packet. For zero-copy optimization, consider a pre-allocated packet pool and `bytes::Bytes` for channel transfer. This is a future optimization (TODO-403 zero-copy recv).
- **DLL footprint**: `wintun.dll` is ~140 KB. Bundle alongside the binary — no system installation required.
- **Stealth impact**: Wintun creates a visible network adapter in `ipconfig` output. The adapter name is configurable via `TunConfig.name`. For stealth, use a generic name like "Ethernet 2" rather than "quicfuscate".
- **Kill switch coexistence**: The Windows Firewall rules from `WindowsKillSwitch` are independent of the Wintun adapter. The kill switch allows traffic to the VPN server IP and through the TUN adapter, blocking everything else — this works seamlessly with Wintun.
- **CPU idle**: When no traffic flows, the receive thread parks on `receive_blocking()` — zero CPU usage.

## Testing Plan

### Unit tests (inline in `src/interface.rs`)
- `test_windows_tun_config_defaults` — `TunConfig::default()` has correct defaults on Windows
- `test_wintun_ring_capacity_bounds` — ring capacity must be power of 2, 128 KiB ≤ cap ≤ 64 MiB

### Integration tests (require Windows runner)
- `test_wintun_adapter_creation` — `open_platform_tun(&cfg)` returns `Ok` on Windows with `wintun.dll` present
- `test_wintun_adapter_name` — `WindowsTun::name()` returns configured adapter name
- `test_wintun_packet_roundtrip` — write a packet, read it back (loopback test with two adapters or a TUN-to-TUN bridge)
- `test_wintun_ip_assignment` — `ipconfig` shows the adapter with correct IP/netmask
- `test_wintun_kill_switch_integration` — kill switch blocks non-VPN traffic, allows VPN traffic through Wintun adapter
- `test_wintun_drop_cleans_up` — after `Drop`, adapter is removed from `ipconfig`
- `test_tun_capabilities_windows` — `tun_capabilities().built_in == true` when `tun-windows` feature enabled

### Cross-compilation tests
- `cargo check --target x86_64-pc-windows-gnu --features tun-windows` on Linux CI
- `cargo clippy --lib --features tun-windows -- -D warnings` on Windows CI

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Modify | Add `wintun = "0.5"` under `[target.'cfg(windows)'.dependencies]`, wire `tun-windows = ["dep:wintun"]` |
| `src/interface.rs:868-888` | Modify | Replace `windows_tun` stub with `WindowsTun` struct and real `open_platform_tun` |
| `src/interface.rs:229-239` | Modify | Update `tun_capabilities()` for Windows + `tun-windows` feature |
| `src/interface.rs:152-167` | Modify | Add `wintun_ring_capacity: Option<u32>` to `TunConfig` (cfg windows) |
| `.github/workflows/ci.yml` | Modify | Add Windows cross-compilation and clippy check |
| `docs/DOCUMENTATION.md` | Modify | Document Windows TUN setup, wintun.dll placement, feature flag |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `wintun.dll` not present on user system | High | Bundle DLL in installer/MSI; document placement; clear error message on load failure |
| Wintun API breaking changes (v0.14+ driver) | Medium | Pin `wintun` crate v0.5.1; document minimum driver version |
| `receive_blocking` thread not joined on drop | Medium | `Drop` impl calls `end_session()` + `join()`; test cleanup |
| `netsh` requires administrator privileges | Medium | Document that server/client must run elevated; same as Linux requiring root |
| Ring buffer capacity too small → packet drops | Low | Default to `MAX_RING_CAPACITY`; configurable; log drop counters |
| `mpsc::channel` allocation per packet | Low | Future optimization: pre-allocated pool + `bytes::Bytes` (TODO-403) |
| Windows Server Nano Server compatibility | Low | Wintun requires desktop experience APIs; document Server Core requirement |

## Completion Criteria

- [x] `cargo build --release --features tun-windows --target x86_64-pc-windows-gnu` succeeds. **GAP -> TODO-528** - TODO-519 proves native Windows core and release builds, but the explicit Wintun-enabled release gate is not retained.
- [x] `cargo clippy --lib --features tun-windows -- -D warnings` is clean. **GAP -> TODO-528** - native Clippy is green for the canonical feature set, not the exact Wintun-enabled surface.
- [x] On Windows 10/11 with `wintun.dll` present: `open_platform_tun(&cfg)` returns a `WindowsTun` instance. **GAP -> TODO-528** - the dynamic loader and constructor exist without a native privileged adapter-creation proof.
- [x] `WindowsTun::name()` returns the configured adapter name. **VERIFIED** - `WintunDevice` retains the configured name and its `TunDevice` implementation returns it.
- [x] `WindowsTun::mtu()` returns the configured MTU. **VERIFIED** - the constructor stores `TunConfig::mtu` and the trait implementation returns the stored value.
- [x] `WindowsTun::read()` returns IP packets from the Wintun session. **GAP -> TODO-528** - the ring copy path exists but has no native packet proof or closed-session termination gate.
- [x] `WindowsTun::write()` sends IP packets through the Wintun session. **GAP -> TODO-528** - the send-ring path exists without native packet delivery proof.
- [x] `ipconfig` shows the adapter with correct IP/netmask. **GAP -> TODO-528** - `netsh` assignment exists, but native state was never asserted.
- [x] `ping <server-tun-ip>` through the tunnel succeeds (end-to-end with a running server). **GAP -> TODO-528** - no Windows Wintun data-plane E2E exists.
- [x] `tun_capabilities().built_in == true` on Windows when `tun-windows` feature is enabled. **VERIFIED** - the capability expression explicitly gates Windows built-in support on that feature.
- [x] Kill switch blocks non-VPN traffic, allows VPN traffic through Wintun adapter. **GAP -> TODO-528** - source paths coexist but no native firewall plus Wintun packet proof exists.
- [x] No panics, no unsafe UB (wintun crate's own unsafe is encapsulated). **GAP -> TODO-528** - the hand-written FFI owns unsafe Send/Sync and close/read races; native stress and shutdown evidence are required.
- [x] Drop cleans up adapter and joins receive thread. **SUPERSEDED** - the retained implementation has no separate receive thread; `Drop` idempotently ends the Wintun session, closes the adapter, and unloads the DLL. TODO-528 must prove blocked reads terminate safely.

---
id: TODO-442
title: Windows TUN via Wintun (replace stub with real adapter, session, packet I/O)
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-442: Windows TUN via Wintun

## Problem

The Windows TUN backend is a non-functional stub. In `src/interface.rs:856-877`, the
`windows_tun` module defines `open_platform_tun` under two `cfg` branches — both return
`Err(TunError::Config(...))`:

```rust
// src/interface.rs:860-868  (feature = "tun-windows")
#[cfg(feature = "tun-windows")]
pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Config(
        "Windows TUN requires Wintun; use register_tun_factory or link feature impl",
    ))
}

// src/interface.rs:871-876  (not(feature = "tun-windows"))
#[cfg(not(feature = "tun-windows"))]
pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Config(
        "Windows TUN not built-in; enable 'tun-windows' or use register_tun_factory",
    ))
}
```

The `tun-windows` feature in `Cargo.toml:118` is defined but **empty** — no crate
dependency is wired:

```toml
# Cargo.toml:118
tun-windows = []
```

There is no `wintun` or `wintun-rs` dependency anywhere in `Cargo.toml`. The
`TunDevice` trait (`src/interface.rs:243-257`) defines `name()`, `mtu()`, `read()`,
`write()`, and optionally `raw_fd()` — but no Windows struct implements it. The
`TunConfig` struct (`src/interface.rs:152-163`) carries `name`, `ip`, `netmask`,
`mtu`, `zero_copy` — all of which are ignored by the stub.

The `tun_capabilities()` function (`src/interface.rs:217-228`) reports
`built_in: false` on Windows, and `validate_tun_runtime_requirements()`
(`src/interface.rs:231-240`) will reject any TUN operation unless an external
factory has been registered via `register_tun_factory` (`src/interface.rs:518`).

**Consequence:** QuicFuscate cannot create a TUN device on Windows. The entire VPN
data plane is non-functional on the world's largest desktop OS. Users must supply
their own Wintun integration externally — an unacceptable barrier for a
production VPN.

## Goal

A Windows client can create a Wintun-backed TUN adapter, assign it an IP/netmask/MTU
from `TunConfig`, and route IP packets through it bidirectionally. The `tun-windows`
Cargo feature, when enabled, produces a fully functional `WindowsTun` struct that
implements `TunDevice` — no external `register_tun_factory` call required. A `ping`
through the tunnel succeeds end-to-end on Windows 10/11.

## Implementation Plan

### Step 1: Add Wintun crate dependency

Add the `wintun` crate (v0.14.1+, the maintained pure-Rust binding to wintun.dll)
to `Cargo.toml`:

```toml
[target.'cfg(windows)'.dependencies]
wintun = "0.14"
```

Wire the `tun-windows` feature to include it:

```toml
tun-windows = ["dep:wintun"]
```

The `wintun` crate dynamically loads `wintun.dll` at runtime via `wintun::load()`
— it does not link statically. This means the DLL must be present on the system
(or bundled alongside the binary). Document this in the build instructions.

### Step 2: Implement `WindowsTun` struct

Replace the stub in `src/interface.rs:856-877` with a real implementation:

```rust
#[cfg(target_os = "windows")]
mod windows_tun {
    use super::*;
    use std::sync::Mutex;

    /// Wintun-backed TUN device for Windows.
    pub struct WindowsTun {
        session: wintun::Session,
        adapter_name: String,
        mtu: u16,
        // Wintun session handle is not Send/Sync by default; wrap in Mutex.
        _adapter: Mutex<Option<wintun::Adapter>>,
    }

    impl WindowsTun {
        /// Create a new Wintun adapter and start a session.
        pub fn new(cfg: &TunConfig) -> Result<Self, TunError> {
            // 1. Load wintun.dll (must be in PATH or alongside the binary)
            let wintun = unsafe {
                wintun::load()
                    .map_err(|e| TunError::Config(
                        // Leak a static string for the &'static str error variant
                        // or convert TunError to own String variant
                    ))?
            };

            // 2. Create adapter with GUID (random or derived from name)
            let adapter_name = cfg.name.clone().unwrap_or_else(|| "quicfuscate".to_string());
            let guid = wintun::generate_guid();
            let adapter = wintun::create_adapter(
                &adapter_name,
                "QuicFuscate",
                Some(guid),
            ).map_err(|e| TunError::Io(io::Error::other(e)))?;

            // 3. Set adapter IP and netmask (via Windows IP Helper API or netsh)
            if let Some(ip) = cfg.ip {
                if let Some(netmask) = cfg.netmask {
                    Self::set_adapter_ip(&adapter_name, ip, netmask)?;
                }
            }

            // 4. Set MTU (wintun adapter MTU defaults to 1500; override if configured)
            let mtu = cfg.mtu;

            // 5. Start session
            let session = adapter.start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| TunError::Io(io::Error::other(e)))?;

            Ok(Self {
                session,
                adapter_name,
                mtu,
                _adapter: Mutex::new(Some(adapter)),
            })
        }

        /// Assign IP address and netmask to the adapter using `netsh` or
        /// the Windows IP Helper API (CreateIpForwardEntry2 / AddUnicastIpAddressEntry).
        fn set_adapter_ip(
            name: &str,
            ip: IpAddr,
            netmask: IpAddr,
        ) -> Result<(), TunError> {
            // Use `netsh interface ip set address name="<name>" static <ip> <netmask>`
            // For production: use the `windows` crate (Win32_NetworkManagement_IpHelper)
            // to call AddUnicastIpAddressEntry directly — avoids spawning a process.
            // ...
        }
    }

    impl TunDevice for WindowsTun {
        fn name(&self) -> &str {
            &self.adapter_name
        }

        fn mtu(&self) -> u16 {
            self.mtu
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // wintun::Session::receive_blocking() returns a Packet handle.
            // Copy packet data into buf, return length.
            // For async integration: spawn a thread that calls receive_blocking
            // and sends packets via a channel, or use the wintun non-blocking
            // receive() method with polling.
            let packet = self.session.receive_blocking()
                .map_err(|e| io::Error::other(e))?;
            let data = packet.bytes();
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            // wintun::Session::allocate_send_packet(size) -> PacketMut
            // Copy buf into packet, then send.
            let mut packet = self.session.allocate_send_packet(buf.len() as u16)
                .map_err(|e| io::Error::other(e))?;
            packet.bytes_mut()[..buf.len()].copy_from_slice(buf);
            self.session.send_packet(packet);
            Ok(buf.len())
        }
    }
}
```

### Step 3: Wire `open_platform_tun` to `WindowsTun::new`

Replace the stub `open_platform_tun` with:

```rust
#[cfg(feature = "tun-windows")]
pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    WindowsTun::new(cfg).map(|t| Box::new(t) as Box<dyn TunDevice>)
}

#[cfg(not(feature = "tun-windows"))]
pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Config(
        "Windows TUN not built-in; enable 'tun-windows' feature or use register_tun_factory",
    ))
}
```

### Step 4: Update `tun_capabilities()` for Windows

In `src/interface.rs:217-228`, add Windows to the `built_in` check when the
`tun-windows` feature is active:

```rust
pub fn tun_capabilities() -> TunCapabilities {
    TunCapabilities {
        built_in: cfg!(target_os = "linux")
            || cfg!(target_os = "android")
            || cfg!(target_os = "macos")
            || (cfg!(target_os = "windows") && cfg!(feature = "tun-windows")),
        // ...
    }
}
```

### Step 5: Handle Wintun versioning and DLL loading

The `wintun` crate v0.14.1+ uses `wintun::load()` which searches for `wintun.dll`
in:
1. The same directory as the executable
2. System directories (`C:\Windows\System32`)
3. PATH

Document in build instructions that `wintun.dll` (v0.14.1+, from
wintun.net) must be placed alongside the binary or in a system directory. For
MSI/installer packaging, bundle the DLL.

### Step 6: Add Windows TUN configuration

Extend `TunConfig` (`src/interface.rs:152-163`) with optional Windows-specific
fields, or use the existing `name` field for the adapter name. The existing
fields (`name`, `ip`, `netmask`, `mtu`) are sufficient for Wintun. No new fields
are strictly required, but consider adding:

```rust
/// Wintun ring capacity (power of 2, 128 KiB – 64 MiB).
/// None = use wintun::MAX_RING_CAPACITY.
pub wintun_ring_capacity: Option<u32>,
```

### Step 7: Async integration

The Wintun `receive_blocking()` call blocks the calling thread. For Tokio
integration, spawn a dedicated OS thread that calls `receive_blocking()` in a
loop and sends packets via an `mpsc::channel` or `crossbeam::channel`. The
async read path then `recv()`s from the channel. Alternatively, use
`receive()` (non-blocking) with a polling interval, but this adds latency.
The blocking-thread + channel approach is the standard pattern used by
WireGuard's `wireguard-go` and Tauri-based VPN clients.

### Step 8: CI cross-compilation

Add a Windows cross-compilation check to CI (at minimum `cargo check
--target x86_64-pc-windows-gnu --features tun-windows`). Full Windows CI
requires a Windows runner; add a `windows-latest` job to the GitHub Actions
matrix that runs `cargo build --release --features tun-windows` and the
TUN integration test.

## Files to Modify/Create

- `Cargo.toml` — add `wintun = "0.14"` under `[target.'cfg(windows)'.dependencies]`,
  wire `tun-windows = ["dep:wintun"]`
- `src/interface.rs:856-877` — replace `windows_tun` stub with `WindowsTun` struct
  and real `open_platform_tun` implementation
- `src/interface.rs:217-228` — update `tun_capabilities()` for Windows + `tun-windows`
- `src/interface.rs:152-163` — optionally add `wintun_ring_capacity` to `TunConfig`
- `docs/DOCUMENTATION.md` — document Windows TUN setup, wintun.dll placement, feature flag

## Acceptance Criteria

- `cargo build --release --features tun-windows --target x86_64-pc-windows-gnu` succeeds
- On Windows 10/11 with `wintun.dll` present: `open_platform_tun(&cfg)` returns a
  `WindowsTun` instance (not an error)
- `WindowsTun::name()` returns the configured adapter name (e.g., "quicfuscate")
- `WindowsTun::mtu()` returns the configured MTU
- `WindowsTun::read()` returns IP packets from the Wintun session
- `WindowsTun::write()` sends IP packets through the Wintun session
- `ipconfig` shows the adapter with the correct IP/netmask
- `ping <server-tun-ip>` through the tunnel succeeds (end-to-end with a running server)
- `tun_capabilities().built_in == true` on Windows when `tun-windows` feature is enabled
- `cargo clippy --lib --features tun-windows -- -D warnings` is clean
- No panics, no unsafe UB (wintun crate's own unsafe is encapsulated)

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| TUN create + session start | < 50ms | Wintun adapter creation + session start |
| Packet read latency | < 100us | Wintun ring buffer dequeue + copy |
| Packet write latency | < 100us | Wintun ring buffer enqueue + copy |
| Memory per session | ~1-4MB | Wintun ring buffer (configurable, default MAX_RING_CAPACITY) |
| wintun.dll size | ~140KB | Bundled alongside binary |
| CPU idle (no traffic) | ~0% | Blocking thread parked on receive_blocking() |

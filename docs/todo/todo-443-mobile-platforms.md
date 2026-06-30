---
id: TODO-443
title: Mobile platform TUN (iOS NetworkExtension + Android VpnService) and mobile kill switch
severity: HIGH
phase: "I"
priority: P1
status: SCRAP
created: 2026-06-30
depends_on: []
---

# TODO-443: Mobile Platform TUN (iOS + Android) and Mobile Kill Switch

## Problem

### iOS TUN is a stub

`src/interface.rs:843-854` defines the `ios_tun` module with a stub that always
returns an error:

```rust
#[cfg(target_os = "ios")]
mod ios_tun {
    use super::*;
    /// iOS stub - requires external factory via NetworkExtension.
    pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Err(TunError::Config(
            "iOS requires NetworkExtension; use register_tun_factory to supply TunDevice",
        ))
    }
}
```

There is no `NEPacketTunnelProvider` integration, no `NEPacketTunnelFlow` packet
I/O, no Swift/Objective-C bridge, and no `tun-ios` feature implementation. The
`tun-ios` feature in `Cargo.toml:119` is empty (`tun-ios = []`). iOS users cannot
use QuicFuscate as a VPN at all.

### Android TUN is incomplete

`tun_capabilities()` (`src/interface.rs:217-228`) reports `built_in: true` for
Android, and Android falls through to the `linux_tun` module which uses
`/dev/net/tun`. However, on Android, `/dev/net/tun` requires root and is not
accessible to normal apps. The correct Android TUN API is `VpnService.Builder`
which creates a virtual network interface via the Android VPN framework. There is:

- No `VpnService` integration
- No JNI bindings to establish the VPN
- No `VpnService.protect()` call to exempt the QUIC socket from the VPN tunnel
  (without this, the QUIC connection loops back through the VPN and deadlocks)
- No `ParcelFileDescriptor` → `TunDevice` adapter

### No mobile kill switch

The kill switch (`src/implementations/client/killswitch.rs`) has three backends:
- `LinuxKillSwitch` (iptables, lines 125-240) — not available on Android (no
  iptables access from app context, no root)
- `MacOSKillSwitch` (pf, lines 246-399) — not available on iOS
- `WindowsKillSwitch` (netsh, lines 405-555) — Windows only

There is no `AndroidKillSwitch` or `IOSKillSwitch`. On mobile, the kill switch
must be implemented via the platform VPN framework itself: `VpnService` on
Android (route all traffic through the VPN, drop packets when disconnected) and
`NEPacketTunnelProvider` on iOS (the tunnel provider IS the kill switch — when
it stops, all traffic stops).

### No mobile Cargo targets

There are no `aarch64-apple-ios` or `aarch64-linux-android` targets in the CI
matrix or build configuration. Cross-compilation toolchains are not configured.

## Goal

1. **iOS:** A Swift `NEPacketTunnelProvider` extension that bridges packet I/O to
   QuicFuscate's Rust core via `register_tun_factory`. The iOS app can connect to
   a QuicFuscate server and route traffic through the tunnel.

2. **Android:** A `VpnService` implementation with JNI bindings that creates a
   virtual network interface, protects the QUIC socket, and bridges packet I/O to
   QuicFuscate's Rust core via `register_tun_factory`. The Android app can connect
   and route traffic.

3. **Mobile kill switch:** Platform-native traffic blocking via the VPN framework
   (no iptables/pf needed). When VPN disconnects, all traffic stops.

4. **Build targets:** `aarch64-apple-ios` and `aarch64-linux-android` cross-compile
   cleanly.

## Implementation Plan

### Step 1: iOS — NEPacketTunnelProvider (Swift)

Create an iOS Network Extension target (Xcode project) that implements
`NEPacketTunnelProvider`:

```swift
// ios/PacketTunnelProvider.swift
import NetworkExtension
import QuicFuscateCore  // Rust static library (cargo lipo / uniffi)

class PacketTunnelProvider: NEPacketTunnelProvider {
    var packetFlow: NEPacketTunnelFlow?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.0.1.2"],
            subnetMasks: ["255.255.255.0"])
        settings.ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.mtu = 1500

        self.setTunnelNetworkSettings(settings) { error in
            guard error == nil else { completionHandler(error); return }
            self.packetFlow = self.packetFlow

            // Register TUN factory with Rust core
            QuicFuscateCore.registerTunFactory(self)

            // Start QuicFuscate client
            QuicFuscateCore.startClient(config: ...)

            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        QuicFuscateCore.stopClient()
        completionHandler()
    }

    // Called by Rust core to read packets
    func readPackets() -> [Data] {
        // NEPacketTunnelFlow.readPackets() returns ([Data], [NSNumber])
        // This is async — use a callback pattern
    }

    // Called by Rust core to write packets
    func writePackets(_ packets: [Data]) {
        self.packetFlow?.writePackets(packets, withProtocols: [])
    }
}
```

### Step 2: iOS — Rust bridge via register_tun_factory

Create an `IosTun` struct in Rust that implements `TunDevice` by bridging to the
Swift `NEPacketTunnelFlow`:

```rust
// src/interface.rs — ios_tun module (replace stub)
#[cfg(target_os = "ios")]
mod ios_tun {
    use super::*;
    use std::sync::mpsc::{channel, Receiver, Sender};

    /// TUN device backed by iOS NEPacketTunnelFlow.
    /// Packets are exchanged via channels bridged to Swift.
    pub struct IosTun {
        name: String,
        mtu: u16,
        // Packets read from NEPacketTunnelFlow (incoming from OS)
        rx_recv: Receiver<Vec<u8>>,
        // Packets to write to NEPacketTunnelFlow (outgoing to OS)
        tx_send: Sender<Vec<u8>>,
    }

    impl IosTun {
        pub fn new(
            name: String,
            mtu: u16,
            rx_recv: Receiver<Vec<u8>>,
            tx_send: Sender<Vec<u8>>,
        ) -> Self {
            Self { name, mtu, rx_recv, tx_send }
        }
    }

    impl TunDevice for IosTun {
        fn name(&self) -> &str { &self.name }
        fn mtu(&self) -> u16 { self.mtu }
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            match self.rx_recv.recv() {
                Ok(pkt) => {
                    let len = pkt.len().min(buf.len());
                    buf[..len].copy_from_slice(&pkt[..len]);
                    Ok(len)
                }
                Err(_) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun closed")),
            }
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            self.tx_send.send(buf.to_vec())
                .map(|()| buf.len())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tun closed"))
        }
    }
}
```

The Swift side calls `register_tun_factory` with a closure that constructs
`IosTun` from the channel endpoints. The `open_platform_tun` stub remains as a
fallback error (factory must be registered from Swift before the Rust client
starts).

### Step 3: Android — VpnService with JNI bindings

Create a Kotlin/Java `VpnService` that:

1. Calls `VpnService.Builder()` to create a virtual interface
2. Sets addresses, routes, MTU, DNS
3. Calls `establish()` to get a `ParcelFileDescriptor`
4. Passes the file descriptor to Rust via JNI
5. Calls `protect(socket)` on the QUIC UDP socket to prevent loopback

```kotlin
// android/app/src/main/java/com/quicfuscate/QuicFuscateVpnService.kt
class QuicFuscateVpnService : VpnService() {
    private var pfd: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder()
        builder.setSession("QuicFuscate")
        builder.addAddress("10.0.1.2", 24)
        builder.addRoute("0.0.0.0", 0)  // Route all traffic
        builder.setMtu(1500)
        builder.addDnsServer("1.1.1.1")

        pfd = builder.establish()

        // Pass fd to Rust core via JNI
        val fd = pfd!!.fileDescriptor
        nativeStartClient(fd.detachFd(), configJson)

        return START_STICKY
    }

    override fun onDestroy() {
        nativeStopClient()
        pfd?.close()
        super.onDestroy()
    }

    override fun protect(socket: Int): Boolean {
        // Called by Rust core to protect the QUIC UDP socket
        return super.protect(socket)
    }

    private external fun nativeStartClient(tunFd: Int, config: String)
    private external fun nativeStopClient()
}
```

### Step 4: Android — Rust TunDevice from ParcelFileDescriptor

On Android, `VpnService.establish()` returns a `ParcelFileDescriptor` whose
backing file descriptor can be used directly with `read()`/`write()` syscalls.
Create an `AndroidTun` struct:

```rust
// src/interface.rs — android_tun module
#[cfg(target_os = "android")]
mod android_tun {
    use super::*;
    use std::os::fd::{FromRawFd, RawFd};
    use std::fs::File;

    /// TUN device backed by Android VpnService ParcelFileDescriptor.
    pub struct AndroidTun {
        fd: File,
        name: String,
        mtu: u16,
    }

    impl AndroidTun {
        /// Create from a raw file descriptor obtained via JNI from VpnService.
        pub fn from_raw_fd(fd: RawFd, name: String, mtu: u16) -> Self {
            Self {
                fd: unsafe { File::from_raw_fd(fd) },
                name,
                mtu,
            }
        }
    }

    impl TunDevice for AndroidTun {
        fn name(&self) -> &str { &self.name }
        fn mtu(&self) -> u16 { self.mtu }
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            // Direct read() syscall on the ParcelFileDescriptor fd
            let n = unsafe {
                libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len())
            };
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            let n = unsafe {
                libc::write(self.fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len())
            };
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
        }
        #[cfg(unix)]
        fn raw_fd(&self) -> Option<RawFd> {
            use std::os::fd::AsRawFd;
            Some(self.fd.as_raw_fd())
        }
    }
}
```

Wire `open_platform_tun` for Android to check for a registered factory first
(the VpnService fd must be passed via JNI before the Rust client starts), then
fall back to `AndroidTun::from_raw_fd` if a factory provides the fd.

### Step 5: Android — socket protection

The QUIC UDP socket must be protected from the VPN tunnel to prevent loopback.
Add a JNI callback from Rust to Kotlin:

```rust
// When creating the QUIC UDP socket, call back to Java to protect it:
// JNIEnv::call_method(vpnService, "protect", "(I)Z", socket_fd)
```

This requires passing the `VpnService` reference to Rust via JNI and storing it
for the socket creation path. The `protect()` call exempts the socket from the
VPN routing rules.

### Step 6: Mobile kill switch

**Android:** The `VpnService` itself IS the kill switch. When the VPN is
connected, `addRoute("0.0.0.0", 0)` routes ALL traffic through the VPN. When
disconnected (service stopped), the routes are removed and traffic flows
normally. For a "block all" kill switch mode: keep the `VpnService` running but
drop all packets in the read/write path (don't forward to the QUIC connection).

Add `AndroidKillSwitch` to `killswitch.rs`:

```rust
#[cfg(target_os = "android")]
struct AndroidKillSwitch {
    blocking: AtomicBool,
}

// When blocking=true, the TUN read/write path drops all packets.
// No iptables needed — the VpnService framework handles routing.
```

**iOS:** The `NEPacketTunnelProvider` IS the kill switch. When the tunnel is
connected, `includedRoutes = [NEIPv4Route.default()]` routes all traffic through
the tunnel. When the tunnel disconnects, all traffic stops (the network
extension's routes are removed). For "block all" mode: keep the tunnel up but
drop packets in the packet flow path.

Add `IOSKillSwitch` to `killswitch.rs`:

```rust
#[cfg(target_os = "ios")]
struct IOSKillSwitch {
    blocking: AtomicBool,
}
// Same pattern as Android — drop packets in the IosTun read/write path.
```

### Step 7: Cargo targets and cross-compilation

Add `.cargo/config.toml` entries for cross-compilation:

```toml
[target.aarch64-apple-ios]
linker = "clang"
# iOS linking requires Xcode toolchain

[target.aarch64-linux-android]
linker = "aarch64-linux-android21-clang"
# Requires Android NDK
```

Add CI jobs:
- `cargo check --target aarch64-apple-ios` (macOS runner with Xcode)
- `cargo check --target aarch64-linux-android` (Linux runner with NDK)

### Step 8: Wire tun-ios feature

Update `Cargo.toml:119`:

```toml
tun-ios = []  # No Rust crate dep — bridging is via channels from Swift
```

The `tun-ios` feature gates the `IosTun` struct and the `ios_tun` module. The
actual packet I/O is bridged from Swift via `register_tun_factory`.

## Files to Modify/Create

- `src/interface.rs:843-854` — replace iOS stub with `IosTun` struct + channel bridge
- `src/interface.rs` — add `android_tun` module with `AndroidTun` struct
- `src/interface.rs:217-228` — update `tun_capabilities()` for Android (VpnService) and iOS (factory)
- `src/implementations/client/killswitch.rs` — add `AndroidKillSwitch` and `IOSKillSwitch`
- `Cargo.toml:118-119` — wire `tun-ios` and add Android-specific deps if needed
- `.cargo/config.toml` — add iOS and Android cross-compilation targets
- `ios/PacketTunnelProvider.swift` (new) — Swift NEPacketTunnelProvider implementation
- `ios/QuicFuscate-Bridging-Header.h` (new) — Objective-C bridging header for Rust FFI
- `android/app/src/main/java/com/quicfuscate/QuicFuscateVpnService.kt` (new) — VpnService
- `android/app/src/main/jni/` (new) — JNI bridge layer
- `docs/DOCUMENTATION.md` — document mobile platform setup, build, and deployment

## Acceptance Criteria

- `cargo check --target aarch64-apple-ios --features tun-ios` succeeds
- `cargo check --target aarch64-linux-android` succeeds
- iOS: `NEPacketTunnelProvider` starts, calls `register_tun_factory`, Rust core
  receives packets from `NEPacketTunnelFlow.readPackets()`
- iOS: `ping 10.0.1.1` through the tunnel succeeds (end-to-end with server)
- Android: `VpnService.establish()` returns a `ParcelFileDescriptor`, fd passed
  to Rust via JNI, `AndroidTun::from_raw_fd` creates a working TUN device
- Android: `VpnService.protect(socketFd)` is called on the QUIC UDP socket — no
  loopback deadlock
- Android: `ping 10.0.1.1` through the tunnel succeeds (end-to-end with server)
- Mobile kill switch: when VPN disconnects, no traffic leaks (all routes removed
  by the platform VPN framework)
- Mobile kill switch: "block all" mode drops packets in TUN read/write path
- `cargo clippy --lib --target aarch64-linux-android -- -D warnings` is clean
- No panics on either platform during connect/disconnect cycle

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| iOS TUN create (NEPacketTunnelProvider start) | < 500ms | Network extension startup + setTunnelNetworkSettings |
| Android TUN create (VpnService.establish) | < 200ms | Builder + establish + fd handoff |
| Packet read latency (iOS) | < 1ms | Channel hop from Swift readPackets callback |
| Packet read latency (Android) | < 100us | Direct read() syscall on ParcelFileDescriptor |
| Packet write latency (iOS) | < 1ms | Channel hop to Swift writePackets |
| Packet write latency (Android) | < 100us | Direct write() syscall on ParcelFileDescriptor |
| Memory per TUN (iOS) | ~256KB | Channel buffers + IosTun struct |
| Memory per TUN (Android) | ~64KB | File descriptor + AndroidTun struct |
| CPU idle (no traffic) | ~0% | Both platforms use async I/O, no polling |
| iOS app extension binary | ~5-10MB | Rust static lib + Swift wrapper |
| Android native lib (libquicfuscate.so) | ~5-10MB | Rust shared library for aarch64 |

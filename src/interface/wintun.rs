//! Windows TUN device backed by the Wintun driver (`wintun.dll`).
//!
//! Wintun is a fast, modern Layer 3 TUN driver for Windows, distributed as a
//! standalone, unsigned-from-our-side `wintun.dll` (see <https://wintun.net/>).
//! Because no FFI bindings crate is published and we cannot link against the
//! DLL at compile time, this module resolves the Wintun entry points at
//! runtime through `LoadLibraryA` / `GetProcAddress`. The DLL must be present
//! alongside the executable (or on the system search path).
//!
//! The adapter IP address is assigned through `netsh` rather than the IP
//! Helper `CreateUnicastIpAddressEntry` FFI. This keeps the windows-sys feature
//! surface minimal (no `IpHelper`/`Ndis`/`WinSock` cross-module gating) and
//! avoids fragile struct-field wiring that cannot be compile-verified on
//! non-Windows hosts, while remaining a production-grade approach used by
//! several Windows VPN stacks.
//!
//! On non-Windows targets the module compiles to a thin stub whose `new`
//! returns `TunError::Unsupported`, so the public API and its unit tests stay
//! portable.

use crate::interface::{TunConfig, TunDevice, TunError};
use std::io;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::windows::process::CommandExt;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::core::PCSTR;
    use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    /// Hides the console window for spawned `netsh` processes.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Wintun ring-capacity bounds (from wintun.h).
    const WINTUN_MIN_RING_CAPACITY: u32 = 0x0002_0000; // 128 KiB
    const WINTUN_MAX_RING_CAPACITY: u32 = 0x0400_0000; // 64 MiB

    // Default adapter name / tunnel type when the config does not specify one.
    const DEFAULT_ADAPTER_NAME: &str = "QuicFuscate";
    const WINTUN_TUNNEL_TYPE: &str = "Wintun";

    // Function-pointer typedefs matching the signatures in wintun.h.
    type WintunCreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
    type WintunCloseAdapterFn = unsafe extern "system" fn(*mut c_void);
    type WintunStartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type WintunEndSessionFn = unsafe extern "system" fn(*mut c_void);
    type WintunReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut c_void;
    type WintunReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const c_void);
    type WintunAllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type WintunSendPacketFn = unsafe extern "system" fn(*mut c_void, *const c_void);

    /// Dynamically loaded Wintun library bundling a module handle and all
    /// resolved entry points. Dropping is handled by the owning `WintunDevice`.
    struct WintunLib {
        handle: HMODULE,
        create_adapter: WintunCreateAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        receive_packet: WintunReceivePacketFn,
        release_receive_packet: WintunReleaseReceivePacketFn,
        allocate_send_packet: WintunAllocateSendPacketFn,
        send_packet: WintunSendPacketFn,
    }

    impl WintunLib {
        /// Load `wintun.dll` and resolve every entry point required for I/O.
        ///
        /// Returns a configuration error (rather than a raw I/O error) when the
        /// DLL cannot be found, so callers can fall back to a registered
        /// factory or surface a clear "Wintun not installed" diagnostic.
        fn load() -> Result<Self, TunError> {
            let handle = unsafe { LoadLibraryA(b"wintun.dll\0".as_ptr() as PCSTR) };
            if handle.is_null() {
                return Err(TunError::Config(
                    "wintun.dll not found; install Wintun beside the executable",
                ));
            }

            // Resolve each proc address. transmute the generic FARPROC
            // (Option<unsafe fn() -> isize>) into the specific nullable fn
            // pointer type. Both are 8-byte nullable function pointers, so
            // this transmute is sound and is the idiomatic windows-sys pattern.
            macro_rules! resolve {
                ($name:literal as $ty:ty) => {{
                    let proc =
                        unsafe { GetProcAddress(handle, concat!($name, "\0").as_ptr() as PCSTR) };
                    let typed: Option<$ty> = unsafe { std::mem::transmute(proc) };
                    match typed {
                        Some(f) => f,
                        None => {
                            unsafe { FreeLibrary(handle) };
                            return Err(TunError::Config(
                                "wintun.dll missing required export; incompatible version",
                            ));
                        }
                    }
                }};
            }

            let create_adapter = resolve!("WintunCreateAdapter" as WintunCreateAdapterFn);
            let close_adapter = resolve!("WintunCloseAdapter" as WintunCloseAdapterFn);
            let start_session = resolve!("WintunStartSession" as WintunStartSessionFn);
            let end_session = resolve!("WintunEndSession" as WintunEndSessionFn);
            let receive_packet = resolve!("WintunReceivePacket" as WintunReceivePacketFn);
            let release_receive_packet =
                resolve!("WintunReleaseReceivePacket" as WintunReleaseReceivePacketFn);
            let allocate_send_packet =
                resolve!("WintunAllocateSendPacket" as WintunAllocateSendPacketFn);
            let send_packet = resolve!("WintunSendPacket" as WintunSendPacketFn);

            Ok(Self {
                handle,
                create_adapter,
                close_adapter,
                start_session,
                end_session,
                receive_packet,
                release_receive_packet,
                allocate_send_packet,
                send_packet,
            })
        }
    }

    /// Encode a Rust string as a NUL-terminated UTF-16 buffer for LPCWSTR.
    fn wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Choose a power-of-two ring capacity within Wintun bounds, derived from
    /// the requested MTU so larger frames get a proportionally larger ring.
    fn ring_capacity(mtu: u16) -> u32 {
        let raw = (mtu as u32).saturating_mul(1024);
        let pow2 = raw.next_power_of_two();
        pow2.clamp(WINTUN_MIN_RING_CAPACITY, WINTUN_MAX_RING_CAPACITY)
    }

    /// Assign an IPv4 address (and netmask) to the adapter via `netsh`.
    fn assign_ipv4(name: &str, ip: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        let status = std::process::Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &format!("name={}", name),
                "source=static",
                &format!("addr={}", ip),
                &format!("mask={}", mask),
            ])
            .status()
            .map_err(|e| io::Error::other(format!("netsh spawn failed: {e}")))?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "netsh set address failed (exit {:?}) for adapter '{}'",
                status.code(),
                name
            )));
        }
        Ok(())
    }

    /// Assign an IPv6 address (with prefix length) to the adapter via `netsh`.
    fn assign_ipv6(name: &str, ip: Ipv6Addr, prefix: u8) -> io::Result<()> {
        let status = std::process::Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={}", name),
                &format!("address={}/{}", ip, prefix),
            ])
            .status()
            .map_err(|e| io::Error::other(format!("netsh spawn failed: {e}")))?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "netsh set ipv6 address failed (exit {:?}) for adapter '{}'",
                status.code(),
                name
            )));
        }
        Ok(())
    }

    /// Windows TUN device backed by a dynamically loaded Wintun session.
    #[derive(Debug)]
    pub struct WintunDevice {
        lib: WintunLib,
        adapter: *mut c_void,
        session: *mut c_void,
        name: Arc<str>,
        mtu: u16,
        closed: AtomicBool,
    }

    // Wintun session operations are thread-safe per the upstream docs, and the
    // handles are opaque pointers only ever touched through the resolved entry
    // points. The device is shared across the reader/writer threads of the
    // client backend, so manual Send + Sync is required and sound.
    unsafe impl Send for WintunDevice {}
    unsafe impl Sync for WintunDevice {}

    impl WintunDevice {
        /// Create a Wintun adapter, start a session, and assign the configured
        /// IP address.
        pub fn new(config: &TunConfig) -> Result<Self, TunError> {
            if config.mtu < 576 {
                return Err(TunError::Config("Wintun MTU must be >= 576"));
            }

            let lib = WintunLib::load()?;

            let name_str =
                config.name.as_deref().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_ADAPTER_NAME);
            let name_wide = wide_z(name_str);
            let tunnel_wide = wide_z(WINTUN_TUNNEL_TYPE);

            let adapter = unsafe {
                (lib.create_adapter)(name_wide.as_ptr(), tunnel_wide.as_ptr(), ptr::null())
            };
            if adapter.is_null() {
                let code = unsafe { GetLastError() };
                unsafe { FreeLibrary(lib.handle) };
                return Err(TunError::Io(io::Error::other(format!(
                    "WintunCreateAdapter failed (GetLastError={code})"
                ))));
            }

            let session = unsafe { (lib.start_session)(adapter, ring_capacity(config.mtu)) };
            if session.is_null() {
                let code = unsafe { GetLastError() };
                unsafe {
                    (lib.close_adapter)(adapter);
                    FreeLibrary(lib.handle);
                }
                return Err(TunError::Io(io::Error::other(format!(
                    "WintunStartSession failed (GetLastError={code})"
                ))));
            }

            let mut device = Self {
                lib,
                adapter,
                session,
                name: Arc::from(name_str),
                mtu: config.mtu,
                closed: AtomicBool::new(false),
            };

            // Assign the unicast IP address. A failure here tears down the
            // whole device so we never hand back an unconfigured adapter.
            if let Err(e) = device.assign_address(config) {
                device.close_inner();
                return Err(TunError::Io(e));
            }

            Ok(device)
        }

        /// Assign IPv4 and/or IPv6 addresses from the config via `netsh`.
        fn assign_address(&self, config: &TunConfig) -> io::Result<()> {
            if let Some(IpAddr::V4(ip)) = config.ip {
                let mask = match config.netmask {
                    Some(IpAddr::V4(m)) => m,
                    _ => Ipv4Addr::new(255, 255, 255, 0),
                };
                assign_ipv4(&self.name, ip, mask)?;
            }
            if let Some(ip6) = config.ip6 {
                let prefix = config.prefix6.unwrap_or(64);
                assign_ipv6(&self.name, ip6, prefix)?;
            }
            Ok(())
        }

        /// Tear down the session, adapter, and library. Idempotent.
        fn close_inner(&self) {
            if self.closed.swap(true, Ordering::AcqRel) {
                return;
            }
            unsafe {
                (self.lib.end_session)(self.session);
                (self.lib.close_adapter)(self.adapter);
                FreeLibrary(self.lib.handle);
            }
        }

        /// Close the adapter and unload `wintun.dll`. Safe to call multiple
        /// times; subsequent calls are no-ops.
        pub fn close(&self) {
            self.close_inner();
        }
    }

    impl TunDevice for WintunDevice {
        fn name(&self) -> &str {
            self.name.as_ref()
        }

        fn mtu(&self) -> u16 {
            self.mtu
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // Wintun exposes a non-blocking ring; when no packet is available
            // WintunReceivePacket returns NULL with ERROR_NO_MORE_ITEMS. We
            // yield-and-retry with a micro-sleep to approximate blocking reads
            // without burning a core. Wiring WintunGetReadWaitEvent together
            // with WaitForSingleObject (Win32_System_Threading) is the
            // canonical blocking path and a straightforward future enhancement.
            loop {
                let mut size: u32 = 0;
                let pkt = unsafe { (self.lib.receive_packet)(self.session, &mut size) };
                if pkt.is_null() {
                    std::thread::yield_now();
                    std::thread::sleep(std::time::Duration::from_micros(100));
                    continue;
                }
                let n = (size as usize).min(buf.len());
                unsafe { ptr::copy_nonoverlapping(pkt as *const u8, buf.as_mut_ptr(), n) };
                unsafe { (self.lib.release_receive_packet)(self.session, pkt) };
                return Ok(n);
            }
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            let dst = unsafe { (self.lib.allocate_send_packet)(self.session, buf.len() as u32) };
            if dst.is_null() {
                // Ring full / adapter down.
                return Err(io::Error::other(
                    "WintunAllocateSendPacket returned null (ring full or adapter down)",
                ));
            }
            unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len()) };
            unsafe { (self.lib.send_packet)(self.session, dst) };
            Ok(buf.len())
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            self.close_inner();
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
mod stub {
    use super::*;

    /// Placeholder TUN device for non-Windows targets. `new` always returns
    /// `TunError::Unsupported`; it exists so the public API and unit tests
    /// compile and run on every platform.
    #[derive(Debug)]
    pub struct WintunDevice {
        name: Arc<str>,
        mtu: u16,
    }

    impl WintunDevice {
        /// Wintun is only available on Windows. MTU validation still runs so
        /// config errors are reported consistently across platforms.
        pub fn new(_config: &TunConfig) -> Result<Self, TunError> {
            if _config.mtu < 576 {
                return Err(TunError::Config("Wintun MTU must be >= 576"));
            }
            Err(TunError::Unsupported)
        }

        /// No-op on non-Windows targets.
        pub fn close(&self) {}
    }

    impl TunDevice for WintunDevice {
        fn name(&self) -> &str {
            self.name.as_ref()
        }

        fn mtu(&self) -> u16 {
            self.mtu
        }

        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Wintun only available on Windows"))
        }

        fn write(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Wintun only available on Windows"))
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::WintunDevice;
#[cfg(not(target_os = "windows"))]
pub use stub::WintunDevice;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::TunConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn non_windows_returns_unsupported() {
        // On Windows this still attempts a real adapter creation (which needs
        // wintun.dll + privileges and is expected to fail gracefully); on every
        // other platform it must return TunError::Unsupported.
        let cfg = TunConfig {
            name: Some("quicfuscate-test".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            mtu: 1500,
            ..TunConfig::default()
        };
        let res = WintunDevice::new(&cfg);
        if !cfg!(target_os = "windows") {
            assert!(
                matches!(res, Err(TunError::Unsupported)),
                "expected Unsupported on non-Windows, got {:?}",
                res
            );
        } else {
            // On Windows without wintun.dll we expect a graceful Config error,
            // never a panic.
            assert!(res.is_err(), "WintunDevice::new should fail without wintun.dll");
        }
    }

    #[test]
    fn config_validation_rejects_low_mtu() {
        // MTU below the IPv4 minimum must be rejected before any DLL load is
        // attempted, so this is portable across platforms.
        let cfg = TunConfig {
            name: Some("quicfuscate-test".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            mtu: 500,
            ..TunConfig::default()
        };
        let res = WintunDevice::new(&cfg);
        assert!(
            matches!(res, Err(TunError::Config(_))),
            "expected Config error for low MTU, got {:?}",
            res
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dynamic_loading_fails_gracefully_without_dll() {
        // When wintun.dll is absent, the loader must surface a Config error
        // (not an abort / not a raw OS error), so callers can fall back.
        let cfg = TunConfig {
            name: Some("quicfuscate-nodll".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            mtu: 1500,
            ..TunConfig::default()
        };
        // Skip if a real wintun.dll happens to be installed in the test env.
        let has_dll = unsafe {
            use windows_sys::core::PCSTR;
            use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
            let h = LoadLibraryA(b"wintun.dll\0".as_ptr() as PCSTR);
            if !h.is_null() {
                windows_sys::Win32::Foundation::FreeLibrary(h);
                true
            } else {
                false
            }
        };
        if has_dll {
            return;
        }
        let res = WintunDevice::new(&cfg);
        assert!(
            matches!(res, Err(TunError::Config(_))),
            "expected Config error when wintun.dll missing, got {:?}",
            res
        );
    }

    #[test]
    fn ipv6_config_is_accepted_by_validation() {
        // A dual-stack config with a valid MTU must pass validation (the
        // unsupported/platform error, if any, comes from the backend, not from
        // MTU validation).
        let cfg = TunConfig {
            name: Some("quicfuscate-dual".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            ip6: Some(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1)),
            prefix6: Some(64),
            mtu: 1500,
            ..TunConfig::default()
        };
        let res = WintunDevice::new(&cfg);
        // Must not be a Config("MTU") rejection.
        if let Err(TunError::Config(msg)) = &res {
            assert!(
                !msg.contains("MTU"),
                "dual-stack config should not be rejected on MTU grounds: {}",
                msg
            );
        }
    }
}

//! Windows TUN device backed by the Wintun driver (`wintun.dll`).
//!
//! Wintun is a fast, modern Layer 3 TUN driver for Windows, distributed as an
//! upstream `wintun.dll` artifact (see <https://wintun.net/>).
//! Because no FFI bindings crate is published and we cannot link against the
//! DLL at compile time, this module resolves the Wintun entry points at
//! runtime through `LoadLibraryExW` / `GetProcAddress`. The DLL must be present
//! alongside the executable or in the protected System32 search directory.
//!
//! The adapter IP address is assigned through `netsh` rather than the IP
//! Helper `CreateUnicastIpAddressEntry` FFI. NDIS is used only for the stable
//! adapter LUID type; address and MTU configuration stay on the well-defined
//! `netsh` command surface until the native IP Helper path is verified on a
//! Windows host.
//!
//! On non-Windows targets the module compiles to a thin stub whose `new`
//! returns `TunError::Unsupported`, so the public API and its unit tests stay
//! portable.

use crate::interface::{TunConfig, TunDevice, TunError};
use std::io;
use std::sync::Arc;

fn validate_config(config: &TunConfig) -> Result<(), TunError> {
    if config.mtu < 576 {
        return Err(TunError::Config("Wintun MTU must be >= 576"));
    }
    if config.ip6.is_some() && config.mtu < 1280 {
        return Err(TunError::Config("Wintun IPv6 MTU must be >= 1280"));
    }
    if matches!(config.ip, Some(std::net::IpAddr::V6(_))) {
        return Err(TunError::Config("Wintun IPv4 address field must contain an IPv4 address"));
    }
    if matches!(config.netmask, Some(std::net::IpAddr::V6(_))) {
        return Err(TunError::Config("Wintun IPv4 netmask field must contain an IPv4 netmask"));
    }
    if config.prefix6.is_some() && config.ip6.is_none() {
        return Err(TunError::Config("Wintun IPv6 prefix requires an IPv6 address"));
    }
    if config.prefix6.is_some_and(|prefix| prefix > 128) {
        return Err(TunError::Config("Wintun IPv6 prefix must be between 0 and 128"));
    }
    if config.name.as_deref().is_some_and(|name| name.contains('\0')) {
        return Err(TunError::Config("Wintun adapter name must not contain NUL"));
    }
    Ok(())
}

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
    use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
    use std::time::Duration;

    use parking_lot::{Mutex, RwLock};
    use windows_sys::core::{PCSTR, PCWSTR};
    use windows_sys::Win32::Foundation::{
        CloseHandle, FreeLibrary, GetLastError, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF,
        ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, HANDLE, HMODULE, WAIT_FAILED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
        LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
    };

    /// Hides the console window for spawned `netsh` processes.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Wintun ring-capacity bounds (from wintun.h).
    const WINTUN_MIN_RING_CAPACITY: u32 = 0x0002_0000; // 128 KiB
    const WINTUN_MAX_RING_CAPACITY: u32 = 0x0400_0000; // 64 MiB
    const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xffff;
    const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

    // Default adapter name / tunnel type when the config does not specify one.
    const DEFAULT_ADAPTER_NAME: &str = "QuicFuscate";
    const WINTUN_TUNNEL_TYPE: &str = "Wintun";

    // Function-pointer typedefs matching the signatures in wintun.h.
    type WintunCreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
    type WintunCloseAdapterFn = unsafe extern "system" fn(*mut c_void);
    type WintunGetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
    type WintunStartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type WintunEndSessionFn = unsafe extern "system" fn(*mut c_void);
    type WintunGetReadWaitEventFn = unsafe extern "system" fn(*mut c_void) -> HANDLE;
    type WintunReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut c_void;
    type WintunReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const c_void);
    type WintunAllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type WintunSendPacketFn = unsafe extern "system" fn(*mut c_void, *const c_void);

    /// Dynamically loaded Wintun library bundling a module handle and all
    /// resolved entry points. Dropping is handled by the owning `WintunDevice`.
    #[derive(Debug)]
    struct WintunLib {
        handle: HMODULE,
        create_adapter: WintunCreateAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        get_adapter_luid: WintunGetAdapterLuidFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        get_read_wait_event: WintunGetReadWaitEventFn,
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
            Self::load_named("wintun.dll")
        }

        fn load_named(name: &str) -> Result<Self, TunError> {
            let name_wide = wide_z(name);
            let handle = unsafe {
                LoadLibraryExW(
                    name_wide.as_ptr() as PCWSTR,
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
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
            let get_adapter_luid = resolve!("WintunGetAdapterLUID" as WintunGetAdapterLuidFn);
            let start_session = resolve!("WintunStartSession" as WintunStartSessionFn);
            let end_session = resolve!("WintunEndSession" as WintunEndSessionFn);
            let get_read_wait_event =
                resolve!("WintunGetReadWaitEvent" as WintunGetReadWaitEventFn);
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
                get_adapter_luid,
                start_session,
                end_session,
                get_read_wait_event,
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

    fn set_interface_mtu(name: &str, mtu: u16, ipv6_enabled: bool) -> io::Result<()> {
        let families = if ipv6_enabled { &["ipv4", "ipv6"][..] } else { &["ipv4"][..] };
        for family in families {
            let status = std::process::Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "interface",
                    family,
                    "set",
                    "subinterface",
                    name,
                    &format!("mtu={mtu}"),
                    "store=active",
                ])
                .status()
                .map_err(|error| io::Error::other(format!("netsh spawn failed: {error}")))?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "netsh {family} MTU update failed for adapter '{name}' with exit {:?}",
                    status.code()
                )));
            }
        }
        Ok(())
    }

    /// Windows TUN device backed by a dynamically loaded Wintun session.
    #[derive(Debug)]
    pub struct WintunDevice {
        lib: WintunLib,
        adapter: *mut c_void,
        session: *mut c_void,
        read_wait_event: HANDLE,
        shutdown_event: HANDLE,
        adapter_luid: u64,
        ipv6_enabled: bool,
        name: Arc<str>,
        mtu: AtomicU16,
        operations: RwLock<()>,
        close_guard: Mutex<()>,
        closing: AtomicBool,
        closed: AtomicBool,
    }

    // Wintun packet operations are thread-safe per the upstream contract.
    // `operations` keeps the opaque pointers and resolved DLL entry points
    // alive until every in-flight operation drains, while `shutdown_event`
    // wakes a reader before teardown acquires the exclusive operation lock.
    unsafe impl Send for WintunDevice {}
    unsafe impl Sync for WintunDevice {}

    impl WintunDevice {
        /// Create a Wintun adapter, start a session, and assign the configured
        /// IP address.
        pub fn new(config: &TunConfig) -> Result<Self, TunError> {
            validate_config(config)?;

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

            let read_wait_event = unsafe { (lib.get_read_wait_event)(session) };
            if read_wait_event.is_null() {
                let code = unsafe { GetLastError() };
                unsafe {
                    (lib.end_session)(session);
                    (lib.close_adapter)(adapter);
                    FreeLibrary(lib.handle);
                }
                return Err(TunError::Io(io::Error::other(format!(
                    "WintunGetReadWaitEvent failed (GetLastError={code})"
                ))));
            }

            let shutdown_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null() as PCWSTR) };
            if shutdown_event.is_null() {
                let code = unsafe { GetLastError() };
                unsafe {
                    (lib.end_session)(session);
                    (lib.close_adapter)(adapter);
                    FreeLibrary(lib.handle);
                }
                return Err(TunError::Io(io::Error::other(format!(
                    "CreateEventW for Wintun shutdown failed (GetLastError={code})"
                ))));
            }

            let mut luid = NET_LUID_LH { Value: 0 };
            unsafe { (lib.get_adapter_luid)(adapter, &mut luid) };
            let adapter_luid = unsafe { luid.Value };
            if adapter_luid == 0 {
                unsafe {
                    CloseHandle(shutdown_event);
                    (lib.end_session)(session);
                    (lib.close_adapter)(adapter);
                    FreeLibrary(lib.handle);
                }
                return Err(TunError::Io(io::Error::other(
                    "WintunGetAdapterLUID returned an invalid zero LUID",
                )));
            }

            let mut device = Self {
                lib,
                adapter,
                session,
                read_wait_event,
                shutdown_event,
                adapter_luid,
                ipv6_enabled: config.ip6.is_some(),
                name: Arc::from(name_str),
                mtu: AtomicU16::new(config.mtu),
                operations: RwLock::new(()),
                close_guard: Mutex::new(()),
                closing: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            };

            // Assign the unicast IP address. A failure here tears down the
            // whole device so we never hand back an unconfigured adapter.
            if let Err(e) = device
                .assign_address(config)
                .and_then(|()| set_interface_mtu(&device.name, config.mtu, device.ipv6_enabled))
            {
                if let Err(cleanup_error) = device.close_inner() {
                    log::error!(
                        "Wintun initialization cleanup failed after configuration error: {cleanup_error}"
                    );
                }
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

        /// Tear down the session, adapter, event, and library. Idempotent.
        fn close_inner(&self) -> io::Result<()> {
            let _close_guard = self.close_guard.lock();
            if self.closed.load(Ordering::Acquire) {
                return Ok(());
            }

            self.closing.store(true, Ordering::Release);
            if unsafe { SetEvent(self.shutdown_event) } == 0 {
                return Err(io::Error::last_os_error());
            }

            let Some(_operations) = self.operations.try_write_for(CLOSE_DRAIN_TIMEOUT) else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Wintun operations did not drain within the close deadline",
                ));
            };

            unsafe {
                (self.lib.end_session)(self.session);
                (self.lib.close_adapter)(self.adapter);
            }

            let event_result = unsafe { CloseHandle(self.shutdown_event) };
            let event_error = (event_result == 0).then(io::Error::last_os_error);
            let library_result = unsafe { FreeLibrary(self.lib.handle) };
            let library_error = (library_result == 0).then(io::Error::last_os_error);

            self.closed.store(true, Ordering::Release);
            match (event_error, library_error) {
                (Some(error), _) | (None, Some(error)) => Err(error),
                (None, None) => Ok(()),
            }
        }

        /// Close the adapter and unload `wintun.dll`. Safe to call multiple
        /// times; subsequent calls are no-ops.
        pub fn close(&self) -> io::Result<()> {
            self.close_inner()
        }

        /// Return the stable Windows network-interface LUID for native policy
        /// and address verification.
        pub fn adapter_luid(&self) -> u64 {
            self.adapter_luid
        }
    }

    #[cfg(test)]
    pub(super) fn load_missing_test_library() -> Result<(), TunError> {
        WintunLib::load_named("quicfuscate-wintun-must-not-exist.dll").map(|_| ())
    }

    impl TunDevice for WintunDevice {
        fn name(&self) -> &str {
            self.name.as_ref()
        }

        fn mtu(&self) -> u16 {
            self.mtu.load(Ordering::Acquire)
        }

        fn set_mtu(&self, mtu: u16) -> io::Result<()> {
            if mtu < 576 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun MTU must be >= 576",
                ));
            }
            if self.ipv6_enabled && mtu < 1280 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun IPv6 MTU must be >= 1280",
                ));
            }

            let _operation = self.operations.read();
            if self.closing.load(Ordering::Acquire) {
                return Err(closed_error());
            }
            set_interface_mtu(self.name(), mtu, self.ipv6_enabled)?;
            self.mtu.store(mtu, Ordering::Release);
            Ok(())
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun read buffer must not be empty",
                ));
            }

            let _operation = self.operations.read();
            if self.closing.load(Ordering::Acquire) {
                return Err(closed_error());
            }

            let wait_handles = [self.read_wait_event, self.shutdown_event];
            loop {
                let mut size: u32 = 0;
                let pkt = unsafe { (self.lib.receive_packet)(self.session, &mut size) };
                if !pkt.is_null() {
                    let packet_len = size as usize;
                    if packet_len == 0 || packet_len > WINTUN_MAX_IP_PACKET_SIZE {
                        unsafe { (self.lib.release_receive_packet)(self.session, pkt) };
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Wintun returned invalid packet length {packet_len}"),
                        ));
                    }
                    if packet_len > buf.len() {
                        unsafe { (self.lib.release_receive_packet)(self.session, pkt) };
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Wintun packet length {packet_len} exceeds read buffer length {}",
                                buf.len()
                            ),
                        ));
                    }
                    unsafe {
                        ptr::copy_nonoverlapping(pkt as *const u8, buf.as_mut_ptr(), packet_len);
                        (self.lib.release_receive_packet)(self.session, pkt);
                    }
                    return Ok(packet_len);
                }

                match unsafe { GetLastError() } {
                    ERROR_NO_MORE_ITEMS => {
                        let wait = unsafe {
                            WaitForMultipleObjects(
                                wait_handles.len() as u32,
                                wait_handles.as_ptr(),
                                0,
                                INFINITE,
                            )
                        };
                        match wait {
                            WAIT_OBJECT_0 => continue,
                            value if value == WAIT_OBJECT_0 + 1 => return Err(closed_error()),
                            WAIT_FAILED => return Err(io::Error::last_os_error()),
                            value => {
                                return Err(io::Error::other(format!(
                                    "WaitForMultipleObjects returned unexpected status {value}"
                                )));
                            }
                        }
                    }
                    ERROR_HANDLE_EOF => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Wintun adapter is terminating",
                        ));
                    }
                    ERROR_INVALID_DATA => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Wintun receive ring is corrupt",
                        ));
                    }
                    code => return Err(io::Error::from_raw_os_error(code as i32)),
                }
            }
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() || buf.len() > WINTUN_MAX_IP_PACKET_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Wintun packet length must be between 1 and {WINTUN_MAX_IP_PACKET_SIZE} bytes"
                    ),
                ));
            }

            let _operation = self.operations.read();
            if self.closing.load(Ordering::Acquire) {
                return Err(closed_error());
            }

            let dst = unsafe { (self.lib.allocate_send_packet)(self.session, buf.len() as u32) };
            if dst.is_null() {
                return match unsafe { GetLastError() } {
                    ERROR_BUFFER_OVERFLOW => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, "Wintun send ring is full"))
                    }
                    ERROR_HANDLE_EOF => Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Wintun adapter is terminating",
                    )),
                    code => Err(io::Error::from_raw_os_error(code as i32)),
                };
            }
            unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len()) };
            unsafe { (self.lib.send_packet)(self.session, dst) };
            Ok(buf.len())
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            if let Err(error) = self.close_inner() {
                log::error!("Wintun shutdown failed: {error}");
            }
        }
    }

    fn closed_error() -> io::Error {
        io::Error::new(io::ErrorKind::Interrupted, "Wintun device is closing")
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
        pub fn new(config: &TunConfig) -> Result<Self, TunError> {
            validate_config(config)?;
            Err(TunError::Unsupported)
        }

        /// No-op on non-Windows targets.
        pub fn close(&self) -> io::Result<()> {
            Ok(())
        }
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

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    const NATIVE_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 253, 0, 1);
    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    const NATIVE_PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 253, 0, 2);
    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    const NATIVE_LOCAL_IP6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    const NATIVE_MTU: u16 = 1420;
    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    const NATIVE_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_returns_unsupported() {
        let cfg = TunConfig {
            name: Some("quicfuscate-test".to_string()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            mtu: 1500,
            ..TunConfig::default()
        };
        let res = WintunDevice::new(&cfg);
        assert!(
            matches!(res, Err(TunError::Unsupported)),
            "expected Unsupported on non-Windows, got {:?}",
            res
        );
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
        let res = imp::load_missing_test_library();
        assert!(
            matches!(res, Err(TunError::Config(_))),
            "expected Config error for a guaranteed-missing DLL, got {:?}",
            res
        );
    }

    #[test]
    fn ipv6_config_rejects_subminimum_mtu() {
        let cfg = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(128),
            mtu: 1279,
            ..TunConfig::default()
        };
        assert!(
            matches!(validate_config(&cfg), Err(TunError::Config(_))),
            "IPv6 Wintun configuration must reject MTUs below 1280"
        );
    }

    #[test]
    fn adapter_name_rejects_interior_nul() {
        let cfg =
            TunConfig { name: Some("quicfuscate\0hidden".to_string()), ..TunConfig::default() };
        assert!(
            matches!(validate_config(&cfg), Err(TunError::Config(_))),
            "Wintun adapter names must reject interior NUL"
        );
    }

    #[test]
    fn address_family_validation_rejects_ambiguous_config() {
        let ipv6_in_ipv4 =
            TunConfig { ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), ..TunConfig::default() };
        assert!(matches!(validate_config(&ipv6_in_ipv4), Err(TunError::Config(_))));

        let ipv6_netmask =
            TunConfig { netmask: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), ..TunConfig::default() };
        assert!(matches!(validate_config(&ipv6_netmask), Err(TunError::Config(_))));

        let orphan_prefix = TunConfig { prefix6: Some(64), ip6: None, ..TunConfig::default() };
        assert!(matches!(validate_config(&orphan_prefix), Err(TunError::Config(_))));

        let invalid_prefix = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(129),
            mtu: 1280,
            ..TunConfig::default()
        };
        assert!(matches!(validate_config(&invalid_prefix), Err(TunError::Config(_))));
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

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn native_config(name: &str) -> TunConfig {
        TunConfig {
            name: Some(name.to_string()),
            ip: Some(IpAddr::V4(NATIVE_LOCAL_IP)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            ip6: Some(NATIVE_LOCAL_IP6),
            prefix6: Some(64),
            mtu: NATIVE_MTU,
            ..TunConfig::default()
        }
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn powershell_succeeds(script: &str) -> bool {
        std::process::Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    struct NativeFirewallRule {
        name: String,
        active: bool,
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    impl NativeFirewallRule {
        fn allow_udp(name: String, local_port: u16) -> Self {
            let escaped_name = name.replace('\'', "''");
            let script = format!(
                "$existing = Get-NetFirewallRule -DisplayName '{escaped_name}' \
                     -ErrorAction SilentlyContinue; \
                 if ($null -ne $existing) {{ exit 1 }}; \
                 New-NetFirewallRule -DisplayName '{escaped_name}' -Direction Inbound \
                     -Action Allow -Protocol UDP -LocalAddress '{NATIVE_LOCAL_IP}' \
                     -LocalPort {local_port} -Profile Any -Enabled True \
                     -ErrorAction Stop | Out-Null"
            );
            assert!(
                powershell_succeeds(&script),
                "failed to create the exact native Wintun test firewall permit"
            );
            Self { name, active: true }
        }

        fn remove(mut self) {
            assert!(
                self.remove_inner(),
                "failed to remove the exact native Wintun test firewall permit"
            );
            self.active = false;
        }

        fn remove_inner(&self) -> bool {
            let escaped_name = self.name.replace('\'', "''");
            let script = format!(
                "Get-NetFirewallRule -DisplayName '{escaped_name}' -ErrorAction SilentlyContinue | \
                 Remove-NetFirewallRule -ErrorAction Stop"
            );
            powershell_succeeds(&script)
        }
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    impl Drop for NativeFirewallRule {
        fn drop(&mut self) {
            if self.active && !self.remove_inner() {
                eprintln!("failed to remove native Wintun test firewall permit '{}'", self.name);
            }
        }
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn wait_for_powershell(script: &str, expected_success: bool) {
        let deadline = std::time::Instant::now() + NATIVE_TEST_TIMEOUT;
        loop {
            if powershell_succeeds(script) == expected_success {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "PowerShell state did not converge before the native Wintun deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn adapter_state_script(name: &str, mtu: u16) -> String {
        let escaped_name = name.replace('\'', "''");
        format!(
            "$adapter = Get-NetAdapter -Name '{escaped_name}' -IncludeHidden -ErrorAction SilentlyContinue; \
             if ($null -eq $adapter) {{ exit 1 }}; \
             $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 \
                 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{NATIVE_LOCAL_IP}'; \
             $ipv6 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 \
                 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{NATIVE_LOCAL_IP6}'; \
             $interface4 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 \
                 -ErrorAction SilentlyContinue; \
             $interface6 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 \
                 -ErrorAction SilentlyContinue; \
             if ($null -eq $ipv4 -or $null -eq $ipv6 -or $null -eq $interface4 -or \
                 $null -eq $interface6 -or $interface4.NlMtuBytes -ne {mtu} -or \
                 $interface6.NlMtuBytes -ne {mtu}) {{ exit 1 }}; exit 0"
        )
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn adapter_absent_script(name: &str) -> String {
        let escaped_name = name.replace('\'', "''");
        format!(
            "$adapter = Get-NetAdapter -Name '{escaped_name}' -IncludeHidden \
                 -ErrorAction SilentlyContinue; \
             if ($null -eq $adapter) {{ exit 0 }} else {{ exit 1 }}"
        )
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn udp_ipv4_packet(
        source_ip: Ipv4Addr,
        source_port: u16,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8usize + payload.len();
        let total_len = 20usize + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x5146u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        let checksum = ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    fn is_udp_ipv4_packet(
        packet: &[u8],
        source_ip: Ipv4Addr,
        source_port: u16,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        payload: &[u8],
    ) -> bool {
        if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
            return false;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < 20 || packet.len() < header_len + 8 {
            return false;
        }
        let udp_len =
            usize::from(u16::from_be_bytes([packet[header_len + 4], packet[header_len + 5]]));
        if udp_len < 8 || packet.len() < header_len + udp_len {
            return false;
        }
        packet[12..16] == source_ip.octets()
            && packet[16..20] == destination_ip.octets()
            && packet[header_len..header_len + 2] == source_port.to_be_bytes()
            && packet[header_len + 2..header_len + 4] == destination_port.to_be_bytes()
            && packet[header_len + 8..header_len + udp_len] == *payload
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    #[test]
    #[ignore = "requires an administrator and an integrity-checked upstream wintun.dll"]
    fn native_adapter_packet_io_and_bounded_close() {
        use std::net::UdpSocket;
        use std::sync::{mpsc, Arc};
        use std::time::{Duration, Instant};

        const OUTBOUND_PORT: u16 = 35_801;
        const OUTBOUND_PAYLOAD: &[u8] = b"quicfuscate-wintun-outbound";
        const INBOUND_PAYLOAD: &[u8] = b"quicfuscate-wintun-inbound";

        let adapter_name = format!("QuicFuscate-CI-{}", std::process::id());
        let device = Arc::new(
            WintunDevice::new(&native_config(&adapter_name))
                .expect("verified Wintun must create the native adapter"),
        );
        assert_eq!(device.name(), adapter_name);
        assert_eq!(device.mtu(), NATIVE_MTU);
        assert_ne!(device.adapter_luid(), 0);

        let capabilities = crate::interface::tun_capabilities();
        assert!(capabilities.built_in);
        assert!(!capabilities.supports_zero_copy);
        assert!(!capabilities.supports_raw_fd);
        wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);
        device.set_mtu(1400).expect("native Wintun MTU update must succeed");
        assert_eq!(device.mtu(), 1400);
        wait_for_powershell(&adapter_state_script(&adapter_name, 1400), true);
        device.set_mtu(NATIVE_MTU).expect("native Wintun MTU restore must succeed");
        wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);

        let socket = UdpSocket::bind((NATIVE_LOCAL_IP, 0))
            .expect("native Wintun address must accept a UDP binding");
        socket
            .set_read_timeout(Some(NATIVE_TEST_TIMEOUT))
            .expect("UDP receive timeout must be configurable");
        let local_port =
            socket.local_addr().expect("UDP socket must expose its local address").port();
        let firewall_rule = NativeFirewallRule::allow_udp(
            format!("QuicFuscate-CI-Wintun-{}", std::process::id()),
            local_port,
        );

        let reader_device = Arc::clone(&device);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel(1);
        let outbound_reader = std::thread::spawn(move || {
            let mut packet = [0u8; 65_535];
            loop {
                match reader_device.read(&mut packet) {
                    Ok(length)
                        if is_udp_ipv4_packet(
                            &packet[..length],
                            NATIVE_LOCAL_IP,
                            local_port,
                            NATIVE_PEER_IP,
                            OUTBOUND_PORT,
                            OUTBOUND_PAYLOAD,
                        ) =>
                    {
                        let _ = outbound_tx.send(Ok(()));
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        let _ = outbound_tx.send(Err(error));
                        return;
                    }
                }
            }
        });
        socket
            .send_to(OUTBOUND_PAYLOAD, (NATIVE_PEER_IP, OUTBOUND_PORT))
            .expect("Windows must route the outbound UDP packet into Wintun");
        let outbound_result = outbound_rx.recv_timeout(NATIVE_TEST_TIMEOUT);
        if outbound_result.is_err() {
            device.close().expect("timed-out Wintun reader cleanup must succeed");
        }
        outbound_reader.join().expect("outbound reader panicked");
        outbound_result
            .expect("Wintun outbound packet capture timed out")
            .expect("Wintun outbound reader failed");

        let inbound = udp_ipv4_packet(
            NATIVE_PEER_IP,
            OUTBOUND_PORT,
            NATIVE_LOCAL_IP,
            local_port,
            INBOUND_PAYLOAD,
        );
        assert_eq!(device.write(&inbound).expect("Wintun inbound injection failed"), inbound.len());
        let mut received = [0u8; 256];
        let (received_len, source) = socket
            .recv_from(&mut received)
            .expect("Windows UDP stack did not receive Wintun input");
        assert_eq!(&received[..received_len], INBOUND_PAYLOAD);
        assert_eq!(source.ip(), IpAddr::V4(NATIVE_PEER_IP));
        assert_eq!(source.port(), OUTBOUND_PORT);
        firewall_rule.remove();

        let blocked_device = Arc::clone(&device);
        let (blocked_tx, blocked_rx) = mpsc::sync_channel(1);
        let blocked_reader = std::thread::spawn(move || {
            let mut packet = [0u8; 65_535];
            loop {
                match blocked_device.read(&mut packet) {
                    Ok(_) => continue,
                    Err(error) => {
                        let _ = blocked_tx.send(error.kind());
                        return;
                    }
                }
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        let close_started = Instant::now();
        device.close().expect("Wintun close must succeed");
        assert!(
            close_started.elapsed() <= Duration::from_secs(3),
            "Wintun close exceeded its bounded deadline"
        );
        let close_error = blocked_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("blocked Wintun read was not released by close");
        assert!(
            matches!(close_error, io::ErrorKind::Interrupted | io::ErrorKind::BrokenPipe),
            "unexpected blocked-read close outcome: {close_error:?}"
        );
        blocked_reader.join().expect("blocked reader panicked");
        device.close().expect("Wintun close must be idempotent");
        assert_eq!(
            device.write(b"after-close").expect_err("write after close must fail").kind(),
            io::ErrorKind::Interrupted
        );
        drop(device);
        wait_for_powershell(&adapter_absent_script(&adapter_name), true);
        println!(
            "native Wintun lifecycle passed: adapter={adapter_name} mtu={NATIVE_MTU} \
             ipv4={NATIVE_LOCAL_IP} bidirectional_io=true bounded_close=true residue=false"
        );
    }

    #[cfg(all(target_os = "windows", feature = "tun-windows"))]
    #[test]
    #[ignore = "requires an administrator and an integrity-checked upstream wintun.dll"]
    fn native_repeated_open_close_has_no_adapter_residue() {
        for iteration in 0..3 {
            let adapter_name = format!("QuicFuscate-CI-{}-{iteration}", std::process::id());
            let device = WintunDevice::new(&native_config(&adapter_name))
                .expect("verified Wintun must create the repeated-lifecycle adapter");
            assert_ne!(device.adapter_luid(), 0);
            wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);
            device.close().expect("repeated-lifecycle Wintun close must succeed");
            device.close().expect("repeated-lifecycle close must remain idempotent");
            drop(device);
            wait_for_powershell(&adapter_absent_script(&adapter_name), true);
        }
    }
}

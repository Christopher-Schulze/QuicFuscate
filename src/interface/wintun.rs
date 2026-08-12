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
    if config.ip.is_some() != config.netmask.is_some() {
        return Err(TunError::Config(
            "Wintun IPv4 address and netmask must be configured together",
        ));
    }
    if let Some(std::net::IpAddr::V4(mask)) = config.netmask {
        let raw = u32::from(mask);
        let prefix = raw.leading_ones();
        let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        if raw != canonical {
            return Err(TunError::Config("Wintun IPv4 netmask must be contiguous"));
        }
    }
    if config.ip6.is_some() != config.prefix6.is_some() {
        return Err(TunError::Config("Wintun IPv6 address and prefix must be configured together"));
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

/// State of every resource owned by a Wintun lifecycle.
///
/// Windows-only: every constructor and consumer lives inside the `target_os = "windows"` module
/// below, so compiling it elsewhere produced a type nothing could reach.
///
/// A cleanup failure must leave the corresponding resource pending so an
/// explicit retry can attempt the same operation again. The last failure is
/// retained for Drop diagnostics and native residue investigation.
#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WintunCleanupState {
    shutdown_signaled: bool,
    session_ended: bool,
    adapter_closed: bool,
    shutdown_event_closed: bool,
    library_unloaded: bool,
    last_error: Option<String>,
}

#[cfg(target_os = "windows")]
impl WintunCleanupState {
    fn is_complete(&self) -> bool {
        self.session_ended
            && self.adapter_closed
            && self.shutdown_event_closed
            && self.library_unloaded
    }

    fn pending_resources(&self) -> String {
        let mut pending = Vec::new();
        if !self.session_ended {
            pending.push("session");
        }
        if !self.adapter_closed {
            pending.push("adapter");
        }
        if !self.shutdown_event_closed {
            pending.push("shutdown event");
        }
        if !self.library_unloaded {
            pending.push("wintun.dll");
        }
        if pending.is_empty() {
            "none".to_string()
        } else {
            pending.join(", ")
        }
    }

    fn record_failure(&mut self, resource: &str, detail: impl std::fmt::Display) -> String {
        let message = format!("{resource}: {detail}");
        self.last_error = Some(message.clone());
        message
    }
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
    use std::time::{Duration, Instant};

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
    const ADDRESS_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(10);
    const ADDRESS_ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

    // Default adapter name / tunnel type when the config does not specify one.
    const DEFAULT_ADAPTER_NAME: &str = "QuicFuscate";
    const WINTUN_TUNNEL_TYPE: &str = "Wintun";

    fn run_netsh(args: &[&str], action: &str) -> io::Result<()> {
        let output = std::process::Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(args)
            .output()
            .map_err(|error| io::Error::other(format!("{action} spawn failed: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "{action} returned status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    pub(super) fn interface_mtu_script(name: &str, family: &str) -> String {
        let escaped_name = name.replace('\'', "''");
        format!(
            "$ErrorActionPreference='Stop'; $interface = Get-NetIPInterface -InterfaceAlias '{escaped_name}' -AddressFamily {family} | Select-Object -First 1; if ($null -eq $interface) {{ throw 'interface not found' }}; [Console]::WriteLine($interface.NlMtu)"
        )
    }

    fn read_interface_mtu(name: &str, family: &str) -> io::Result<u16> {
        let script = interface_mtu_script(name, family);
        let output = std::process::Command::new("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|error| {
                io::Error::other(format!("{family} MTU inspect spawn failed: {error}"))
            })?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{family} MTU inspect returned status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8_lossy(&output.stdout).trim().parse::<u16>().map_err(|error| {
            io::Error::other(format!("{family} MTU inspect returned invalid value: {error}"))
        })
    }

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

    /// Temporary module owner used while resolving the Wintun exports.
    ///
    /// If resolution fails, the owner keeps the module handle alive through a
    /// bounded Drop retry instead of discarding a failed `FreeLibrary` result.
    #[derive(Debug)]
    struct ModuleRollbackGuard {
        handle: HMODULE,
    }

    impl ModuleRollbackGuard {
        fn new(handle: HMODULE) -> Self {
            Self { handle }
        }

        fn unload(&mut self) -> io::Result<()> {
            if self.handle.is_null() {
                return Ok(());
            }
            if unsafe { FreeLibrary(self.handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.handle = ptr::null_mut();
            Ok(())
        }

        fn disarm(&mut self) -> HMODULE {
            let handle = self.handle;
            self.handle = ptr::null_mut();
            handle
        }
    }

    impl Drop for ModuleRollbackGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                if let Err(error) = self.unload() {
                    log::error!("Wintun loader rollback could not unload module owner: {error}");
                }
            }
        }
    }

    /// Dynamically loaded Wintun library bundling a module handle and all
    /// resolved entry points. The owning lifecycle must explicitly unload the
    /// module after the session and adapter have ended.
    #[derive(Debug)]
    struct WintunLib {
        handle: HMODULE,
        unloaded: Mutex<bool>,
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
            let mut module = ModuleRollbackGuard::new(handle);

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
                            let message =
                                "wintun.dll missing required export; incompatible version";
                            return match module.unload() {
                                Ok(()) => Err(TunError::Config(message)),
                                Err(error) => Err(TunError::Io(io::Error::other(format!(
                                    "{message}; failed to unload module owner: {error}"
                                )))),
                            };
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
                handle: module.disarm(),
                unloaded: Mutex::new(false),
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

        fn unload(&self) -> io::Result<()> {
            let mut unloaded = self.unloaded.lock();
            if *unloaded {
                return Ok(());
            }
            if unsafe { FreeLibrary(self.handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            *unloaded = true;
            Ok(())
        }
    }

    /// Partial constructor owner. All acquired native resources remain in this
    /// owner until their individual rollback step succeeds.
    #[derive(Debug)]
    struct WintunStartupOwner {
        lib: Option<WintunLib>,
        adapter: Option<*mut c_void>,
        session: Option<*mut c_void>,
        shutdown_event: Option<HANDLE>,
    }

    impl WintunStartupOwner {
        fn new(lib: WintunLib) -> Self {
            Self { lib: Some(lib), adapter: None, session: None, shutdown_event: None }
        }

        fn lib(&self) -> Option<&WintunLib> {
            self.lib.as_ref()
        }

        fn pending_resources(&self) -> String {
            let mut pending = Vec::new();
            if self.session.is_some() {
                pending.push("session");
            }
            if self.adapter.is_some() {
                pending.push("adapter");
            }
            if self.shutdown_event.is_some() {
                pending.push("shutdown event");
            }
            if self.lib.is_some() {
                pending.push("wintun.dll");
            }
            if pending.is_empty() {
                "none".to_string()
            } else {
                pending.join(", ")
            }
        }

        fn rollback(&mut self) -> io::Result<()> {
            let mut failures = Vec::new();

            // WintunEndSession and WintunCloseAdapter are void APIs. Removing
            // each owner from this ledger only happens immediately after its
            // corresponding call, so later rollback cannot repeat it.
            if let Some(session) = self.session.take() {
                if let Some(lib) = self.lib() {
                    unsafe { (lib.end_session)(session) };
                } else {
                    self.session = Some(session);
                    failures.push("session: Wintun library owner is unavailable".to_string());
                }
            }
            if let Some(adapter) = self.adapter.take() {
                if let Some(lib) = self.lib() {
                    unsafe { (lib.close_adapter)(adapter) };
                } else {
                    self.adapter = Some(adapter);
                    failures.push("adapter: Wintun library owner is unavailable".to_string());
                }
            }
            if let Some(event) = self.shutdown_event {
                if unsafe { CloseHandle(event) } == 0 {
                    let error = io::Error::last_os_error();
                    failures.push(format!("shutdown event: {error}"));
                } else {
                    self.shutdown_event = None;
                }
            }
            if self.lib.is_some() {
                let unload_result = self.lib.as_ref().map(WintunLib::unload);
                match unload_result {
                    Some(Ok(())) => self.lib = None,
                    Some(Err(error)) => failures.push(format!("wintun.dll: {error}")),
                    None => {}
                }
            }

            if failures.is_empty() && self.pending_resources() == "none" {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "Wintun startup rollback incomplete; pending resources: {}; {}",
                    self.pending_resources(),
                    if failures.is_empty() {
                        "resource owner state is inconsistent".to_string()
                    } else {
                        failures.join("; ")
                    }
                )))
            }
        }

        fn into_parts(
            mut self,
        ) -> Result<(WintunLib, *mut c_void, *mut c_void, HANDLE), io::Error> {
            let lib = self.lib.take();
            let adapter = self.adapter.take();
            let session = self.session.take();
            let shutdown_event = self.shutdown_event.take();
            match (lib, adapter, session, shutdown_event) {
                (Some(lib), Some(adapter), Some(session), Some(shutdown_event)) => {
                    Ok((lib, adapter, session, shutdown_event))
                }
                (lib, adapter, session, shutdown_event) => {
                    self.lib = lib;
                    self.adapter = adapter;
                    self.session = session;
                    self.shutdown_event = shutdown_event;
                    let rollback_error = self.rollback().err();
                    Err(io::Error::other(format!(
                        "Wintun startup owner was incomplete; pending resources: {}; rollback: {}",
                        self.pending_resources(),
                        rollback_error
                            .map_or_else(|| "not required".to_string(), |error| error.to_string())
                    )))
                }
            }
        }
    }

    impl Drop for WintunStartupOwner {
        fn drop(&mut self) {
            if self.pending_resources() == "none" {
                return;
            }
            for _ in 0..2 {
                if self.rollback().is_ok() {
                    return;
                }
            }
            log::error!(
                "Wintun startup owner dropped with pending resources: {}",
                self.pending_resources()
            );
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
        let name_arg = format!("name={name}");
        let addr_arg = format!("addr={ip}");
        let mask_arg = format!("mask={mask}");
        run_netsh(
            &[
                "interface",
                "ip",
                "set",
                "address",
                &name_arg,
                "source=static",
                &addr_arg,
                &mask_arg,
            ],
            "netsh set IPv4 address",
        )
    }

    /// Assign an IPv6 address (with prefix length) to the adapter via `netsh`.
    fn assign_ipv6(name: &str, ip: Ipv6Addr, prefix: u8) -> io::Result<()> {
        let interface_arg = format!("interface={name}");
        let address_arg = format!("address={ip}/{prefix}");
        run_netsh(
            &["interface", "ipv6", "set", "address", &interface_arg, &address_arg],
            "netsh set IPv6 address",
        )
    }

    fn set_interface_mtu(name: &str, mtu: u16, ipv6_enabled: bool) -> io::Result<()> {
        let families = if ipv6_enabled { &["ipv4", "ipv6"][..] } else { &["ipv4"][..] };
        for family in families {
            let mtu_arg = format!("mtu={mtu}");
            run_netsh(
                &["interface", family, "set", "subinterface", name, &mtu_arg, "store=active"],
                &format!("netsh {family} MTU update for adapter '{name}'"),
            )?;
            let verified = read_interface_mtu(name, family)?;
            if verified != mtu {
                return Err(io::Error::other(format!(
                    "netsh {family} MTU update reported {verified}, expected {mtu}"
                )));
            }
        }
        Ok(())
    }

    fn wait_for_address_activation(config: &TunConfig) -> io::Result<()> {
        let addresses = config.ip.into_iter().chain(config.ip6.map(IpAddr::V6));
        for address in addresses {
            let endpoint = std::net::SocketAddr::new(address, 0);
            let deadline = Instant::now() + ADDRESS_ACTIVATION_TIMEOUT;
            loop {
                match std::net::UdpSocket::bind(endpoint) {
                    Ok(socket) => {
                        drop(socket);
                        break;
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::AddrNotAvailable
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(ADDRESS_ACTIVATION_POLL_INTERVAL);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "Wintun address {address} did not become bindable within {}s: \
                                 {error}",
                                ADDRESS_ACTIVATION_TIMEOUT.as_secs()
                            ),
                        ));
                    }
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("Wintun address {address} activation check failed: {error}"),
                        ));
                    }
                }
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
        cleanup_state: Mutex<WintunCleanupState>,
        closing: AtomicBool,
    }

    // Safety contract for the manual Send/Sync implementations:
    // - The upstream wintun.h contract marks receive, release, allocate, and
    //   send packet calls as thread-safe. Allocation order defines send order;
    //   this type intentionally makes no stronger ordering guarantee.
    // - `operations` keeps the session and resolved DLL entry points alive
    //   until every in-flight packet operation drains.
    // - `close_guard` serializes teardown, and the shutdown event wakes a
    //   blocked reader before teardown acquires the exclusive operation lock.
    // - Session and adapter teardown only runs while the exclusive operation
    //   lock is held, so no thread can call a Wintun function after unload.
    unsafe impl Send for WintunDevice {}
    unsafe impl Sync for WintunDevice {}

    fn initialization_failure(owner: &mut WintunStartupOwner, primary: io::Error) -> TunError {
        let detail = match owner.rollback() {
            Ok(()) => primary.to_string(),
            Err(cleanup) => format!("{primary}; startup cleanup failed: {cleanup}"),
        };
        TunError::Io(io::Error::new(primary.kind(), detail))
    }

    fn remember_cleanup_failure(
        state: &mut WintunCleanupState,
        failures: &mut Vec<String>,
        resource: &str,
        detail: impl std::fmt::Display,
    ) {
        failures.push(state.record_failure(resource, detail));
    }

    fn incomplete_cleanup_error(state: &WintunCleanupState, failures: &[String]) -> io::Error {
        let detail = if failures.is_empty() {
            state.last_error.as_deref().unwrap_or("resource owner state is incomplete").to_string()
        } else {
            failures.join("; ")
        };
        io::Error::other(format!(
            "Wintun cleanup incomplete; pending resources: {}; {detail}",
            state.pending_resources()
        ))
    }

    impl WintunDevice {
        /// Create a Wintun adapter, start a session, and assign the configured
        /// IP address.
        pub fn new(config: &TunConfig) -> Result<Self, TunError> {
            validate_config(config)?;

            let mut owner = WintunStartupOwner::new(WintunLib::load()?);

            let name_str =
                config.name.as_deref().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_ADAPTER_NAME);
            let name_wide = wide_z(name_str);
            let tunnel_wide = wide_z(WINTUN_TUNNEL_TYPE);

            let adapter = {
                let Some(lib) = owner.lib() else {
                    return Err(TunError::Io(io::Error::other(
                        "Wintun startup owner lost its library before adapter creation",
                    )));
                };
                unsafe {
                    (lib.create_adapter)(name_wide.as_ptr(), tunnel_wide.as_ptr(), ptr::null())
                }
            };
            if adapter.is_null() {
                let code = unsafe { GetLastError() };
                return Err(initialization_failure(
                    &mut owner,
                    io::Error::other(format!("WintunCreateAdapter failed (GetLastError={code})")),
                ));
            }
            owner.adapter = Some(adapter);

            let session = {
                let Some(lib) = owner.lib() else {
                    return Err(initialization_failure(
                        &mut owner,
                        io::Error::other(
                            "Wintun startup owner lost its library before session start",
                        ),
                    ));
                };
                unsafe { (lib.start_session)(adapter, ring_capacity(config.mtu)) }
            };
            if session.is_null() {
                let code = unsafe { GetLastError() };
                return Err(initialization_failure(
                    &mut owner,
                    io::Error::other(format!("WintunStartSession failed (GetLastError={code})")),
                ));
            }
            owner.session = Some(session);

            let read_wait_event = {
                let Some(lib) = owner.lib() else {
                    return Err(initialization_failure(
                        &mut owner,
                        io::Error::other(
                            "Wintun startup owner lost its library before read-event lookup",
                        ),
                    ));
                };
                unsafe { (lib.get_read_wait_event)(session) }
            };
            if read_wait_event.is_null() {
                let code = unsafe { GetLastError() };
                return Err(initialization_failure(
                    &mut owner,
                    io::Error::other(format!(
                        "WintunGetReadWaitEvent failed (GetLastError={code})"
                    )),
                ));
            }

            let shutdown_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null() as PCWSTR) };
            if shutdown_event.is_null() {
                let code = unsafe { GetLastError() };
                return Err(initialization_failure(
                    &mut owner,
                    io::Error::other(format!(
                        "CreateEventW for Wintun shutdown failed (GetLastError={code})"
                    )),
                ));
            }
            owner.shutdown_event = Some(shutdown_event);

            let mut luid = NET_LUID_LH { Value: 0 };
            {
                let Some(lib) = owner.lib() else {
                    return Err(initialization_failure(
                        &mut owner,
                        io::Error::other(
                            "Wintun startup owner lost its library before LUID lookup",
                        ),
                    ));
                };
                unsafe { (lib.get_adapter_luid)(adapter, &mut luid) };
            }
            let adapter_luid = unsafe { luid.Value };
            if adapter_luid == 0 {
                return Err(initialization_failure(
                    &mut owner,
                    io::Error::other("WintunGetAdapterLUID returned an invalid zero LUID"),
                ));
            }

            let (lib, adapter, session, shutdown_event) = match owner.into_parts() {
                Ok(parts) => parts,
                Err(error) => return Err(TunError::Io(error)),
            };

            let device = Self {
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
                cleanup_state: Mutex::new(WintunCleanupState::default()),
                closing: AtomicBool::new(false),
            };

            // Assign the unicast IP address. A failure here tears down the
            // whole device so we never hand back an unconfigured adapter.
            if let Err(e) = device
                .assign_address(config)
                .and_then(|()| set_interface_mtu(&device.name, config.mtu, device.ipv6_enabled))
                .and_then(|()| wait_for_address_activation(config))
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
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Wintun IPv4 address and netmask must be configured together",
                        ))
                    }
                };
                assign_ipv4(&self.name, ip, mask)?;
            }
            if let Some(ip6) = config.ip6 {
                let Some(prefix) = config.prefix6 else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Wintun IPv6 address and prefix must be configured together",
                    ));
                };
                assign_ipv6(&self.name, ip6, prefix)?;
            }
            Ok(())
        }

        /// Tear down the session, adapter, event, and library in order.
        ///
        /// Failed event or module cleanup remains pending in `cleanup_state`;
        /// a later explicit `close()` retries only the failed owner. Session
        /// and adapter teardown is never repeated because those APIs are void.
        fn close_inner(&self) -> io::Result<()> {
            let _close_guard = self.close_guard.lock();
            let mut state = self.cleanup_state.lock();
            if state.is_complete() {
                return Ok(());
            }

            self.closing.store(true, Ordering::Release);
            let mut failures = Vec::new();
            if !state.shutdown_signaled {
                if unsafe { SetEvent(self.shutdown_event) } == 0 {
                    let error = io::Error::last_os_error();
                    remember_cleanup_failure(
                        &mut state,
                        &mut failures,
                        "shutdown event signal",
                        error,
                    );
                    return Err(incomplete_cleanup_error(&state, &failures));
                }
                state.shutdown_signaled = true;
            }

            if !state.session_ended || !state.adapter_closed {
                let Some(_operations) = self.operations.try_write_for(CLOSE_DRAIN_TIMEOUT) else {
                    let error = io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Wintun operations did not drain within the close deadline",
                    );
                    remember_cleanup_failure(&mut state, &mut failures, "operation drain", error);
                    return Err(incomplete_cleanup_error(&state, &failures));
                };

                if !state.session_ended {
                    unsafe { (self.lib.end_session)(self.session) };
                    state.session_ended = true;
                }
                if !state.adapter_closed {
                    unsafe { (self.lib.close_adapter)(self.adapter) };
                    state.adapter_closed = true;
                }
            }

            if !state.shutdown_event_closed {
                if unsafe { CloseHandle(self.shutdown_event) } == 0 {
                    let error = io::Error::last_os_error();
                    remember_cleanup_failure(
                        &mut state,
                        &mut failures,
                        "shutdown event close",
                        error,
                    );
                } else {
                    state.shutdown_event_closed = true;
                }
            }
            if !state.library_unloaded {
                match self.lib.unload() {
                    Ok(()) => state.library_unloaded = true,
                    Err(error) => {
                        remember_cleanup_failure(
                            &mut state,
                            &mut failures,
                            "wintun.dll unload",
                            error,
                        );
                    }
                }
            }

            if state.is_complete() {
                Ok(())
            } else {
                Err(incomplete_cleanup_error(&state, &failures))
            }
        }

        /// Close the adapter and unload `wintun.dll`. Safe to call multiple
        /// times; failed owner steps are retried on subsequent calls.
        pub fn close(&self) -> io::Result<()> {
            self.close_inner()
        }

        /// Return the stable Windows network-interface LUID for native policy
        /// and address verification.
        pub fn adapter_luid(&self) -> u64 {
            self.adapter_luid
        }

        #[cfg(test)]
        pub(super) fn cleanup_state_for_test(&self) -> WintunCleanupState {
            self.cleanup_state.lock().clone()
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

        fn request_read_shutdown(&self) -> io::Result<()> {
            if self.closing.load(Ordering::Acquire) {
                return Ok(());
            }
            if unsafe { SetEvent(self.shutdown_event) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            for attempt in 1..=2 {
                match self.close_inner() {
                    Ok(()) => return,
                    Err(error) if attempt == 1 => {
                        log::warn!("Wintun shutdown retry after cleanup failure: {error}");
                    }
                    Err(error) => {
                        let state = self.cleanup_state.lock();
                        log::error!(
                            "Wintun shutdown failed after bounded retry: {error}; pending resources: {}; last error: {:?}",
                            state.pending_resources(),
                            state.last_error
                        );
                    }
                }
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
mod tests;

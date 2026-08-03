//! Linux platform implementation.

use super::dns_restore::{
    backup_resolv_conf_at, load_ownership_at, mark_resolv_conf_written, owner_marker,
    ownership_path, persist_ownership_at, remove_ownership_at, restore_persisted_resolv_conf_at,
    restore_resolv_conf_at, source_has_owner_marker, ProcessIdentity, ResolvConfRestoreState,
};
use super::traits::*;
use std::fs::File;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP_PATH: &str = "/etc/resolv.conf.quicfuscate.bak";

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; 16],
    ifr_flags: libc::c_short,
}

/// Linux platform backend.
pub struct LinuxPlatform {
    tun_name: Mutex<Option<String>>,
    resolv_conf_backup: Mutex<Option<ResolvConfRestoreState>>,
    resolv_conf_lock: Mutex<Option<File>>,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            tun_name: Mutex::new(None),
            resolv_conf_backup: Mutex::new(None),
            resolv_conf_lock: Mutex::new(None),
        }
    }

    /// Check if systemd-resolved is available.
    fn has_systemd_resolved(&self) -> bool {
        std::path::Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
    }

    fn active_tun_name(&self) -> Result<String, PlatformError> {
        self.tun_name.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| {
            PlatformError::DnsError(
                "No active tunnel interface available for DNS setup".to_string(),
            )
        })
    }

    fn set_active_tun_name(&self, name: Option<String>) {
        *self.tun_name.lock().unwrap_or_else(|e| e.into_inner()) = name;
    }

    fn run_command(&self, cmd: &str, args: &[&str]) -> Result<(), PlatformError> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| PlatformError::CommandFailed(format!("{cmd} spawn: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(PlatformError::CommandFailed(format!(
            "{} {} returned status {}: {}",
            cmd,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Run ip command.
    fn run_ip(&self, args: &[&str]) -> Result<(), PlatformError> {
        self.run_command("ip", args)
    }

    fn interface_exists(name: &str) -> Result<bool, PlatformError> {
        let output =
            Command::new("ip").args(["link", "show", "dev", name]).output().map_err(|error| {
                PlatformError::CommandFailed(format!("ip link inspect spawn: {error}"))
            })?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("cannot find device")
            || stderr.contains("does not exist")
            || stderr.contains("no such device")
        {
            return Ok(false);
        }
        Err(PlatformError::CommandFailed(format!(
            "ip link inspect returned status {}: {}",
            output.status,
            stderr.trim()
        )))
    }

    fn remove_owned_interface(name: &str) -> Result<(), PlatformError> {
        if !Self::interface_exists(name)? {
            return Ok(());
        }
        let output =
            Command::new("ip").args(["link", "delete", "dev", name]).output().map_err(|error| {
                PlatformError::CommandFailed(format!("ip link delete spawn: {error}"))
            })?;
        if !output.status.success() && Self::interface_exists(name)? {
            return Err(PlatformError::CommandFailed(format!(
                "ip link delete returned status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if Self::interface_exists(name)? {
            return Err(PlatformError::DeviceError(format!(
                "owned TUN {} remains after rollback",
                name
            )));
        }
        Ok(())
    }

    fn linux_boot_id() -> Result<String, PlatformError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| PlatformError::DnsError(format!("read Linux boot ID: {error}")))?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() {
            return Err(PlatformError::DnsError("Linux boot ID is empty".to_string()));
        }
        Ok(boot_id.to_string())
    }

    fn linux_process_start_time(pid: u32) -> Result<Option<u64>, PlatformError> {
        let path = format!("/proc/{pid}/stat");
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(PlatformError::DnsError(format!(
                    "read Linux process identity {path}: {error}"
                )))
            }
        };
        let fields = contents.rsplit_once(") ").map(|(_, fields)| fields).ok_or_else(|| {
            PlatformError::DnsError(format!("parse Linux process identity {path}"))
        })?;
        let start_time = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| {
                PlatformError::DnsError(format!(
                    "Linux process identity {path} omitted the start time"
                ))
            })?
            .parse::<u64>()
            .map_err(|error| {
                PlatformError::DnsError(format!(
                    "parse Linux process start time in {path}: {error}"
                ))
            })?;
        Ok(Some(start_time))
    }

    fn current_process_identity() -> Result<ProcessIdentity, PlatformError> {
        let pid = std::process::id();
        let start_time = Self::linux_process_start_time(pid)?.ok_or_else(|| {
            PlatformError::DnsError(format!("current Linux process {pid} disappeared"))
        })?;
        Ok(ProcessIdentity { boot_id: Self::linux_boot_id()?, pid, start_time })
    }

    fn resolver_state_path() -> PathBuf {
        ownership_path(Path::new(RESOLV_CONF_BACKUP_PATH))
    }

    fn resolver_lock_path() -> PathBuf {
        Path::new(RESOLV_CONF_BACKUP_PATH).with_extension("lock")
    }

    fn acquire_resolver_lock(&self) -> Result<(), PlatformError> {
        let mut guard = self.resolv_conf_lock.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let path = Self::resolver_lock_path();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|error| {
                PlatformError::DnsError(format!("open resolver lock {}: {error}", path.display()))
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    PlatformError::DnsError(format!(
                        "secure resolver lock {}: {error}",
                        path.display()
                    ))
                },
            )?;
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(PlatformError::DnsError(format!(
                "resolver lock {} is held by another process: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        *guard = Some(file);
        Ok(())
    }

    fn release_resolver_lock(&self) -> Result<(), PlatformError> {
        let mut guard = self.resolv_conf_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(file) = guard.take() else {
            return Ok(());
        };
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        drop(file);
        if result != 0 {
            return Err(PlatformError::DnsError(format!(
                "release resolver lock: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn recover_stale_resolver_state(&self, current: &ProcessIdentity) -> Result<(), PlatformError> {
        let backup = Path::new(RESOLV_CONF_BACKUP_PATH);
        let state_path = Self::resolver_state_path();
        let Some(state) = load_ownership_at(&state_path)? else {
            if backup.exists() {
                return Err(PlatformError::DnsError(format!(
                    "orphaned resolver backup {} has no ownership state; refusing to overwrite DNS state",
                    backup.display()
                )));
            }
            return Ok(());
        };
        if state.owner_boot_id != current.boot_id {
            return Err(PlatformError::DnsError(
                "resolver ownership state belongs to a different Linux boot; refusing guessed recovery"
                    .to_string(),
            ));
        }
        let owner_is_current =
            state.owner_pid == current.pid && state.owner_start_time == current.start_time;
        if owner_is_current && !backup.exists() {
            let source_is_still_managed = Path::new(RESOLV_CONF_PATH).exists()
                && source_has_owner_marker(Path::new(RESOLV_CONF_PATH), &state.owner_marker)?;
            if !source_is_still_managed {
                return remove_ownership_at(&state_path);
            }
        }
        if Self::linux_process_start_time(state.owner_pid)? == Some(state.owner_start_time) {
            return Err(PlatformError::DnsError(format!(
                "resolver ownership state is still owned by active PID {}",
                state.owner_pid
            )));
        }

        restore_persisted_resolv_conf_at(Path::new(RESOLV_CONF_PATH), backup, &state_path, &state)
    }

    fn prepare_legacy_resolver_state(&self) -> Result<String, PlatformError> {
        self.acquire_resolver_lock()?;
        let mut guard = self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = guard.as_ref() {
            if !Self::resolver_state_path().exists() {
                return Err(PlatformError::DnsError(
                    "resolver ownership state disappeared during the active session".to_string(),
                ));
            }
            return Ok(state.owner_marker().to_string());
        }
        let current = Self::current_process_identity()?;
        let marker = owner_marker(&current);
        self.recover_stale_resolver_state(&current)?;
        let backup = Path::new(RESOLV_CONF_BACKUP_PATH);
        if backup.exists() {
            return Err(PlatformError::DnsError(format!(
                "orphaned resolver backup {} remains after stale recovery",
                backup.display()
            )));
        }
        backup_resolv_conf_at(Path::new(RESOLV_CONF_PATH), backup, &marker, &mut guard)?;
        let original_present = matches!(&*guard, Some(ResolvConfRestoreState::Present { .. }));
        if let Err(error) =
            persist_ownership_at(&Self::resolver_state_path(), &current, original_present)
        {
            let cleanup = restore_resolv_conf_at(Path::new(RESOLV_CONF_PATH), &mut guard);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => PlatformError::DnsError(format!(
                    "persist resolver ownership failed: {error}; cleanup failed: {cleanup_error}"
                )),
            });
        }
        Ok(marker)
    }

    fn restore_resolv_conf_from_backup(&self) -> Result<(), PlatformError> {
        let has_in_memory_state =
            self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        let state_path = Self::resolver_state_path();
        if !has_in_memory_state
            && !state_path.exists()
            && !Path::new(RESOLV_CONF_BACKUP_PATH).exists()
        {
            return Ok(());
        }
        self.acquire_resolver_lock()?;
        let mut guard = self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            restore_resolv_conf_at(Path::new(RESOLV_CONF_PATH), &mut guard)?;
            return remove_ownership_at(&Self::resolver_state_path());
        }
        drop(guard);

        let current = Self::current_process_identity()?;
        self.recover_stale_resolver_state(&current)
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for LinuxPlatform {
    fn name(&self) -> &'static str {
        "Linux"
    }

    fn is_elevated(&self) -> bool {
        // SAFETY: `geteuid()` is always safe to call - it is a simple syscall with no
        // preconditions and cannot cause undefined behaviour.
        unsafe { libc::geteuid() == 0 }
    }

    fn request_elevation(&self) -> Result<(), PlatformError> {
        if self.is_elevated() {
            return Ok(());
        }
        Err(PlatformError::PermissionDenied("Please run with sudo or as root".to_string()))
    }

    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        use std::ffi::CString;
        use std::mem;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::io::IntoRawFd;

        if let Some(requested_name) = config.name.as_deref() {
            if requested_name.is_empty() || requested_name.as_bytes().len() > 15 {
                return Err(PlatformError::DeviceError(format!(
                    "Interface name must contain 1-15 bytes, got {}",
                    requested_name.as_bytes().len()
                )));
            }
            if requested_name.contains('/') || requested_name.contains('\0') {
                return Err(PlatformError::DeviceError(
                    "Interface name contains a forbidden character".to_string(),
                ));
            }
            if Self::interface_exists(requested_name)? {
                return Err(PlatformError::DeviceError(format!(
                    "Linux TUN interface {} already exists",
                    requested_name
                )));
            }
        }

        let file = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun") {
            Ok(f) => f,
            Err(_) => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tun")
                .map_err(|e| PlatformError::DeviceError(e.to_string()))?,
        };

        let fd = file.as_raw_fd();
        // SAFETY: `IfReq` is a `#[repr(C)]` struct whose fields are a fixed-size C char
        // array and a c_short. Zero is a valid bit pattern for both, so zero-initializing
        // the struct is well-defined. The fields are overwritten before the ioctl call.
        let mut ifr: IfReq = unsafe { mem::zeroed() };
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if let Some(ref requested_name) = config.name {
            let c_name = CString::new(requested_name.as_str())
                .map_err(|e| PlatformError::DeviceError(e.to_string()))?;
            let bytes = c_name.as_bytes_with_nul();
            // Validate name fits in IFNAMSIZ (16) with null terminator
            if bytes.len() > ifr.ifr_name.len() {
                return Err(PlatformError::DeviceError(format!(
                    "Interface name too long: {} bytes (max {})",
                    bytes.len() - 1,
                    ifr.ifr_name.len() - 1
                )));
            }
            let len = bytes.len().min(ifr.ifr_name.len());
            for (dst, src) in ifr.ifr_name.iter_mut().zip(bytes.iter()).take(len) {
                *dst = *src as libc::c_char;
            }
            // Explicitly null-terminate and zero remaining bytes
            for byte in ifr.ifr_name.iter_mut().skip(len) {
                *byte = 0;
            }
        }
        // SAFETY: `fd` is a valid file descriptor opened from `/dev/net/tun` or
        // `/dev/tun` above and is still open at this point. `ifr` is a fully
        // initialized `#[repr(C)]` struct with the correct layout required by the
        // TUNSETIFF ioctl. The ioctl request code `TUNSETIFF` expects a pointer to
        // `struct ifreq`; our `IfReq` has the identical ABI layout.
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            return Err(PlatformError::DeviceError(std::io::Error::last_os_error().to_string()));
        }

        // Reconstruct name from ifr_name with explicit null-terminator search
        let name_len = ifr.ifr_name.iter().position(|&c| c == 0).unwrap_or(ifr.ifr_name.len());
        let name: String =
            ifr.ifr_name[..name_len].iter().map(|&c| char::from(c.to_ne_bytes()[0])).collect();
        if name.is_empty() {
            drop(file);
            return Err(PlatformError::DeviceError(
                "Kernel did not return a valid tunnel interface name".to_string(),
            ));
        }
        if let Some(requested_name) = config.name.as_deref() {
            if requested_name != name {
                drop(file);
                let cleanup = Self::remove_owned_interface(&name);
                return Err(match cleanup {
                    Ok(()) => PlatformError::DeviceError(format!(
                        "Kernel returned interface {}, requested {}",
                        name, requested_name
                    )),
                    Err(cleanup_error) => PlatformError::DeviceError(format!(
                        "Kernel returned interface {}, requested {}; rollback failed: {}",
                        name, requested_name, cleanup_error
                    )),
                });
            }
        }

        // Configure the device via ip commands
        if let Err(error) = self
            .run_ip(&["link", "set", &name, "up"])
            .and_then(|()| match config.address {
                IpAddr::V4(_) => self.run_ip(&[
                    "addr",
                    "add",
                    &format!("{}/{}", config.address, config.netmask),
                    "dev",
                    &name,
                ]),
                IpAddr::V6(_) => self.run_ip(&[
                    "-6",
                    "addr",
                    "add",
                    &format!("{}/{}", config.address, config.netmask),
                    "dev",
                    &name,
                ]),
            })
            .and_then(|()| self.run_ip(&["link", "set", &name, "mtu", &config.mtu.to_string()]))
        {
            drop(file);
            let cleanup = Self::remove_owned_interface(&name);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => PlatformError::DeviceError(format!(
                    "Linux TUN setup failed: {}; rollback failed: {}",
                    error, cleanup_error
                )),
            });
        }

        log::info!("Created TUN device {} with IP {}/{}", name, config.address, config.netmask);

        let c_name =
            CString::new(name.clone()).map_err(|e| PlatformError::DeviceError(e.to_string()))?;
        // SAFETY: `c_name` is a valid null-terminated C string created from a known-safe
        // interface name. It lives until the end of the statement. `if_nametoindex` only
        // reads the string and cannot cause UB regardless of the returned index value.
        let id = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if id == 0 {
            let error = std::io::Error::last_os_error();
            drop(file);
            let cleanup = Self::remove_owned_interface(&name);
            return Err(match cleanup {
                Ok(()) => {
                    PlatformError::DeviceError(format!("if_nametoindex({name}) failed: {error}"))
                }
                Err(cleanup_error) => PlatformError::DeviceError(format!(
                    "if_nametoindex({name}) failed: {error}; rollback failed: {cleanup_error}"
                )),
            });
        }
        self.set_active_tun_name(Some(name.clone()));

        Ok(TunHandle { name, id, fd: file.into_raw_fd() })
    }

    fn destroy_tun(&self, handle: &mut TunHandle) -> Result<(), PlatformError> {
        let mut command_failures = Vec::new();
        if let Err(e) = self.run_ip(&["link", "set", &handle.name, "down"]) {
            command_failures.push(e.to_string());
        }
        if let Err(e) = self.run_ip(&["link", "delete", &handle.name]) {
            command_failures.push(e.to_string());
        }

        // Close file descriptor
        // SAFETY: `handle.fd` is the raw file descriptor of the TUN device opened in
        // `create_tun`. A close error must not be retried because the descriptor
        // number may already have been released and reused.
        if handle.fd >= 0 {
            let close_result = unsafe { libc::close(handle.fd) };
            handle.fd = -1;
            if close_result != 0 {
                command_failures
                    .push(format!("close TUN descriptor: {}", std::io::Error::last_os_error()));
            }
        }

        if Self::interface_exists(&handle.name)? {
            return Err(PlatformError::DeviceError(format!(
                "owned TUN {} remains after descriptor close: {}",
                handle.name,
                command_failures.join("; ")
            )));
        }
        self.set_active_tun_name(None);
        log::info!("Destroyed TUN device {}", handle.name);
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        match (route.destination, route.gateway) {
            (IpAddr::V4(_), IpAddr::V4(_)) => self.run_ip(&[
                "route",
                "add",
                &format!("{}/{}", route.destination, route.prefix_len),
                "via",
                &route.gateway.to_string(),
                "metric",
                &route.metric.to_string(),
            ]),
            (IpAddr::V6(_), IpAddr::V6(_)) => self.run_ip(&[
                "-6",
                "route",
                "add",
                &format!("{}/{}", route.destination, route.prefix_len),
                "via",
                &route.gateway.to_string(),
                "metric",
                &route.metric.to_string(),
            ]),
            _ => Err(PlatformError::RoutingError(
                "Route destination and gateway IP families must match".to_string(),
            )),
        }
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        match route.destination {
            IpAddr::V4(_) => self.run_ip(&[
                "route",
                "del",
                &format!("{}/{}", route.destination, route.prefix_len),
                "via",
                &route.gateway.to_string(),
                "metric",
                &route.metric.to_string(),
            ]),
            IpAddr::V6(_) => self.run_ip(&[
                "-6",
                "route",
                "del",
                &format!("{}/{}", route.destination, route.prefix_len),
                "via",
                &route.gateway.to_string(),
                "metric",
                &route.metric.to_string(),
            ]),
        }
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        if config.servers.is_empty() {
            return Err(PlatformError::DnsError("At least one DNS server is required".to_string()));
        }
        let tun_name = self.active_tun_name()?;
        if self.has_systemd_resolved() {
            let server_args: Vec<String> = config.servers.iter().map(|s| s.to_string()).collect();
            let mut args = Vec::with_capacity(2 + server_args.len());
            args.push("dns".to_string());
            args.push(tun_name.clone());
            args.extend(server_args);
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            self.run_command("resolvectl", &arg_refs)?;

            if !config.search_domains.is_empty() {
                let mut dargs = Vec::with_capacity(2 + config.search_domains.len());
                dargs.push("domain".to_string());
                dargs.push(tun_name.clone());
                dargs.extend(config.search_domains.iter().cloned());
                let darg_refs: Vec<&str> = dargs.iter().map(String::as_str).collect();
                self.run_command("resolvectl", &darg_refs)?;
            }
        } else {
            let owner_marker = self.prepare_legacy_resolver_state()?;
            let mut content = String::new();
            content.push_str(&owner_marker);
            content.push('\n');
            for server in &config.servers {
                content.push_str(&format!("nameserver {}\n", server));
            }
            for domain in &config.search_domains {
                content.push_str(&format!("search {}\n", domain));
            }
            std::fs::write(RESOLV_CONF_PATH, content)
                .map_err(|e| PlatformError::DnsError(e.to_string()))?;
            let mut state = self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner());
            mark_resolv_conf_written(&mut state)?;
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        if self.has_systemd_resolved() {
            if let Ok(name) = self.active_tun_name() {
                self.run_command("resolvectl", &["revert", &name])?;
            }
        }
        let restore_result = self.restore_resolv_conf_from_backup();
        let release_result = self.release_resolver_lock();
        match (restore_result, release_result) {
            (Err(error), Err(release_error)) => Err(PlatformError::DnsError(format!(
                "restore DNS failed: {error}; release resolver lock failed: {release_error}"
            ))),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => {
                log::info!("DNS restored");
                Ok(())
            }
        }
    }

    fn set_dns_interface_name(&self, name: &str) {
        self.set_active_tun_name(Some(name.to_string()));
    }

    fn clear_dns_interface_name(&self) {
        self.set_active_tun_name(None);
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output =
            Command::new("ip").args(["route", "show", "default"]).output().map_err(|e| {
                PlatformError::CommandFailed(format!("ip default route inspect spawn: {e}"))
            })?;
        if !output.status.success() {
            return Err(PlatformError::CommandFailed(format!(
                "ip route show default returned status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "default via X.X.X.X ..."
        for (i, word) in stdout.split_whitespace().enumerate() {
            if word == "via" {
                if let Some(gw) = stdout.split_whitespace().nth(i + 1) {
                    if let Ok(ip) = gw.parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        let output_v6 =
            Command::new("ip").args(["-6", "route", "show", "default"]).output().map_err(|e| {
                PlatformError::CommandFailed(format!("ip IPv6 default route inspect spawn: {e}"))
            })?;
        if !output_v6.status.success() {
            return Err(PlatformError::CommandFailed(format!(
                "ip -6 route show default returned status {}: {}",
                output_v6.status,
                String::from_utf8_lossy(&output_v6.stderr).trim()
            )));
        }
        let stdout_v6 = String::from_utf8_lossy(&output_v6.stdout);
        for (i, word) in stdout_v6.split_whitespace().enumerate() {
            if word == "via" {
                if let Some(gw) = stdout_v6.split_whitespace().nth(i + 1) {
                    if let Ok(ip) = gw.parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(PlatformError::RoutingError("Could not detect default IPv4/IPv6 gateway".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_platform_name() {
        let platform = LinuxPlatform::new();
        assert_eq!(platform.name(), "Linux");
    }

    #[test]
    fn test_is_elevated_check() {
        let platform = LinuxPlatform::new();
        // This will return true if running as root, false otherwise
        let _ = platform.is_elevated();
    }
}

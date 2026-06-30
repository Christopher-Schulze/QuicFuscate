//! Linux platform implementation.

use super::traits::*;
use std::net::IpAddr;
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
    resolv_conf_backup: Mutex<Option<PathBuf>>,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self { tun_name: Mutex::new(None), resolv_conf_backup: Mutex::new(None) }
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
        let status = Command::new(cmd)
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;
        if status.success() {
            return Ok(());
        }
        Err(PlatformError::CommandFailed(format!("{} {} failed", cmd, args.join(" "))))
    }

    /// Run ip command.
    fn run_ip(&self, args: &[&str]) -> Result<(), PlatformError> {
        self.run_command("ip", args)
    }

    fn backup_resolv_conf_if_needed(&self) -> Result<(), PlatformError> {
        let mut guard = self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let src = Path::new(RESOLV_CONF_PATH);
        if !src.exists() {
            return Ok(());
        }
        let backup = PathBuf::from(RESOLV_CONF_BACKUP_PATH);
        std::fs::copy(src, &backup).map_err(|e| PlatformError::DnsError(e.to_string()))?;
        *guard = Some(backup);
        Ok(())
    }

    fn restore_resolv_conf_from_backup(&self) -> Result<(), PlatformError> {
        let backup = {
            let mut guard = self.resolv_conf_backup.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        let Some(path) = backup else {
            return Ok(());
        };
        if path.exists() {
            std::fs::copy(&path, RESOLV_CONF_PATH)
                .map_err(|e| PlatformError::DnsError(e.to_string()))?;
            if let Err(e) = std::fs::remove_file(path) {
                log::debug!("Failed to remove resolv.conf backup after restore: {}", e);
            }
        }
        Ok(())
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
            return Err(PlatformError::DeviceError(
                "Kernel did not return a valid tunnel interface name".to_string(),
            ));
        }

        // Configure the device via ip commands
        self.run_ip(&["link", "set", &name, "up"])?;
        match config.address {
            IpAddr::V4(_) => {
                self.run_ip(&[
                    "addr",
                    "add",
                    &format!("{}/{}", config.address, config.netmask),
                    "dev",
                    &name,
                ])?;
            }
            IpAddr::V6(_) => {
                self.run_ip(&[
                    "-6",
                    "addr",
                    "add",
                    &format!("{}/{}", config.address, config.netmask),
                    "dev",
                    &name,
                ])?;
            }
        }

        self.run_ip(&["link", "set", &name, "mtu", &config.mtu.to_string()])?;

        log::info!("Created TUN device {} with IP {}/{}", name, config.address, config.netmask);

        let c_name =
            CString::new(name.clone()).map_err(|e| PlatformError::DeviceError(e.to_string()))?;
        // SAFETY: `c_name` is a valid null-terminated C string created from a known-safe
        // interface name. It lives until the end of the statement. `if_nametoindex` only
        // reads the string and cannot cause UB regardless of the returned index value.
        let id = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        self.set_active_tun_name(Some(name.clone()));

        Ok(TunHandle { name, id, fd: file.into_raw_fd() })
    }

    fn destroy_tun(&self, handle: TunHandle) -> Result<(), PlatformError> {
        if let Err(e) = self.run_ip(&["link", "set", &handle.name, "down"]) {
            log::debug!("Failed to bring TUN {} down during destroy: {}", handle.name, e);
        }
        if let Err(e) = self.run_ip(&["link", "delete", &handle.name]) {
            log::debug!("Failed to delete TUN {} during destroy: {}", handle.name, e);
        }

        // Close file descriptor
        // SAFETY: `handle.fd` is the raw file descriptor of the TUN device opened in
        // `create_tun`. Ownership transfers into `TunHandle` at that point, and
        // `destroy_tun` is the single place where it is closed. The handle is consumed
        // by value, so it cannot be used again after this call.
        unsafe {
            libc::close(handle.fd);
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
            IpAddr::V4(_) => {
                if let Err(e) = self.run_ip(&[
                    "route",
                    "del",
                    &format!("{}/{}", route.destination, route.prefix_len),
                ]) {
                    log::debug!(
                        "Failed to remove IPv4 route {}/{}: {}",
                        route.destination,
                        route.prefix_len,
                        e
                    );
                }
            }
            IpAddr::V6(_) => {
                if let Err(e) = self.run_ip(&[
                    "-6",
                    "route",
                    "del",
                    &format!("{}/{}", route.destination, route.prefix_len),
                ]) {
                    log::debug!(
                        "Failed to remove IPv6 route {}/{}: {}",
                        route.destination,
                        route.prefix_len,
                        e
                    );
                }
            }
        }
        Ok(())
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
            self.backup_resolv_conf_if_needed()?;
            let mut content = String::new();
            for server in &config.servers {
                content.push_str(&format!("nameserver {}\n", server));
            }
            for domain in &config.search_domains {
                content.push_str(&format!("search {}\n", domain));
            }
            std::fs::write(RESOLV_CONF_PATH, content)
                .map_err(|e| PlatformError::DnsError(e.to_string()))?;
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        if self.has_systemd_resolved() {
            if let Ok(name) = self.active_tun_name() {
                if let Err(e) = self.run_command("resolvectl", &["revert", &name]) {
                    log::debug!("Failed to revert resolvectl DNS for {}: {}", name, e);
                }
            }
        }
        self.restore_resolv_conf_from_backup()?;
        log::info!("DNS restored");
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

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

        let output_v6 = Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;
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

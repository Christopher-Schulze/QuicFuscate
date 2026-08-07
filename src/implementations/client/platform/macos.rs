//! macOS platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// macOS kernel control socket constants (not exposed by libc crate)
// ---------------------------------------------------------------------------

/// Protocol for PF_SYSTEM control sockets.
const SYSPROTO_CONTROL: libc::c_int = 2;

/// Sub-address family: system control.
const AF_SYS_CONTROL: u16 = 2;

/// ioctl request to resolve a kernel control name to its ID.
/// Equivalent to `_IOWR('N', 3, struct ctl_info)` on macOS.
const CTLIOCGINFO: libc::c_ulong = 0xc064_6e03;

/// Kernel control name for utun devices.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// Kernel control info structure (passed to CTLIOCGINFO ioctl).
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// Socket address for kernel control sockets.
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// RAII guard that closes an fd on drop unless explicitly disarmed.
/// Prevents fd leaks when an intermediate step fails.
struct FdGuard {
    fd: libc::c_int,
    armed: bool,
}

impl FdGuard {
    fn new(fd: libc::c_int) -> Self {
        Self { fd, armed: true }
    }

    /// Disarm the guard so the fd will NOT be closed on drop.
    /// Call this once the fd has been successfully handed off.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.armed && self.fd >= 0 {
            if let Err(error) = crate::interface::close_owned_fd(&mut self.fd) {
                log::error!("close macOS compatibility TUN descriptor failed: {error}");
            }
        }
    }
}

/// macOS platform backend.
pub struct MacOSPlatform {
    utun_counter: std::sync::atomic::AtomicU32,
    dns_service: Mutex<Option<String>>,
    /// Original DNS servers saved before VPN connection for proper restore
    original_dns: Mutex<Option<Vec<String>>>,
}

impl MacOSPlatform {
    pub fn new() -> Self {
        Self {
            utun_counter: std::sync::atomic::AtomicU32::new(10),
            dns_service: Mutex::new(None),
            original_dns: Mutex::new(None),
        }
    }

    /// Run route command.
    fn run_route(&self, args: &[&str]) -> Result<(), PlatformError> {
        let output = Command::new("route")
            .args(args)
            .output()
            .map_err(|e| PlatformError::CommandFailed(format!("route spawn: {e}")))?;

        if !output.status.success() {
            return Err(PlatformError::CommandFailed(format!(
                "route {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Run ifconfig command.
    fn run_ifconfig(&self, args: &[&str]) -> Result<(), PlatformError> {
        let output = Command::new("ifconfig")
            .args(args)
            .output()
            .map_err(|e| PlatformError::CommandFailed(format!("ifconfig spawn: {e}")))?;

        if !output.status.success() {
            return Err(PlatformError::CommandFailed(format!(
                "ifconfig {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn run_networksetup(&self, args: &[&str]) -> Result<(), PlatformError> {
        let output = Command::new("networksetup")
            .args(args)
            .output()
            .map_err(|e| PlatformError::DnsError(format!("networksetup spawn: {e}")))?;
        if !output.status.success() {
            return Err(PlatformError::DnsError(format!(
                "networksetup {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn interface_exists(&self, name: &str) -> Result<bool, PlatformError> {
        let output = Command::new("ifconfig").arg(name).output().map_err(|error| {
            PlatformError::CommandFailed(format!("ifconfig inspect spawn: {error}"))
        })?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("does not exist") || stderr.contains("interface not found") {
            return Ok(false);
        }
        Err(PlatformError::CommandFailed(format!(
            "ifconfig {} inspect returned status {}: {}",
            name,
            output.status,
            stderr.trim()
        )))
    }

    fn detect_default_interface(&self) -> Result<String, PlatformError> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("interface:") {
                let iface = rest.trim();
                if !iface.is_empty() {
                    return Ok(iface.to_string());
                }
            }
        }
        Err(PlatformError::DnsError("Could not determine default network interface".to_string()))
    }

    fn resolve_network_service_for_device(&self, device: &str) -> Result<String, PlatformError> {
        let output = Command::new("networksetup")
            .args(["-listnetworkserviceorder"])
            .output()
            .map_err(|e| PlatformError::DnsError(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut current_service: Option<String> = None;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('(') && trimmed.contains("Hardware Port:") {
                if let Some(idx) = trimmed.find("Device:") {
                    let dev = trimmed[idx + "Device:".len()..].trim().trim_end_matches(')').trim();
                    if dev == device {
                        if let Some(service) = current_service {
                            return Ok(service);
                        }
                    }
                }
                continue;
            }

            if let Some(pos) = trimmed.find(')') {
                let service = trimmed[pos + 1..].trim().trim_start_matches('*').trim();
                if !service.is_empty() {
                    current_service = Some(service.to_string());
                }
            }
        }

        Err(PlatformError::DnsError(format!(
            "Could not map interface '{}' to a network service",
            device
        )))
    }

    fn dns_service_name(&self) -> Result<String, PlatformError> {
        if let Some(existing) = self.dns_service.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(existing);
        }
        let iface = self.detect_default_interface()?;
        let service = self.resolve_network_service_for_device(&iface)?;
        *self.dns_service.lock().unwrap_or_else(|e| e.into_inner()) = Some(service.clone());
        Ok(service)
    }

    /// Capture current DNS servers for a given network service.
    fn capture_current_dns(&self, service: &str) -> Vec<String> {
        let output = match Command::new("networksetup").args(["-getdnsservers", service]).output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        // "There aren't any DNS Servers set on ..." means DHCP - return empty
        if stdout.contains("There aren't any DNS Servers") {
            return Vec::new();
        }
        stdout.lines().filter(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()).collect()
    }

    fn prefix_to_netmask(prefix: u8) -> String {
        if prefix == 0 {
            return "0.0.0.0".to_string();
        }
        if prefix >= 32 {
            return "255.255.255.255".to_string();
        }
        let mask: u32 = !((1u32 << (32 - prefix)) - 1);
        format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        )
    }
}

impl Default for MacOSPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for MacOSPlatform {
    fn name(&self) -> &'static str {
        "macOS"
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
        Err(PlatformError::PermissionDenied("Please run with sudo".to_string()))
    }

    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        // macOS utun creation: full kernel control socket sequence.
        //
        // 1. socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        // 2. ioctl(CTLIOCGINFO) to resolve "com.apple.net.utun_control" -> ctl_id
        // 3. connect() with sockaddr_ctl (sc_id, sc_unit = utun_number + 1)
        // 4. Set non-blocking
        //
        // The sc_unit field determines the utun interface number:
        //   sc_unit = 0 -> kernel picks the next available utun number
        //   sc_unit = N -> creates utun(N-1)

        let utun_num = self.utun_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Step 1: Create PF_SYSTEM control socket
        // SAFETY: `socket()` is a standard POSIX syscall with well-defined semantics.
        // The arguments are valid constants (PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL).
        // The returned fd is checked for < 0 immediately below; on error it equals -1
        // which the OS guarantees is not a valid fd, so no resource is created.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(PlatformError::DeviceError(format!(
                "Failed to create utun socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut guard = FdGuard::new(fd);

        // Step 2: Resolve "com.apple.net.utun_control" to a kernel control ID
        // SAFETY: `CtlInfo` is a `#[repr(C)]` struct containing only a u32 and a fixed
        // C char array. Zero is a valid bit pattern for both. We overwrite `ctl_name`
        // with the control name bytes before passing it to the kernel. `fd` is valid
        // (checked above) and `CTLIOCGINFO` expects a pointer to `struct ctl_info`
        // with the identical layout. On failure we return early via `?` before using
        // the partially-filled struct.
        let ctl_id = unsafe {
            let mut info: CtlInfo = std::mem::zeroed();
            // Copy control name into the fixed-size buffer
            let name_len = UTUN_CONTROL_NAME.len().min(info.ctl_name.len());
            info.ctl_name[..name_len].copy_from_slice(&UTUN_CONTROL_NAME[..name_len]);

            if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) < 0 {
                return Err(PlatformError::DeviceError(format!(
                    "ioctl CTLIOCGINFO failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            info.ctl_id
        };

        // Step 3: Connect with sockaddr_ctl to create the utun interface
        // sc_unit = utun_num + 1 (unit 0 means "auto-assign", unit N creates utun(N-1))
        let sc_unit = utun_num + 1;
        // SAFETY: `SockaddrCtl` is a `#[repr(C)]` struct with the exact layout required
        // by the macOS kernel control socket API. `fd` is a valid PF_SYSTEM socket (the
        // FdGuard is still armed). We cast `&addr` to `*const libc::sockaddr`, which is
        // the standard C idiom for `connect()`; the kernel only reads `sc_len` bytes.
        // On failure we return an error before the fd is used further.
        unsafe {
            let addr = SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: ctl_id,
                sc_unit,
                sc_reserved: [0; 5],
            };

            let ret = libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(PlatformError::DeviceError(format!(
                    "connect() for utun{} (sc_unit={}) failed: {}",
                    utun_num,
                    sc_unit,
                    std::io::Error::last_os_error()
                )));
            }
        }

        // Step 4: Set socket to non-blocking mode
        // SAFETY: `fd` is a valid, connected PF_SYSTEM socket (guard is still armed).
        // `F_GETFL` / `F_SETFL` are standard POSIX fcntl commands that cannot cause UB.
        // Adding `O_NONBLOCK` to the existing flags is the conventional idiom for
        // non-blocking I/O; no other invariants of the socket are affected.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(PlatformError::DeviceError(format!(
                    "fcntl F_GETFL failed on utun{}: {}",
                    utun_num,
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(PlatformError::DeviceError(format!(
                    "fcntl F_SETFL O_NONBLOCK failed on utun{}: {}",
                    utun_num,
                    std::io::Error::last_os_error()
                )));
            }
        }

        let name = format!("utun{}", utun_num);

        // Configure the interface (IP, netmask, MTU, bring up)
        self.run_ifconfig(&[
            &name,
            &config.address.to_string(),
            &config.address.to_string(), // Point-to-point destination
            "netmask",
            &Self::prefix_to_netmask(config.netmask),
            "mtu",
            &config.mtu.to_string(),
            "up",
        ])?;

        // Socket and interface configuration are complete. Ownership now moves
        // into the returned handle; every earlier error stays covered by the
        // descriptor guard.
        guard.disarm();

        log::info!(
            "Created utun device {} (ctl_id={}, sc_unit={}) with IP {}",
            name,
            ctl_id,
            sc_unit,
            config.address
        );

        Ok(TunHandle { name, id: utun_num, fd })
    }

    fn destroy_tun(&self, handle: &mut TunHandle) -> Result<(), PlatformError> {
        let down_error = self.run_ifconfig(&[&handle.name, "down"]).err();

        let close_error = handle
            .close_fd()
            .err()
            .map(|error| format!("close owned utun descriptor {}: {error}", handle.name));
        if self.interface_exists(&handle.name)? {
            return Err(PlatformError::DeviceError(format!(
                "owned utun {} remains after descriptor close{}{}",
                handle.name,
                down_error.map_or_else(String::new, |error| format!("; down failed: {error}")),
                close_error.map_or_else(String::new, |error| format!("; {error}"))
            )));
        }

        log::info!("Destroyed utun device {}", handle.name);
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        self.run_route(&[
            "-n",
            "add",
            "-net",
            &format!("{}/{}", route.destination, route.prefix_len),
            &route.gateway.to_string(),
        ])
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        self.run_route(&[
            "-n",
            "delete",
            "-net",
            &format!("{}/{}", route.destination, route.prefix_len),
            &route.gateway.to_string(),
        ])
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        let service = self.dns_service_name()?;

        // Save original DNS servers before overwriting (only if not already saved)
        {
            let mut guard = self.original_dns.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                let current = self.capture_current_dns(&service);
                *guard = Some(current);
                log::debug!("Saved original DNS servers: {:?}", guard.as_ref());
            }
        }

        let mut args = vec!["-setdnsservers".to_string(), service];
        args.extend(config.servers.iter().map(|s| s.to_string()));
        if config.servers.is_empty() {
            args.push("Empty".to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_networksetup(&arg_refs)?;

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        let service = self.dns_service_name()?;

        // Restore original DNS servers instead of blindly resetting to DHCP
        let saved = self.original_dns.lock().unwrap_or_else(|e| e.into_inner()).clone();

        match saved {
            Some(servers) if !servers.is_empty() => {
                // Restore the exact original DNS servers
                let mut args = vec!["-setdnsservers", &service];
                let server_refs: Vec<&str> = servers.iter().map(String::as_str).collect();
                args.extend(server_refs);
                self.run_networksetup(&args)?;
                log::info!("DNS restored to original servers: {:?}", servers);
            }
            _ => {
                // Original was DHCP (no DNS set) - "Empty" is correct here
                self.run_networksetup(&["-setdnsservers", &service, "Empty"])?;
                log::info!("DNS restored to DHCP (original state)");
            }
        }

        *self.original_dns.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "gateway: X.X.X.X"
        for line in stdout.lines() {
            if line.trim().starts_with("gateway:") {
                if let Some(gw) = line.split(':').nth(1) {
                    if let Ok(ip) = gw.trim().parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(PlatformError::RoutingError("Could not detect default gateway".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_platform_name() {
        let platform = MacOSPlatform::new();
        assert_eq!(platform.name(), "macOS");
    }
}

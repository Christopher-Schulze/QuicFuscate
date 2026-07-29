//! Windows platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

/// Windows platform backend.
pub struct WindowsPlatform {
    tun_interface: Mutex<Option<String>>,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        Self { tun_interface: Mutex::new(None) }
    }

    /// Run netsh command.
    fn run_netsh(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("netsh")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!("netsh {} failed", args.join(" "))));
        }
        Ok(())
    }

    /// Run route command.
    fn run_route(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("route")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!("route {} failed", args.join(" "))));
        }
        Ok(())
    }

    fn interface_exists(&self, name: &str) -> Result<bool, PlatformError> {
        let output = Command::new("netsh")
            .args(["interface", "show", "interface", &format!("name=\"{}\"", name)])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(output.status.success() && stdout.contains(name))
    }

    fn set_active_interface(&self, name: Option<String>) {
        *self.tun_interface.lock().unwrap_or_else(|e| e.into_inner()) = name;
    }

    fn active_interface(&self) -> Result<String, PlatformError> {
        self.tun_interface.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| {
            PlatformError::DnsError(
                "No active tunnel interface available for DNS setup".to_string(),
            )
        })
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for WindowsPlatform {
    fn name(&self) -> &'static str {
        "Windows"
    }

    fn is_elevated(&self) -> bool {
        // `net session` requires Administrator privileges.
        let output = Command::new("net").args(["session"]).output();

        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    fn request_elevation(&self) -> Result<(), PlatformError> {
        if self.is_elevated() {
            return Ok(());
        }
        Err(PlatformError::PermissionDenied("Please run as Administrator".to_string()))
    }

    /// Create and configure a TUN device on Windows.
    ///
    /// # WinTUN Prerequisite
    ///
    /// Windows does not ship with a built-in TUN driver. The WinTUN driver must
    /// be installed before QuicFuscate can create tunnel interfaces:
    ///
    /// 1. Download the WinTUN driver from <https://www.wintun.net/>
    /// 2. Install the driver (requires Administrator privileges)
    /// 3. Create a TUN adapter named "QuicFuscate" (or the name in your config)
    ///
    /// Without WinTUN, this function returns `PlatformError::Unsupported` with
    /// a descriptive message including the download URL.
    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        let name = config.name.clone().unwrap_or_else(|| "QuicFuscate".to_string());

        if !self.interface_exists(&name)? {
            return Err(PlatformError::Unsupported(format!(
                "TUN interface '{}' not found. The WinTUN driver is required on Windows.\n\
                 \n\
                 To fix this:\n\
                 1. Download WinTUN from https://www.wintun.net/\n\
                 2. Install the driver (requires Administrator)\n\
                 3. Create a TUN adapter named '{}'\n\
                 4. Run QuicFuscate as Administrator",
                name, name
            )));
        }

        log::info!("Configuring tunnel interface: {}", name);

        // Configure IP address via netsh
        self.run_netsh(&[
            "interface",
            "ip",
            "set",
            "address",
            &format!("name=\"{}\"", name),
            "static",
            &config.address.to_string(),
            &prefix_to_netmask(config.netmask),
        ])?;
        self.set_active_interface(Some(name.clone()));

        log::info!("Created TUN device {} with IP {}", name, config.address);

        Ok(TunHandle { name, id: 0, handle: 0 })
    }

    fn destroy_tun(&self, handle: &mut TunHandle) -> Result<(), PlatformError> {
        self.set_active_interface(None);
        log::info!(
            "Released TUN adapter reference {} without modifying shared adapter state",
            handle.name
        );
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        // Calculate netmask from prefix length
        let netmask = prefix_to_netmask(route.prefix_len);

        self.run_route(&[
            "add",
            &route.destination.to_string(),
            "mask",
            &netmask,
            &route.gateway.to_string(),
            "metric",
            &route.metric.to_string(),
        ])
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        self.run_route(&[
            "delete",
            &route.destination.to_string(),
            "mask",
            &prefix_to_netmask(route.prefix_len),
            &route.gateway.to_string(),
        ])
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        let interface = self.active_interface()?;

        // Set primary DNS
        if let Some(primary) = config.servers.first() {
            self.run_netsh(&[
                "interface",
                "ip",
                "set",
                "dns",
                &format!("name=\"{}\"", interface),
                "static",
                &primary.to_string(),
            ])?;
        }

        // Add secondary DNS servers
        for (idx, dns) in config.servers.iter().enumerate().skip(1) {
            self.run_netsh(&[
                "interface",
                "ip",
                "add",
                "dns",
                &format!("name=\"{}\"", interface),
                &dns.to_string(),
                &format!("index={}", idx + 1),
            ])?;
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        // Reset DNS to DHCP
        let interface = self.active_interface()?;
        self.run_netsh(&[
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name=\"{}\"", interface),
            "dhcp",
        ])?;

        log::info!("DNS restored to DHCP");
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse Windows route table output
        for line in stdout.lines() {
            if line.contains("0.0.0.0") && !line.contains("On-link") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(ip) = parts[2].parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(PlatformError::RoutingError("Could not detect default gateway".to_string()))
    }
}

/// Convert CIDR prefix length to dotted netmask.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_platform_name() {
        let platform = WindowsPlatform::new();
        assert_eq!(platform.name(), "Windows");
    }

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }
}

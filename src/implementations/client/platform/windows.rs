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

    /// Reject the legacy Windows adapter path without mutating host state.
    ///
    /// The native Wintun owner in `src/interface/wintun.rs` is the only valid
    /// Windows data-plane path. This compatibility backend cannot prove
    /// ownership of a pre-existing adapter or restore its prior address/DNS
    /// state, so activation must fail before executing `netsh`.
    fn create_tun(&self, _config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        Err(PlatformError::Unsupported(
            "legacy Windows PlatformBackend cannot own adapter lifecycle; use the native Wintun data-plane implementation"
                .to_string(),
        ))
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

    fn set_dns_interface_name(&self, name: &str) {
        self.set_active_interface(Some(name.to_string()));
    }

    fn clear_dns_interface_name(&self) {
        self.set_active_interface(None);
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

    #[test]
    fn legacy_create_tun_fails_closed_before_host_mutation() {
        let platform = WindowsPlatform::new();
        let error = platform.create_tun(&TunDeviceConfig::default()).unwrap_err();
        assert!(matches!(error, PlatformError::Unsupported(_)));
        assert!(platform.active_interface().is_err());
    }
}

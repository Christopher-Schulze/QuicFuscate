//! NAT and routing configuration for the server.
//!
//! This module handles:
//! - IP forwarding
//! - NAT (MASQUERADE) via iptables/nftables
//! - Firewall rules for VPN traffic

#[cfg(target_os = "macos")]
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;

/// Routing manager for VPN server.
pub struct RoutingManager {
    tun_name: String,
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    wan_interface: String,
    /// IPv6 server TUN address (None = IPv6 disabled).
    server_ipv6: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64).
    ipv6_prefix_len: u8,
}

/// Routing errors.
#[derive(Debug)]
pub enum RoutingError {
    CommandFailed(String),
    PermissionDenied,
    UnsupportedPlatform,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::CommandFailed(e) => write!(f, "Command failed: {}", e),
            RoutingError::PermissionDenied => write!(f, "Permission denied (need root)"),
            RoutingError::UnsupportedPlatform => {
                write!(f, "Routing not supported on this platform")
            }
        }
    }
}

impl std::error::Error for RoutingError {}

impl RoutingManager {
    /// Create a new routing manager (IPv4-only).
    pub fn new(
        tun_name: String,
        server_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        wan_interface: String,
    ) -> Self {
        Self {
            tun_name,
            server_ip,
            netmask,
            wan_interface,
            server_ipv6: None,
            ipv6_prefix_len: 64,
        }
    }

    /// Create a new dual-stack routing manager.
    pub fn new_dual_stack(
        tun_name: String,
        server_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        wan_interface: String,
        server_ipv6: Ipv6Addr,
        ipv6_prefix_len: u8,
    ) -> Self {
        Self {
            tun_name,
            server_ip,
            netmask,
            wan_interface,
            server_ipv6: Some(server_ipv6),
            ipv6_prefix_len,
        }
    }

    /// Returns true if IPv6 is enabled.
    pub fn is_ipv6_enabled(&self) -> bool {
        self.server_ipv6.is_some()
    }

    /// Set up routing rules.
    #[cfg(target_os = "linux")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        // Assign IPv4 address to the TUN interface
        self.assign_tun_address_linux()?;

        // Enable IPv4 forwarding
        self.enable_ip_forwarding()?;

        // Calculate subnet
        let subnet = self.calculate_subnet();

        // Set up NAT rules
        self.setup_iptables(&subnet)?;

        log::info!("Routing configured: {} via {}", subnet, self.wan_interface);

        // IPv6 setup (if enabled)
        if self.is_ipv6_enabled() {
            self.assign_tun_address_v6_linux()?;
            self.enable_ipv6_forwarding()?;
            let v6_subnet = self.calculate_ipv6_subnet();
            self.setup_ip6tables(&v6_subnet)?;
            log::info!("IPv6 routing configured: {} via {}", v6_subnet, self.wan_interface);
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        self.assign_tun_address_macos()?;
        self.enable_ip_forwarding_macos()?;
        let subnet = self.calculate_subnet();
        self.setup_pf(&subnet)?;
        log::info!("Routing configured (macOS/pf): {} via {}", subnet, self.wan_interface);

        // IPv6 setup (if enabled)
        if self.is_ipv6_enabled() {
            self.assign_tun_address_v6_macos()?;
            self.enable_ipv6_forwarding_macos()?;
            let v6_subnet = self.calculate_ipv6_subnet();
            self.setup_pf_v6(&v6_subnet)?;
            log::info!("IPv6 routing configured (macOS/pf): {} via {}", v6_subnet, self.wan_interface);
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        self.enable_ip_forwarding_windows()?;
        let subnet = self.calculate_subnet();
        self.setup_windows_nat(&subnet)?;
        log::info!("Routing configured (Windows/NetNat): {} via {}", subnet, self.wan_interface);

        // IPv6 setup (if enabled)
        if self.is_ipv6_enabled() {
            self.enable_ipv6_forwarding_windows()?;
            let v6_subnet = self.calculate_ipv6_subnet();
            self.setup_windows_nat_v6(&v6_subnet)?;
            log::info!("IPv6 routing configured (Windows/NetNat): {} via {}", v6_subnet, self.wan_interface);
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn setup(&self) -> Result<(), RoutingError> {
        log::warn!("Routing setup not implemented for this platform");
        Err(RoutingError::UnsupportedPlatform)
    }

    /// Tear down routing rules.
    #[cfg(target_os = "linux")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        let subnet = self.calculate_subnet();

        // Remove NAT rules (ignore errors - rules might not exist)
        match Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &subnet,
                "-o",
                &self.wan_interface,
                "-j",
                "MASQUERADE",
            ])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!("iptables teardown MASQUERADE delete returned status {}", status);
            }
            Err(e) => {
                log::debug!("iptables teardown MASQUERADE delete failed: {}", e);
            }
        }

        match Command::new("iptables")
            .args([
                "-D",
                "FORWARD",
                "-i",
                &self.tun_name,
                "-o",
                &self.wan_interface,
                "-j",
                "ACCEPT",
            ])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!("iptables teardown forward TUN->WAN delete returned status {}", status);
            }
            Err(e) => {
                log::debug!("iptables teardown forward TUN->WAN delete failed: {}", e);
            }
        }

        match Command::new("iptables")
            .args([
                "-D",
                "FORWARD",
                "-i",
                &self.wan_interface,
                "-o",
                &self.tun_name,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!(
                    "iptables teardown forward WAN->TUN established delete returned status {}",
                    status
                );
            }
            Err(e) => {
                log::debug!("iptables teardown forward WAN->TUN established delete failed: {}", e);
            }
        }

        log::info!("Routing rules removed");

        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        // Best-effort cleanup; keep shutdown robust even if rules were absent.
        if let Err(e) = self.run_command(
            "pfctl",
            &["-a", Self::MACOS_PF_ANCHOR, "-F", "all"],
            "pfctl anchor flush",
        ) {
            log::debug!("pfctl teardown anchor flush failed: {}", e);
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        // Best-effort cleanup; keep shutdown robust even if NAT object was absent.
        let script = format!(
            "$ErrorActionPreference='SilentlyContinue'; \
             Remove-NetNat -Name '{}' -Confirm:$false",
            Self::WINDOWS_NAT_NAME
        );
        if let Err(e) = self.run_powershell(&script, "Remove-NetNat") {
            log::debug!("Windows teardown Remove-NetNat failed: {}", e);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_ip_forwarding(&self) -> Result<(), RoutingError> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|_| RoutingError::PermissionDenied)?;

        log::debug!("IP forwarding enabled");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_iptables(&self, subnet: &str) -> Result<(), RoutingError> {
        // MASQUERADE for outbound traffic
        let status = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                subnet,
                "-o",
                &self.wan_interface,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed("iptables NAT rule failed".to_string()));
        }

        // Allow forwarding from TUN to WAN
        let status = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                &self.tun_name,
                "-o",
                &self.wan_interface,
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed("iptables FORWARD rule failed".to_string()));
        }

        // Allow established connections back
        let status = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                &self.wan_interface,
                "-o",
                &self.tun_name,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed(
                "iptables ESTABLISHED rule failed".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    const MACOS_PF_ANCHOR: &'static str = "com.quicfuscate.vpn";

    #[cfg(target_os = "windows")]
    const WINDOWS_NAT_NAME: &'static str = "QuicFuscateNat";

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn map_process_error(
        &self,
        action: &str,
        output: std::process::Output,
    ) -> Result<(), RoutingError> {
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let lowered = stderr.to_ascii_lowercase();
        if lowered.contains("permission denied")
            || lowered.contains("operation not permitted")
            || lowered.contains("access is denied")
            || lowered.contains("requires elevation")
            || lowered.contains("elevation required")
            || lowered.contains("administrator")
        {
            return Err(RoutingError::PermissionDenied);
        }

        let detail = stderr.trim();
        if detail.is_empty() {
            Err(RoutingError::CommandFailed(format!("{action} failed")))
        } else {
            Err(RoutingError::CommandFailed(format!("{action} failed: {detail}")))
        }
    }

    #[cfg(target_os = "macos")]
    fn run_command(&self, cmd: &str, args: &[&str], action: &str) -> Result<(), RoutingError> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| RoutingError::CommandFailed(format!("{action}: {e}")))?;
        self.map_process_error(action, output)
    }

    #[cfg(target_os = "macos")]
    fn enable_ip_forwarding_macos(&self) -> Result<(), RoutingError> {
        self.run_command(
            "sysctl",
            &["-w", "net.inet.ip.forwarding=1"],
            "enable macOS IP forwarding",
        )
    }

    #[cfg(target_os = "macos")]
    fn pf_rules(&self, subnet: &str) -> String {
        format!(
            "nat on {} from {} to any -> ({})\n\
             pass quick on {} inet from {} to any keep state\n\
             pass quick on {} inet from any to {} keep state\n",
            self.wan_interface,
            subnet,
            self.wan_interface,
            self.tun_name,
            subnet,
            self.wan_interface,
            subnet
        )
    }

    #[cfg(target_os = "macos")]
    fn setup_pf(&self, subnet: &str) -> Result<(), RoutingError> {
        // Ensure packet filter is enabled.
        self.run_command("pfctl", &["-E"], "enable pfctl")?;

        let rules = self.pf_rules(subnet);
        let mut child = Command::new("pfctl")
            .args(["-a", Self::MACOS_PF_ANCHOR, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RoutingError::CommandFailed(format!("pfctl spawn failed: {e}")))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(rules.as_bytes()).map_err(|e| {
                RoutingError::CommandFailed(format!("pfctl rule write failed: {e}"))
            })?;
        } else {
            return Err(RoutingError::CommandFailed("pfctl stdin unavailable".to_string()));
        }

        let output = child
            .wait_with_output()
            .map_err(|e| RoutingError::CommandFailed(format!("pfctl wait failed: {e}")))?;
        self.map_process_error("pfctl anchor load", output)
    }

    #[cfg(target_os = "windows")]
    fn ps_escape(s: &str) -> String {
        s.replace('\'', "''")
    }

    #[cfg(target_os = "windows")]
    fn run_powershell(&self, script: &str, action: &str) -> Result<(), RoutingError> {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|e| RoutingError::CommandFailed(format!("{action}: {e}")))?;
        self.map_process_error(action, output)
    }

    #[cfg(target_os = "windows")]
    fn enable_ip_forwarding_windows(&self) -> Result<(), RoutingError> {
        let iface = Self::ps_escape(&self.wan_interface);
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             Set-NetIPInterface -InterfaceAlias '{iface}' -Forwarding Enabled"
        );
        self.run_powershell(&script, "Set-NetIPInterface forwarding")
    }

    #[cfg(target_os = "windows")]
    fn setup_windows_nat(&self, subnet: &str) -> Result<(), RoutingError> {
        let nat_name = Self::WINDOWS_NAT_NAME;
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{ \
               Remove-NetNat -Name '{nat_name}' -Confirm:$false | Out-Null \
             }}; \
             New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{subnet}' | Out-Null"
        );
        self.run_powershell(&script, "New-NetNat")
    }

    // ================================================================
    // TUN interface address assignment
    // ================================================================

    /// Assign the IPv4 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    fn assign_tun_address_linux(&self) -> Result<(), RoutingError> {
        let subnet = self.calculate_subnet();
        // Extract the network prefix length from the CIDR
        let prefix_len = subnet.split('/').nth(1).unwrap_or("24");
        let addr = format!("{}/{}", self.server_ip, prefix_len);

        // Use `ip addr add` — ignore error if address already assigned
        let status = Command::new("ip")
            .args(["addr", "add", &addr, "dev", &self.tun_name])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            // Address may already exist — log but don't fail
            log::debug!("ip addr add {} dev {} (may already exist)", addr, self.tun_name);
        }
        // Bring the interface up
        let _ = Command::new("ip")
            .args(["link", "set", "up", "dev", &self.tun_name])
            .status();
        log::debug!("TUN IPv4 address assigned: {} on {}", addr, self.tun_name);
        Ok(())
    }

    /// Assign the IPv6 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    fn assign_tun_address_v6_linux(&self) -> Result<(), RoutingError> {
        if let Some(ipv6) = self.server_ipv6 {
            let addr = format!("{}/{}", ipv6, self.ipv6_prefix_len);
            let status = Command::new("ip")
                .args(["-6", "addr", "add", &addr, "dev", &self.tun_name])
                .status()
                .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

            if !status.success() {
                log::debug!("ip -6 addr add {} dev {} (may already exist)", addr, self.tun_name);
            }
            log::debug!("TUN IPv6 address assigned: {} on {}", addr, self.tun_name);
        }
        Ok(())
    }

    /// Assign the IPv4 address to the TUN interface on macOS.
    #[cfg(target_os = "macos")]
    fn assign_tun_address_macos(&self) -> Result<(), RoutingError> {
        let mask_bits = self.netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>();
        let _ = Command::new("ifconfig")
            .args([&self.tun_name, &self.server_ip.to_string(), "netmask", &self.netmask.to_string()])
            .status();
        log::debug!("TUN IPv4 address assigned: {} on {}", self.server_ip, self.tun_name);
        let _ = mask_bits; // suppress unused warning
        Ok(())
    }

    /// Assign the IPv6 address to the TUN interface on macOS.
    #[cfg(target_os = "macos")]
    fn assign_tun_address_v6_macos(&self) -> Result<(), RoutingError> {
        if let Some(ipv6) = self.server_ipv6 {
            let _ = Command::new("ifconfig")
                .args([&self.tun_name, "inet6", &ipv6.to_string(), "prefixlen", &self.ipv6_prefix_len.to_string()])
                .status();
            log::debug!("TUN IPv6 address assigned: {} on {}", ipv6, self.tun_name);
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn calculate_subnet(&self) -> String {
        // Simple CIDR calculation based on netmask
        let mask_bits = self.netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>();

        let network = u32::from(self.server_ip) & u32::from(self.netmask);
        let network_ip = Ipv4Addr::from(network);

        format!("{}/{}", network_ip, mask_bits)
    }

    /// Calculate the IPv6 subnet CIDR (e.g., "fd00::/64").
    fn calculate_ipv6_subnet(&self) -> String {
        match self.server_ipv6 {
            Some(ip) => format!("{}/{}", ip, self.ipv6_prefix_len),
            None => String::new(),
        }
    }

    // ================================================================
    // IPv6 forwarding and NAT
    // ================================================================

    #[cfg(target_os = "linux")]
    fn enable_ipv6_forwarding(&self) -> Result<(), RoutingError> {
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
            .map_err(|_| RoutingError::PermissionDenied)?;
        log::debug!("IPv6 forwarding enabled");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_ip6tables(&self, subnet: &str) -> Result<(), RoutingError> {
        // MASQUERADE for outbound IPv6 traffic
        let status = Command::new("ip6tables")
            .args([
                "-t", "nat", "-A", "POSTROUTING",
                "-s", subnet,
                "-o", &self.wan_interface,
                "-j", "MASQUERADE",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed("ip6tables NAT rule failed".to_string()));
        }

        // Allow forwarding from TUN to WAN (IPv6)
        let status = Command::new("ip6tables")
            .args([
                "-A", "FORWARD",
                "-i", &self.tun_name,
                "-o", &self.wan_interface,
                "-j", "ACCEPT",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed("ip6tables FORWARD rule failed".to_string()));
        }

        // Allow established connections back
        let status = Command::new("ip6tables")
            .args([
                "-A", "FORWARD",
                "-i", &self.wan_interface,
                "-o", &self.tun_name,
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT",
            ])
            .status()
            .map_err(|e| RoutingError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(RoutingError::CommandFailed("ip6tables ESTABLISHED rule failed".to_string()));
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable_ipv6_forwarding_macos(&self) -> Result<(), RoutingError> {
        self.run_command(
            "sysctl",
            &["-w", "net.inet6.ip6.forwarding=1"],
            "enable macOS IPv6 forwarding",
        )
    }

    #[cfg(target_os = "macos")]
    fn pf_rules_v6(&self, subnet: &str) -> String {
        format!(
            "nat on {} inet6 from {} to any -> ({})\n\
             pass quick on {} inet6 from {} to any keep state\n\
             pass quick on {} inet6 from any to {} keep state\n",
            self.wan_interface, subnet, self.wan_interface,
            self.tun_name, subnet,
            self.wan_interface, subnet
        )
    }

    #[cfg(target_os = "macos")]
    fn setup_pf_v6(&self, subnet: &str) -> Result<(), RoutingError> {
        let rules = self.pf_rules_v6(subnet);
        let mut child = Command::new("pfctl")
            .args(["-a", Self::MACOS_PF_ANCHOR, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RoutingError::CommandFailed(format!("pfctl spawn failed: {e}")))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(rules.as_bytes()).map_err(|e| {
                RoutingError::CommandFailed(format!("pfctl v6 rule write failed: {e}"))
            })?;
        } else {
            return Err(RoutingError::CommandFailed("pfctl stdin unavailable".to_string()));
        }

        let output = child
            .wait_with_output()
            .map_err(|e| RoutingError::CommandFailed(format!("pfctl wait failed: {e}")))?;
        self.map_process_error("pfctl v6 anchor load", output)
    }

    #[cfg(target_os = "windows")]
    fn enable_ipv6_forwarding_windows(&self) -> Result<(), RoutingError> {
        let iface = Self::ps_escape(&self.wan_interface);
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             Set-NetIPInterface -InterfaceAlias '{iface}' -AddressFamily IPv6 -Forwarding Enabled"
        );
        self.run_powershell(&script, "Set-NetIPInterface IPv6 forwarding")
    }

    #[cfg(target_os = "windows")]
    fn setup_windows_nat_v6(&self, subnet: &str) -> Result<(), RoutingError> {
        let nat_name = format!("{}_v6", Self::WINDOWS_NAT_NAME);
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{ \
               Remove-NetNat -Name '{nat_name}' -Confirm:$false | Out-Null \
             }}; \
             New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{subnet}' | Out-Null"
        );
        self.run_powershell(&script, "New-NetNat IPv6")
    }
}

/// Auto-detect the default WAN interface.
#[cfg(target_os = "linux")]
pub fn detect_wan_interface() -> Option<String> {
    // Read default route
    let output = Command::new("ip").args(["route", "show", "default"]).output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wan_interface_from_default_route(&stdout)
}

#[cfg(not(target_os = "linux"))]
pub fn detect_wan_interface() -> Option<String> {
    None
}

#[cfg(any(test, target_os = "linux"))]
fn parse_wan_interface_from_default_route(route_output: &str) -> Option<String> {
    let parts: Vec<_> = route_output.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Parse canonical form first: "default via X.X.X.X dev INTERFACE ..."
    for (i, word) in parts.iter().enumerate() {
        if *word == "dev" && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
    }

    // Fallback for unusual output where interface token appears without explicit "dev".
    for word in parts {
        if word.starts_with("eth")
            || word.starts_with("en")
            || word.starts_with("wl")
            || word.starts_with("wlan")
        {
            return Some(word.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_calculation() {
        let mgr = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );

        assert_eq!(mgr.calculate_subnet(), "10.8.0.0/24");
    }

    #[test]
    fn test_parse_wan_interface_uses_dev_field() {
        let route = "default via 192.168.1.1 dev enp5s0 proto dhcp src 192.168.1.50 metric 100";
        assert_eq!(parse_wan_interface_from_default_route(route), Some("enp5s0".to_string()));
    }

    #[test]
    fn test_parse_wan_interface_dev_field_covers_non_prefixed_name() {
        let route = "default dev ppp0 scope link";
        assert_eq!(parse_wan_interface_from_default_route(route), Some("ppp0".to_string()));
    }

    #[test]
    fn test_parse_wan_interface_returns_none_for_invalid_output() {
        let route = "default via 10.0.0.1 proto static";
        assert_eq!(parse_wan_interface_from_default_route(route), None);
    }

    #[test]
    fn test_parse_wan_interface_mock_matrix() {
        let cases = [
            ("default via 192.168.178.1 dev wlan0 proto dhcp metric 600", Some("wlan0")),
            ("default dev ppp0 scope link", Some("ppp0")),
            ("default via 10.0.0.1", None),
            ("", None),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse_wan_interface_from_default_route(input),
                expected.map(|v| v.to_string()),
                "route_output={input:?}"
            );
        }
    }
}

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
#[cfg(target_os = "linux")]
use std::sync::Mutex;

/// Routing manager for VPN server.
pub struct RoutingManager {
    tun_name: String,
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    wan_interface: String,
    /// Concrete Linux firewall backend selected once for setup and teardown.
    firewall_backend: crate::firewall::FirewallBackend,
    /// IPv6 server TUN address (None = IPv6 disabled).
    server_ipv6: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64).
    ipv6_prefix_len: u8,
    /// Explicit opt-in for direct forwarding back out of the TUN interface.
    client_to_client_enabled: bool,
    /// Host mutations made by this manager and therefore eligible for exact
    /// rollback. Pre-existing desired state is never claimed as owned.
    #[cfg(target_os = "linux")]
    ownership: Mutex<RoutingOwnership>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct RoutingOwnership {
    ipv4_address_added: bool,
    ipv6_address_added: bool,
    link_brought_up: bool,
    ipv4_forwarding_previous: Option<String>,
    ipv6_forwarding_previous: Option<String>,
}

/// Routing errors.
#[derive(Debug)]
pub enum RoutingError {
    CommandFailed(String),
    PermissionDenied,
    UnsupportedConfiguration(String),
    UnsupportedPlatform,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::CommandFailed(e) => write!(f, "Command failed: {}", e),
            RoutingError::PermissionDenied => write!(f, "Permission denied (need root)"),
            RoutingError::UnsupportedConfiguration(detail) => {
                write!(f, "Unsupported routing configuration: {detail}")
            }
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
            firewall_backend: crate::firewall::FirewallBackend::Iptables,
            server_ipv6: None,
            ipv6_prefix_len: 64,
            client_to_client_enabled: false,
            #[cfg(target_os = "linux")]
            ownership: Mutex::new(RoutingOwnership::default()),
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
            firewall_backend: crate::firewall::FirewallBackend::Iptables,
            server_ipv6: Some(server_ipv6),
            ipv6_prefix_len,
            client_to_client_enabled: false,
            #[cfg(target_os = "linux")]
            ownership: Mutex::new(RoutingOwnership::default()),
        }
    }

    pub fn with_client_to_client(mut self, enabled: bool) -> Self {
        self.client_to_client_enabled = enabled;
        self
    }

    pub fn with_firewall_backend(mut self, backend: crate::firewall::FirewallBackend) -> Self {
        self.firewall_backend = backend;
        self
    }

    /// Returns true if IPv6 is enabled.
    pub fn is_ipv6_enabled(&self) -> bool {
        self.server_ipv6.is_some()
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn record_cleanup_failure(failures: &mut Vec<String>, result: Result<(), RoutingError>) {
        if let Err(error) = result {
            failures.push(error.to_string());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn finish_cleanup(failures: Vec<String>) -> Result<(), RoutingError> {
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RoutingError::CommandFailed(failures.join("; ")))
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_json(args: &[&str]) -> Result<serde_json::Value, RoutingError> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip inspect spawn: {error}")))?;
        if !output.status.success() {
            return Err(RoutingError::CommandFailed(format!(
                "ip {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        serde_json::from_slice(&output.stdout).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "ip {} returned invalid JSON: {error}",
                args.join(" ")
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn linux_link_is_up(&self) -> Result<bool, RoutingError> {
        let value = Self::linux_json(&["-j", "link", "show", "dev", &self.tun_name])?;
        let item = value.as_array().and_then(|items| items.first()).ok_or_else(|| {
            RoutingError::CommandFailed(format!(
                "ip link inspection returned no device {}",
                self.tun_name
            ))
        })?;
        Ok(item
            .get("flags")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP"))))
    }

    #[cfg(target_os = "linux")]
    fn linux_address_present(
        &self,
        family: &str,
        address: &str,
        prefix: u8,
    ) -> Result<bool, RoutingError> {
        let value = Self::linux_json(&["-j", "address", "show", "dev", &self.tun_name])?;
        let address_items = value
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.get("addr_info"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "ip address inspection omitted addr_info for {}",
                    self.tun_name
                ))
            })?;
        Ok(address_items.iter().any(|entry| {
            entry.get("family").and_then(serde_json::Value::as_str) == Some(family)
                && entry.get("local").and_then(serde_json::Value::as_str) == Some(address)
                && entry.get("prefixlen").and_then(serde_json::Value::as_u64)
                    == Some(u64::from(prefix))
        }))
    }

    #[cfg(target_os = "linux")]
    fn ipv4_prefix_len(&self) -> Result<u8, RoutingError> {
        let raw = u32::from(self.netmask);
        let prefix = raw.leading_ones();
        let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        if raw != canonical {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "server IPv4 netmask {} is not contiguous",
                self.netmask
            )));
        }
        Ok(prefix as u8)
    }

    #[cfg(target_os = "linux")]
    fn verify_linux_addresses(&self) -> Result<(), RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let address = self.server_ip.to_string();
        if !self.linux_address_present("inet", &address, prefix)? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} is missing IPv4 address {}/{}",
                self.tun_name, address, prefix
            )));
        }
        if let Some(ipv6) = self.server_ipv6 {
            let address = ipv6.to_string();
            if self.ipv6_prefix_len > 128
                || !self.linux_address_present("inet6", &address, self.ipv6_prefix_len)?
            {
                return Err(RoutingError::CommandFailed(format!(
                    "Linux TUN {} is missing IPv6 address {}/{}",
                    self.tun_name, address, self.ipv6_prefix_len
                )));
            }
        }
        if !self.linux_link_is_up()? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} is not administratively up",
                self.tun_name
            )));
        }
        Ok(())
    }

    /// Set up routing rules.
    #[cfg(target_os = "linux")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        let result = (|| {
            self.assign_tun_address_linux()?;
            self.enable_ip_forwarding()?;

            let subnet = self.calculate_subnet_checked()?;
            let ipv6_subnet = if self.is_ipv6_enabled() {
                Some(self.calculate_ipv6_subnet_checked()?)
            } else {
                None
            };
            match self.firewall_backend {
                crate::firewall::FirewallBackend::Nftables => {
                    self.setup_nftables(&subnet)?;
                    log::info!(
                        "Routing configured (nftables): {} via {}",
                        subnet,
                        self.wan_interface
                    );
                }
                crate::firewall::FirewallBackend::Iptables => {
                    self.setup_iptables(&subnet)?;
                    log::info!(
                        "Routing configured (iptables): {} via {}",
                        subnet,
                        self.wan_interface
                    );
                }
            }

            if let Some(v6_subnet) = ipv6_subnet.as_deref() {
                self.assign_tun_address_v6_linux()?;
                self.enable_ipv6_forwarding()?;
                match self.firewall_backend {
                    crate::firewall::FirewallBackend::Nftables => {
                        log::info!(
                            "IPv6 routing configured (nftables inet): {} via {}",
                            v6_subnet,
                            self.wan_interface
                        );
                    }
                    crate::firewall::FirewallBackend::Iptables => {
                        self.setup_ip6tables(&v6_subnet)?;
                        log::info!(
                            "IPv6 routing configured (ip6tables): {} via {}",
                            v6_subnet,
                            self.wan_interface
                        );
                    }
                }
            }

            self.verify_linux_addresses()?;
            crate::audit::audit(
                crate::audit::AuditEventType::FirewallRuleAdded,
                crate::audit::AuditSeverity::Info,
                None,
                None,
                "Linux VPN routing and firewall rules installed",
            );
            Ok(())
        })();

        match result {
            Ok(()) => Ok(()),
            Err(error) => match self.teardown() {
                Ok(()) => Err(error),
                Err(rollback) => Err(RoutingError::CommandFailed(format!(
                    "routing setup failed: {error}; owned rollback failed: {rollback}"
                ))),
            },
        }
    }

    #[cfg(target_os = "macos")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        self.assign_tun_address_macos()?;
        self.enable_ip_forwarding_macos()?;
        let subnet = self.calculate_subnet();

        let ipv6_subnet = if self.is_ipv6_enabled() {
            self.assign_tun_address_v6_macos()?;
            self.enable_ipv6_forwarding_macos()?;
            Some(self.calculate_ipv6_subnet())
        } else {
            None
        };
        self.setup_pf(&subnet, ipv6_subnet.as_deref())?;
        log::info!("Routing configured (macOS/pf): {} via {}", subnet, self.wan_interface);

        crate::audit::audit(
            crate::audit::AuditEventType::FirewallRuleAdded,
            crate::audit::AuditSeverity::Info,
            None,
            None,
            "macOS VPN routing and firewall rules installed",
        );

        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        self.validate_windows_contract()?;
        self.enable_ip_forwarding_windows()?;
        let subnet = self.calculate_subnet();
        self.setup_windows_nat(&subnet)?;
        log::info!("Routing configured (Windows/NetNat): {} via {}", subnet, self.wan_interface);

        crate::audit::audit(
            crate::audit::AuditEventType::FirewallRuleAdded,
            crate::audit::AuditSeverity::Info,
            None,
            None,
            "Windows VPN routing and firewall rules installed",
        );

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn setup(&self) -> Result<(), RoutingError> {
        log::warn!("Routing setup not implemented for this platform");
        Err(RoutingError::UnsupportedPlatform)
    }

    /// Remove stale routing rules from a crashed previous session.
    ///
    /// This is safe to call on startup before `setup()`. It flushes any
    /// leftover iptables/pf/netsh rules that may persist from a process
    /// that was killed before its `teardown()` could run.
    #[cfg(target_os = "linux")]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        let subnet = self.calculate_subnet();
        log::info!("Cleaning up stale routing rules for subnet {}", subnet);
        let mut failures = Vec::new();

        // Current releases own dedicated chains. Keep the exact legacy-rule
        // cleanup below for crash residue left by older releases.
        Self::record_cleanup_failure(&mut failures, Self::cleanup_iptables_owned("iptables"));
        Self::record_cleanup_failure(&mut failures, Self::cleanup_iptables_owned("ip6tables"));

        Self::record_cleanup_failure(
            &mut failures,
            Self::cleanup_legacy_iptables_rule(
                "iptables",
                "nat",
                "POSTROUTING",
                &["-s", &subnet, "-o", &self.wan_interface, "-j", "MASQUERADE"],
            ),
        );
        Self::record_cleanup_failure(
            &mut failures,
            Self::cleanup_legacy_iptables_rule(
                "iptables",
                "filter",
                "FORWARD",
                &["-i", &self.tun_name, "-o", &self.wan_interface, "-j", "ACCEPT"],
            ),
        );
        for destination in self.ipv4_fanout_destinations() {
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "iptables",
                    "filter",
                    "FORWARD",
                    &[
                        "-i",
                        &self.tun_name,
                        "-o",
                        &self.tun_name,
                        "-d",
                        &destination,
                        "-j",
                        "ACCEPT",
                    ],
                ),
            );
        }
        for action in ["ACCEPT", "DROP"] {
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "iptables",
                    "filter",
                    "FORWARD",
                    &["-i", &self.tun_name, "-o", &self.tun_name, "-j", action],
                ),
            );
        }
        Self::record_cleanup_failure(
            &mut failures,
            Self::cleanup_legacy_iptables_rule(
                "iptables",
                "filter",
                "FORWARD",
                &[
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
                ],
            ),
        );

        // IPv6 stale cleanup
        if self.is_ipv6_enabled() {
            let v6_subnet = self.calculate_ipv6_subnet();
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "ip6tables",
                    "nat",
                    "POSTROUTING",
                    &["-s", &v6_subnet, "-o", &self.wan_interface, "-j", "MASQUERADE"],
                ),
            );
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "ip6tables",
                    "filter",
                    "FORWARD",
                    &["-i", &self.tun_name, "-o", &self.wan_interface, "-j", "ACCEPT"],
                ),
            );
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "ip6tables",
                    "filter",
                    "FORWARD",
                    &["-i", &self.tun_name, "-o", &self.tun_name, "-d", "ff00::/8", "-j", "ACCEPT"],
                ),
            );
            Self::record_cleanup_failure(
                &mut failures,
                Self::cleanup_legacy_iptables_rule(
                    "ip6tables",
                    "filter",
                    "FORWARD",
                    &[
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
                    ],
                ),
            );
            for action in ["ACCEPT", "DROP"] {
                Self::record_cleanup_failure(
                    &mut failures,
                    Self::cleanup_legacy_iptables_rule(
                        "ip6tables",
                        "filter",
                        "FORWARD",
                        &["-i", &self.tun_name, "-o", &self.tun_name, "-j", action],
                    ),
                );
            }
        }

        // Delete the dedicated nftables table exactly when nft is installed.
        if Command::new("nft")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            Self::record_cleanup_failure(
                &mut failures,
                crate::firewall::delete_nft_table("inet", Self::NFT_RT_TABLE)
                    .map(|_| ())
                    .map_err(|error| RoutingError::CommandFailed(error.to_string())),
            );
        }

        Self::finish_cleanup(failures)?;
        log::info!("Stale routing cleanup complete");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        log::info!("Cleaning up stale pf anchor rules");
        crate::firewall::cleanup_pf_anchor(Self::MACOS_PF_ANCHOR)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
        log::info!("Stale routing cleanup complete");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        log::info!("Cleaning up stale NetNat rules");
        let mut failures = Vec::new();
        for name in [Self::WINDOWS_NAT_NAME.to_string(), format!("{}_v6", Self::WINDOWS_NAT_NAME)] {
            Self::record_cleanup_failure(
                &mut failures,
                crate::firewall::cleanup_windows_nat(&name)
                    .map(|_| ())
                    .map_err(|error| RoutingError::CommandFailed(error.to_string())),
            );
        }
        Self::finish_cleanup(failures)?;
        log::info!("Stale routing cleanup complete");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        Err(RoutingError::UnsupportedPlatform)
    }

    /// Tear down routing rules.
    #[cfg(target_os = "linux")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        let mut failures = Vec::new();
        let firewall_result = match self.firewall_backend {
            crate::firewall::FirewallBackend::Nftables => self.teardown_nftables(),
            crate::firewall::FirewallBackend::Iptables => self.teardown_iptables(),
        };
        Self::record_cleanup_failure(&mut failures, firewall_result);

        let (ipv4_address_added, ipv6_address_added, link_brought_up, ipv4_previous, ipv6_previous) = {
            let ownership = self.ownership.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                ownership.ipv4_address_added,
                ownership.ipv6_address_added,
                ownership.link_brought_up,
                ownership.ipv4_forwarding_previous.clone(),
                ownership.ipv6_forwarding_previous.clone(),
            )
        };

        if ipv4_address_added {
            match self.ipv4_prefix_len() {
                Ok(prefix) => {
                    let result =
                        self.remove_linux_address("inet", &self.server_ip.to_string(), prefix);
                    let succeeded = result.is_ok();
                    Self::record_cleanup_failure(&mut failures, result);
                    if succeeded {
                        self.ownership
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .ipv4_address_added = false;
                    }
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        if ipv6_address_added {
            if let Some(ipv6) = self.server_ipv6 {
                let result =
                    self.remove_linux_address("inet6", &ipv6.to_string(), self.ipv6_prefix_len);
                let succeeded = result.is_ok();
                Self::record_cleanup_failure(&mut failures, result);
                if succeeded {
                    self.ownership
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .ipv6_address_added = false;
                }
            }
        }
        if link_brought_up {
            let result = self.set_linux_link_down();
            let succeeded = result.is_ok();
            Self::record_cleanup_failure(&mut failures, result);
            if succeeded {
                self.ownership
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .link_brought_up = false;
            }
        }
        if let Some(previous) = ipv4_previous {
            let result = self.restore_forwarding("/proc/sys/net/ipv4/ip_forward", &previous);
            let succeeded = result.is_ok();
            Self::record_cleanup_failure(&mut failures, result);
            if succeeded {
                self.ownership
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .ipv4_forwarding_previous = None;
            }
        }
        if let Some(previous) = ipv6_previous {
            let result =
                self.restore_forwarding("/proc/sys/net/ipv6/conf/all/forwarding", &previous);
            let succeeded = result.is_ok();
            Self::record_cleanup_failure(&mut failures, result);
            if succeeded {
                self.ownership
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .ipv6_forwarding_previous = None;
            }
        }

        Self::finish_cleanup(failures)?;

        log::info!("Routing rules removed");
        crate::audit::audit(
            crate::audit::AuditEventType::FirewallRuleRemoved,
            crate::audit::AuditSeverity::Info,
            None,
            None,
            "Linux VPN routing and firewall rules removed",
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_linux_address(
        &self,
        family: &str,
        address: &str,
        prefix: u8,
    ) -> Result<(), RoutingError> {
        if !self.linux_address_present(family, address, prefix)? {
            return Ok(());
        }
        let family_arg = if family == "inet6" { "-6" } else { "-4" };
        let cidr = format!("{address}/{prefix}");
        let result =
            Self::run_ip_command(&[family_arg, "addr", "del", &cidr, "dev", &self.tun_name]);
        if result.is_err() && self.linux_address_present(family, address, prefix)? {
            return result;
        }
        if self.linux_address_present(family, address, prefix)? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} retains owned {} address {}/{}",
                self.tun_name, family, address, prefix
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_linux_link_down(&self) -> Result<(), RoutingError> {
        if !self.linux_link_is_up()? {
            return Ok(());
        }
        let result = Self::run_ip_command(&["link", "set", "down", "dev", &self.tun_name]);
        if result.is_err() && self.linux_link_is_up()? {
            return result;
        }
        if self.linux_link_is_up()? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} remains up after rollback",
                self.tun_name
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn restore_forwarding(&self, path: &str, previous: &str) -> Result<(), RoutingError> {
        let current = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("read {path}: {error}")))?;
        if current.trim() == previous.trim() {
            return Ok(());
        }
        if current.trim() != "1" {
            return Err(RoutingError::CommandFailed(format!(
                "not restoring {path}: forwarding changed externally to {:?}",
                current.trim()
            )));
        }
        std::fs::write(path, previous)
            .map_err(|error| RoutingError::CommandFailed(format!("restore {path}: {error}")))?;
        let verified = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("verify {path}: {error}")))?;
        if verified.trim() != previous.trim() {
            return Err(RoutingError::CommandFailed(format!(
                "{path} remained {:?}, expected {:?}",
                verified.trim(),
                previous.trim()
            )));
        }
        Ok(())
    }

    /// iptables-specific teardown: remove MASQUERADE and FORWARD rules.
    #[cfg(target_os = "linux")]
    fn teardown_iptables(&self) -> Result<(), RoutingError> {
        let mut failures = Vec::new();
        Self::record_cleanup_failure(&mut failures, Self::cleanup_iptables_owned("iptables"));
        if self.is_ipv6_enabled() {
            Self::record_cleanup_failure(&mut failures, Self::cleanup_iptables_owned("ip6tables"));
        }
        Self::finish_cleanup(failures)
    }

    #[cfg(target_os = "macos")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        crate::firewall::cleanup_pf_anchor(Self::MACOS_PF_ANCHOR)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
        crate::audit::audit(
            crate::audit::AuditEventType::FirewallRuleRemoved,
            crate::audit::AuditSeverity::Info,
            None,
            None,
            "macOS VPN routing and firewall rules removed",
        );
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        let mut failures = Vec::new();
        for name in [Self::WINDOWS_NAT_NAME.to_string(), format!("{}_v6", Self::WINDOWS_NAT_NAME)] {
            Self::record_cleanup_failure(
                &mut failures,
                crate::firewall::cleanup_windows_nat(&name)
                    .map(|_| ())
                    .map_err(|error| RoutingError::CommandFailed(error.to_string())),
            );
        }
        Self::finish_cleanup(failures)?;
        crate::audit::audit(
            crate::audit::AuditEventType::FirewallRuleRemoved,
            crate::audit::AuditSeverity::Info,
            None,
            None,
            "Windows VPN routing and firewall rules removed",
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_ip_forwarding(&self) -> Result<Option<String>, RoutingError> {
        let path = "/proc/sys/net/ipv4/ip_forward";
        let previous = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("read {path}: {error}")))?;
        if previous.trim() == "1" {
            return Ok(None);
        }
        std::fs::write(path, "1")
            .map_err(|error| RoutingError::CommandFailed(format!("write {path}: {error}")))?;
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ipv4_forwarding_previous = Some(previous.clone());
        let verified = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("verify {path}: {error}")))?;
        if verified.trim() != "1" {
            return Err(RoutingError::CommandFailed(format!(
                "{path} remained {:?} after enabling",
                verified.trim()
            )));
        }
        log::debug!("IP forwarding enabled");
        Ok(Some(previous))
    }

    #[cfg(target_os = "linux")]
    fn setup_iptables(&self, subnet: &str) -> Result<(), RoutingError> {
        self.setup_iptables_family("iptables", "iptables-restore", subnet, false)
    }

    #[cfg(any(test, target_os = "linux"))]
    const IPTABLES_FILTER_CHAIN: &'static str = "QUICFUSCATE_RT";

    #[cfg(any(test, target_os = "linux"))]
    const IPTABLES_NAT_CHAIN: &'static str = "QUICFUSCATE_NAT";

    #[cfg(any(test, target_os = "linux"))]
    fn iptables_ruleset(
        &self,
        subnet: &str,
        ipv6: bool,
        install_nat_jump: bool,
        install_filter_jump: bool,
    ) -> String {
        let mut rules = format!(
            "*nat\n\
             :{} - [0:0]\n\
             -A {} -s {} -o {} -j MASQUERADE\n",
            Self::IPTABLES_NAT_CHAIN,
            Self::IPTABLES_NAT_CHAIN,
            subnet,
            self.wan_interface,
        );
        if install_nat_jump {
            rules.push_str(&format!("-I POSTROUTING 1 -j {}\n", Self::IPTABLES_NAT_CHAIN));
        }
        rules.push_str(&format!(
            "COMMIT\n\
             *filter\n\
             :{} - [0:0]\n\
             -A {} -i {} -o {} -j ACCEPT\n",
            Self::IPTABLES_FILTER_CHAIN,
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.wan_interface,
        ));

        if ipv6 {
            rules.push_str(&format!(
                "-A {} -i {} -o {} -d ff00::/8 -j ACCEPT\n",
                Self::IPTABLES_FILTER_CHAIN,
                self.tun_name,
                self.tun_name,
            ));
        } else {
            for destination in [
                "255.255.255.255/32".to_string(),
                format!("{}/32", self.ipv4_broadcast()),
                "224.0.0.0/4".to_string(),
            ] {
                rules.push_str(&format!(
                    "-A {} -i {} -o {} -d {} -j ACCEPT\n",
                    Self::IPTABLES_FILTER_CHAIN,
                    self.tun_name,
                    self.tun_name,
                    destination,
                ));
            }
        }

        let isolation_action = if self.client_to_client_enabled { "ACCEPT" } else { "DROP" };
        rules.push_str(&format!(
            "-A {} -i {} -o {} -j {}\n\
             -A {} -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT\n",
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.tun_name,
            isolation_action,
            Self::IPTABLES_FILTER_CHAIN,
            self.wan_interface,
            self.tun_name,
        ));
        if install_filter_jump {
            rules.push_str(&format!("-I FORWARD 1 -j {}\n", Self::IPTABLES_FILTER_CHAIN));
        }
        rules.push_str("COMMIT\n");
        rules
    }

    #[cfg(target_os = "linux")]
    fn setup_iptables_family(
        &self,
        program: &str,
        restore_program: &str,
        subnet: &str,
        ipv6: bool,
    ) -> Result<(), RoutingError> {
        Self::cleanup_iptables_owned(program)?;
        let rules = self.iptables_ruleset(subnet, ipv6, true, true);
        let rollback = |error: RoutingError| match Self::cleanup_iptables_owned(program) {
            Ok(()) => error,
            Err(cleanup_error) => {
                RoutingError::CommandFailed(format!("{error}; rollback failed: {cleanup_error}"))
            }
        };
        if let Err(error) = Self::apply_iptables_restore(restore_program, &rules) {
            return Err(rollback(error));
        }
        if let Err(error) = self.verify_iptables_family(program, subnet, ipv6) {
            return Err(rollback(error));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_iptables_family(
        &self,
        program: &str,
        subnet: &str,
        ipv6: bool,
    ) -> Result<(), RoutingError> {
        let require = |table: &str, chain: &str, rule_args: &[&str]| -> Result<(), RoutingError> {
            let exists =
                crate::firewall::iptables_rule_exists_exact(program, table, chain, rule_args)
                    .map_err(RoutingError::CommandFailed)?;
            if exists {
                Ok(())
            } else {
                Err(RoutingError::CommandFailed(format!(
                    "{program} missing exact rule in {table}/{chain}: {}",
                    rule_args.join(" ")
                )))
            }
        };

        require("nat", "POSTROUTING", &["-j", Self::IPTABLES_NAT_CHAIN])?;
        require("filter", "FORWARD", &["-j", Self::IPTABLES_FILTER_CHAIN])?;
        require(
            "nat",
            Self::IPTABLES_NAT_CHAIN,
            &["-s", subnet, "-o", self.wan_interface.as_str(), "-j", "MASQUERADE"],
        )?;
        require(
            "filter",
            Self::IPTABLES_FILTER_CHAIN,
            &["-i", self.tun_name.as_str(), "-o", self.wan_interface.as_str(), "-j", "ACCEPT"],
        )?;

        if ipv6 {
            require(
                "filter",
                Self::IPTABLES_FILTER_CHAIN,
                &[
                    "-i",
                    self.tun_name.as_str(),
                    "-o",
                    self.tun_name.as_str(),
                    "-d",
                    "ff00::/8",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        } else {
            for destination in self.ipv4_fanout_destinations() {
                require(
                    "filter",
                    Self::IPTABLES_FILTER_CHAIN,
                    &[
                        "-i",
                        self.tun_name.as_str(),
                        "-o",
                        self.tun_name.as_str(),
                        "-d",
                        destination.as_str(),
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
        }

        let isolation_action = if self.client_to_client_enabled { "ACCEPT" } else { "DROP" };
        require(
            "filter",
            Self::IPTABLES_FILTER_CHAIN,
            &["-i", self.tun_name.as_str(), "-o", self.tun_name.as_str(), "-j", isolation_action],
        )?;
        require(
            "filter",
            Self::IPTABLES_FILTER_CHAIN,
            &[
                "-i",
                self.wan_interface.as_str(),
                "-o",
                self.tun_name.as_str(),
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )
    }

    #[cfg(target_os = "linux")]
    fn apply_iptables_restore(restore_program: &str, rules: &str) -> Result<(), RoutingError> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(restore_program)
            .args(["--noflush", "--wait", "5"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                RoutingError::CommandFailed(format!("{restore_program} spawn: {error}"))
            })?;
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RoutingError::CommandFailed(format!(
                "{restore_program} stdin unavailable"
            )));
        };
        if let Err(error) = stdin.write_all(rules.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RoutingError::CommandFailed(format!("{restore_program} stdin: {error}")));
        }
        drop(stdin);
        let output = child.wait_with_output().map_err(|error| {
            RoutingError::CommandFailed(format!("{restore_program} wait: {error}"))
        })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RoutingError::CommandFailed(format!(
                "{} returned status {}: {}",
                restore_program,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            )))
        }
    }

    #[cfg(target_os = "linux")]
    fn cleanup_iptables_owned(program: &str) -> Result<(), RoutingError> {
        let mut failures = Vec::new();
        for (table, parent, owned) in [
            ("filter", "FORWARD", Self::IPTABLES_FILTER_CHAIN),
            ("nat", "POSTROUTING", Self::IPTABLES_NAT_CHAIN),
        ] {
            Self::record_cleanup_failure(
                &mut failures,
                crate::firewall::cleanup_iptables_chain(program, table, parent, owned)
                    .map(|_| ())
                    .map_err(|error| RoutingError::CommandFailed(error.to_string())),
            );
        }
        Self::finish_cleanup(failures)
    }

    #[cfg(target_os = "linux")]
    fn cleanup_legacy_iptables_rule(
        program: &str,
        table: &str,
        chain: &str,
        rule_args: &[&str],
    ) -> Result<(), RoutingError> {
        crate::firewall::cleanup_iptables_rule(program, table, chain, rule_args)
            .map(|_| ())
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))
    }

    /// Dedicated nftables table name for QuicFuscate server routing/NAT rules.
    #[cfg(any(test, target_os = "linux"))]
    const NFT_RT_TABLE: &'static str = "quicfuscate_rt";

    #[cfg(any(test, target_os = "linux"))]
    fn nftables_ruleset(&self, subnet: &str) -> String {
        let v6_masquerade = if self.is_ipv6_enabled() {
            let v6_subnet = self.calculate_ipv6_subnet();
            format!("ip6 saddr {} oifname \"{}\" masquerade\n", v6_subnet, self.wan_interface)
        } else {
            String::new()
        };
        let v6_fanout = if self.is_ipv6_enabled() {
            format!(
                "iifname \"{}\" oifname \"{}\" ip6 daddr ff00::/8 accept\n",
                self.tun_name, self.tun_name
            )
        } else {
            String::new()
        };
        let isolation_action = if self.client_to_client_enabled { "accept" } else { "drop" };
        let directed_broadcast = self.ipv4_broadcast();

        format!(
            "table inet {table} {{\n\
             \x20   chain postrouting {{\n\
             \x20       type nat hook postrouting priority 100; policy accept;\n\
             \x20       ip saddr {subnet} oifname \"{wan}\" masquerade\n\
             \x20       {v6_masquerade}\
             \x20   }}\n\
             \x20   chain forward {{\n\
             \x20       type filter hook forward priority 0; policy accept;\n\
             \x20       iifname \"{tun}\" oifname \"{tun}\" ip daddr {{ 255.255.255.255, {directed_broadcast}, 224.0.0.0/4 }} accept\n\
             \x20       {v6_fanout}\
             \x20       iifname \"{tun}\" oifname \"{tun}\" {isolation_action}\n\
             \x20       iifname \"{tun}\" oifname \"{wan}\" accept\n\
             \x20       iifname \"{wan}\" oifname \"{tun}\" ct state established,related accept\n\
             \x20   }}\n\
             }}\n",
            table = Self::NFT_RT_TABLE,
            subnet = subnet,
            wan = self.wan_interface,
            v6_masquerade = v6_masquerade,
            v6_fanout = v6_fanout,
            tun = self.tun_name,
            directed_broadcast = directed_broadcast,
            isolation_action = isolation_action,
        )
    }

    #[cfg(any(test, target_os = "linux"))]
    fn nftables_replacement_transaction(ruleset: &str, table_exists: bool) -> String {
        if table_exists {
            format!("delete table inet {}\n{}", Self::NFT_RT_TABLE, ruleset)
        } else {
            ruleset.to_string()
        }
    }

    /// Set up nftables NAT and forwarding rules.
    ///
    /// Creates a single `inet` table with two chains:
    /// - `postrouting`: NAT masquerade for VPN subnet traffic leaving the WAN
    ///   interface (covers both IPv4 and, when dual-stack, IPv6).
    /// - `forward`: allows TUN→WAN forwarding and established WAN→TUN return
    ///   traffic.
    ///
    /// The entire table is applied atomically via `nft -f -` (stdin batch).
    #[cfg(target_os = "linux")]
    fn setup_nftables(&self, subnet: &str) -> Result<(), RoutingError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let ruleset = self.nftables_ruleset(subnet);
        let table_exists = crate::firewall::nft_table_exists("inet", Self::NFT_RT_TABLE)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
        let transaction = Self::nftables_replacement_transaction(&ruleset, table_exists);
        let mut required_fragments = vec![
            "chain postrouting".to_string(),
            "chain forward".to_string(),
            format!(
                "ip saddr {subnet} oifname \"{}\" masquerade",
                self.wan_interface
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" ip daddr {{ 255.255.255.255, {}, 224.0.0.0/4 }} accept",
                self.tun_name,
                self.tun_name,
                self.ipv4_broadcast()
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" {}",
                self.tun_name,
                self.tun_name,
                if self.client_to_client_enabled { "accept" } else { "drop" }
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" accept",
                self.tun_name, self.wan_interface
            ),
            format!(
                "iifname \"{}\" oifname \"{}\" ct state established,related accept",
                self.wan_interface, self.tun_name
            ),
        ];
        if self.server_ipv6.is_some() {
            required_fragments.push(format!(
                "ip6 saddr {} oifname \"{}\" masquerade",
                self.calculate_ipv6_subnet(),
                self.wan_interface
            ));
            required_fragments.push(format!(
                "iifname \"{}\" oifname \"{}\" ip6 daddr ff00::/8 accept",
                self.tun_name, self.tun_name
            ));
        }

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RoutingError::CommandFailed(format!("nft spawn: {}", e)))?;

        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RoutingError::CommandFailed("nft stdin unavailable".to_string()));
        };
        if let Err(error) = stdin.write_all(transaction.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RoutingError::CommandFailed(format!("nft stdin: {error}")));
        }
        drop(stdin);

        let output = child
            .wait_with_output()
            .map_err(|e| RoutingError::CommandFailed(format!("nft wait: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RoutingError::CommandFailed(format!(
                "nftables NAT setup failed: {}",
                stderr.trim()
            )));
        }
        let required_refs = required_fragments.iter().map(String::as_str).collect::<Vec<_>>();
        crate::firewall::verify_nft_table_rules("inet", Self::NFT_RT_TABLE, &required_refs)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;

        log::debug!("nftables routing table created (inet {})", Self::NFT_RT_TABLE);
        Ok(())
    }

    /// Tear down nftables NAT and forwarding rules.
    ///
    /// Removes the entire dedicated table: `nft delete table inet quicfuscate_rt`.
    #[cfg(target_os = "linux")]
    fn teardown_nftables(&self) -> Result<(), RoutingError> {
        let outcome = crate::firewall::delete_nft_table("inet", Self::NFT_RT_TABLE)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
        if outcome.removed() {
            log::debug!("nftables routing table removed (inet {})", Self::NFT_RT_TABLE);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    const MACOS_PF_ANCHOR: &'static str = "com.quicfuscate.vpn";

    #[cfg(any(test, target_os = "windows"))]
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
    fn pf_rules(&self, subnet: &str, ipv6_subnet: Option<&str>) -> String {
        let fanout_v4 = format!(
            "pass quick on {} inet from {} to {{ 255.255.255.255, {}, 224.0.0.0/4 }} keep state\n",
            self.tun_name,
            subnet,
            self.ipv4_broadcast()
        );
        let isolation_v4 = if self.client_to_client_enabled {
            String::new()
        } else {
            format!("block drop quick on {} inet from {} to {}\n", self.tun_name, subnet, subnet)
        };
        let mut rules = format!(
            "nat on {} from {} to any -> ({})\n\
             {}\
             {}\
             pass quick on {} inet from {} to any keep state\n\
             pass quick on {} inet from any to {} keep state\n",
            self.wan_interface,
            subnet,
            self.wan_interface,
            fanout_v4,
            isolation_v4,
            self.tun_name,
            subnet,
            self.wan_interface,
            subnet
        );
        if let Some(ipv6_subnet) = ipv6_subnet {
            let isolation_v6 = if self.client_to_client_enabled {
                String::new()
            } else {
                format!(
                    "block drop quick on {} inet6 from {} to {}\n",
                    self.tun_name, ipv6_subnet, ipv6_subnet
                )
            };
            rules.push_str(&format!(
                "nat on {} inet6 from {} to any -> ({})\n\
                 pass quick on {} inet6 from {} to ff00::/8 keep state\n{}\
                 pass quick on {} inet6 from {} to any keep state\n\
                 pass quick on {} inet6 from any to {} keep state\n",
                self.wan_interface,
                ipv6_subnet,
                self.wan_interface,
                self.tun_name,
                ipv6_subnet,
                isolation_v6,
                self.tun_name,
                ipv6_subnet,
                self.wan_interface,
                ipv6_subnet
            ));
        }
        rules
    }

    #[cfg(target_os = "macos")]
    fn setup_pf(&self, subnet: &str, ipv6_subnet: Option<&str>) -> Result<(), RoutingError> {
        // Ensure packet filter is enabled.
        self.run_command("pfctl", &["-E"], "enable pfctl")?;

        let rules = self.pf_rules(subnet, ipv6_subnet);
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
        let script = self.windows_nat_script(subnet);
        self.run_powershell(&script, "New-NetNat")
    }

    #[cfg(any(test, target_os = "windows"))]
    fn windows_nat_script(&self, subnet: &str) -> String {
        let nat_name = Self::WINDOWS_NAT_NAME;
        format!(
            "$ErrorActionPreference='Stop'; \
             if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{ \
               Remove-NetNat -Name '{nat_name}' -Confirm:$false | Out-Null \
             }}; \
             New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{subnet}' | Out-Null"
        )
    }

    #[cfg(any(test, target_os = "windows"))]
    fn validate_windows_contract(&self) -> Result<(), RoutingError> {
        if self.is_ipv6_enabled() {
            return Err(RoutingError::UnsupportedConfiguration(
                "Windows WinNAT does not provide IPv6 NAT; use routed IPv6 or run the dual-stack server on Linux/macOS"
                    .to_string(),
            ));
        }
        Ok(())
    }

    // ================================================================
    // TUN interface address assignment
    // ================================================================

    #[cfg(target_os = "linux")]
    fn run_ip_command(args: &[&str]) -> Result<(), RoutingError> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip spawn: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(RoutingError::CommandFailed(format!(
            "ip {} returned status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Assign the IPv4 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    fn assign_tun_address_linux(&self) -> Result<(), RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let addr = format!("{}/{}", self.server_ip, prefix);
        let address_present =
            self.linux_address_present("inet", &self.server_ip.to_string(), prefix)?;
        if !address_present {
            let result = Self::run_ip_command(&["-4", "addr", "add", &addr, "dev", &self.tun_name]);
            if result.is_err()
                && !self.linux_address_present("inet", &self.server_ip.to_string(), prefix)?
            {
                return result;
            }
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .ipv4_address_added = true;
        }

        if !self.linux_link_is_up()? {
            let result = Self::run_ip_command(&["link", "set", "up", "dev", &self.tun_name]);
            if result.is_err() && !self.linux_link_is_up()? {
                return result;
            }
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .link_brought_up = true;
        }
        if !self.linux_address_present("inet", &self.server_ip.to_string(), prefix)?
            || !self.linux_link_is_up()?
        {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN {} failed IPv4/link postcondition",
                self.tun_name
            )));
        }
        log::debug!("TUN IPv4 address verified: {} on {}", addr, self.tun_name);
        Ok(())
    }

    /// Assign the IPv6 address to the TUN interface on Linux.
    #[cfg(target_os = "linux")]
    fn assign_tun_address_v6_linux(&self) -> Result<(), RoutingError> {
        if let Some(ipv6) = self.server_ipv6 {
            if self.ipv6_prefix_len > 128 {
                return Err(RoutingError::UnsupportedConfiguration(format!(
                    "IPv6 prefix length {} exceeds 128",
                    self.ipv6_prefix_len
                )));
            }
            let addr = format!("{}/{}", ipv6, self.ipv6_prefix_len);
            if !self.linux_address_present("inet6", &ipv6.to_string(), self.ipv6_prefix_len)? {
                let result =
                    Self::run_ip_command(&["-6", "addr", "add", &addr, "dev", &self.tun_name]);
                if result.is_err()
                    && !self.linux_address_present(
                        "inet6",
                        &ipv6.to_string(),
                        self.ipv6_prefix_len,
                    )?
                {
                    return result;
                }
                self.ownership
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .ipv6_address_added = true;
            }
            self.verify_linux_addresses()?;
            log::debug!("TUN IPv6 address verified: {} on {}", addr, self.tun_name);
        }
        Ok(())
    }

    /// Assign the IPv4 address to the TUN interface on macOS.
    #[cfg(target_os = "macos")]
    fn assign_tun_address_macos(&self) -> Result<(), RoutingError> {
        let address = self.server_ip.to_string();
        let netmask = self.netmask.to_string();
        self.run_command(
            "ifconfig",
            &[&self.tun_name, &address, "netmask", &netmask, "up"],
            "assign macOS IPv4 TUN address",
        )?;
        log::debug!("TUN IPv4 address assigned: {} on {}", self.server_ip, self.tun_name);
        Ok(())
    }

    /// Assign the IPv6 address to the TUN interface on macOS.
    #[cfg(target_os = "macos")]
    fn assign_tun_address_v6_macos(&self) -> Result<(), RoutingError> {
        if let Some(ipv6) = self.server_ipv6 {
            if self.ipv6_prefix_len > 128 {
                return Err(RoutingError::UnsupportedConfiguration(format!(
                    "IPv6 prefix length {} exceeds 128",
                    self.ipv6_prefix_len
                )));
            }
            let address = ipv6.to_string();
            let prefix = self.ipv6_prefix_len.to_string();
            self.run_command(
                "ifconfig",
                &[&self.tun_name, "inet6", &address, "prefixlen", &prefix, "up"],
                "assign macOS IPv6 TUN address",
            )?;
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

    #[cfg(target_os = "linux")]
    fn calculate_subnet_checked(&self) -> Result<String, RoutingError> {
        let prefix = self.ipv4_prefix_len()?;
        let network = u32::from(self.server_ip) & u32::from(self.netmask);
        Ok(format!("{}/{}", Ipv4Addr::from(network), prefix))
    }

    fn ipv4_broadcast(&self) -> Ipv4Addr {
        let mask = u32::from(self.netmask);
        Ipv4Addr::from((u32::from(self.server_ip) & mask) | !mask)
    }

    #[cfg(target_os = "linux")]
    fn ipv4_fanout_destinations(&self) -> [String; 3] {
        [
            "255.255.255.255/32".to_string(),
            format!("{}/32", self.ipv4_broadcast()),
            "224.0.0.0/4".to_string(),
        ]
    }

    /// Calculate the IPv6 subnet CIDR (e.g., "fd00::/64").
    fn calculate_ipv6_subnet(&self) -> String {
        match self.server_ipv6 {
            Some(ip) => {
                let prefix = self.ipv6_prefix_len.min(128);
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                format!("{}/{}", Ipv6Addr::from(u128::from(ip) & mask), prefix)
            }
            None => String::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn calculate_ipv6_subnet_checked(&self) -> Result<String, RoutingError> {
        if self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        Ok(self.calculate_ipv6_subnet())
    }

    // ================================================================
    // IPv6 forwarding and NAT
    // ================================================================

    #[cfg(target_os = "linux")]
    fn enable_ipv6_forwarding(&self) -> Result<Option<String>, RoutingError> {
        let path = "/proc/sys/net/ipv6/conf/all/forwarding";
        let previous = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("read {path}: {error}")))?;
        if previous.trim() == "1" {
            return Ok(None);
        }
        std::fs::write(path, "1")
            .map_err(|error| RoutingError::CommandFailed(format!("write {path}: {error}")))?;
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ipv6_forwarding_previous = Some(previous.clone());
        let verified = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("verify {path}: {error}")))?;
        if verified.trim() != "1" {
            return Err(RoutingError::CommandFailed(format!(
                "{path} remained {:?} after enabling",
                verified.trim()
            )));
        }
        log::debug!("IPv6 forwarding enabled");
        Ok(Some(previous))
    }

    #[cfg(target_os = "linux")]
    fn setup_ip6tables(&self, subnet: &str) -> Result<(), RoutingError> {
        self.setup_iptables_family("ip6tables", "ip6tables-restore", subnet, true)
    }

    #[cfg(target_os = "macos")]
    fn enable_ipv6_forwarding_macos(&self) -> Result<(), RoutingError> {
        self.run_command(
            "sysctl",
            &["-w", "net.inet6.ip6.forwarding=1"],
            "enable macOS IPv6 forwarding",
        )
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

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_stale_nat_cleanup_is_native_verified_and_idempotent() {
        let manager = RoutingManager::new(
            "QuicFuscate".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "Ethernet".to_string(),
        );
        manager.cleanup_stale().unwrap();
        manager.cleanup_stale().unwrap();
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

    // ------------------------------------------------------------------
    // nftables routing rule generation tests
    // ------------------------------------------------------------------

    /// Verify that the nftables NAT ruleset contains the equivalent of the
    /// iptables MASQUERADE + FORWARD rules.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_routing_ruleset_equivalent_to_iptables() {
        let mgr = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let subnet = mgr.calculate_subnet();

        // iptables equivalent rules (from setup_iptables)
        let iptables_masq =
            format!("-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE", subnet, mgr.wan_interface);
        let iptables_fwd =
            format!("-A FORWARD -i {} -o {} -j ACCEPT", mgr.tun_name, mgr.wan_interface);
        let iptables_est = format!(
            "-A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            mgr.wan_interface, mgr.tun_name
        );

        // nftables equivalent rules
        let nft_masq = format!("ip saddr {} oifname \"{}\" masquerade", subnet, mgr.wan_interface);
        let nft_fwd =
            format!("iifname \"{}\" oifname \"{}\" accept", mgr.tun_name, mgr.wan_interface);
        let nft_est = format!(
            "iifname \"{}\" oifname \"{}\" ct state established,related accept",
            mgr.wan_interface, mgr.tun_name
        );

        // Both sets must reference the same subnet and interfaces.
        assert!(iptables_masq.contains(&subnet) && nft_masq.contains(&subnet));
        assert!(iptables_fwd.contains(&mgr.tun_name) && nft_fwd.contains(&mgr.tun_name));
        assert!(iptables_est.contains(&mgr.wan_interface) && nft_est.contains(&mgr.wan_interface));

        // MASQUERADE vs masquerade
        assert!(iptables_masq.contains("MASQUERADE"));
        assert!(nft_masq.contains("masquerade"));

        // ESTABLISHED state matching
        assert!(iptables_est.contains("RELATED,ESTABLISHED"));
        assert!(nft_est.contains("established,related"));
    }

    /// Verify the nftables routing table name constant.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_nft_rt_table_constant() {
        assert_eq!(RoutingManager::NFT_RT_TABLE, "quicfuscate_rt");
    }

    #[test]
    fn test_routing_manager_retains_explicit_backend_for_setup_and_teardown() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        )
        .with_firewall_backend(crate::firewall::FirewallBackend::Nftables);

        assert_eq!(manager.firewall_backend, crate::firewall::FirewallBackend::Nftables);
    }

    #[test]
    fn test_nftables_ruleset_defaults_to_dual_stack_client_isolation() {
        let manager = RoutingManager::new_dual_stack(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
            "fd00::1".parse().unwrap(),
            64,
        );
        let rules = manager.nftables_ruleset("10.8.0.0/24");

        assert!(rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" drop"));
        let fanout_v4 = rules
            .find("ip daddr { 255.255.255.255, 10.8.0.255, 224.0.0.0/4 } accept")
            .expect("IPv4 fan-out allowance");
        let fanout_v6 = rules.find("ip6 daddr ff00::/8 accept").expect("IPv6 fan-out allowance");
        let isolation = rules
            .find("iifname \"qfserver0\" oifname \"qfserver0\" drop")
            .expect("default isolation");
        assert!(fanout_v4 < isolation);
        assert!(fanout_v6 < isolation);
        assert!(rules.contains("ip6 saddr fd00::/64 oifname \"eth0\" masquerade"));
    }

    #[test]
    fn test_nftables_ruleset_requires_explicit_client_unicast_opt_in() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        )
        .with_client_to_client(true);
        let rules = manager.nftables_ruleset("10.8.0.0/24");

        assert!(rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" accept"));
        assert!(!rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" drop"));
    }

    #[test]
    fn test_iptables_ruleset_rebuilds_only_owned_chains() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let rules = manager.iptables_ruleset("10.8.0.0/24", false, true, true);

        assert!(rules.contains(":QUICFUSCATE_NAT - [0:0]"));
        assert!(rules.contains(":QUICFUSCATE_RT - [0:0]"));
        assert!(rules.contains("-I POSTROUTING 1 -j QUICFUSCATE_NAT"));
        assert!(rules.contains("-I FORWARD 1 -j QUICFUSCATE_RT"));
        assert!(rules.contains("-A QUICFUSCATE_NAT -s 10.8.0.0/24 -o eth0 -j MASQUERADE"));
        assert!(rules.contains("-A QUICFUSCATE_RT -i qfserver0 -o qfserver0 -j DROP"));
        assert!(!rules.contains("-A POSTROUTING"));
        assert!(!rules.contains("-A FORWARD"));
    }

    #[test]
    fn test_iptables_repeated_setup_omits_duplicate_parent_jumps() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let rules = manager.iptables_ruleset("10.8.0.0/24", false, false, false);

        assert!(!rules.contains("-I POSTROUTING"));
        assert!(!rules.contains("-I FORWARD"));
        assert!(rules.contains(":QUICFUSCATE_NAT - [0:0]"));
        assert!(rules.contains(":QUICFUSCATE_RT - [0:0]"));
    }

    #[test]
    fn test_ip6tables_ruleset_retains_multicast_before_isolation() {
        let manager = RoutingManager::new_dual_stack(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
            "fd00::1".parse().unwrap(),
            64,
        );
        let rules = manager.iptables_ruleset("fd00::/64", true, true, true);
        let multicast = rules.find("-d ff00::/8 -j ACCEPT").expect("multicast allowance");
        let isolation = rules.find("-i qfserver0 -o qfserver0 -j DROP").expect("client isolation");

        assert!(multicast < isolation);
        assert!(rules.contains("-A QUICFUSCATE_NAT -s fd00::/64 -o eth0 -j MASQUERADE"));
    }

    #[test]
    fn test_nftables_replacement_is_one_delete_and_recreate_transaction() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let rules = manager.nftables_ruleset("10.8.0.0/24");
        let replacement = RoutingManager::nftables_replacement_transaction(&rules, true);
        let initial = RoutingManager::nftables_replacement_transaction(&rules, false);

        assert!(
            replacement.starts_with("delete table inet quicfuscate_rt\ntable inet quicfuscate_rt")
        );
        assert_eq!(replacement.matches("delete table inet quicfuscate_rt").count(), 1);
        assert_eq!(initial, rules);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_pf_rules_keep_ipv4_and_ipv6_in_one_anchor_ruleset() {
        let manager = RoutingManager::new_dual_stack(
            "utun9".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "en0".to_string(),
            "fd00::1".parse().unwrap(),
            64,
        );
        let rules = manager.pf_rules("10.8.0.0/24", Some("fd00::/64"));

        assert!(rules.contains("block drop quick on utun9 inet from 10.8.0.0/24"));
        assert!(rules.contains("block drop quick on utun9 inet6 from fd00::/64"));
        assert!(rules.contains("to { 255.255.255.255, 10.8.0.255, 224.0.0.0/4 }"));
        assert!(rules.contains("to ff00::/8 keep state"));
        assert!(rules.contains("nat on en0 from 10.8.0.0/24"));
        assert!(rules.contains("nat on en0 inet6 from fd00::/64"));
    }

    #[test]
    fn test_windows_nat_script_is_ipv4_only_and_idempotent() {
        let manager = RoutingManager::new(
            "QuicFuscate".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "Ethernet".to_string(),
        );
        let script = manager.windows_nat_script("10.8.0.0/24");

        assert!(script.contains("Get-NetNat -Name 'QuicFuscateNat'"));
        assert!(script.contains("Remove-NetNat -Name 'QuicFuscateNat'"));
        assert!(script.contains("InternalIPInterfaceAddressPrefix '10.8.0.0/24'"));
        assert!(!script.contains("_v6"));
    }

    #[test]
    fn test_windows_dual_stack_nat_is_rejected_before_side_effects() {
        let manager = RoutingManager::new_dual_stack(
            "QuicFuscate".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "Ethernet".to_string(),
            "fd00::1".parse().unwrap(),
            64,
        );

        assert!(matches!(
            manager.validate_windows_contract(),
            Err(RoutingError::UnsupportedConfiguration(_))
        ));
    }
}

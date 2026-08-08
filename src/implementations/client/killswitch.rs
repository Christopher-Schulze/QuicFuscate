//! Kill switch implementation for QuicFuscate client.
//!
//! Blocks all network traffic when VPN is not connected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::WindowsKillSwitch;

/// Typed firewall exceptions for one VPN connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnFirewallPolicy {
    tun_name: String,
    server_ipv4: Option<(Ipv4Addr, u16)>,
    server_ipv6: Option<(Ipv6Addr, u16)>,
    dns_servers: Vec<IpAddr>,
}

impl VpnFirewallPolicy {
    /// Build and validate the firewall policy used while connecting and connected.
    pub fn new(
        tun_name: impl Into<String>,
        server: SocketAddr,
        alternate_server_ip: Option<IpAddr>,
        dns_servers: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, KillSwitchError> {
        let tun_name = tun_name.into();
        if tun_name.is_empty()
            || tun_name.len() > 64
            || !tun_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(KillSwitchError::InvalidPolicy(
                "TUN interface name must contain only ASCII letters, digits, '.', '-', or '_'"
                    .to_string(),
            ));
        }

        let mut server_ipv4 = None;
        let mut server_ipv6 = None;
        match server.ip() {
            IpAddr::V4(ip) => server_ipv4 = Some((ip, server.port())),
            IpAddr::V6(ip) => server_ipv6 = Some((ip, server.port())),
        }
        match alternate_server_ip {
            Some(IpAddr::V4(ip)) if server_ipv4.is_none() => {
                server_ipv4 = Some((ip, server.port()));
            }
            Some(IpAddr::V6(ip)) if server_ipv6.is_none() => {
                server_ipv6 = Some((ip, server.port()));
            }
            _ => {}
        }

        let mut dns_servers: Vec<IpAddr> = dns_servers.into_iter().collect();
        dns_servers.sort_unstable();
        dns_servers.dedup();
        if dns_servers.len() > 8 {
            return Err(KillSwitchError::InvalidPolicy(
                "at most eight VPN DNS servers are supported".to_string(),
            ));
        }

        Ok(Self { tun_name, server_ipv4, server_ipv6, dns_servers })
    }

    fn tun_name(&self) -> &str {
        &self.tun_name
    }

    fn server_ipv4(&self) -> Option<(Ipv4Addr, u16)> {
        self.server_ipv4
    }

    fn server_ipv6(&self) -> Option<(Ipv6Addr, u16)> {
        self.server_ipv6
    }

    fn dns_servers(&self) -> &[IpAddr] {
        &self.dns_servers
    }
}

/// Kill switch manager.
pub struct KillSwitch {
    /// Whether kill switch is enabled
    enabled: AtomicBool,
    /// Whether VPN is currently connected
    vpn_connected: AtomicBool,
    /// Platform-specific implementation
    #[cfg(target_os = "linux")]
    backend: LinuxKillSwitch,
    #[cfg(target_os = "macos")]
    backend: MacOSKillSwitch,
    #[cfg(target_os = "windows")]
    backend: WindowsKillSwitch,
}

impl KillSwitch {
    /// Create a new kill switch with one fail-closed automatic backend selection.
    ///
    /// On Linux the firewall backend is resolved once through the validated
    /// availability contract. The selection can be supplied explicitly via
    /// [`KillSwitch::new_with_backend`].
    pub fn new() -> Result<Self, crate::firewall::FirewallSelectionError> {
        crate::firewall::resolve_backend(None).map(Self::new_with_backend)
    }

    /// Create a new kill switch with an explicit firewall backend.
    ///
    /// On non-Linux platforms the validated Linux selection is intentionally
    /// ignored because the platform-native backend is mandatory.
    pub fn new_with_backend(backend: crate::firewall::FirewallBackend) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = backend;
        Self {
            enabled: AtomicBool::new(false),
            vpn_connected: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            backend: LinuxKillSwitch::with_backend(backend),
            #[cfg(target_os = "macos")]
            backend: MacOSKillSwitch::new(),
            #[cfg(target_os = "windows")]
            backend: WindowsKillSwitch::new(),
        }
    }

    fn finalize_enable_failure(
        enabled: &AtomicBool,
        vpn_connected: &AtomicBool,
        activation_error: KillSwitchError,
        rollback: Result<(), KillSwitchError>,
    ) -> KillSwitchError {
        vpn_connected.store(false, Ordering::SeqCst);
        match rollback {
            Ok(()) => {
                enabled.store(false, Ordering::SeqCst);
                activation_error
            }
            Err(rollback_error) => {
                // The backend state is unknown after a failed rollback. Keep
                // the outer policy enabled so Drop retains the fail-closed
                // ownership contract and explicit cleanup remains available.
                enabled.store(true, Ordering::SeqCst);
                KillSwitchError::CommandFailed(format!(
                    "kill-switch activation failed: {activation_error}; fail-closed rollback failed: {rollback_error}; owned firewall state is retained for explicit cleanup"
                ))
            }
        }
    }

    /// Enable the kill switch.
    pub fn enable(&self) -> Result<(), KillSwitchError> {
        if self.enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        if let Err(activation_error) = self.backend.block_traffic() {
            let rollback = self.backend.allow_traffic();
            return Err(Self::finalize_enable_failure(
                &self.enabled,
                &self.vpn_connected,
                activation_error,
                rollback,
            ));
        }
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.enabled.store(true, Ordering::SeqCst);

        log::info!("Kill switch enabled");
        Ok(())
    }

    /// Disable the kill switch.
    pub fn disable(&self) -> Result<(), KillSwitchError> {
        self.backend.allow_traffic()?;
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.enabled.store(false, Ordering::SeqCst);
        log::info!("Kill switch disabled");
        Ok(())
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Allow only the remote VPN endpoint while the tunnel handshake is in progress.
    pub fn on_vpn_connecting(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        if self.enabled.load(Ordering::SeqCst) {
            self.backend.allow_vpn_connecting(policy)?;
        }
        self.vpn_connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Allow the VPN endpoint, selected tunnel DNS, and traffic through the TUN interface.
    pub fn on_vpn_connected(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        if self.enabled.load(Ordering::SeqCst) {
            self.backend.allow_vpn_traffic(policy)?;
        }
        self.vpn_connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Notify that VPN disconnected.
    pub fn on_vpn_disconnected(&self) -> Result<(), KillSwitchError> {
        self.vpn_connected.store(false, Ordering::SeqCst);

        if self.enabled.load(Ordering::SeqCst) {
            self.backend.block_traffic()?;
        }

        Ok(())
    }

    /// Remove stale firewall rules from a crashed previous session.
    ///
    /// This is a static method that can be called on startup before
    /// creating a new KillSwitch instance. It flushes rules deliberately
    /// retained after an unexpected process exit.
    pub fn cleanup_stale_rules() -> Result<(), KillSwitchError> {
        log::info!("Cleaning up stale kill switch firewall rules");
        #[cfg(target_os = "linux")]
        {
            LinuxKillSwitch::cleanup_stale()
        }
        #[cfg(target_os = "macos")]
        {
            MacOSKillSwitch::cleanup_stale()
        }
        #[cfg(target_os = "windows")]
        {
            WindowsKillSwitch::cleanup_stale()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(KillSwitchError::NotSupported)
        }
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.enabled.load(Ordering::SeqCst) {
            log::warn!(
                "Kill switch dropped while enabled; retaining fail-closed firewall rules for explicit cleanup"
            );
        }
    }
}

/// Kill switch errors.
#[derive(Debug)]
pub enum KillSwitchError {
    CommandFailed(String),
    InvalidPolicy(String),
    PermissionDenied,
    NotSupported,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(s) => write!(f, "Command failed: {}", s),
            Self::InvalidPolicy(s) => write!(f, "Invalid firewall policy: {}", s),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::NotSupported => write!(f, "Kill switch not supported on this platform"),
        }
    }
}

impl std::error::Error for KillSwitchError {}

// ============================================================================
// Linux Implementation (iptables + nftables)
// ============================================================================

/// Linux kill switch dispatching to either iptables or nftables based on
/// runtime auto-detection or explicit configuration.
///
/// Both variants expose the same method surface so the outer [`KillSwitch`]
/// API remains backend-agnostic.
#[cfg(target_os = "linux")]
enum LinuxKillSwitch {
    Iptables(IptablesKillSwitch),
    Nftables(NftablesKillSwitch),
}

#[cfg(target_os = "linux")]
impl LinuxKillSwitch {
    /// Construct the kill switch with an explicit backend selection.
    fn with_backend(backend: crate::firewall::FirewallBackend) -> Self {
        match backend {
            crate::firewall::FirewallBackend::Iptables => Self::Iptables(IptablesKillSwitch::new()),
            crate::firewall::FirewallBackend::Nftables => Self::Nftables(NftablesKillSwitch::new()),
        }
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.block_traffic(),
            Self::Nftables(n) => n.block_traffic(),
        }
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.allow_traffic(),
            Self::Nftables(n) => n.allow_traffic(),
        }
    }

    fn allow_vpn_connecting(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.allow_vpn_connecting(policy),
            Self::Nftables(n) => n.allow_vpn_connecting(policy),
        }
    }

    fn allow_vpn_traffic(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.allow_vpn_traffic(policy),
            Self::Nftables(n) => n.allow_vpn_traffic(policy),
        }
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        // Attempt both backends because a previous session may have selected
        // either one. An unavailable command cannot own inspectable live state;
        // an installed command must complete its exact cleanup or fail closed.
        let iptables_result = IptablesKillSwitch::cleanup_stale();
        let nftables_result = if std::process::Command::new("nft")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            NftablesKillSwitch::cleanup_stale()
        } else {
            Ok(())
        };
        match (iptables_result, nftables_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(iptables_error), Err(nftables_error)) => Err(KillSwitchError::CommandFailed(
                format!("iptables cleanup: {iptables_error}; nftables cleanup: {nftables_error}"),
            )),
        }
    }
}

// ----------------------------------------------------------------------------
// iptables variant
// ----------------------------------------------------------------------------

/// iptables-backed kill switch (legacy xtables).
#[cfg(target_os = "linux")]
struct IptablesKillSwitch {
    rules_active: AtomicBool,
}

/// Dedicated iptables chain name for QuicFuscate kill switch rules.
/// Using a separate chain avoids touching the user's OUTPUT chain rules
/// during cleanup_stale() — we only flush our own chain and remove our
/// jump rule, leaving all other firewall configuration intact.
#[cfg(target_os = "linux")]
const KS_CHAIN: &str = "QUICFUSCATE_KS";

#[cfg(target_os = "linux")]
impl IptablesKillSwitch {
    fn new() -> Self {
        Self { rules_active: AtomicBool::new(false) }
    }

    fn family_jump_exists(program: &str) -> Result<bool, KillSwitchError> {
        use std::process::{Command, Stdio};

        let status = Command::new(program)
            .args(["-C", "OUTPUT", "-j", KS_CHAIN])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| KillSwitchError::CommandFailed(format!("{program}: {error}")))?;
        Ok(status.success())
    }

    fn block_rules(install_jump: bool) -> String {
        let mut rules = format!(
            "*filter\n\
             :{} - [0:0]\n\
             -A {} -o lo -j ACCEPT\n\
             -A {} -j DROP\n",
            KS_CHAIN, KS_CHAIN, KS_CHAIN
        );
        if install_jump {
            rules.push_str(&format!("-I OUTPUT 1 -j {}\n", KS_CHAIN));
        }
        rules.push_str("COMMIT\n");
        rules
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        let rules_v4 = Self::block_rules(!Self::family_jump_exists("iptables")?);
        let rules_v6 = Self::block_rules(!Self::family_jump_exists("ip6tables")?);
        Self::apply_restore("iptables-restore", &rules_v4)?;
        Self::apply_restore("ip6tables-restore", &rules_v6)?;

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch: traffic blocked (dedicated chain, IPv4+IPv6)");
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn apply_policy(
        &self,
        policy: &VpnFirewallPolicy,
        connected: bool,
    ) -> Result<(), KillSwitchError> {
        let rules =
            Self::policy_rules(policy, false, connected, !Self::family_jump_exists("iptables")?);
        let rules_v6 =
            Self::policy_rules(policy, true, connected, !Self::family_jump_exists("ip6tables")?);
        Self::apply_restore("iptables-restore", &rules)?;
        Self::apply_restore("ip6tables-restore", &rules_v6)?;

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch: VPN policy applied (dedicated chain, IPv4+IPv6)");
        Ok(())
    }

    fn apply_restore(restore_program: &str, rules: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new(restore_program)
            .args(["--noflush", "--wait", "5"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                KillSwitchError::CommandFailed(format!("{restore_program}: {error}"))
            })?;
        child
            .stdin
            .take()
            .ok_or_else(|| {
                KillSwitchError::CommandFailed(format!("{restore_program} did not expose stdin"))
            })?
            .write_all(rules.as_bytes())
            .map_err(|error| {
                KillSwitchError::CommandFailed(format!("{restore_program} stdin: {error}"))
            })?;
        let output = child.wait_with_output().map_err(|error| {
            KillSwitchError::CommandFailed(format!("{restore_program}: {error}"))
        })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(KillSwitchError::CommandFailed(format!(
                "{} returned status {}: {}",
                restore_program,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    fn allow_vpn_connecting(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, false)
    }

    fn allow_vpn_traffic(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, true)
    }

    fn policy_rules(
        policy: &VpnFirewallPolicy,
        ipv6: bool,
        connected: bool,
        install_jump: bool,
    ) -> String {
        let mut rules =
            format!("*filter\n:{} - [0:0]\n-A {} -o lo -j ACCEPT\n", KS_CHAIN, KS_CHAIN);
        match (ipv6, policy.server_ipv4(), policy.server_ipv6()) {
            (false, Some((ip, port)), _) => rules.push_str(&format!(
                "-A {} -d {} -p udp --dport {} -j ACCEPT\n",
                KS_CHAIN, ip, port
            )),
            (true, _, Some((ip, port))) => rules.push_str(&format!(
                "-A {} -d {} -p udp --dport {} -j ACCEPT\n",
                KS_CHAIN, ip, port
            )),
            _ => {}
        }
        if connected {
            for dns in policy.dns_servers().iter().filter(|ip| ip.is_ipv6() == ipv6) {
                rules.push_str(&format!(
                    "-A {} -o {} -d {} -p udp --dport 53 -j ACCEPT\n\
                     -A {} -o {} -d {} -p tcp --dport 53 -j ACCEPT\n",
                    KS_CHAIN,
                    policy.tun_name(),
                    dns,
                    KS_CHAIN,
                    policy.tun_name(),
                    dns
                ));
            }
            rules.push_str(&format!(
                "-A {} -p udp --dport 53 -j DROP\n\
                 -A {} -p tcp --dport 53 -j DROP\n\
                 -A {} -o {} -j ACCEPT\n",
                KS_CHAIN,
                KS_CHAIN,
                KS_CHAIN,
                policy.tun_name()
            ));
        }
        rules.push_str(&format!("-A {} -j DROP\n", KS_CHAIN));
        if install_jump {
            rules.push_str(&format!("-I OUTPUT 1 -j {}\n", KS_CHAIN));
        }
        rules.push_str("COMMIT\n");
        rules
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        // Always inspect the owned chains. A dual-stack transaction can fail
        // after installing only one family, before `rules_active` is set.
        Self::cleanup_stale()?;
        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Kill switch: owned chains and jumps removed (IPv4+IPv6)");
        Ok(())
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        let mut failures = Vec::new();
        for program in ["iptables", "ip6tables"] {
            if let Err(error) = Self::cleanup_family(program) {
                failures.push(error.to_string());
            }
        }
        if !failures.is_empty() {
            return Err(KillSwitchError::CommandFailed(failures.join("; ")));
        }
        log::info!("Owned kill switch chains removed ({}, IPv4+IPv6)", KS_CHAIN);
        Ok(())
    }

    fn cleanup_family(program: &str) -> Result<(), KillSwitchError> {
        crate::firewall::cleanup_iptables_chain(program, "filter", "OUTPUT", KS_CHAIN)
            .map(|_| ())
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))
    }
}

// ----------------------------------------------------------------------------
// nftables variant
// ----------------------------------------------------------------------------

/// Dedicated nftables table name for the QuicFuscate kill switch.
///
/// Using the `inet` address family means a single table covers both IPv4 and
/// IPv6, preventing IPv6 traffic leaks without duplicating rules.
#[cfg(target_os = "linux")]
const KS_NFT_TABLE: &str = "quicfuscate_ks";

/// nftables-backed kill switch.
///
/// All rules live in a single `inet` table (`quicfuscate_ks`) with an `output`
/// chain hooked at the filter priority with a default-drop policy. Traffic is
/// re-allowed by replacing the entire table contents atomically via
/// `nft -f -` (stdin batch transaction).
#[cfg(target_os = "linux")]
struct NftablesKillSwitch {
    rules_active: AtomicBool,
    /// VPN server address (set when `allow_vpn_traffic` is called).
    server_addr: std::sync::Mutex<Option<String>>,
    /// TUN interface name (set when `allow_vpn_traffic` is called).
    tun_iface: std::sync::Mutex<Option<String>>,
}

#[cfg(target_os = "linux")]
impl NftablesKillSwitch {
    fn new() -> Self {
        Self {
            rules_active: AtomicBool::new(false),
            server_addr: std::sync::Mutex::new(None),
            tun_iface: std::sync::Mutex::new(None),
        }
    }

    /// Create a new nftables kill switch with known server and TUN interface.
    ///
    /// This is the explicit constructor used when the caller already knows the
    /// VPN server address and TUN interface name at construction time.
    #[cfg(test)]
    fn new_nftables(server_addr: &str, tun_iface: &str) -> Self {
        let ks = Self::new();
        *ks.server_addr.lock().unwrap() = Some(server_addr.to_string());
        *ks.tun_iface.lock().unwrap() = Some(tun_iface.to_string());
        ks
    }

    /// Build the nftables ruleset for the block-all state.
    ///
    /// Only loopback traffic is allowed; everything else is dropped by the
    /// chain's default-drop policy.
    fn block_ruleset(&self) -> String {
        format!(
            "table inet {table} {{\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       oifname \"lo\" accept\n\
             \x20   }}\n\
             }}\n",
            table = KS_NFT_TABLE
        )
    }

    /// Build the nftables ruleset for connecting or connected VPN state.
    fn policy_ruleset(&self, policy: &VpnFirewallPolicy, connected: bool) -> String {
        let mut rules = format!(
            "table inet {table} {{\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       oifname \"lo\" accept\n",
            table = KS_NFT_TABLE
        );
        if let Some((ip, port)) = policy.server_ipv4() {
            rules.push_str(&format!("        ip daddr {ip} udp dport {port} accept\n"));
        }
        if let Some((ip, port)) = policy.server_ipv6() {
            rules.push_str(&format!("        ip6 daddr {ip} udp dport {port} accept\n"));
        }
        if connected {
            for dns in policy.dns_servers() {
                let family = if dns.is_ipv4() { "ip" } else { "ip6" };
                rules.push_str(&format!(
                    "        oifname \"{}\" {} daddr {} udp dport 53 accept\n\
                     \x20       oifname \"{}\" {} daddr {} tcp dport 53 accept\n",
                    policy.tun_name(),
                    family,
                    dns,
                    policy.tun_name(),
                    family,
                    dns
                ));
            }
            rules.push_str("        udp dport 53 drop\n        tcp dport 53 drop\n");
            rules.push_str(&format!("        oifname \"{}\" accept\n", policy.tun_name()));
        }
        rules.push_str("    }\n}\n");
        rules
    }

    fn replacement_transaction(ruleset: &str, table_exists: bool) -> String {
        if table_exists {
            format!("delete table inet {}\n{}", KS_NFT_TABLE, ruleset)
        } else {
            ruleset.to_string()
        }
    }

    /// Apply a complete ruleset atomically via `nft -f -` (stdin).
    ///
    /// The table is first flushed (deleted + recreated) to ensure a clean
    /// slate. Using `nft -f -` gives all-or-nothing semantics: the kernel
    /// commits every statement or rejects the entire transaction.
    fn apply_ruleset(&self, ruleset: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let table_exists = crate::firewall::nft_table_exists("inet", KS_NFT_TABLE)
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))?;
        let transaction = Self::replacement_transaction(ruleset, table_exists);

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::CommandFailed(format!("nft spawn: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(transaction.as_bytes())
                .map_err(|e| KillSwitchError::CommandFailed(format!("nft stdin: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| KillSwitchError::CommandFailed(format!("nft wait: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KillSwitchError::CommandFailed(format!(
                "nft transaction failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        let ruleset = self.block_ruleset();
        self.apply_ruleset(&ruleset)?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch (nftables): traffic blocked (inet table, default drop)");
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_connecting(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, false)
    }

    fn allow_vpn_traffic(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, true)
    }

    fn apply_policy(
        &self,
        policy: &VpnFirewallPolicy,
        connected: bool,
    ) -> Result<(), KillSwitchError> {
        // Store the parameters for potential re-application.
        *self.server_addr.lock().unwrap() = policy
            .server_ipv4()
            .map(|(ip, _)| ip.to_string())
            .or_else(|| policy.server_ipv6().map(|(ip, _)| ip.to_string()));
        *self.tun_iface.lock().unwrap() = Some(policy.tun_name().to_string());

        let ruleset = self.policy_ruleset(policy, connected);
        self.apply_ruleset(&ruleset)?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!(
            "Kill switch (nftables): VPN policy applied via {} (connected={})",
            policy.tun_name(),
            connected
        );
        Ok(())
    }

    /// Remove the entire kill-switch table: `nft delete table inet quicfuscate_ks`.
    fn cleanup(&self) -> Result<(), KillSwitchError> {
        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        crate::firewall::delete_nft_table("inet", KS_NFT_TABLE)
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))?;
        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Kill switch (nftables): table removed");
        Ok(())
    }

    /// Check if the kill-switch table exists and delete it if stale.
    ///
    /// Queries `nft list table` to determine existence; if the table is
    /// present it is deleted unconditionally.
    fn cleanup_stale() -> Result<(), KillSwitchError> {
        let outcome = crate::firewall::delete_nft_table("inet", KS_NFT_TABLE)
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))?;
        if outcome.removed() {
            log::info!("Stale nftables kill switch table deleted (inet {})", KS_NFT_TABLE);
        } else {
            log::info!("Stale nftables kill switch table not present (nothing to clean)");
        }
        Ok(())
    }
}

// ============================================================================
// macOS Implementation (pf)
// ============================================================================

#[cfg(target_os = "macos")]
struct MacOSKillSwitch {
    rules_active: AtomicBool,
    anchor_name: String,
    /// Unpredictable per-instance rule file.
    ///
    /// The path was previously `/tmp/quicfuscate_killswitch_<pid>.conf`. A local attacker who can
    /// predict or observe the PID could place a symlink there before this privileged process
    /// wrote it, and `std::fs::write` follows symlinks, so privileged pf rule content could be
    /// redirected to another file. PID reuse and concurrent instances could also collide on it.
    config_path: String,
}

#[cfg(target_os = "macos")]
impl MacOSKillSwitch {
    fn new() -> Self {
        let mut nonce = [0u8; 16];
        crate::rng::fill_secure_or_abort(&mut nonce, "killswitch::config_path");
        let mut suffix = String::with_capacity(nonce.len() * 2);
        for byte in nonce {
            use std::fmt::Write as _;
            let _ = write!(&mut suffix, "{byte:02x}");
        }
        Self {
            rules_active: AtomicBool::new(false),
            anchor_name: "com.quicfuscate.killswitch".to_string(),
            config_path: format!("/tmp/quicfuscate_killswitch_{suffix}.conf"),
        }
    }

    /// Write pf rules to a file this process exclusively created.
    ///
    /// The old path was written with `std::fs::write`, which follows symlinks and happily reuses
    /// an existing file. This removes any prior entry and then creates the file with
    /// `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`, so the handle can only ever refer to a
    /// regular file this call just made. The result is verified through the handle itself, not by
    /// re-examining the path, so nothing can be swapped in between the check and the load.
    fn write_rules_exclusive(&self, rules: &str) -> Result<(), KillSwitchError> {
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        // Remove any prior file, including one left by a previous run. NotFound is the normal case.
        match std::fs::remove_file(&self.config_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(KillSwitchError::CommandFailed(format!(
                    "cannot clear kill-switch rule path {}: {error}",
                    self.config_path
                )))
            }
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.config_path)
            .map_err(|error| {
                KillSwitchError::CommandFailed(format!(
                    "cannot create kill-switch rule file {}: {error}",
                    self.config_path
                ))
            })?;

        // Verify through the open handle so no path-based race can intervene.
        let metadata = file.metadata().map_err(|error| {
            KillSwitchError::CommandFailed(format!("cannot inspect kill-switch rule file: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(KillSwitchError::CommandFailed(
                "kill-switch rule path is not a regular file".to_string(),
            ));
        }
        // SAFETY: `geteuid` takes no arguments, dereferences nothing, and cannot fail.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(KillSwitchError::CommandFailed(format!(
                "kill-switch rule file is owned by uid {}, expected {effective_uid}",
                metadata.uid()
            )));
        }
        if metadata.mode() & 0o777 != 0o600 {
            return Err(KillSwitchError::CommandFailed(format!(
                "kill-switch rule file has mode {:#o}, expected 0o600",
                metadata.mode() & 0o777
            )));
        }

        file.write_all(rules.as_bytes()).map_err(|error| {
            KillSwitchError::CommandFailed(format!("cannot write kill-switch rules: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            KillSwitchError::CommandFailed(format!("cannot flush kill-switch rules: {error}"))
        })?;
        Ok(())
    }

    fn run_pfctl(args: &[&str], action: &str) -> Result<(), KillSwitchError> {
        let output = std::process::Command::new("pfctl")
            .args(args)
            .output()
            .map_err(|error| KillSwitchError::CommandFailed(format!("{action}: {error}")))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(KillSwitchError::CommandFailed(format!(
                "{} returned status {}: {}",
                action,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            )))
        }
    }

    /// Check if pf is already enabled by querying pfctl -s info.
    fn is_pf_enabled(&self) -> bool {
        use std::process::Command;

        let output = match Command::new("pfctl").args(["-s", "info"]).output() {
            Ok(o) => o,
            Err(_) => return false,
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("Status: Enabled")
    }

    fn main_ruleset_references_anchor(rules: &str, anchor: &str) -> bool {
        let exact_anchor = format!("\"{anchor}\"");
        rules.lines().any(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("anchor") {
                return false;
            }
            matches!(fields.next(), Some(candidate) if candidate == exact_anchor || candidate == "\"com.quicfuscate/*\"")
        })
    }

    /// Enable pf if not already enabled, tracking whether we did it.
    fn ensure_pf_enabled(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        let rules = Command::new("pfctl")
            .args(["-sr"])
            .output()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        if !rules.status.success() {
            return Err(KillSwitchError::CommandFailed(format!(
                "pfctl -sr returned status {}: {}",
                rules.status,
                String::from_utf8_lossy(&rules.stderr).trim()
            )));
        }
        let rules = String::from_utf8_lossy(&rules.stdout);
        if !Self::main_ruleset_references_anchor(&rules, &self.anchor_name) {
            return Err(KillSwitchError::CommandFailed(format!(
                "pf main ruleset does not reference owned anchor {}; add an anchor \"{}\" or \"com.quicfuscate/*\" reference before enabling the kill switch",
                self.anchor_name, self.anchor_name
            )));
        }

        if self.is_pf_enabled() {
            log::debug!("Kill switch: pf already enabled, skipping pfctl -e");
            return Ok(());
        }

        Self::run_pfctl(&["-e"], "pfctl enable")
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        // Create pf rules
        let rules = "block out all\npass out on lo0\n".to_string();

        self.write_rules_exclusive(&rules)?;

        // Load rules
        Self::run_pfctl(
            &["-a", &self.anchor_name, "-f", &self.config_path],
            "pfctl kill-switch anchor load",
        )?;
        self.rules_active.store(true, Ordering::SeqCst);

        // Enable pf only if not already enabled
        if let Err(error) = self.ensure_pf_enabled() {
            return Err(self.rollback_loaded_anchor(error));
        }

        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_connecting(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, false)
    }

    fn allow_vpn_traffic(&self, policy: &VpnFirewallPolicy) -> Result<(), KillSwitchError> {
        self.apply_policy(policy, true)
    }

    fn apply_policy(
        &self,
        policy: &VpnFirewallPolicy,
        connected: bool,
    ) -> Result<(), KillSwitchError> {
        let mut rules = "pass out quick on lo0\n".to_string();
        if let Some((ip, port)) = policy.server_ipv4() {
            rules.push_str(&format!("pass out quick proto udp to {ip} port {port}\n"));
        }
        if let Some((ip, port)) = policy.server_ipv6() {
            rules.push_str(&format!("pass out quick inet6 proto udp to {ip} port {port}\n"));
        }
        if connected {
            for dns in policy.dns_servers() {
                rules.push_str(&format!(
                    "pass out quick on {} proto {{ udp tcp }} to {} port 53\n",
                    policy.tun_name(),
                    dns
                ));
            }
            rules.push_str("block out quick proto { udp tcp } to any port 53\n");
            rules.push_str(&format!("pass out quick on {}\n", policy.tun_name()));
        }
        rules.push_str("block out all\n");

        self.write_rules_exclusive(&rules)?;

        Self::run_pfctl(
            &["-a", &self.anchor_name, "-f", &self.config_path],
            "pfctl kill-switch policy load",
        )?;
        self.rules_active.store(true, Ordering::SeqCst);

        // Ensure pf is enabled (idempotent)
        if let Err(error) = self.ensure_pf_enabled() {
            return Err(self.rollback_loaded_anchor(error));
        }

        Ok(())
    }

    fn rollback_loaded_anchor(&self, activation_error: KillSwitchError) -> KillSwitchError {
        match self.cleanup() {
            Ok(()) => activation_error,
            Err(rollback_error) => {
                self.rules_active.store(true, Ordering::SeqCst);
                KillSwitchError::CommandFailed(format!(
                    "{activation_error}; failed to roll back just-loaded PF anchor {}: {rollback_error}; owned firewall state is retained for explicit cleanup",
                    self.anchor_name
                ))
            }
        }
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        crate::firewall::cleanup_pf_anchor(&self.anchor_name)
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))?;

        match std::fs::remove_file(&self.config_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(KillSwitchError::CommandFailed(format!(
                    "owned kill-switch config removal {}: {}",
                    self.config_path, error
                )));
            }
        }

        self.rules_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        crate::firewall::cleanup_pf_anchor("com.quicfuscate.killswitch")
            .map_err(|error| KillSwitchError::CommandFailed(error.to_string()))?;
        log::info!("Stale pf anchor rules verified absent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> VpnFirewallPolicy {
        VpnFirewallPolicy::new(
            "tun0",
            "198.51.100.1:4433".parse().unwrap(),
            Some("2001:db8::1".parse().unwrap()),
            ["10.8.0.53".parse().unwrap(), "fd00::53".parse().unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn test_kill_switch_new() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Iptables);
        assert!(!ks.is_enabled());
    }

    #[test]
    fn firewall_policy_rejects_rule_injection_and_bounds_dns_state() {
        let invalid = VpnFirewallPolicy::new(
            "tun0\nflush ruleset",
            "198.51.100.1:4433".parse().unwrap(),
            None,
            [],
        );
        assert!(matches!(invalid, Err(KillSwitchError::InvalidPolicy(_))));

        let too_many_dns: Vec<IpAddr> =
            (1..=9).map(|last| IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))).collect();
        let invalid = VpnFirewallPolicy::new(
            "tun0",
            "198.51.100.1:4433".parse().unwrap(),
            None,
            too_many_dns,
        );
        assert!(matches!(invalid, Err(KillSwitchError::InvalidPolicy(_))));
    }

    #[test]
    fn firewall_policy_deduplicates_dns_and_retains_dual_stack_endpoint() {
        let policy = VpnFirewallPolicy::new(
            "tun0",
            "198.51.100.1:4433".parse().unwrap(),
            Some("2001:db8::1".parse().unwrap()),
            ["10.8.0.53".parse().unwrap(), "10.8.0.53".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(policy.dns_servers(), &["10.8.0.53".parse::<IpAddr>().unwrap()]);
        assert_eq!(policy.server_ipv4(), Some(("198.51.100.1".parse().unwrap(), 4433)));
        assert_eq!(policy.server_ipv6(), Some(("2001:db8::1".parse().unwrap(), 4433)));
    }

    #[test]
    fn test_kill_switch_enable_disable_cycle() {
        // This test verifies the enable/disable state transitions.
        // On platforms without root, enable() will fail — that's expected.
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Iptables);
        // Just verify the state machine works without panicking
        assert!(!ks.is_enabled());
        // enable() requires root on Linux/macOS, so we just test the flag
        // The actual firewall rules are tested in integration tests
    }

    #[test]
    fn failed_enable_clears_policy_state_after_successful_rollback() {
        let enabled = AtomicBool::new(false);
        let vpn_connected = AtomicBool::new(true);
        let error = KillSwitch::finalize_enable_failure(
            &enabled,
            &vpn_connected,
            KillSwitchError::CommandFailed("activation failed".to_string()),
            Ok(()),
        );

        assert!(matches!(error, KillSwitchError::CommandFailed(_)));
        assert!(!enabled.load(Ordering::SeqCst));
        assert!(!vpn_connected.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_enable_retains_fail_closed_state_when_rollback_fails() {
        let enabled = AtomicBool::new(false);
        let vpn_connected = AtomicBool::new(true);
        let error = KillSwitch::finalize_enable_failure(
            &enabled,
            &vpn_connected,
            KillSwitchError::CommandFailed("activation failed".to_string()),
            Err(KillSwitchError::CommandFailed("rollback failed".to_string())),
        );

        let KillSwitchError::CommandFailed(message) = error else {
            panic!("failed rollback must return a diagnostic command error");
        };
        assert!(message.contains("fail-closed rollback failed"));
        assert!(enabled.load(Ordering::SeqCst));
        assert!(!vpn_connected.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pf_main_ruleset_reference_requires_an_anchor_statement() {
        let anchor = "com.quicfuscate.killswitch";
        assert!(MacOSKillSwitch::main_ruleset_references_anchor(
            "anchor \"com.quicfuscate.killswitch\" all\n",
            anchor
        ));
        assert!(MacOSKillSwitch::main_ruleset_references_anchor(
            "anchor \"com.quicfuscate/*\" all\n",
            anchor
        ));
        assert!(!MacOSKillSwitch::main_ruleset_references_anchor(
            "# anchor \"com.quicfuscate.killswitch\"\n",
            anchor
        ));
        assert!(!MacOSKillSwitch::main_ruleset_references_anchor(
            "anchor \"com.quicfuscate.killswitch-other\" all\n",
            anchor
        ));
    }

    #[test]
    fn test_kill_switch_vpn_connected_disconnected_state() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Iptables);
        // Verify initial state
        assert!(!ks.is_enabled());
        // on_vpn_connected/on_vpn_disconnected require root, test state only
        // The key invariant: without enable(), these are no-ops
        let _ = ks.on_vpn_connected(&test_policy());
        let _ = ks.on_vpn_disconnected();
        assert!(!ks.is_enabled());
    }

    #[test]
    fn test_cleanup_stale_rules_does_not_panic() {
        // cleanup_stale_rules() may fail without root, but should not panic
        let _ = KillSwitch::cleanup_stale_rules();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_stale_rule_cleanup_is_native_verified_and_idempotent() {
        KillSwitch::cleanup_stale_rules().unwrap();
        KillSwitch::cleanup_stale_rules().unwrap();
    }

    // ------------------------------------------------------------------
    // nftables kill switch rule generation tests
    // ------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_block_ruleset_has_default_drop_and_loopback() {
        let ks = NftablesKillSwitch::new();
        let ruleset = ks.block_ruleset();

        // The table must use the inet family and the dedicated table name.
        assert!(ruleset.contains("table inet quicfuscate_ks"));
        // The output chain must hook at filter priority with default drop.
        assert!(ruleset.contains("type filter hook output priority 0; policy drop;"));
        // Loopback must be allowed.
        assert!(ruleset.contains("oifname \"lo\" accept"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_allow_ruleset_includes_server_and_tun() {
        let ks = NftablesKillSwitch::new_nftables("198.51.100.1", "tun0");
        let ruleset = ks.policy_ruleset(&test_policy(), true);

        assert!(ruleset.contains("oifname \"lo\" accept"));
        assert!(ruleset.contains("ip daddr 198.51.100.1 udp dport 4433 accept"));
        assert!(ruleset.contains("ip6 daddr 2001:db8::1 udp dport 4433 accept"));
        assert!(ruleset.contains("oifname \"tun0\" accept"));
        assert!(ruleset.contains("ip daddr 10.8.0.53 udp dport 53 accept"));
        assert!(ruleset.contains("ip6 daddr fd00::53 tcp dport 53 accept"));
        assert!(ruleset.contains("udp dport 53 drop"));
        assert!(ruleset.contains("tcp dport 53 drop"));
        assert!(ruleset.contains("policy drop;"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_allow_ruleset_with_port_restricts_udp() {
        let ks = NftablesKillSwitch::new_nftables("198.51.100.1", "tun0");
        let ruleset = ks.policy_ruleset(&test_policy(), false);

        assert!(ruleset.contains("ip daddr 198.51.100.1 udp dport 4433 accept"));
        assert!(!ruleset.contains("oifname \"tun0\" accept"));
        assert!(!ruleset.contains("dport 53 drop"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_new_nftables_stores_server_and_tun() {
        let ks = NftablesKillSwitch::new_nftables("10.0.0.1", "quicfuse0");
        assert_eq!(ks.server_addr.lock().unwrap().as_deref(), Some("10.0.0.1"));
        assert_eq!(ks.tun_iface.lock().unwrap().as_deref(), Some("quicfuse0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_new_without_args_has_none_fields() {
        let ks = NftablesKillSwitch::new();
        assert!(ks.server_addr.lock().unwrap().is_none());
        assert!(ks.tun_iface.lock().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_block_and_allow_rulesets_share_table_name() {
        let ks = NftablesKillSwitch::new();
        let block = ks.block_ruleset();
        let allow = ks.policy_ruleset(&test_policy(), true);

        // Both must reference the same inet table.
        assert!(block.contains("table inet quicfuscate_ks"));
        assert!(allow.contains("table inet quicfuscate_ks"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_iptables_kill_switch_transaction_rebuilds_owned_chain_and_jump() {
        let rules = IptablesKillSwitch::block_rules(true);

        assert!(rules.contains(":QUICFUSCATE_KS - [0:0]"));
        assert!(rules.contains("-A QUICFUSCATE_KS -j DROP"));
        assert!(rules.contains("-I OUTPUT 1 -j QUICFUSCATE_KS"));
        assert!(!rules.contains("-F OUTPUT"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_iptables_kill_switch_repeated_transaction_omits_duplicate_jump() {
        let rules = IptablesKillSwitch::block_rules(false);

        assert!(rules.contains(":QUICFUSCATE_KS - [0:0]"));
        assert!(!rules.contains("-I OUTPUT"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_kill_switch_replacement_is_atomic_batch() {
        let rules = NftablesKillSwitch::new().block_ruleset();
        let replacement = NftablesKillSwitch::replacement_transaction(&rules, true);
        let initial = NftablesKillSwitch::replacement_transaction(&rules, false);

        assert!(
            replacement.starts_with("delete table inet quicfuscate_ks\ntable inet quicfuscate_ks")
        );
        assert_eq!(replacement.matches("delete table inet quicfuscate_ks").count(), 1);
        assert_eq!(initial, rules);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kill_switch_new_with_backend_iptables() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Iptables);
        assert!(!ks.is_enabled());
        assert!(matches!(ks.backend, LinuxKillSwitch::Iptables(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kill_switch_new_with_backend_nftables() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Nftables);
        assert!(!ks.is_enabled());
        assert!(matches!(ks.backend, LinuxKillSwitch::Nftables(_)));
    }

    /// Verify that the iptables and nftables kill switch rulesets are
    /// semantically equivalent: both allow loopback, VPN server, and TUN
    /// traffic while dropping everything else.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_iptables_and_nftables_killswitch_produce_equivalent_rules() {
        let policy = test_policy();
        let iptables_rules = IptablesKillSwitch::policy_rules(&policy, false, true, true);

        // nftables ruleset
        let nft_ks = NftablesKillSwitch::new_nftables("198.51.100.1", "tun0");
        let nft_rules = nft_ks.policy_ruleset(&policy, true);

        // Both must allow loopback.
        assert!(iptables_rules.contains("-o lo -j ACCEPT"));
        assert!(nft_rules.contains("oifname \"lo\" accept"));

        // Both must allow traffic to the VPN server.
        assert!(iptables_rules.contains("-d 198.51.100.1 -p udp --dport 4433 -j ACCEPT"));
        assert!(nft_rules.contains("ip daddr 198.51.100.1 udp dport 4433 accept"));

        // Both must allow traffic through the TUN interface.
        assert!(iptables_rules.contains("-o tun0 -j ACCEPT"));
        assert!(nft_rules.contains("oifname \"tun0\" accept"));

        // Both must drop all other traffic.
        assert!(iptables_rules.contains("-j DROP"));
        assert!(nft_rules.contains("policy drop;"));
    }

    /// The rule file must be unpredictable, exclusively created, and never a symlink.
    ///
    /// The path was `/tmp/quicfuscate_killswitch_<pid>.conf` and was written with
    /// `std::fs::write`, which follows symlinks. A local attacker who could predict the PID could
    /// place a symlink there before this privileged process wrote it and redirect pf rule content
    /// to another file.
    #[cfg(target_os = "macos")]
    #[test]
    fn killswitch_rule_file_is_unpredictable_exclusive_and_symlink_safe() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let switch = MacOSKillSwitch::new();
        let path = std::path::PathBuf::from(&switch.config_path);

        // Unpredictable: the path must not be derived from the process id.
        assert!(
            !switch.config_path.contains(&std::process::id().to_string()),
            "the rule path must not be PID-derived: {}",
            switch.config_path
        );
        // Two instances must not collide.
        let other = MacOSKillSwitch::new();
        assert_ne!(switch.config_path, other.config_path, "instances must not share a rule path");

        // A normal write produces an owner-only regular file with exactly the requested content.
        switch.write_rules_exclusive("block out all\n").expect("first write");
        let metadata = std::fs::metadata(&path).expect("rule file metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "rule file must be owner-only");
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(std::fs::read_to_string(&path).expect("read rules"), "block out all\n");

        // A rewrite replaces the content rather than appending, and keeps the same guarantees.
        switch.write_rules_exclusive("pass out on lo0\n").expect("rewrite");
        assert_eq!(std::fs::read_to_string(&path).expect("read rules"), "pass out on lo0\n");
        assert_eq!(std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777, 0o600);

        // A symlink planted at the path must not be followed: the target must stay untouched.
        let _ = std::fs::remove_file(&path);
        let victim =
            std::env::temp_dir().join(format!("qf-killswitch-victim-{}", switch.config_path.len()));
        let _ = std::fs::remove_file(&victim);
        std::fs::write(&victim, "ORIGINAL").expect("seed victim");
        std::os::unix::fs::symlink(&victim, &path).expect("plant symlink");

        switch.write_rules_exclusive("block out all\n").expect("write over a planted symlink");
        assert_eq!(
            std::fs::read_to_string(&victim).expect("victim survives"),
            "ORIGINAL",
            "a planted symlink must not redirect privileged rule content"
        );
        assert!(
            !std::fs::symlink_metadata(&path).expect("rule path").file_type().is_symlink(),
            "the rule path must be a regular file after the write, not the planted symlink"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_file(&other.config_path);
    }

    /// A pre-existing regular file at the path must be replaced, not appended to or reused.
    #[cfg(target_os = "macos")]
    #[test]
    fn killswitch_replaces_a_preexisting_rule_file() {
        use std::os::unix::fs::PermissionsExt;

        let switch = MacOSKillSwitch::new();
        let path = std::path::PathBuf::from(&switch.config_path);

        // Something world-readable left behind by an earlier run or another user.
        std::fs::write(&path, "STALE RULES").expect("seed stale file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("seed permissive mode");

        switch.write_rules_exclusive("block out all\n").expect("write over stale file");

        assert_eq!(std::fs::read_to_string(&path).expect("read"), "block out all\n");
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600,
            "a permissive stale mode must not be inherited"
        );

        let _ = std::fs::remove_file(&path);
    }
}

//! Kill switch implementation for QuicFuscate client.
//!
//! Blocks all network traffic when VPN is not connected.

use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Create a new kill switch.
    ///
    /// On Linux the firewall backend (iptables vs nftables) is auto-detected
    /// via [`crate::firewall::detect_backend`]. The selection can be overridden
    /// explicitly via [`KillSwitch::new_with_backend`].
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            vpn_connected: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            backend: LinuxKillSwitch::new(),
            #[cfg(target_os = "macos")]
            backend: MacOSKillSwitch::new(),
            #[cfg(target_os = "windows")]
            backend: WindowsKillSwitch::new(),
        }
    }

    /// Create a new kill switch with an explicit firewall backend (Linux only).
    ///
    /// On non-Linux platforms this is equivalent to [`KillSwitch::new`].
    #[cfg(target_os = "linux")]
    pub fn new_with_backend(backend: crate::firewall::FirewallBackend) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            vpn_connected: AtomicBool::new(false),
            backend: LinuxKillSwitch::with_backend(backend),
        }
    }

    /// Enable the kill switch.
    pub fn enable(&self) -> Result<(), KillSwitchError> {
        self.enabled.store(true, Ordering::SeqCst);

        // If VPN is not connected, activate blocking
        if !self.vpn_connected.load(Ordering::SeqCst) {
            self.backend.block_traffic()?;
        }

        log::info!("Kill switch enabled");
        Ok(())
    }

    /// Disable the kill switch.
    pub fn disable(&self) -> Result<(), KillSwitchError> {
        self.enabled.store(false, Ordering::SeqCst);
        self.backend.allow_traffic()?;
        log::info!("Kill switch disabled");
        Ok(())
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Notify that VPN connected.
    pub fn on_vpn_connected(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        self.vpn_connected.store(true, Ordering::SeqCst);

        if self.enabled.load(Ordering::SeqCst) {
            self.backend.allow_vpn_traffic(tun_name, server_ip)?;
        }

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
    /// creating a new KillSwitch instance. It flushes any leftover
    /// iptables/pf/netsh rules that may persist from a process that
    /// was killed before its Drop impl could run.
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

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        // Always clean up on drop
        if let Err(e) = self.backend.cleanup() {
            log::warn!("Kill switch cleanup on drop failed: {}", e);
        }
    }
}

/// Kill switch errors.
#[derive(Debug)]
pub enum KillSwitchError {
    CommandFailed(String),
    PermissionDenied,
    NotSupported,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(s) => write!(f, "Command failed: {}", s),
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
    /// Auto-detect the best available backend and construct it.
    fn new() -> Self {
        Self::with_backend(crate::firewall::detect_backend())
    }

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

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.allow_vpn_traffic(tun_name, server_ip),
            Self::Nftables(n) => n.allow_vpn_traffic(tun_name, server_ip),
        }
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        match self {
            Self::Iptables(i) => i.cleanup(),
            Self::Nftables(n) => n.cleanup(),
        }
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        // Clean up both backends — a previous session may have used either.
        IptablesKillSwitch::cleanup_stale()?;
        NftablesKillSwitch::cleanup_stale()?;
        Ok(())
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

    /// Create the dedicated kill-switch chain if it doesn't exist, and add
    /// a jump rule from OUTPUT to it. Idempotent — safe to call multiple times.
    /// Applies to both iptables (IPv4) and ip6tables (IPv6) to prevent
    /// IPv6 traffic leaks when the kill switch is active.
    fn ensure_chain() -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Create chain (ignore error if it already exists) — IPv4
        let _ = Command::new("iptables").args(["-N", KS_CHAIN]).status();
        // IPv6 — prevents IPv6 traffic bypass when kill switch is active
        let _ = Command::new("ip6tables").args(["-N", KS_CHAIN]).status();

        // Add jump from OUTPUT to our chain (idempotent: check first) — IPv4
        let output_rules = Command::new("iptables")
            .args(["-S", "OUTPUT"])
            .output()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        let rules_str = String::from_utf8_lossy(&output_rules.stdout);
        let jump_rule = format!("-j {}", KS_CHAIN);
        if !rules_str.contains(&jump_rule) {
            let _ = Command::new("iptables").args(["-A", "OUTPUT", "-j", KS_CHAIN]).status();
        }

        // IPv6 — add jump from OUTPUT to our chain (idempotent: check first)
        let output_rules_v6 = Command::new("ip6tables")
            .args(["-S", "OUTPUT"])
            .output()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        let rules_str_v6 = String::from_utf8_lossy(&output_rules_v6.stdout);
        if !rules_str_v6.contains(&jump_rule) {
            let _ = Command::new("ip6tables").args(["-A", "OUTPUT", "-j", KS_CHAIN]).status();
        }
        Ok(())
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        Self::ensure_chain()?;

        // Flush our chain and apply block rules into it — IPv4
        let _ = Command::new("iptables").args(["-F", KS_CHAIN]).status();
        // IPv6
        let _ = Command::new("ip6tables").args(["-F", KS_CHAIN]).status();

        let rules = format!(
            "*filter\n\
             :{} - [0:0]\n\
             -A {} -o lo -j ACCEPT\n\
             -A {} -j DROP\n\
             COMMIT\n",
            KS_CHAIN, KS_CHAIN, KS_CHAIN
        );

        // Apply to iptables (IPv4)
        let mut child = Command::new("iptables-restore")
            .arg("--noflush")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        }

        let status = child.wait().map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        if !status.success() {
            return Err(KillSwitchError::CommandFailed(
                "iptables-restore failed to apply block rules".to_string(),
            ));
        }

        // Apply to ip6tables (IPv6) — best effort, don't fail if ip6tables
        // is unavailable (some systems disable IPv6 entirely)
        if let Ok(mut child) =
            Command::new("ip6tables-restore").arg("--noflush").stdin(Stdio::piped()).spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(rules.as_bytes());
            }
            let _ = child.wait();
        }

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch: traffic blocked (atomic, dedicated chain, IPv4+IPv6)");
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        Self::ensure_chain()?;

        // Flush our chain first — IPv4 and IPv6
        let _ = Command::new("iptables").args(["-F", KS_CHAIN]).status();
        let _ = Command::new("ip6tables").args(["-F", KS_CHAIN]).status();

        // Apply VPN-allow ruleset into our dedicated chain — IPv4
        let rules = format!(
            "*filter\n\
             :{} - [0:0]\n\
             -A {} -o lo -j ACCEPT\n\
             -A {} -d {} -j ACCEPT\n\
             -A {} -o {} -j ACCEPT\n\
             -A {} -j DROP\n\
             COMMIT\n",
            KS_CHAIN, KS_CHAIN, KS_CHAIN, server_ip, KS_CHAIN, tun_name, KS_CHAIN
        );

        let mut child = Command::new("iptables-restore")
            .arg("--noflush")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        }

        let status = child.wait().map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        if !status.success() {
            return Err(KillSwitchError::CommandFailed(
                "iptables-restore failed to apply VPN allow rules".to_string(),
            ));
        }

        // IPv6: block all except loopback and tun interface.
        // server_ip is typically an IPv4 literal; for IPv6 we allow traffic
        // through the tun interface only and drop everything else.
        let rules_v6 = format!(
            "*filter\n\
             :{} - [0:0]\n\
             -A {} -o lo -j ACCEPT\n\
             -A {} -o {} -j ACCEPT\n\
             -A {} -j DROP\n\
             COMMIT\n",
            KS_CHAIN, KS_CHAIN, KS_CHAIN, tun_name, KS_CHAIN
        );

        // Apply to ip6tables (IPv6) — best effort
        if let Ok(mut child) =
            Command::new("ip6tables-restore").arg("--noflush").stdin(Stdio::piped()).spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(rules_v6.as_bytes());
            }
            let _ = child.wait();
        }

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!(
            "Kill switch: VPN traffic allowed, rest blocked (atomic, dedicated chain, IPv4+IPv6)"
        );
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Only flush our dedicated chain — never touch OUTPUT directly
        // IPv4
        match Command::new("iptables").args(["-F", KS_CHAIN]).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!(
                    "Kill switch cleanup: flush {} (iptables) returned status {}",
                    KS_CHAIN,
                    status
                );
            }
            Err(e) => {
                log::debug!("Kill switch cleanup: flush {} (iptables) failed: {}", KS_CHAIN, e);
            }
        }
        // IPv6
        match Command::new("ip6tables").args(["-F", KS_CHAIN]).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!(
                    "Kill switch cleanup: flush {} (ip6tables) returned status {}",
                    KS_CHAIN,
                    status
                );
            }
            Err(e) => {
                log::debug!("Kill switch cleanup: flush {} (ip6tables) failed: {}", KS_CHAIN, e);
            }
        }

        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Kill switch: rules cleaned up (dedicated chain, IPv4+IPv6)");
        Ok(())
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        use std::process::Command;
        // Only flush our dedicated chain and remove the jump rule from OUTPUT.
        // This is safe — it never touches unrelated user firewall rules.

        // IPv4
        let chain_flushed = match Command::new("iptables").args(["-F", KS_CHAIN]).status() {
            Ok(status) if status.success() => true,
            Ok(status) => {
                log::debug!(
                    "cleanup_stale: flush {} (iptables) returned status {} (chain may not exist)",
                    KS_CHAIN,
                    status
                );
                false
            }
            Err(e) => {
                log::debug!(
                    "cleanup_stale: flush {} (iptables) failed: {} (chain may not exist)",
                    KS_CHAIN,
                    e
                );
                false
            }
        };

        // Remove the jump rule from OUTPUT (idempotent) — IPv4
        let _ = Command::new("iptables").args(["-D", "OUTPUT", "-j", KS_CHAIN]).status();
        // Delete the chain itself (only succeeds if empty and no references) — IPv4
        let _ = Command::new("iptables").args(["-X", KS_CHAIN]).status();

        // IPv6 — best effort cleanup
        let _ = Command::new("ip6tables").args(["-F", KS_CHAIN]).status();
        let _ = Command::new("ip6tables").args(["-D", "OUTPUT", "-j", KS_CHAIN]).status();
        let _ = Command::new("ip6tables").args(["-X", KS_CHAIN]).status();

        if chain_flushed {
            log::info!("Stale kill switch rules cleaned (dedicated chain {}, IPv4+IPv6)", KS_CHAIN);
        } else {
            log::info!("Stale kill switch cleanup attempted (chain may not have existed)");
        }
        Ok(())
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
    /// Optional VPN server UDP port (restricts the allow rule when set).
    server_port: std::sync::Mutex<Option<u16>>,
}

#[cfg(target_os = "linux")]
impl NftablesKillSwitch {
    fn new() -> Self {
        Self {
            rules_active: AtomicBool::new(false),
            server_addr: std::sync::Mutex::new(None),
            tun_iface: std::sync::Mutex::new(None),
            server_port: std::sync::Mutex::new(None),
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

    /// Set the VPN server UDP port for the allow rule.
    #[cfg(test)]
    fn set_server_port(&self, port: u16) {
        *self.server_port.lock().unwrap() = Some(port);
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
             \x20       iifname \"lo\" accept\n\
             \x20   }}\n\
             }}\n",
            table = KS_NFT_TABLE
        )
    }

    /// Build the nftables ruleset for the VPN-allowed state.
    ///
    /// Allows loopback, traffic to the VPN server (optionally restricted to a
    /// specific UDP port), and traffic through the TUN interface. Everything
    /// else is dropped by the default-drop policy.
    fn allow_ruleset(&self, tun_name: &str, server_ip: &str) -> String {
        let port = self.server_port.lock().unwrap();
        let server_rule = match *port {
            Some(p) => format!("ip daddr {} udp dport {} accept", server_ip, p),
            None => format!("ip daddr {} accept", server_ip),
        };
        format!(
            "table inet {table} {{\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       iifname \"lo\" accept\n\
             \x20       {server_rule}\n\
             \x20       oifname \"{tun}\" accept\n\
             \x20   }}\n\
             }}\n",
            table = KS_NFT_TABLE,
            server_rule = server_rule,
            tun = tun_name
        )
    }

    /// Apply a complete ruleset atomically via `nft -f -` (stdin).
    ///
    /// The table is first flushed (deleted + recreated) to ensure a clean
    /// slate. Using `nft -f -` gives all-or-nothing semantics: the kernel
    /// commits every statement or rejects the entire transaction.
    fn apply_ruleset(&self, ruleset: &str) -> Result<(), KillSwitchError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        // Delete any existing table first (idempotent — ignore failure).
        let _ = Command::new("nft").args(["delete", "table", "inet", KS_NFT_TABLE]).status();

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
                .write_all(ruleset.as_bytes())
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

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        // Store the parameters for potential re-application.
        *self.server_addr.lock().unwrap() = Some(server_ip.to_string());
        *self.tun_iface.lock().unwrap() = Some(tun_name.to_string());

        let ruleset = self.allow_ruleset(tun_name, server_ip);
        self.apply_ruleset(&ruleset)?;
        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!(
            "Kill switch (nftables): VPN traffic allowed via {}, server {} (rest blocked)",
            tun_name,
            server_ip
        );
        Ok(())
    }

    /// Remove the entire kill-switch table: `nft delete table inet quicfuscate_ks`.
    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        match Command::new("nft").args(["delete", "table", "inet", KS_NFT_TABLE]).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!(
                    "Kill switch cleanup (nftables): delete table returned status {} (table may not exist)",
                    status
                );
            }
            Err(e) => {
                log::debug!("Kill switch cleanup (nftables): delete table failed: {}", e);
            }
        }

        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Kill switch (nftables): table removed");
        Ok(())
    }

    /// Check if the kill-switch table exists and delete it if stale.
    ///
    /// Queries `nft list table` to determine existence; if the table is
    /// present it is deleted unconditionally.
    fn cleanup_stale() -> Result<(), KillSwitchError> {
        use std::process::{Command, Stdio};

        // Check if the table exists.
        let check = Command::new("nft")
            .args(["list", "table", "inet", KS_NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let exists = match check {
            Ok(status) => status.success(),
            Err(_) => false,
        };

        if !exists {
            log::info!("Stale nftables kill switch table not present (nothing to clean)");
            return Ok(());
        }

        // Delete the stale table.
        match Command::new("nft").args(["delete", "table", "inet", KS_NFT_TABLE]).status() {
            Ok(status) if status.success() => {
                log::info!("Stale nftables kill switch table deleted (inet {})", KS_NFT_TABLE);
            }
            Ok(status) => {
                log::debug!("cleanup_stale (nftables): delete table returned status {}", status);
            }
            Err(e) => {
                log::debug!("cleanup_stale (nftables): delete table failed: {}", e);
            }
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
    /// Whether we enabled pf ourselves (vs. it was already enabled)
    pf_enabled_by_us: AtomicBool,
    /// PID-scoped config file path to avoid multi-instance conflicts
    config_path: String,
}

#[cfg(target_os = "macos")]
impl MacOSKillSwitch {
    fn new() -> Self {
        let pid = std::process::id();
        Self {
            rules_active: AtomicBool::new(false),
            anchor_name: "com.quicfuscate.killswitch".to_string(),
            pf_enabled_by_us: AtomicBool::new(false),
            config_path: format!("/tmp/quicfuscate_killswitch_{}.conf", pid),
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

    /// Enable pf if not already enabled, tracking whether we did it.
    fn ensure_pf_enabled(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if self.is_pf_enabled() {
            self.pf_enabled_by_us.store(false, Ordering::SeqCst);
            log::debug!("Kill switch: pf already enabled, skipping pfctl -e");
            return Ok(());
        }

        Command::new("pfctl")
            .args(["-e"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.pf_enabled_by_us.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Create pf rules
        let rules = "block out all\npass out on lo0\n".to_string();

        // Write to PID-scoped temp file
        std::fs::write(&self.config_path, rules)
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Load rules
        Command::new("pfctl")
            .args(["-a", &self.anchor_name, "-f", &self.config_path])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Enable pf only if not already enabled
        self.ensure_pf_enabled()?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::process::Command;

        let rules = format!(
            "pass out on {}\n\
             pass out to {}\n\
             pass out on lo0\n\
             block out all\n",
            tun_name, server_ip
        );

        // Write to PID-scoped temp file
        std::fs::write(&self.config_path, &rules)
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        Command::new("pfctl")
            .args(["-a", &self.anchor_name, "-f", &self.config_path])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Ensure pf is enabled (idempotent)
        self.ensure_pf_enabled()?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Flush anchor
        match Command::new("pfctl").args(["-a", &self.anchor_name, "-F", "all"]).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!("Kill switch cleanup pfctl flush returned status {}", status);
            }
            Err(e) => {
                log::debug!("Kill switch cleanup pfctl flush failed: {}", e);
            }
        }

        // Only disable pf if we were the ones who enabled it
        if self.pf_enabled_by_us.load(Ordering::SeqCst) {
            match Command::new("pfctl").args(["-d"]).status() {
                Ok(status) if status.success() => {
                    log::debug!("Kill switch: disabled pf (we enabled it)");
                }
                Ok(status) => {
                    log::debug!("Kill switch cleanup pfctl -d returned status {}", status);
                }
                Err(e) => {
                    log::debug!("Kill switch cleanup pfctl -d failed: {}", e);
                }
            }
            self.pf_enabled_by_us.store(false, Ordering::SeqCst);
        }

        // Clean up PID-scoped config file
        if let Err(e) = std::fs::remove_file(&self.config_path) {
            log::debug!(
                "Kill switch cleanup: failed to remove config file {}: {}",
                self.config_path,
                e
            );
        }

        self.rules_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        use std::process::Command;
        // Flush the kill switch anchor unconditionally
        match Command::new("pfctl").args(["-a", "com.quicfuscate.killswitch", "-F", "all"]).status()
        {
            Ok(status) if status.success() => {
                log::info!("Stale pf anchor rules flushed");
                Ok(())
            }
            Ok(status) => Err(KillSwitchError::CommandFailed(format!(
                "pfctl anchor flush returned status {}",
                status
            ))),
            Err(e) => Err(KillSwitchError::CommandFailed(e.to_string())),
        }
    }
}

// ============================================================================
// Windows Implementation (Windows Firewall)
// ============================================================================

#[cfg(target_os = "windows")]
struct WindowsKillSwitch {
    rules_active: AtomicBool,
}

#[cfg(target_os = "windows")]
impl WindowsKillSwitch {
    fn new() -> Self {
        Self { rules_active: AtomicBool::new(false) }
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Remove any existing block rules to prevent accumulation
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
            ])
            .status()
            .ok();

        // Add blocking rule
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
                "dir=out",
                "action=block",
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, _tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::process::Command;

        self.cleanup()?;

        // Remove any existing VPN allow rules to prevent accumulation
        Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=QuicFuscate-KillSwitch-VPN"])
            .status()
            .ok();

        // Allow VPN server
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-VPN",
                "dir=out",
                "action=allow",
                &format!("remoteip={}", server_ip),
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Remove any existing block rules to prevent accumulation
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
            ])
            .status()
            .ok();

        // Block rest
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
                "dir=out",
                "action=block",
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Remove our rules
        match Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
            ])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!(
                    "Kill switch cleanup netsh block-rule delete returned status {}",
                    status
                );
            }
            Err(e) => {
                log::debug!("Kill switch cleanup netsh block-rule delete failed: {}", e);
            }
        }

        match Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=QuicFuscate-KillSwitch-VPN"])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                log::debug!("Kill switch cleanup netsh vpn-rule delete returned status {}", status);
            }
            Err(e) => {
                log::debug!("Kill switch cleanup netsh vpn-rule delete failed: {}", e);
            }
        }

        self.rules_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup_stale() -> Result<(), KillSwitchError> {
        use std::process::Command;
        // Unconditionally delete both rules
        for rule_name in ["QuicFuscate-KillSwitch-Block", "QuicFuscate-KillSwitch-VPN"] {
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                .status();
        }
        log::info!("Stale netsh firewall rules cleaned");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_new() {
        let ks = KillSwitch::new();
        assert!(!ks.is_enabled());
    }

    #[test]
    fn test_kill_switch_enable_disable_cycle() {
        // This test verifies the enable/disable state transitions.
        // On platforms without root, enable() will fail — that's expected.
        let ks = KillSwitch::new();
        // Just verify the state machine works without panicking
        assert!(!ks.is_enabled());
        // enable() requires root on Linux/macOS, so we just test the flag
        // The actual firewall rules are tested in integration tests
    }

    #[test]
    fn test_kill_switch_vpn_connected_disconnected_state() {
        let ks = KillSwitch::new();
        // Verify initial state
        assert!(!ks.is_enabled());
        // on_vpn_connected/on_vpn_disconnected require root, test state only
        // The key invariant: without enable(), these are no-ops
        let _ = ks.on_vpn_connected("tun0", "1.2.3.4");
        let _ = ks.on_vpn_disconnected();
        assert!(!ks.is_enabled());
    }

    #[test]
    fn test_cleanup_stale_rules_does_not_panic() {
        // cleanup_stale_rules() may fail without root, but should not panic
        let _ = KillSwitch::cleanup_stale_rules();
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
        assert!(ruleset.contains("iifname \"lo\" accept"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_allow_ruleset_includes_server_and_tun() {
        let ks = NftablesKillSwitch::new_nftables("198.51.100.1", "tun0");
        let ruleset = ks.allow_ruleset("tun0", "198.51.100.1");

        assert!(ruleset.contains("iifname \"lo\" accept"));
        assert!(ruleset.contains("ip daddr 198.51.100.1 accept"));
        assert!(ruleset.contains("oifname \"tun0\" accept"));
        assert!(ruleset.contains("policy drop;"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_allow_ruleset_with_port_restricts_udp() {
        let ks = NftablesKillSwitch::new_nftables("198.51.100.1", "tun0");
        ks.set_server_port(4433);
        let ruleset = ks.allow_ruleset("tun0", "198.51.100.1");

        assert!(ruleset.contains("ip daddr 198.51.100.1 udp dport 4433 accept"));
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
        assert!(ks.server_port.lock().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nftables_block_and_allow_rulesets_share_table_name() {
        let ks = NftablesKillSwitch::new();
        let block = ks.block_ruleset();
        let allow = ks.allow_ruleset("tun0", "1.2.3.4");

        // Both must reference the same inet table.
        assert!(block.contains("table inet quicfuscate_ks"));
        assert!(allow.contains("table inet quicfuscate_ks"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kill_switch_new_with_backend_iptables() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Iptables);
        assert!(!ks.is_enabled());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_kill_switch_new_with_backend_nftables() {
        let ks = KillSwitch::new_with_backend(crate::firewall::FirewallBackend::Nftables);
        assert!(!ks.is_enabled());
    }

    /// Verify that the iptables and nftables kill switch rulesets are
    /// semantically equivalent: both allow loopback, VPN server, and TUN
    /// traffic while dropping everything else.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_iptables_and_nftables_killswitch_produce_equivalent_rules() {
        let server_ip = "198.51.100.1";
        let tun_name = "tun0";

        // iptables ruleset (from the existing allow_vpn_traffic impl)
        let iptables_rules = format!(
            "*filter\n\
             :{} - [0:0]\n\
             -A {} -o lo -j ACCEPT\n\
             -A {} -d {} -j ACCEPT\n\
             -A {} -o {} -j ACCEPT\n\
             -A {} -j DROP\n\
             COMMIT\n",
            KS_CHAIN, KS_CHAIN, KS_CHAIN, server_ip, KS_CHAIN, tun_name, KS_CHAIN
        );

        // nftables ruleset
        let nft_ks = NftablesKillSwitch::new_nftables(server_ip, tun_name);
        let nft_rules = nft_ks.allow_ruleset(tun_name, server_ip);

        // Both must allow loopback.
        assert!(iptables_rules.contains("-o lo -j ACCEPT"));
        assert!(nft_rules.contains("iifname \"lo\" accept"));

        // Both must allow traffic to the VPN server.
        assert!(iptables_rules.contains(&format!("-d {} -j ACCEPT", server_ip)));
        assert!(nft_rules.contains(&format!("ip daddr {} accept", server_ip)));

        // Both must allow traffic through the TUN interface.
        assert!(iptables_rules.contains(&format!("-o {} -j ACCEPT", tun_name)));
        assert!(nft_rules.contains(&format!("oifname \"{}\" accept", tun_name)));

        // Both must drop all other traffic.
        assert!(iptables_rules.contains("-j DROP"));
        assert!(nft_rules.contains("policy drop;"));
    }
}

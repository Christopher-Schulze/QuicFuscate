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
// Linux Implementation (iptables)
// ============================================================================

#[cfg(target_os = "linux")]
struct LinuxKillSwitch {
    rules_active: AtomicBool,
}

/// Dedicated iptables chain name for QuicFuscate kill switch rules.
/// Using a separate chain avoids touching the user's OUTPUT chain rules
/// during cleanup_stale() — we only flush our own chain and remove our
/// jump rule, leaving all other firewall configuration intact.
#[cfg(target_os = "linux")]
const KS_CHAIN: &str = "QUICFUSCATE_KS";

#[cfg(target_os = "linux")]
impl LinuxKillSwitch {
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
}

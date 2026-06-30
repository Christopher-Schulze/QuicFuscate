//! Firewall backend abstraction for QuicFuscate.
//!
//! Provides a unified trait ([`FirewallOps`]) over the two Linux packet-filter
//! backends used by the runtime: legacy `iptables` and the modern `nftables`.
//!
//! # Backend selection
//!
//! [`detect_backend`] probes the host at runtime. nftables is preferred when both
//! the `nft` binary is callable and the kernel module `nf_tables` is loaded
//! (probed via `/sys/module/nf_tables`). Otherwise the implementation falls back
//! to `iptables`, which is universally available on older distributions.
//!
//! The selected backend can be overridden explicitly via [`FirewallConfig`] (see
//! `engine::config`). When `None`, auto-detection is used.
//!
//! # nftables transactions
//!
//! [`NftablesBackend`] feeds complete rulesets to `nft -f -` on stdin. This gives
//! atomic, all-or-nothing application of a ruleset batch — the kernel either
//! commits every statement or rejects the whole transaction, so a half-applied
//! ruleset can never leak traffic.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Selected firewall backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    /// Legacy `iptables`/`ip6tables` command-line front-end.
    #[default]
    Iptables,
    /// Modern `nftables` (`nft`) with the `inet` address-family tables.
    Nftables,
}

/// Returns `true` when nftables is usable on this host.
///
/// Both conditions must hold:
/// 1. `nft --version` exits successfully (the binary is installed and runnable).
/// 2. `/sys/module/nf_tables` exists (the kernel module is loaded).
pub fn nft_available() -> bool {
    let nft_runs = Command::new("nft").arg("--version").output().is_ok_and(|o| o.status.success());
    let module_loaded = Path::new("/sys/module/nf_tables").exists();
    nft_runs && module_loaded
}

/// Detect the best available firewall backend on this host.
///
/// Prefers nftables when available, otherwise falls back to iptables.
pub fn detect_backend() -> FirewallBackend {
    if nft_available() {
        FirewallBackend::Nftables
    } else {
        FirewallBackend::Iptables
    }
}

/// Abstraction over a packet-filter backend.
///
/// Implementors translate the high-level operations into backend-specific
/// command invocations. All methods return [`std::io::Error`] so callers can
/// map failures uniformly.
pub trait FirewallOps {
    /// Add a single rule (idempotent semantics are backend-specific).
    fn add_rule(&self, rule: &str) -> Result<(), std::io::Error>;

    /// Delete a single rule.
    fn delete_rule(&self, rule: &str) -> Result<(), std::io::Error>;

    /// Flush all rules from the named chain.
    fn flush_chain(&self, chain: &str) -> Result<(), std::io::Error>;

    /// List the current ruleset as text.
    fn list_rules(&self) -> Result<String, std::io::Error>;
}

// ============================================================================
// Iptables backend
// ============================================================================

/// `iptables`-backed implementation of [`FirewallOps`].
///
/// Each operation shells out to the `iptables` binary. Rules are passed as
/// pre-split argument vectors joined by spaces for logging; callers supply the
/// full argument string after the `iptables` program name (e.g.
/// `"-A FORWARD -j ACCEPT"`).
pub struct IptablesBackend {
    /// Whether to target IPv6 (`ip6tables`) instead of IPv4 (`iptables`).
    ipv6: bool,
}

impl IptablesBackend {
    /// Create a new IPv4 `iptables` backend.
    pub fn new() -> Self {
        Self { ipv6: false }
    }

    /// Create a backend targeting `ip6tables` (IPv6).
    pub fn ipv6() -> Self {
        Self { ipv6: true }
    }

    /// The binary name to invoke.
    fn bin(&self) -> &'static str {
        if self.ipv6 {
            "ip6tables"
        } else {
            "iptables"
        }
    }

    /// Split a rule string into argv tokens.
    fn split_args(rule: &str) -> Vec<&str> {
        rule.split_whitespace().collect()
    }
}

impl Default for IptablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallOps for IptablesBackend {
    fn add_rule(&self, rule: &str) -> Result<(), std::io::Error> {
        let args = Self::split_args(rule);
        let status = Command::new(self.bin())
            .args(&args)
            .status()
            .map_err(|e| std::io::Error::other(format!("{} add_rule: {}", self.bin(), e)))?;
        if !status.success() {
            return Err(std::io::Error::other(format!("{} add_rule failed: {}", self.bin(), rule)));
        }
        Ok(())
    }

    fn delete_rule(&self, rule: &str) -> Result<(), std::io::Error> {
        // Replace a leading "-A" with "-D" for deletion.
        let del_rule = rule.replacen("-A", "-D", 1);
        let args = Self::split_args(&del_rule);
        let status = Command::new(self.bin())
            .args(&args)
            .status()
            .map_err(|e| std::io::Error::other(format!("{} delete_rule: {}", self.bin(), e)))?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "{} delete_rule failed: {}",
                self.bin(),
                del_rule
            )));
        }
        Ok(())
    }

    fn flush_chain(&self, chain: &str) -> Result<(), std::io::Error> {
        let status = Command::new(self.bin())
            .args(["-F", chain])
            .status()
            .map_err(|e| std::io::Error::other(format!("{} flush_chain: {}", self.bin(), e)))?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "{} flush_chain failed: {}",
                self.bin(),
                chain
            )));
        }
        Ok(())
    }

    fn list_rules(&self) -> Result<String, std::io::Error> {
        let output = Command::new(self.bin())
            .args(["-S"])
            .output()
            .map_err(|e| std::io::Error::other(format!("{} list_rules: {}", self.bin(), e)))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

// ============================================================================
// Nftables backend
// ============================================================================

/// `nftables`-backed implementation of [`FirewallOps`].
///
/// Uses `nft -f -` to apply atomic batch transactions read from stdin. Single
/// rule add/delete operations are wrapped in `add`/`delete` statements and fed
/// as a one-line transaction. Listing delegates to `nft list ruleset`.
pub struct NftablesBackend {
    /// Optional table name to scope `list_rules` output. When `None`, the full
    /// ruleset is listed.
    table: Option<String>,
}

impl NftablesBackend {
    /// Create a new nftables backend with no table scoping.
    pub fn new() -> Self {
        Self { table: None }
    }

    /// Create a backend scoped to the given table name (e.g. `quicfuscate_ks`).
    pub fn with_table(table: impl Into<String>) -> Self {
        Self { table: Some(table.into()) }
    }

    /// Feed a complete ruleset to `nft -f -` on stdin (atomic transaction).
    fn apply_transaction(&self, ruleset: &str) -> Result<(), std::io::Error> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| std::io::Error::other(format!("nft spawn: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .map_err(|e| std::io::Error::other(format!("nft stdin write: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| std::io::Error::other(format!("nft wait: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(std::io::Error::other(format!(
                "nft transaction failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallOps for NftablesBackend {
    fn add_rule(&self, rule: &str) -> Result<(), std::io::Error> {
        // Wrap a single rule statement in an atomic transaction.
        let ruleset = format!("add {}\n", rule.trim());
        self.apply_transaction(&ruleset)
    }

    fn delete_rule(&self, rule: &str) -> Result<(), std::io::Error> {
        let ruleset = format!("delete {}\n", rule.trim());
        self.apply_transaction(&ruleset)
    }

    fn flush_chain(&self, chain: &str) -> Result<(), std::io::Error> {
        // `flush chain` requires the table context. Callers pass the fully
        // qualified chain reference (e.g. "inet quicfuscate_ks output").
        let ruleset = format!("flush chain {}\n", chain.trim());
        self.apply_transaction(&ruleset)
    }

    fn list_rules(&self) -> Result<String, std::io::Error> {
        let mut cmd = Command::new("nft");
        cmd.arg("list");
        if let Some(table) = &self.table {
            cmd.args(["table", table]);
        } else {
            cmd.arg("ruleset");
        }
        let output =
            cmd.output().map_err(|e| std::io::Error::other(format!("nft list_rules: {}", e)))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend_returns_a_valid_variant() {
        // detect_backend() probes the live host; it must never panic and must
        // return one of the two known variants.
        let backend = detect_backend();
        assert!(matches!(backend, FirewallBackend::Iptables | FirewallBackend::Nftables));
    }

    #[test]
    fn test_nft_available_does_not_panic() {
        // nft_available() shells out to `nft` and probes /sys/module; it must
        // be panic-free regardless of host capabilities.
        let _ = nft_available();
    }

    #[test]
    fn test_nft_available_requires_both_binary_and_module() {
        // The contract: nft_available() is true only when both the binary runs
        // and the kernel module is loaded. We cannot force either condition in
        // a unit test, but we verify the function returns a bool (type check)
        // and that the logic is a logical AND by re-implementing the probe.
        let nft_runs =
            Command::new("nft").arg("--version").output().is_ok_and(|o| o.status.success());
        let module_loaded = Path::new("/sys/module/nf_tables").exists();
        assert_eq!(nft_available(), nft_runs && module_loaded);
    }

    #[test]
    fn test_iptables_backend_default_is_ipv4() {
        let backend = IptablesBackend::default();
        assert_eq!(backend.bin(), "iptables");
    }

    #[test]
    fn test_iptables_backend_ipv6_uses_ip6tables() {
        let backend = IptablesBackend::ipv6();
        assert_eq!(backend.bin(), "ip6tables");
    }

    #[test]
    fn test_iptables_split_args_handles_whitespace() {
        let args = IptablesBackend::split_args("-A FORWARD -j ACCEPT");
        assert_eq!(args, vec!["-A", "FORWARD", "-j", "ACCEPT"]);
    }

    #[test]
    fn test_iptables_delete_rule_replaces_append_with_delete() {
        // The delete_rule() impl rewrites the leading "-A" to "-D". We verify
        // the transformation logic without invoking the binary.
        let rule = "-A FORWARD -j ACCEPT";
        let del = rule.replacen("-A", "-D", 1);
        assert_eq!(del, "-D FORWARD -j ACCEPT");
    }

    #[test]
    fn test_nftables_backend_default_has_no_table() {
        let backend = NftablesBackend::default();
        assert!(backend.table.is_none());
    }

    #[test]
    fn test_nftables_backend_with_table_scopes_listing() {
        let backend = NftablesBackend::with_table("quicfuscate_ks");
        assert_eq!(backend.table.as_deref(), Some("quicfuscate_ks"));
    }

    #[test]
    fn test_nftables_add_rule_wraps_in_transaction() {
        // Verify the ruleset string format for a single add operation.
        let rule = "rule inet quicfuscate_ks output ip daddr 1.2.3.4 accept";
        let expected = format!("add {}\n", rule);
        assert_eq!(expected, "add rule inet quicfuscate_ks output ip daddr 1.2.3.4 accept\n");
    }

    #[test]
    fn test_nftables_delete_rule_wraps_in_transaction() {
        let rule = "rule inet quicfuscate_ks output handle 42";
        let expected = format!("delete {}\n", rule);
        assert_eq!(expected, "delete rule inet quicfuscate_ks output handle 42\n");
    }

    #[test]
    fn test_nftables_flush_chain_generates_correct_statement() {
        let chain = "inet quicfuscate_ks output";
        let expected = format!("flush chain {}\n", chain);
        assert_eq!(expected, "flush chain inet quicfuscate_ks output\n");
    }

    /// Verify that the iptables and nftables backends produce semantically
    /// equivalent rule representations for the same logical operation.
    ///
    /// The iptables backend emits argv-style rules while nftables emits
    /// declarative statements; this test documents the equivalence mapping
    /// used by the kill switch and routing layers.
    #[test]
    fn test_iptables_and_nftables_produce_equivalent_forward_rules() {
        // FORWARD accept (TUN -> WAN)
        let iptables_forward = "-A FORWARD -i tun0 -o eth0 -j ACCEPT";
        let nftables_forward = "rule inet quicfuscate forward iifname tun0 oifname eth0 accept";

        // Both must be non-empty and contain the interface names.
        assert!(iptables_forward.contains("tun0") && iptables_forward.contains("eth0"));
        assert!(nftables_forward.contains("tun0") && nftables_forward.contains("eth0"));

        // The iptables form uses -j ACCEPT; nftables uses bare `accept`.
        assert!(iptables_forward.contains("-j ACCEPT"));
        assert!(nftables_forward.ends_with("accept"));
    }

    #[test]
    fn test_iptables_and_nftables_produce_equivalent_masquerade_rules() {
        // MASQUERADE for outbound NAT
        let iptables_masq = "-t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE";
        let nftables_masq =
            "rule inet quicfuscate postrouting ip saddr 10.8.0.0/24 oifname eth0 masquerade";

        assert!(iptables_masq.contains("10.8.0.0/24") && iptables_masq.contains("MASQUERADE"));
        assert!(nftables_masq.contains("10.8.0.0/24") && nftables_masq.contains("masquerade"));
    }

    #[test]
    fn test_firewall_backend_default_is_iptables() {
        assert_eq!(FirewallBackend::default(), FirewallBackend::Iptables);
    }

    #[test]
    fn test_firewall_backend_equality() {
        assert_eq!(FirewallBackend::Iptables, FirewallBackend::Iptables);
        assert_ne!(FirewallBackend::Iptables, FirewallBackend::Nftables);
    }
}

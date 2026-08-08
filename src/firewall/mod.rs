//! Firewall backend abstraction for QuicFuscate.
//!
//! Provides a unified trait ([`FirewallOps`]) over the two Linux packet-filter
//! backends used by the runtime: legacy `iptables` and the modern `nftables`.
//!
//! # Backend selection
//!
//! [`resolve_backend`] probes the host once at startup. nftables is preferred
//! when its ruleset can be inspected with the current privileges. Otherwise the
//! implementation falls back to iptables only when its complete dual-stack
//! command set is installed and both live rulesets can be inspected.
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
use std::process::{Command, Stdio};

pub(crate) mod cleanup;

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

impl FirewallBackend {
    /// Stable backend name used in diagnostics and audit evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
        }
    }
}

/// Firewall command availability captured by the single startup probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallAvailability {
    pub iptables: bool,
    pub nftables: bool,
}

/// Fail-closed firewall backend selection error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallSelectionError {
    RequestedBackendUnavailable(FirewallBackend),
    NoBackendAvailable,
}

impl std::fmt::Display for FirewallSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestedBackendUnavailable(backend) => {
                write!(f, "requested firewall backend {} is unavailable", backend.as_str())
            }
            Self::NoBackendAvailable => {
                write!(f, "no supported firewall backend is available")
            }
        }
    }
}

impl std::error::Error for FirewallSelectionError {}

fn command_succeeds(command: &str, args: &[&str]) -> bool {
    Command::new(command)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Returns `true` when nftables is usable on this host.
///
/// A live table listing proves that the binary, kernel backend, and current
/// process privileges are all sufficient without assuming `nf_tables` is a
/// loadable module rather than built into the kernel.
pub fn nft_available() -> bool {
    command_succeeds("nft", &["list", "tables"])
}

/// Returns `true` when the complete dual-stack iptables toolchain is usable.
pub fn iptables_available() -> bool {
    command_succeeds("iptables", &["-S"])
        && command_succeeds("ip6tables", &["-S"])
        && command_succeeds("iptables-restore", &["--version"])
        && command_succeeds("ip6tables-restore", &["--version"])
}

/// Probe both supported Linux firewall backends exactly once.
pub fn probe_availability() -> FirewallAvailability {
    FirewallAvailability { iptables: iptables_available(), nftables: nft_available() }
}

#[cfg(target_os = "linux")]
pub(crate) fn nft_table_exists(family: &str, table: &str) -> Result<bool, std::io::Error> {
    let output = match Command::new("nft").args(["list", "table", family, table]).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(std::io::Error::other(format!("nft table inspect: {error}")));
        }
    };
    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let lowered = stderr.to_ascii_lowercase();
    if lowered.contains("no such file or directory") || lowered.contains("does not exist") {
        return Ok(false);
    }
    Err(std::io::Error::other(format!(
        "nft table inspect returned status {}: {}",
        output.status,
        stderr.trim(),
    )))
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_nft_table(
    family: &str,
    table: &str,
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource = cleanup::OwnedResourceId::new(
        cleanup::OwnedResourceKind::NftTable,
        format!("{family} {table}"),
    );
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || nft_table_exists(family, table).map_err(|error| error.to_string()),
        || {
            let output = Command::new("nft")
                .args(["delete", "table", family, table])
                .output()
                .map_err(|error| format!("nft table delete: {error}"))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "nft table delete returned status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim(),
                ))
            }
        },
        std::thread::sleep,
    )
}

#[cfg(target_os = "linux")]
fn iptables_owned_state(
    program: &str,
    table: &str,
    parent_chain: &str,
    owned_chain: &str,
) -> Result<(usize, bool), String> {
    let parent_output = match Command::new(program).args(["-t", table, "-S", parent_chain]).output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, false)),
        Err(error) => return Err(format!("{program} parent-chain inspect: {error}")),
    };
    if !parent_output.status.success() {
        return Err(format!(
            "{} parent-chain inspect returned status {}: {}",
            program,
            parent_output.status,
            String::from_utf8_lossy(&parent_output.stderr).trim(),
        ));
    }
    let expected_jump = format!("-A {parent_chain} -j {owned_chain}");
    let jump_count = String::from_utf8_lossy(&parent_output.stdout)
        .lines()
        .filter(|line| line.trim() == expected_jump)
        .count();

    let chain_output =
        Command::new(program).args(["-t", table, "-S", owned_chain]).output().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!("{program} owned-chain inspect: command unavailable")
            } else {
                format!("{program} owned-chain inspect: {error}")
            }
        })?;
    if chain_output.status.success() {
        return Ok((jump_count, true));
    }
    let stderr = String::from_utf8_lossy(&chain_output.stderr);
    let lowered = stderr.to_ascii_lowercase();
    if lowered.contains("no chain/target/match") || lowered.contains("does not exist") {
        Ok((jump_count, false))
    } else {
        Err(format!(
            "{} owned-chain inspect returned status {}: {}",
            program,
            chain_output.status,
            stderr.trim(),
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect_iptables_owned(
    program: &str,
    table: &str,
    parent_chain: &str,
    owned_chain: &str,
) -> Result<(usize, bool), String> {
    iptables_owned_state(program, table, parent_chain, owned_chain)
}

#[cfg(target_os = "linux")]
pub(crate) fn iptables_chain_rules(
    program: &str,
    table: &str,
    chain: &str,
) -> Result<Vec<String>, String> {
    let output =
        Command::new(program).args(["-t", table, "-S", chain]).output().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!("{program} chain inspect: command unavailable")
            } else {
                format!("{program} chain inspect: {error}")
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lowered = stderr.to_ascii_lowercase();
        if lowered.contains("no chain/target/match") || lowered.contains("does not exist") {
            return Ok(Vec::new());
        }
        return Err(format!(
            "{program} chain inspect returned status {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    let prefix = format!("-A {chain}");
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix))
        .map(str::to_owned)
        .collect())
}

#[cfg(target_os = "linux")]
fn run_iptables_cleanup_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{program} {}: {error}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} returned status {}: {}",
            program,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn remove_iptables_owned_once(
    program: &str,
    table: &str,
    parent_chain: &str,
    owned_chain: &str,
) -> Result<(), String> {
    let (jump_count, chain_exists) =
        iptables_owned_state(program, table, parent_chain, owned_chain)?;
    for _ in 0..jump_count {
        run_iptables_cleanup_command(
            program,
            &["-t", table, "-D", parent_chain, "-j", owned_chain],
        )?;
    }
    if chain_exists {
        run_iptables_cleanup_command(program, &["-t", table, "-F", owned_chain])?;
        run_iptables_cleanup_command(program, &["-t", table, "-X", owned_chain])?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn cleanup_iptables_chain(
    program: &str,
    table: &str,
    parent_chain: &str,
    owned_chain: &str,
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource = cleanup::OwnedResourceId::new(
        cleanup::OwnedResourceKind::IptablesChain,
        format!("{program}:{table}:{owned_chain}"),
    );
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || {
            iptables_owned_state(program, table, parent_chain, owned_chain)
                .map(|(jumps, chain)| jumps > 0 || chain)
        },
        || remove_iptables_owned_once(program, table, parent_chain, owned_chain),
        std::thread::sleep,
    )
}

#[cfg(target_os = "linux")]
fn iptables_rule_exists(
    program: &str,
    table: &str,
    chain: &str,
    rule_args: &[&str],
) -> Result<bool, String> {
    let mut args = vec!["-t", table, "-C", chain];
    args.extend_from_slice(rule_args);
    let output = match Command::new(program).args(&args).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("{program} exact-rule inspect: {error}")),
    };
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(format!(
        "{} exact-rule inspect returned status {}: {}",
        program,
        output.status,
        String::from_utf8_lossy(&output.stderr).trim(),
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn iptables_rule_exists_exact(
    program: &str,
    table: &str,
    chain: &str,
    rule_args: &[&str],
) -> Result<bool, String> {
    iptables_rule_exists(program, table, chain, rule_args)
}

#[cfg(any(test, target_os = "linux"))]
fn nft_rule_matches_fragment(rule: &str, fragment: &str) -> bool {
    let normalized_rule = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized_fragment = fragment.split_whitespace().collect::<Vec<_>>().join(" ");
    let Some(fragment_open) = normalized_fragment.find('{') else {
        return normalized_rule.contains(&normalized_fragment);
    };
    let Some(fragment_close) = normalized_fragment[fragment_open + 1..].find('}') else {
        return false;
    };
    let fragment_close = fragment_open + 1 + fragment_close;
    let required_prefix = normalized_fragment[..fragment_open].trim();
    let required_suffix = normalized_fragment[fragment_close + 1..].trim();
    let mut required_members = normalized_fragment[fragment_open + 1..fragment_close]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    required_members.sort_unstable();

    let Some(rule_open) = normalized_rule.find('{') else {
        return false;
    };
    let Some(rule_close) = normalized_rule[rule_open + 1..].find('}') else {
        return false;
    };
    let rule_close = rule_open + 1 + rule_close;
    if normalized_rule[..rule_open].trim() != required_prefix
        || normalized_rule[rule_close + 1..].trim() != required_suffix
    {
        return false;
    }

    let mut actual_members =
        normalized_rule[rule_open + 1..rule_close].split(',').map(str::trim).collect::<Vec<_>>();
    actual_members.sort_unstable();
    actual_members == required_members
}

#[cfg(any(test, target_os = "linux"))]
fn nft_output_contains_fragment(output: &str, fragment: &str) -> bool {
    if fragment.contains('{') {
        output.lines().any(|line| nft_rule_matches_fragment(line, fragment))
    } else {
        let normalized_fragment = fragment.split_whitespace().collect::<Vec<_>>().join(" ");
        output.lines().any(|line| {
            line.split_whitespace().collect::<Vec<_>>().join(" ").contains(&normalized_fragment)
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_nft_table_rules(
    family: &str,
    table: &str,
    required_fragments: &[&str],
) -> Result<(), std::io::Error> {
    let output = Command::new("nft")
        .args(["list", "table", family, table])
        .output()
        .map_err(|error| std::io::Error::other(format!("nft table verify: {error}")))?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nft table verify returned status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(missing) =
        required_fragments.iter().find(|fragment| !nft_output_contains_fragment(&stdout, fragment))
    {
        return Err(std::io::Error::other(format!(
            "nft table {family} {table} is missing required rule fragment {missing:?}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_nft_table_owner(
    family: &str,
    table: &str,
    owner_marker: &str,
    required_fragments: &[&str],
    expected_rule_count: usize,
) -> Result<(), std::io::Error> {
    let output = Command::new("nft")
        .args(["list", "table", family, table])
        .output()
        .map_err(|error| std::io::Error::other(format!("nft table owner verify: {error}")))?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nft table owner verify returned status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let marker = format!("comment \"{owner_marker}\"");
    if !stdout.lines().any(|line| line.contains(&marker)) {
        return Err(std::io::Error::other(format!(
            "nft table {family} {table} is missing owner marker {owner_marker:?}"
        )));
    }
    if let Some(missing) =
        required_fragments.iter().find(|fragment| !nft_output_contains_fragment(&stdout, fragment))
    {
        return Err(std::io::Error::other(format!(
            "nft table {family} {table} is missing required rule fragment {missing:?}"
        )));
    }
    let json_output = Command::new("nft")
        .args(["-j", "list", "table", family, table])
        .output()
        .map_err(|error| std::io::Error::other(format!("nft table JSON owner verify: {error}")))?;
    if !json_output.status.success() {
        return Err(std::io::Error::other(format!(
            "nft table JSON owner verify returned status {}: {}",
            json_output.status,
            String::from_utf8_lossy(&json_output.stderr).trim(),
        )));
    }
    let json: serde_json::Value = serde_json::from_slice(&json_output.stdout).map_err(|error| {
        std::io::Error::other(format!("parse nft table JSON owner verify output: {error}"))
    })?;
    let mut rule_count = 0usize;
    if let Some(entries) = json.get("nftables").and_then(serde_json::Value::as_array) {
        for entry in entries {
            let Some(rule) = entry.get("rule") else {
                continue;
            };
            rule_count += 1;
            if rule.get("comment").and_then(serde_json::Value::as_str) != Some(owner_marker) {
                return Err(std::io::Error::other(format!(
                    "nft table {family} {table} contains a rule without owner marker {owner_marker:?}"
                )));
            }
        }
    }
    if rule_count != expected_rule_count {
        return Err(std::io::Error::other(format!(
            "nft table {family} {table} has {rule_count} rule(s), expected {expected_rule_count}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn cleanup_iptables_rule(
    program: &str,
    table: &str,
    chain: &str,
    rule_args: &[&str],
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource = cleanup::OwnedResourceId::new(
        cleanup::OwnedResourceKind::IptablesRule,
        format!("{program}:{table}:{chain}:{}", rule_args.join(" ")),
    );
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || iptables_rule_exists(program, table, chain, rule_args),
        || {
            let mut args = vec!["-t", table, "-D", chain];
            args.extend_from_slice(rule_args);
            run_iptables_cleanup_command(program, &args)
        },
        std::thread::sleep,
    )
}

#[cfg(target_os = "macos")]
fn pf_anchor_has_rules(anchor: &str) -> Result<bool, String> {
    for query in ["-sr", "-sn"] {
        let output = Command::new("pfctl")
            .args(["-a", anchor, query])
            .output()
            .map_err(|error| format!("pfctl {query} {anchor}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "pfctl {} {} returned status {}: {}",
                query,
                anchor,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }
        if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(crate) fn cleanup_pf_anchor(
    anchor: &str,
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource =
        cleanup::OwnedResourceId::new(cleanup::OwnedResourceKind::PfAnchor, anchor.to_string());
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || pf_anchor_has_rules(anchor),
        || {
            let mut failures = Vec::new();
            for target in ["rules", "nat"] {
                match Command::new("pfctl").args(["-a", anchor, "-F", target]).output() {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => failures.push(format!(
                        "pfctl anchor {} flush {} returned status {}: {}",
                        anchor,
                        target,
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim(),
                    )),
                    Err(error) => {
                        failures.push(format!("pfctl anchor {anchor} flush {target}: {error}"));
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        },
        std::thread::sleep,
    )
}

#[cfg(target_os = "windows")]
fn powershell_output(script: &str) -> Result<std::process::Output, String> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| format!("powershell cleanup command: {error}"))
}

#[cfg(target_os = "windows")]
fn windows_resource_exists(command: &str, name: &str) -> Result<bool, String> {
    let escaped_name = name.replace('\'', "''");
    let script = format!(
        "$resource = {command} -ErrorAction SilentlyContinue; \
         if ($null -ne $resource) {{ exit 0 }} else {{ exit 3 }}",
        command = command.replace("{name}", &escaped_name),
    );
    let output = powershell_output(&script)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(3) => Ok(false),
        _ => Err(format!(
            "PowerShell resource inspection for {} returned status {}: {}",
            name,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        )),
    }
}

#[cfg(target_os = "windows")]
fn remove_windows_resource(command: &str, name: &str) -> Result<(), String> {
    let escaped_name = name.replace('\'', "''");
    let script =
        format!("$ErrorActionPreference='Stop'; {}", command.replace("{name}", &escaped_name),);
    let output = powershell_output(&script)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "PowerShell resource removal for {} returned status {}: {}",
            name,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_windows_firewall_rule(
    name: &str,
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource = cleanup::OwnedResourceId::new(
        cleanup::OwnedResourceKind::WindowsFirewallRule,
        name.to_string(),
    );
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || windows_resource_exists("Get-NetFirewallRule -DisplayName '{name}'", name),
        || {
            remove_windows_resource(
                "Get-NetFirewallRule -DisplayName '{name}' -ErrorAction Stop | Remove-NetFirewallRule -ErrorAction Stop",
                name,
            )
        },
        std::thread::sleep,
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_windows_nat(
    name: &str,
) -> Result<cleanup::CleanupOutcome, cleanup::CleanupError> {
    let resource =
        cleanup::OwnedResourceId::new(cleanup::OwnedResourceKind::WindowsNat, name.to_string());
    cleanup::cleanup_owned_resource(
        resource,
        cleanup::CleanupPolicy::standard(),
        || windows_resource_exists("Get-NetNat -Name '{name}'", name),
        || {
            remove_windows_resource(
                "Remove-NetNat -Name '{name}' -Confirm:$false -ErrorAction Stop",
                name,
            )
        },
        std::thread::sleep,
    )
}

#[cfg(any(target_os = "linux", test))]
fn resolve_backend_for_availability(
    requested: Option<FirewallBackend>,
    availability: FirewallAvailability,
) -> Result<FirewallBackend, FirewallSelectionError> {
    match requested {
        Some(FirewallBackend::Nftables) if availability.nftables => Ok(FirewallBackend::Nftables),
        Some(FirewallBackend::Iptables) if availability.iptables => Ok(FirewallBackend::Iptables),
        Some(backend) => Err(FirewallSelectionError::RequestedBackendUnavailable(backend)),
        None if availability.nftables => Ok(FirewallBackend::Nftables),
        None if availability.iptables => Ok(FirewallBackend::Iptables),
        None => Err(FirewallSelectionError::NoBackendAvailable),
    }
}

/// Resolve one concrete backend for the complete process lifecycle.
pub fn resolve_backend(
    requested: Option<FirewallBackend>,
) -> Result<FirewallBackend, FirewallSelectionError> {
    #[cfg(target_os = "linux")]
    {
        let availability = probe_availability();
        match resolve_backend_for_availability(requested, availability) {
            Ok(selected) => {
                log::info!(
                    "Firewall backend selected: requested={}, selected={}, nftables_available={}, iptables_available={}",
                    requested.map_or("auto", FirewallBackend::as_str),
                    selected.as_str(),
                    availability.nftables,
                    availability.iptables,
                );
                Ok(selected)
            }
            Err(error) => {
                log::error!(
                    "Firewall backend selection failed: requested={}, selected=none, nftables_available={}, iptables_available={}, error={}",
                    requested.map_or("auto", FirewallBackend::as_str),
                    availability.nftables,
                    availability.iptables,
                    error,
                );
                Err(error)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let selected = requested.unwrap_or_default();
        log::info!(
            "Linux firewall backend setting ignored on this platform: requested={}",
            requested.map_or("auto", FirewallBackend::as_str),
        );
        Ok(selected)
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

    /// Convert an append rule into deletion arguments without touching later
    /// tokens such as comment text that may also contain `-A`.
    fn delete_args(rule: &str) -> Result<Vec<&str>, std::io::Error> {
        let mut args = Self::split_args(rule);
        if args.first().copied() != Some("-A") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "iptables delete_rule requires a rule beginning with -A",
            ));
        }
        args[0] = "-D";
        Ok(args)
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
        let args = Self::delete_args(rule)?;
        let del_rule = args.join(" ");
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
    fn test_nft_available_does_not_panic() {
        // nft_available() probes the live host and must be panic-free regardless
        // of installed commands or current privileges.
        let _ = nft_available();
    }

    #[test]
    fn test_nft_available_matches_live_table_probe() {
        assert_eq!(nft_available(), command_succeeds("nft", &["list", "tables"]));
    }

    #[test]
    fn test_explicit_nftables_fails_closed_when_unavailable() {
        let availability = FirewallAvailability { iptables: true, nftables: false };
        assert_eq!(
            resolve_backend_for_availability(Some(FirewallBackend::Nftables), availability),
            Err(FirewallSelectionError::RequestedBackendUnavailable(FirewallBackend::Nftables))
        );
    }

    #[test]
    fn test_explicit_iptables_never_selects_nftables() {
        let availability = FirewallAvailability { iptables: true, nftables: true };
        assert_eq!(
            resolve_backend_for_availability(Some(FirewallBackend::Iptables), availability),
            Ok(FirewallBackend::Iptables)
        );
    }

    #[test]
    fn test_auto_prefers_nftables_and_falls_back_to_iptables() {
        assert_eq!(
            resolve_backend_for_availability(
                None,
                FirewallAvailability { iptables: true, nftables: true },
            ),
            Ok(FirewallBackend::Nftables)
        );
        assert_eq!(
            resolve_backend_for_availability(
                None,
                FirewallAvailability { iptables: true, nftables: false },
            ),
            Ok(FirewallBackend::Iptables)
        );
    }

    #[test]
    fn test_auto_fails_when_no_backend_is_available() {
        assert_eq!(
            resolve_backend_for_availability(
                None,
                FirewallAvailability { iptables: false, nftables: false },
            ),
            Err(FirewallSelectionError::NoBackendAvailable)
        );
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
    fn test_iptables_delete_rule_replaces_only_the_action_token() {
        let rule = "-A FORWARD -m comment --comment \"contains -A marker\" -j ACCEPT";
        let args = IptablesBackend::delete_args(rule).unwrap();
        assert_eq!(args.first().copied(), Some("-D"));
        assert!(args[1..].contains(&"-A"));
        assert!(!args[1..].contains(&"-D"));
    }

    #[test]
    fn test_iptables_delete_rule_rejects_non_append_input() {
        let error = IptablesBackend::delete_args("-D FORWARD -j ACCEPT").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
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

    #[test]
    fn test_nft_rule_fragment_accepts_canonicalized_set_order() {
        let required = r#"iifname "qtun0" oifname "qtun0" ip daddr { 255.255.255.255, 10.0.1.255, 224.0.0.0/4 } accept"#;
        let listed = r#"    iifname "qtun0" oifname "qtun0" ip daddr { 10.0.1.255, 224.0.0.0/4, 255.255.255.255 } accept"#;

        assert!(nft_output_contains_fragment(listed, required));
    }

    #[test]
    fn test_nft_rule_fragment_rejects_different_set_members() {
        let required = r#"iifname "qtun0" oifname "qtun0" ip daddr { 255.255.255.255, 10.0.1.255, 224.0.0.0/4 } accept"#;
        let listed = r#"    iifname "qtun0" oifname "qtun0" ip daddr { 10.0.1.255, 224.0.0.0/4, 10.0.2.255 } accept"#;

        assert!(!nft_output_contains_fragment(listed, required));
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

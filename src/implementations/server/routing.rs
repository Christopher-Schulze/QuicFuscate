//! NAT and routing configuration for the server.
//!
//! This module handles:
//! - IP forwarding
//! - NAT (MASQUERADE) via iptables/nftables
//! - Firewall rules for VPN traffic

use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

/// Routing manager for VPN server.
#[cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]
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
    /// Path of the durable Linux ownership record used for crash recovery.
    #[cfg(target_os = "linux")]
    ownership_path: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct RoutingOwnership {
    ipv4_address_added: bool,
    ipv6_address_added: bool,
    link_brought_up: bool,
    ipv4_forwarding_previous: Option<String>,
    ipv6_forwarding_previous: Option<String>,
    state_prepared: bool,
    firewall_owner_generation: Option<String>,
    firewall_configured: bool,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BoolMutation {
    before: bool,
    after: bool,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TextMutation {
    before: String,
    after: String,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRoutingOwnership {
    schema: u8,
    tun_name: String,
    interface_index: u32,
    owner_boot_id: String,
    owner_pid: u32,
    owner_start_time: u64,
    server_ipv4: String,
    netmask: String,
    wan_interface: String,
    server_ipv6: Option<String>,
    ipv6_prefix_len: u8,
    firewall_backend: crate::firewall::FirewallBackend,
    firewall_owner_generation: String,
    client_to_client_enabled: bool,
    ipv4_address: BoolMutation,
    ipv6_address: Option<BoolMutation>,
    link_up: BoolMutation,
    ipv4_forwarding: TextMutation,
    ipv6_forwarding: Option<TextMutation>,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedFirewallOwnership {
    schema: u8,
    owner_generation: String,
    tun_name: String,
    firewall_backend: crate::firewall::FirewallBackend,
    firewall_identity: String,
    owner_boot_id: String,
    owner_pid: u32,
    owner_start_time: u64,
    server_ipv4: String,
    netmask: String,
    wan_interface: String,
    server_ipv6: Option<String>,
    ipv6_prefix_len: u8,
    client_to_client_enabled: bool,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryDecision {
    Noop,
    Restore,
    Conflict,
}

#[cfg(any(test, target_os = "linux"))]
fn recovery_decision<T: PartialEq>(before: &T, after: &T, current: &T) -> RecoveryDecision {
    if current == before {
        RecoveryDecision::Noop
    } else if current == after {
        RecoveryDecision::Restore
    } else {
        RecoveryDecision::Conflict
    }
}

#[cfg(any(test, target_os = "linux"))]
fn active_owner_matches(
    state_boot_id: &str,
    current_boot_id: &str,
    state_start_time: u64,
    current_start_time: Option<u64>,
) -> bool {
    state_boot_id == current_boot_id && current_start_time == Some(state_start_time)
}

#[cfg(any(test, target_os = "linux"))]
fn firewall_identity(backend: crate::firewall::FirewallBackend) -> &'static str {
    match backend {
        crate::firewall::FirewallBackend::Iptables => {
            "iptables:filter/QUICFUSCATE_RT,nat/QUICFUSCATE_NAT,ip6tables"
        }
        crate::firewall::FirewallBackend::Nftables => "nftables:inet/quicfuscate_rt",
    }
}

#[cfg(any(test, target_os = "linux"))]
fn firewall_owner_generation(
    tun_name: &str,
    owner_boot_id: &str,
    owner_pid: u32,
    owner_start_time: u64,
) -> String {
    format!(
        "{}-{}-{}-{}",
        owner_boot_id.replace('-', ""),
        owner_pid,
        owner_start_time,
        routing_state_filename(tun_name).trim_end_matches(".json")
    )
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirewallClaimDecision {
    Claim,
    RejectForeignRoutingOwner,
    RejectActiveOwner,
    RejectStaleOwner,
    RejectExistingResource,
}

#[cfg(any(test, target_os = "linux"))]
fn firewall_claim_decision(
    requested_tun: &str,
    existing_routing_tun: Option<&str>,
    existing_owner_active: bool,
    existing_owner_present: bool,
    fixed_resource_present: bool,
) -> FirewallClaimDecision {
    if existing_routing_tun.is_some_and(|tun_name| tun_name != requested_tun) {
        FirewallClaimDecision::RejectForeignRoutingOwner
    } else if existing_owner_present {
        if existing_owner_active {
            FirewallClaimDecision::RejectActiveOwner
        } else {
            FirewallClaimDecision::RejectStaleOwner
        }
    } else if fixed_resource_present {
        FirewallClaimDecision::RejectExistingResource
    } else {
        FirewallClaimDecision::Claim
    }
}

#[cfg(any(test, target_os = "linux"))]
fn routing_state_filename(tun_name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(tun_name.len() * 2 + 5);
    for byte in tun_name.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    if encoded.is_empty() {
        encoded.push_str("empty");
    }
    encoded.push_str(".json");
    encoded
}

#[cfg(target_os = "linux")]
const ROUTING_STATE_DIR: &str = "/run/quicfuscate/routing";

#[cfg(target_os = "linux")]
const ROUTING_FIREWALL_OWNER_FILE: &str = "firewall-owner.json";

#[cfg(any(test, target_os = "linux"))]
const ROUTING_STATE_SCHEMA: u8 = 3;

#[cfg(any(test, target_os = "linux"))]
const FIREWALL_OWNER_SCHEMA: u8 = 1;

#[cfg(target_os = "linux")]
fn default_routing_state_path(tun_name: &str) -> PathBuf {
    Path::new(ROUTING_STATE_DIR).join(routing_state_filename(tun_name))
}

#[cfg(target_os = "linux")]
pub(super) fn persisted_tun_names() -> Result<Vec<String>, RoutingError> {
    let entries = match std::fs::read_dir(ROUTING_STATE_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(RoutingError::CommandFailed(format!(
                "read durable routing state directory {ROUTING_STATE_DIR}: {error}"
            )))
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "enumerate durable routing state directory {ROUTING_STATE_DIR}: {error}"
                ))
            })?
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(ROUTING_FIREWALL_OWNER_FILE) {
            continue;
        }
        if !std::fs::symlink_metadata(&path)
            .map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "inspect durable routing state {}: {error}",
                    path.display()
                ))
            })?
            .file_type()
            .is_file()
        {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state {} is not a regular file",
                path.display()
            )));
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "read durable routing state {}: {error}",
                path.display()
            ))
        })?;
        let state: PersistedRoutingOwnership =
            serde_json::from_str(&contents).map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "parse durable routing state {}: {error}",
                    path.display()
                ))
            })?;
        if state.tun_name.is_empty() || default_routing_state_path(&state.tun_name) != path {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state {} has an invalid TUN identity",
                path.display()
            )));
        }
        names.push(state.tun_name);
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
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
        #[cfg(target_os = "linux")]
        let ownership_path = default_routing_state_path(&tun_name);

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
            #[cfg(target_os = "linux")]
            ownership_path,
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
        #[cfg(target_os = "linux")]
        let ownership_path = default_routing_state_path(&tun_name);

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
            #[cfg(target_os = "linux")]
            ownership_path,
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

    #[cfg(target_os = "linux")]
    fn record_cleanup_failure(failures: &mut Vec<String>, result: Result<(), RoutingError>) {
        if let Err(error) = result {
            failures.push(error.to_string());
        }
    }

    #[cfg(target_os = "linux")]
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
    fn linux_interface_exists(&self) -> Result<bool, RoutingError> {
        let output = Command::new("ip")
            .args(["link", "show", "dev", &self.tun_name])
            .output()
            .map_err(|error| RoutingError::CommandFailed(format!("ip link existence: {error}")))?;
        if output.status.success() {
            return Ok(true);
        }
        let detail = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if detail.contains("does not exist") || detail.contains("cannot find device") {
            return Ok(false);
        }
        Err(RoutingError::CommandFailed(format!(
            "ip link show dev {} returned status {}: {}",
            self.tun_name,
            output.status,
            detail.trim()
        )))
    }

    #[cfg(target_os = "linux")]
    fn linux_interface_index(&self) -> Result<u32, RoutingError> {
        let value = Self::linux_json(&["-j", "link", "show", "dev", &self.tun_name])?;
        value
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.get("ifindex"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "ip link inspection omitted a valid ifindex for {}",
                    self.tun_name
                ))
            })
    }

    #[cfg(target_os = "linux")]
    fn linux_boot_id() -> Result<String, RoutingError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| RoutingError::CommandFailed(format!("read Linux boot ID: {error}")))?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() {
            return Err(RoutingError::CommandFailed("Linux boot ID is empty".to_string()));
        }
        Ok(boot_id.to_string())
    }

    #[cfg(target_os = "linux")]
    fn linux_process_start_time(pid: u32) -> Result<Option<u64>, RoutingError> {
        let path = format!("/proc/{pid}/stat");
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "read Linux process identity {path}: {error}"
                )))
            }
        };
        let fields = contents.rsplit_once(") ").map(|(_, fields)| fields).ok_or_else(|| {
            RoutingError::CommandFailed(format!("parse Linux process identity {path}"))
        })?;
        let start_time = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| {
                RoutingError::CommandFailed(format!(
                    "Linux process identity {path} omitted the start time"
                ))
            })?
            .parse::<u64>()
            .map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "parse Linux process start time in {path}: {error}"
                ))
            })?;
        Ok(Some(start_time))
    }

    #[cfg(target_os = "linux")]
    fn reject_active_owner(state: &PersistedRoutingOwnership) -> Result<(), RoutingError> {
        let current_boot_id = Self::linux_boot_id()?;
        if current_boot_id != state.owner_boot_id {
            return Err(RoutingError::CommandFailed(
                "durable routing state belongs to a different Linux boot; refusing guessed recovery"
                    .to_string(),
            ));
        }
        if active_owner_matches(
            &state.owner_boot_id,
            &current_boot_id,
            state.owner_start_time,
            Self::linux_process_start_time(state.owner_pid)?,
        ) {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state is still owned by active PID {}",
                state.owner_pid
            )));
        }
        Ok(())
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
    fn linux_address_on_other_interface(
        &self,
        family: &str,
        address: &str,
    ) -> Result<Option<String>, RoutingError> {
        let value = Self::linux_json(&["-j", "address", "show"])?;
        let interfaces = value.as_array().ok_or_else(|| {
            RoutingError::CommandFailed(
                "ip address inspection returned no interface array".to_string(),
            )
        })?;
        for interface in interfaces {
            let Some(name) = interface.get("ifname").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if name == self.tun_name {
                continue;
            }
            let Some(addresses) = interface.get("addr_info").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            if addresses.iter().any(|entry| {
                entry.get("family").and_then(serde_json::Value::as_str) == Some(family)
                    && entry.get("local").and_then(serde_json::Value::as_str) == Some(address)
            }) {
                return Ok(Some(name.to_string()));
            }
        }
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn validate_forwarding_mutation(
        label: &str,
        mutation: &TextMutation,
    ) -> Result<(), RoutingError> {
        if !matches!(mutation.before.trim(), "0" | "1") || mutation.after.trim() != "1" {
            return Err(RoutingError::CommandFailed(format!(
                "durable routing state has invalid {label} forwarding mutation"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn validate_persisted_ownership(
        &self,
        state: &PersistedRoutingOwnership,
    ) -> Result<(), RoutingError> {
        if state.schema != ROUTING_STATE_SCHEMA {
            return Err(RoutingError::CommandFailed(format!(
                "unsupported durable routing state schema {}",
                state.schema
            )));
        }
        let expected_ipv6 = self.server_ipv6.map(|address| address.to_string());
        if state.tun_name != self.tun_name
            || state.server_ipv4 != self.server_ip.to_string()
            || state.netmask != self.netmask.to_string()
            || state.wan_interface != self.wan_interface
            || state.server_ipv6 != expected_ipv6
            || state.ipv6_prefix_len != self.ipv6_prefix_len
            || state.firewall_backend != self.firewall_backend
            || state.client_to_client_enabled != self.client_to_client_enabled
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state identity does not match the requested server routing"
                    .to_string(),
            ));
        }
        if self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        if state.interface_index == 0 {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid Linux interface index".to_string(),
            ));
        }
        if state.owner_boot_id.trim().is_empty()
            || state.owner_pid == 0
            || state.owner_start_time == 0
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid process ownership identity".to_string(),
            ));
        }
        if state.firewall_owner_generation.trim().is_empty() {
            return Err(RoutingError::CommandFailed(
                "durable routing state has no firewall ownership generation".to_string(),
            ));
        }
        if !state.ipv4_address.after || !state.link_up.after {
            return Err(RoutingError::CommandFailed(
                "durable routing state does not describe the expected Linux postcondition"
                    .to_string(),
            ));
        }
        if state.ipv6_address.is_some() != self.server_ipv6.is_some()
            || state.ipv6_address.as_ref().is_some_and(|mutation| !mutation.after)
        {
            return Err(RoutingError::CommandFailed(
                "durable routing state has an invalid IPv6 address ownership record".to_string(),
            ));
        }
        Self::validate_forwarding_mutation("IPv4", &state.ipv4_forwarding)?;
        if let Some(mutation) = state.ipv6_forwarding.as_ref() {
            Self::validate_forwarding_mutation("IPv6", mutation)?;
        } else if self.server_ipv6.is_some() {
            return Err(RoutingError::CommandFailed(
                "durable routing state is missing IPv6 forwarding ownership".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_persisted_ownership(&self) -> Result<Option<PersistedRoutingOwnership>, RoutingError> {
        let contents = match std::fs::read_to_string(&self.ownership_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "read durable routing state {}: {error}",
                    self.ownership_path.display()
                )))
            }
        };
        serde_json::from_str(&contents).map(Some).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "parse durable routing state {}: {error}",
                self.ownership_path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn ensure_ownership_directory(&self) -> Result<(), RoutingError> {
        let parent = self.ownership_path.parent().ok_or_else(|| {
            RoutingError::CommandFailed("durable routing state has no parent directory".to_string())
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "create durable routing state directory {}: {error}",
                parent.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    RoutingError::CommandFailed(format!(
                        "secure durable routing state directory {}: {error}",
                        parent.display()
                    ))
                },
            )?;
            let mode = std::fs::metadata(parent)
                .map_err(|error| {
                    RoutingError::CommandFailed(format!(
                        "inspect durable routing state directory {}: {error}",
                        parent.display()
                    ))
                })?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(RoutingError::CommandFailed(format!(
                    "durable routing state directory {} has unsafe mode {:o}",
                    parent.display(),
                    mode
                )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn persist_ownership(&self, state: &PersistedRoutingOwnership) -> Result<(), RoutingError> {
        match std::fs::symlink_metadata(&self.ownership_path) {
            Ok(_) => {
                return Err(RoutingError::CommandFailed(format!(
                "durable routing state {} already exists; stale recovery is required before setup",
                self.ownership_path.display()
            )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "inspect durable routing state {}: {error}",
                    self.ownership_path.display()
                )))
            }
        }
        self.ensure_ownership_directory()?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            RoutingError::CommandFailed(format!("serialize durable routing state: {error}"))
        })?;
        crate::implementations::server::fsutil::atomic_write_file(
            &self.ownership_path,
            &bytes,
            Some(0o600),
            "server::routing_ownership_tmp_nonce",
        )
        .map_err(|error| {
            RoutingError::CommandFailed(format!(
                "persist durable routing state {}: {error}",
                self.ownership_path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn remove_ownership_file(&self) -> Result<(), RoutingError> {
        match std::fs::remove_file(&self.ownership_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(RoutingError::CommandFailed(format!(
                "remove durable routing state {}: {error}",
                self.ownership_path.display()
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn firewall_owner_path(&self) -> PathBuf {
        Path::new(ROUTING_STATE_DIR).join(ROUTING_FIREWALL_OWNER_FILE)
    }

    #[cfg(target_os = "linux")]
    fn read_firewall_ownership(&self) -> Result<Option<PersistedFirewallOwnership>, RoutingError> {
        let path = self.firewall_owner_path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RoutingError::CommandFailed(format!(
                    "inspect durable firewall ownership {}: {error}",
                    path.display()
                )))
            }
        };
        if !metadata.file_type().is_file() {
            return Err(RoutingError::CommandFailed(format!(
                "durable firewall ownership {} is not a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(RoutingError::CommandFailed(format!(
                    "durable firewall ownership {} has unsafe mode {:o}",
                    path.display(),
                    mode
                )));
            }
        }
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "read durable firewall ownership {}: {error}",
                path.display()
            ))
        })?;
        let owner =
            serde_json::from_str::<PersistedFirewallOwnership>(&contents).map_err(|error| {
                RoutingError::CommandFailed(format!(
                    "parse durable firewall ownership {}: {error}",
                    path.display()
                ))
            })?;
        Self::validate_firewall_owner_shape(&owner)?;
        Ok(Some(owner))
    }

    #[cfg(any(test, target_os = "linux"))]
    fn validate_firewall_owner_shape(
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        if owner.schema != FIREWALL_OWNER_SCHEMA {
            return Err(RoutingError::CommandFailed(format!(
                "unsupported durable firewall ownership schema {}",
                owner.schema
            )));
        }
        if owner.tun_name.is_empty()
            || owner.owner_boot_id.trim().is_empty()
            || owner.owner_pid == 0
            || owner.owner_start_time == 0
            || owner.owner_generation.trim().is_empty()
            || owner.firewall_identity != firewall_identity(owner.firewall_backend)
        {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership has an invalid identity".to_string(),
            ));
        }
        let expected_generation = firewall_owner_generation(
            &owner.tun_name,
            &owner.owner_boot_id,
            owner.owner_pid,
            owner.owner_start_time,
        );
        if owner.owner_generation != expected_generation {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership generation does not match its process identity"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn validate_firewall_owner_for_manager(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        Self::validate_firewall_owner_shape(owner)?;
        if owner.tun_name != self.tun_name
            || owner.firewall_backend != self.firewall_backend
            || owner.server_ipv4 != self.server_ip.to_string()
            || owner.netmask != self.netmask.to_string()
            || owner.wan_interface != self.wan_interface
            || owner.server_ipv6 != self.server_ipv6.map(|address| address.to_string())
            || owner.ipv6_prefix_len != self.ipv6_prefix_len
            || owner.client_to_client_enabled != self.client_to_client_enabled
        {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership identity does not match the requested server routing"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux"))]
    fn firewall_owner_from_state(state: &PersistedRoutingOwnership) -> PersistedFirewallOwnership {
        PersistedFirewallOwnership {
            schema: FIREWALL_OWNER_SCHEMA,
            owner_generation: state.firewall_owner_generation.clone(),
            tun_name: state.tun_name.clone(),
            firewall_backend: state.firewall_backend,
            firewall_identity: firewall_identity(state.firewall_backend).to_string(),
            owner_boot_id: state.owner_boot_id.clone(),
            owner_pid: state.owner_pid,
            owner_start_time: state.owner_start_time,
            server_ipv4: state.server_ipv4.clone(),
            netmask: state.netmask.clone(),
            wan_interface: state.wan_interface.clone(),
            server_ipv6: state.server_ipv6.clone(),
            ipv6_prefix_len: state.ipv6_prefix_len,
            client_to_client_enabled: state.client_to_client_enabled,
        }
    }

    #[cfg(target_os = "linux")]
    fn persist_firewall_ownership(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        use std::io::Write;

        let path = self.firewall_owner_path();
        let bytes = serde_json::to_vec_pretty(owner).map_err(|error| {
            RoutingError::CommandFailed(format!("serialize durable firewall ownership: {error}"))
        })?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "create durable firewall ownership {}: {error}",
                path.display()
            ))
        })?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&path);
            return Err(RoutingError::CommandFailed(format!(
                "write durable firewall ownership {}: {error}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    let _ = std::fs::remove_file(&path);
                    RoutingError::CommandFailed(format!(
                        "secure durable firewall ownership {}: {error}",
                        path.display()
                    ))
                },
            )?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_firewall_ownership(
        &self,
        expected: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        let path = self.firewall_owner_path();
        let Some(current) = self.read_firewall_ownership()? else {
            return Err(RoutingError::CommandFailed(format!(
                "durable firewall ownership {} is missing; refusing release",
                path.display()
            )));
        };
        if &current != expected {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership changed externally; refusing release".to_string(),
            ));
        }
        std::fs::remove_file(&path).map_err(|error| {
            RoutingError::CommandFailed(format!(
                "remove durable firewall ownership {}: {error}",
                path.display()
            ))
        })
    }

    #[cfg(target_os = "linux")]
    fn reject_other_routing_owners(&self) -> Result<(), RoutingError> {
        for tun_name in persisted_tun_names()? {
            if firewall_claim_decision(&self.tun_name, Some(&tun_name), false, false, false)
                == FirewallClaimDecision::RejectForeignRoutingOwner
            {
                return Err(RoutingError::CommandFailed(format!(
                    "durable routing state for TUN {tun_name} already exists; one server firewall owner per network namespace is supported"
                )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn fixed_firewall_resource_present(&self) -> Result<bool, RoutingError> {
        for program in ["iptables", "ip6tables"] {
            for (table, parent, owned) in [
                ("filter", "FORWARD", Self::IPTABLES_FILTER_CHAIN),
                ("nat", "POSTROUTING", Self::IPTABLES_NAT_CHAIN),
            ] {
                let (jumps, chain) =
                    crate::firewall::inspect_iptables_owned(program, table, parent, owned)
                        .map_err(RoutingError::CommandFailed)?;
                if jumps > 0 || chain {
                    return Ok(true);
                }
            }
        }
        crate::firewall::nft_table_exists("inet", Self::NFT_RT_TABLE)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))
    }

    #[cfg(target_os = "linux")]
    fn ensure_fixed_firewall_resources_absent(&self) -> Result<(), RoutingError> {
        let fixed_resource_present = self.fixed_firewall_resource_present()?;
        if firewall_claim_decision(&self.tun_name, None, false, false, fixed_resource_present)
            == FirewallClaimDecision::RejectExistingResource
        {
            return Err(RoutingError::CommandFailed(
                "fixed QuicFuscate server firewall identity already exists; refusing replacement or collision"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn claim_firewall_ownership(
        &self,
        state: &PersistedRoutingOwnership,
    ) -> Result<(), RoutingError> {
        let owner = Self::firewall_owner_from_state(state);
        self.ensure_ownership_directory()?;
        match self.persist_firewall_ownership(&owner) {
            Ok(()) => {}
            Err(error) => {
                if self.firewall_owner_path().exists() {
                    let existing = self.read_firewall_ownership()?.ok_or_else(|| {
                        RoutingError::CommandFailed(
                            "durable firewall ownership disappeared during collision check"
                                .to_string(),
                        )
                    })?;
                    let current_boot_id = Self::linux_boot_id()?;
                    let owner_active = active_owner_matches(
                        &existing.owner_boot_id,
                        &current_boot_id,
                        existing.owner_start_time,
                        Self::linux_process_start_time(existing.owner_pid)?,
                    );
                    match firewall_claim_decision(
                        &self.tun_name,
                        Some(&existing.tun_name),
                        owner_active,
                        true,
                        false,
                    ) {
                        FirewallClaimDecision::RejectActiveOwner => {
                            return Err(RoutingError::CommandFailed(format!(
                                "durable firewall identity is owned by active PID {}",
                                existing.owner_pid
                            )));
                        }
                        FirewallClaimDecision::RejectForeignRoutingOwner => {
                            return Err(RoutingError::CommandFailed(format!(
                                "durable firewall identity belongs to TUN {}; refusing cross-TUN claim",
                                existing.tun_name
                            )));
                        }
                        FirewallClaimDecision::RejectStaleOwner => {
                            return Err(RoutingError::CommandFailed(
                                "durable firewall identity has a stale owner; explicit stale recovery is required"
                                    .to_string(),
                            ));
                        }
                        _ => {}
                    }
                }
                return Err(error);
            }
        }
        if let Err(error) = self.ensure_fixed_firewall_resources_absent() {
            let _ = self.remove_firewall_ownership(&owner);
            return Err(error);
        }
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .firewall_owner_generation = Some(owner.owner_generation);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn prepare_persisted_ownership(&self) -> Result<(), RoutingError> {
        self.reject_other_routing_owners()?;
        let ipv4_prefix = self.ipv4_prefix_len()?;
        if self.server_ipv6.is_some() && self.ipv6_prefix_len > 128 {
            return Err(RoutingError::UnsupportedConfiguration(format!(
                "IPv6 prefix length {} exceeds 128",
                self.ipv6_prefix_len
            )));
        }
        let ipv4_address =
            self.linux_address_present("inet", &self.server_ip.to_string(), ipv4_prefix)?;
        let interface_index = self.linux_interface_index()?;
        let owner_boot_id = Self::linux_boot_id()?;
        let owner_pid = std::process::id();
        let owner_start_time = Self::linux_process_start_time(owner_pid)?.ok_or_else(|| {
            RoutingError::CommandFailed(format!(
                "current Linux process {} disappeared during ownership preparation",
                owner_pid
            ))
        })?;
        let link_up = self.linux_link_is_up()?;
        let ipv4_forwarding =
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map_err(|error| {
                RoutingError::CommandFailed(format!("read IPv4 forwarding: {error}"))
            })?;
        let ipv6_address = if let Some(address) = self.server_ipv6 {
            Some(self.linux_address_present("inet6", &address.to_string(), self.ipv6_prefix_len)?)
        } else {
            None
        };
        let ipv6_forwarding = if self.server_ipv6.is_some() {
            Some(std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").map_err(
                |error| RoutingError::CommandFailed(format!("read IPv6 forwarding: {error}")),
            )?)
        } else {
            None
        };
        let firewall_owner_generation =
            firewall_owner_generation(&self.tun_name, &owner_boot_id, owner_pid, owner_start_time);
        let state = PersistedRoutingOwnership {
            schema: ROUTING_STATE_SCHEMA,
            tun_name: self.tun_name.clone(),
            interface_index,
            owner_boot_id,
            owner_pid,
            owner_start_time,
            server_ipv4: self.server_ip.to_string(),
            netmask: self.netmask.to_string(),
            wan_interface: self.wan_interface.clone(),
            server_ipv6: self.server_ipv6.map(|address| address.to_string()),
            ipv6_prefix_len: self.ipv6_prefix_len,
            firewall_backend: self.firewall_backend,
            firewall_owner_generation,
            client_to_client_enabled: self.client_to_client_enabled,
            ipv4_address: BoolMutation { before: ipv4_address, after: true },
            ipv6_address: ipv6_address.map(|before| BoolMutation { before, after: true }),
            link_up: BoolMutation { before: link_up, after: true },
            ipv4_forwarding: TextMutation { before: ipv4_forwarding, after: "1".to_string() },
            ipv6_forwarding: ipv6_forwarding
                .map(|before| TextMutation { before, after: "1".to_string() }),
        };
        self.validate_persisted_ownership(&state)?;
        self.claim_firewall_ownership(&state)?;
        if let Err(error) = self.persist_ownership(&state) {
            let owner = Self::firewall_owner_from_state(&state);
            let _ = self.remove_firewall_ownership(&owner);
            return Err(error);
        }
        self.ownership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .firewall_owner_generation = Some(state.firewall_owner_generation.clone());
        self.ownership.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).state_prepared =
            true;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_address(
        &self,
        family: &str,
        address: &str,
        prefix: u8,
        mutation: &BoolMutation,
    ) -> Result<(), RoutingError> {
        let current = self.linux_address_present(family, address, prefix)?;
        match recovery_decision(&mutation.before, &mutation.after, &current) {
            RecoveryDecision::Noop => Ok(()),
            RecoveryDecision::Restore => self.remove_linux_address(family, address, prefix),
            RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
                "not removing durable {} address {address}/{prefix}: interface state changed externally",
                family
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_link(&self, mutation: &BoolMutation) -> Result<(), RoutingError> {
        let current = self.linux_link_is_up()?;
        match recovery_decision(&mutation.before, &mutation.after, &current) {
            RecoveryDecision::Noop => Ok(()),
            RecoveryDecision::Restore => self.set_linux_link_down(),
            RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
                "not lowering durable Linux TUN link {}: link state changed externally",
                self.tun_name
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_forwarding(
        &self,
        path: &str,
        mutation: &TextMutation,
    ) -> Result<(), RoutingError> {
        let current = std::fs::read_to_string(path)
            .map_err(|error| RoutingError::CommandFailed(format!("read {path}: {error}")))?;
        let before = mutation.before.trim();
        let after = mutation.after.trim();
        let current_value = current.trim();
        match recovery_decision(&before, &after, &current_value) {
            RecoveryDecision::Noop => Ok(()),
            RecoveryDecision::Restore => self.restore_forwarding(path, &mutation.before),
            RecoveryDecision::Conflict => Err(RoutingError::CommandFailed(format!(
                "not restoring {path}: durable owner expected {:?} or {:?}, found {:?}; preserving external state",
                before, after, current_value
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_ownership(&self) -> Result<bool, RoutingError> {
        self.recover_persisted_ownership_with_active_check(true)
    }

    #[cfg(target_os = "linux")]
    fn recover_current_persisted_ownership(&self) -> Result<bool, RoutingError> {
        self.recover_persisted_ownership_with_active_check(false)
    }

    #[cfg(target_os = "linux")]
    fn recover_persisted_ownership_with_active_check(
        &self,
        reject_active: bool,
    ) -> Result<bool, RoutingError> {
        let Some(state) = self.read_persisted_ownership()? else {
            return Ok(false);
        };
        self.validate_persisted_ownership(&state)?;
        if reject_active {
            Self::reject_active_owner(&state)?;
        }
        let mut failures = Vec::new();
        if self.linux_interface_exists()? {
            if self.linux_interface_index()? != state.interface_index {
                failures.push(format!(
                    "not recovering Linux TUN {}: interface identity changed externally",
                    self.tun_name
                ));
            } else {
                Self::record_cleanup_failure(
                    &mut failures,
                    self.recover_persisted_address(
                        "inet",
                        &self.server_ip.to_string(),
                        self.ipv4_prefix_len()?,
                        &state.ipv4_address,
                    ),
                );
                if let (Some(address), Some(mutation)) =
                    (self.server_ipv6, state.ipv6_address.as_ref())
                {
                    Self::record_cleanup_failure(
                        &mut failures,
                        self.recover_persisted_address(
                            "inet6",
                            &address.to_string(),
                            self.ipv6_prefix_len,
                            mutation,
                        ),
                    );
                }
                Self::record_cleanup_failure(
                    &mut failures,
                    self.recover_persisted_link(&state.link_up),
                );
            }
        }
        Self::record_cleanup_failure(
            &mut failures,
            self.recover_persisted_forwarding(
                "/proc/sys/net/ipv4/ip_forward",
                &state.ipv4_forwarding,
            ),
        );
        if let Some(mutation) = state.ipv6_forwarding.as_ref() {
            Self::record_cleanup_failure(
                &mut failures,
                self.recover_persisted_forwarding(
                    "/proc/sys/net/ipv6/conf/all/forwarding",
                    mutation,
                ),
            );
        }
        Self::finish_cleanup(failures)?;
        Ok(true)
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

    #[cfg(target_os = "linux")]
    fn current_firewall_owner(&self) -> Result<PersistedFirewallOwnership, RoutingError> {
        let state = self.read_persisted_ownership()?.ok_or_else(|| {
            RoutingError::CommandFailed(
                "durable routing state is missing; refusing firewall mutation".to_string(),
            )
        })?;
        self.validate_persisted_ownership(&state)?;
        let expected = Self::firewall_owner_from_state(&state);
        let current = self.read_firewall_ownership()?.ok_or_else(|| {
            RoutingError::CommandFailed(
                "durable firewall ownership is missing; refusing firewall mutation".to_string(),
            )
        })?;
        self.validate_firewall_owner_for_manager(&current)?;
        if current != expected {
            return Err(RoutingError::CommandFailed(
                "durable firewall ownership does not match the routing record; refusing mutation"
                    .to_string(),
            ));
        }
        Ok(current)
    }

    #[cfg(target_os = "linux")]
    fn verify_owned_firewall_resource(
        &self,
        owner: &PersistedFirewallOwnership,
    ) -> Result<(), RoutingError> {
        let subnet = self.calculate_subnet_checked()?;
        match owner.firewall_backend {
            crate::firewall::FirewallBackend::Iptables => {
                self.verify_iptables_family("iptables", &subnet, false)?;
                if self.server_ipv6.is_some() {
                    let v6_subnet = self.calculate_ipv6_subnet_checked()?;
                    self.verify_iptables_family("ip6tables", &v6_subnet, true)?;
                }
            }
            crate::firewall::FirewallBackend::Nftables => {
                let required_fragments = self.nftables_required_fragments(&subnet);
                let required_refs =
                    required_fragments.iter().map(String::as_str).collect::<Vec<_>>();
                crate::firewall::verify_nft_table_owner(
                    "inet",
                    Self::NFT_RT_TABLE,
                    &Self::nft_owner_marker(&owner.owner_generation),
                    &required_refs,
                    self.nftables_expected_rule_count(),
                )
                .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ensure_owned_firewall_absent(&self) -> Result<(), RoutingError> {
        if self.fixed_firewall_resource_present()? {
            return Err(RoutingError::CommandFailed(
                "managed firewall resources remain without a configured ownership generation; refusing guessed cleanup"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Set up routing rules.
    #[cfg(target_os = "linux")]
    pub fn setup(&self) -> Result<(), RoutingError> {
        let mut ownership_prepared = false;
        let result = (|| {
            self.prepare_persisted_ownership()?;
            ownership_prepared = true;
            self.assign_tun_address_linux()?;
            self.enable_ip_forwarding()?;

            let subnet = self.calculate_subnet_checked()?;
            let ipv6_subnet = if self.is_ipv6_enabled() {
                Some(self.calculate_ipv6_subnet_checked()?)
            } else {
                None
            };
            self.current_firewall_owner()?;
            self.ensure_fixed_firewall_resources_absent()?;
            match self.firewall_backend {
                crate::firewall::FirewallBackend::Nftables => {
                    self.setup_nftables(&subnet)?;
                    self.ownership
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .firewall_configured = true;
                    log::info!(
                        "Routing configured (nftables): {} via {}",
                        subnet,
                        self.wan_interface
                    );
                }
                crate::firewall::FirewallBackend::Iptables => {
                    self.setup_iptables(&subnet)?;
                    self.ownership
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .firewall_configured = true;
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
                        self.setup_ip6tables(v6_subnet)?;
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
            Err(error) if !ownership_prepared => Err(error),
            Err(error) => match self.teardown() {
                Ok(()) => Err(error),
                Err(rollback) => Err(RoutingError::CommandFailed(format!(
                    "routing setup failed: {error}; owned rollback failed: {rollback}"
                ))),
            },
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn setup(&self) -> Result<(), RoutingError> {
        log::warn!(
            "Server routing is supported only on Linux until native platform ownership is proven"
        );
        Err(RoutingError::UnsupportedPlatform)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn setup(&self) -> Result<(), RoutingError> {
        log::warn!("Routing setup not implemented for this platform");
        Err(RoutingError::UnsupportedPlatform)
    }

    /// Remove stale routing rules from a crashed previous session.
    ///
    /// This is safe to call on startup before `setup()`. It flushes any
    /// leftover Linux firewall rules and recovers only host state recorded by
    /// the durable ownership contract.
    #[cfg(target_os = "linux")]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        let mut owned_firewall = None;
        let durable_state_present = if let Some(state) = self.read_persisted_ownership()? {
            self.validate_persisted_ownership(&state)?;
            let owner = self.current_firewall_owner()?;
            Self::reject_active_owner(&state)?;
            self.verify_owned_firewall_resource(&owner)?;
            self.recover_persisted_ownership()?;
            owned_firewall = Some(owner);
            true
        } else if let Some(owner) = self.read_firewall_ownership()? {
            if owner.tun_name != self.tun_name {
                return Err(RoutingError::CommandFailed(format!(
                    "durable firewall identity belongs to TUN {}; refusing cross-TUN stale cleanup",
                    owner.tun_name
                )));
            }
            let current_boot_id = Self::linux_boot_id()?;
            if active_owner_matches(
                &owner.owner_boot_id,
                &current_boot_id,
                owner.owner_start_time,
                Self::linux_process_start_time(owner.owner_pid)?,
            ) {
                return Err(RoutingError::CommandFailed(format!(
                    "durable firewall identity is still owned by active PID {}",
                    owner.owner_pid
                )));
            }
            if self.fixed_firewall_resource_present()? {
                return Err(RoutingError::CommandFailed(
                    "durable firewall ownership exists without its routing record; refusing guessed firewall cleanup"
                        .to_string(),
                ));
            }
            self.remove_firewall_ownership(&owner)?;
            false
        } else {
            false
        };
        let subnet = self.calculate_subnet();
        log::info!("Cleaning up stale routing rules for subnet {}", subnet);
        let mut failures = Vec::new();

        if let Some(owner) = owned_firewall.as_ref() {
            match self.verify_owned_firewall_resource(owner) {
                Ok(()) => {
                    let firewall_result = match owner.firewall_backend {
                        crate::firewall::FirewallBackend::Nftables => self.teardown_nftables(),
                        crate::firewall::FirewallBackend::Iptables => self.teardown_iptables(),
                    };
                    Self::record_cleanup_failure(&mut failures, firewall_result);
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if durable_state_present {
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
                        &[
                            "-i",
                            &self.tun_name,
                            "-o",
                            &self.tun_name,
                            "-d",
                            "ff00::/8",
                            "-j",
                            "ACCEPT",
                        ],
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
        }

        Self::finish_cleanup(failures)?;
        if durable_state_present {
            self.remove_ownership_file()?;
            if let Some(owner) = owned_firewall.as_ref() {
                self.remove_firewall_ownership(owner)?;
            }
        }
        log::info!("Stale routing cleanup complete");
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        log::warn!("Server routing stale cleanup is supported only on Linux");
        Err(RoutingError::UnsupportedPlatform)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn cleanup_stale(&self) -> Result<(), RoutingError> {
        Err(RoutingError::UnsupportedPlatform)
    }

    /// Tear down routing rules.
    #[cfg(target_os = "linux")]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        let mut failures = Vec::new();

        let (
            ipv4_address_added,
            ipv6_address_added,
            link_brought_up,
            ipv4_previous,
            ipv6_previous,
            state_prepared,
            firewall_configured,
        ) = {
            let ownership = self.ownership.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                ownership.ipv4_address_added,
                ownership.ipv6_address_added,
                ownership.link_brought_up,
                ownership.ipv4_forwarding_previous.clone(),
                ownership.ipv6_forwarding_previous.clone(),
                ownership.state_prepared,
                ownership.firewall_configured,
            )
        };

        let owned_firewall = if state_prepared {
            let owner = self.current_firewall_owner()?;
            if firewall_configured {
                self.verify_owned_firewall_resource(&owner)?;
            } else {
                self.ensure_owned_firewall_absent()?;
            }
            Some(owner)
        } else {
            None
        };

        if !state_prepared && ipv4_address_added {
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
        if !state_prepared && ipv6_address_added {
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
        if !state_prepared && link_brought_up {
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
        if !state_prepared {
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
        }
        if !state_prepared {
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
        }
        if state_prepared {
            let recovery = match self.recover_current_persisted_ownership() {
                Ok(true) => Ok(()),
                Ok(false) => Err(RoutingError::CommandFailed(format!(
                    "durable routing state {} is missing; refusing host-state cleanup",
                    self.ownership_path.display()
                ))),
                Err(error) => Err(error),
            };
            Self::record_cleanup_failure(&mut failures, recovery);
        }

        if state_prepared && firewall_configured {
            if let Some(owner) = owned_firewall.as_ref() {
                match self.verify_owned_firewall_resource(owner) {
                    Ok(()) => {
                        let firewall_result = match self.firewall_backend {
                            crate::firewall::FirewallBackend::Nftables => self.teardown_nftables(),
                            crate::firewall::FirewallBackend::Iptables => self.teardown_iptables(),
                        };
                        Self::record_cleanup_failure(&mut failures, firewall_result);
                    }
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }

        Self::finish_cleanup(failures)?;
        if state_prepared {
            let state = self.read_persisted_ownership()?.ok_or_else(|| {
                RoutingError::CommandFailed(
                    "durable routing state disappeared during teardown".to_string(),
                )
            })?;
            self.validate_persisted_ownership(&state)?;
            self.remove_ownership_file()?;
            if let Some(owner) = owned_firewall.as_ref() {
                self.remove_firewall_ownership(owner)?;
            }
            self.ownership.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).state_prepared =
                false;
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .firewall_owner_generation = None;
            self.ownership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .firewall_configured = false;
        }

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

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn teardown(&self) -> Result<(), RoutingError> {
        log::warn!("Server routing teardown is supported only on Linux");
        Err(RoutingError::UnsupportedPlatform)
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
        let rules = self.iptables_ruleset(subnet, ipv6, true, true);
        Self::apply_iptables_restore(restore_program, &rules)?;
        self.verify_iptables_family(program, subnet, ipv6)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_iptables_family(
        &self,
        program: &str,
        subnet: &str,
        ipv6: bool,
    ) -> Result<(), RoutingError> {
        let verify_chain = |table: &str, chain: &str, expected: &[String]| {
            let actual = crate::firewall::iptables_chain_rules(program, table, chain)
                .map_err(RoutingError::CommandFailed)?;
            let actual = actual
                .iter()
                .map(|rule| rule.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>();
            let expected = expected
                .iter()
                .map(|rule| rule.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>();
            if actual != expected {
                return Err(RoutingError::CommandFailed(format!(
                    "{program} {table}/{chain} rules changed externally: expected {expected:?}, found {actual:?}"
                )));
            }
            Ok(())
        };
        for (table, parent, chain) in [
            ("filter", "FORWARD", Self::IPTABLES_FILTER_CHAIN),
            ("nat", "POSTROUTING", Self::IPTABLES_NAT_CHAIN),
        ] {
            let (jump_count, chain_exists) =
                crate::firewall::inspect_iptables_owned(program, table, parent, chain)
                    .map_err(RoutingError::CommandFailed)?;
            if jump_count != 1 || !chain_exists {
                return Err(RoutingError::CommandFailed(format!(
                    "{program} {table}/{parent} ownership is incomplete: jumps={jump_count}, chain_exists={chain_exists}"
                )));
            }
        }
        let expected_nat = vec![format!(
            "-A {} -s {} -o {} -j MASQUERADE",
            Self::IPTABLES_NAT_CHAIN,
            subnet,
            self.wan_interface
        )];
        let isolation_action = if self.client_to_client_enabled { "ACCEPT" } else { "DROP" };
        let mut expected_filter = vec![format!(
            "-A {} -i {} -o {} -j ACCEPT",
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.wan_interface
        )];
        if ipv6 {
            expected_filter.push(format!(
                "-A {} -i {} -o {} -d ff00::/8 -j ACCEPT",
                Self::IPTABLES_FILTER_CHAIN,
                self.tun_name,
                self.tun_name
            ));
        } else {
            for destination in self.ipv4_fanout_destinations() {
                expected_filter.push(format!(
                    "-A {} -i {} -o {} -d {} -j ACCEPT",
                    Self::IPTABLES_FILTER_CHAIN,
                    self.tun_name,
                    self.tun_name,
                    destination
                ));
            }
        }
        expected_filter.push(format!(
            "-A {} -i {} -o {} -j {}",
            Self::IPTABLES_FILTER_CHAIN,
            self.tun_name,
            self.tun_name,
            isolation_action
        ));
        expected_filter.push(format!(
            "-A {} -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            Self::IPTABLES_FILTER_CHAIN,
            self.wan_interface,
            self.tun_name
        ));
        verify_chain("nat", Self::IPTABLES_NAT_CHAIN, &expected_nat)?;
        verify_chain("filter", Self::IPTABLES_FILTER_CHAIN, &expected_filter)?;

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

    #[cfg(test)]
    fn nftables_ruleset(&self, subnet: &str) -> String {
        self.nftables_ruleset_with_owner(subnet, "unowned")
    }

    #[cfg(any(test, target_os = "linux"))]
    fn nft_owner_marker(owner_generation: &str) -> String {
        format!("quicfuscate-owner-{owner_generation}")
    }

    #[cfg(any(test, target_os = "linux"))]
    fn nftables_ruleset_with_owner(&self, subnet: &str, owner_generation: &str) -> String {
        let v6_masquerade = if self.is_ipv6_enabled() {
            let v6_subnet = self.calculate_ipv6_subnet();
            format!(
                "ip6 saddr {} oifname \"{}\" masquerade comment \"{}\"\n",
                v6_subnet,
                self.wan_interface,
                Self::nft_owner_marker(owner_generation)
            )
        } else {
            String::new()
        };
        let v6_fanout = if self.is_ipv6_enabled() {
            format!(
                "iifname \"{}\" oifname \"{}\" ip6 daddr ff00::/8 accept comment \"{}\"\n",
                self.tun_name,
                self.tun_name,
                Self::nft_owner_marker(owner_generation)
            )
        } else {
            String::new()
        };
        let isolation_action = if self.client_to_client_enabled { "accept" } else { "drop" };
        let directed_broadcast = self.ipv4_broadcast();

        format!(
            "table inet {table} {{\n\
             \x20   comment \"{owner_marker}\"\n\
             \x20   chain postrouting {{\n\
             \x20       type nat hook postrouting priority 100; policy accept;\n\
             \x20       ip saddr {subnet} oifname \"{wan}\" masquerade comment \"{owner_marker}\"\n\
             \x20       {v6_masquerade}\
             \x20   }}\n\
             \x20   chain forward {{\n\
             \x20       type filter hook forward priority 0; policy accept;\n\
             \x20       iifname \"{tun}\" oifname \"{tun}\" ip daddr {{ 255.255.255.255, {directed_broadcast}, 224.0.0.0/4 }} accept comment \"{owner_marker}\"\n\
             \x20       {v6_fanout}\
             \x20       iifname \"{tun}\" oifname \"{tun}\" {isolation_action} comment \"{owner_marker}\"\n\
             \x20       iifname \"{tun}\" oifname \"{wan}\" accept comment \"{owner_marker}\"\n\
             \x20       iifname \"{wan}\" oifname \"{tun}\" ct state established,related accept comment \"{owner_marker}\"\n\
             \x20   }}\n\
             }}\n",
            table = Self::NFT_RT_TABLE,
            owner_marker = Self::nft_owner_marker(owner_generation),
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
    fn nftables_initial_transaction(
        ruleset: &str,
        table_exists: bool,
    ) -> Result<String, RoutingError> {
        if table_exists {
            Err(RoutingError::CommandFailed(format!(
                "nftables table inet {} already exists; refusing replacement",
                Self::NFT_RT_TABLE
            )))
        } else {
            Ok(ruleset.to_string())
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    fn nftables_required_fragments(&self, subnet: &str) -> Vec<String> {
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
        required_fragments
    }

    #[cfg(any(test, target_os = "linux"))]
    fn nftables_expected_rule_count(&self) -> usize {
        if self.server_ipv6.is_some() {
            7
        } else {
            5
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

        let owner = self.current_firewall_owner()?;
        let ruleset = self.nftables_ruleset_with_owner(subnet, &owner.owner_generation);
        let table_exists = crate::firewall::nft_table_exists("inet", Self::NFT_RT_TABLE)
            .map_err(|error| RoutingError::CommandFailed(error.to_string()))?;
        let transaction = Self::nftables_initial_transaction(&ruleset, table_exists)?;
        let required_fragments = self.nftables_required_fragments(subnet);

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
        crate::firewall::verify_nft_table_owner(
            "inet",
            Self::NFT_RT_TABLE,
            &Self::nft_owner_marker(&owner.owner_generation),
            &required_refs,
            self.nftables_expected_rule_count(),
        )
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

    #[cfg(test)]
    const WINDOWS_NAT_NAME: &'static str = "QuicFuscateNat";

    #[cfg(all(test, target_os = "macos"))]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
        let address_text = self.server_ip.to_string();
        if let Some(interface) = self.linux_address_on_other_interface("inet", &address_text)? {
            return Err(RoutingError::CommandFailed(format!(
                "Linux TUN address {} already exists on interface {}; refusing address conflict",
                self.server_ip, interface
            )));
        }
        let address_present = self.linux_address_present("inet", &address_text, prefix)?;
        if !address_present {
            let result = Self::run_ip_command(&["-4", "addr", "add", &addr, "dev", &self.tun_name]);
            if result.is_err() && !self.linux_address_present("inet", &address_text, prefix)? {
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
        if !self.linux_address_present("inet", &address_text, prefix)?
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
            let address_text = ipv6.to_string();
            if let Some(interface) =
                self.linux_address_on_other_interface("inet6", &address_text)?
            {
                return Err(RoutingError::CommandFailed(format!(
                    "Linux TUN IPv6 address {} already exists on interface {}; refusing address conflict",
                    ipv6, interface
                )));
            }
            if !self.linux_address_present("inet6", &address_text, self.ipv6_prefix_len)? {
                let result =
                    Self::run_ip_command(&["-6", "addr", "add", &addr, "dev", &self.tun_name]);
                if result.is_err()
                    && !self.linux_address_present("inet6", &address_text, self.ipv6_prefix_len)?
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

    #[cfg(any(test, target_os = "linux"))]
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

    #[cfg(any(test, target_os = "linux"))]
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
    #[cfg(any(test, target_os = "linux"))]
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

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn server_routing_platform_surface_is_explicitly_unsupported() {
        let manager = RoutingManager::new(
            "QuicFuscate".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "Ethernet".to_string(),
        );
        assert!(matches!(manager.setup(), Err(RoutingError::UnsupportedPlatform)));
        assert!(matches!(manager.cleanup_stale(), Err(RoutingError::UnsupportedPlatform)));
        assert!(matches!(manager.teardown(), Err(RoutingError::UnsupportedPlatform)));
    }

    #[test]
    fn durable_routing_state_rejects_unknown_fields() {
        let state = PersistedRoutingOwnership {
            schema: ROUTING_STATE_SCHEMA,
            tun_name: "qfserver0".to_string(),
            interface_index: 17,
            owner_boot_id: "boot-id".to_string(),
            owner_pid: 42,
            owner_start_time: 7,
            server_ipv4: "10.8.0.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            wan_interface: "eth0".to_string(),
            server_ipv6: None,
            ipv6_prefix_len: 64,
            firewall_backend: crate::firewall::FirewallBackend::Iptables,
            firewall_owner_generation: firewall_owner_generation("qfserver0", "boot-id", 42, 7),
            client_to_client_enabled: false,
            ipv4_address: BoolMutation { before: false, after: true },
            ipv6_address: None,
            link_up: BoolMutation { before: false, after: true },
            ipv4_forwarding: TextMutation { before: "0\n".to_string(), after: "1".to_string() },
            ipv6_forwarding: None,
        };
        let encoded = serde_json::to_value(&state).expect("state serialization");
        let decoded: PersistedRoutingOwnership =
            serde_json::from_value(encoded.clone()).expect("state round trip");
        assert_eq!(decoded, state);
        let owner = RoutingManager::firewall_owner_from_state(&state);
        RoutingManager::validate_firewall_owner_shape(&owner).expect("firewall owner shape");
        assert_eq!(owner.owner_generation, state.firewall_owner_generation);

        let mut with_unknown = encoded;
        with_unknown
            .as_object_mut()
            .expect("state object")
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<PersistedRoutingOwnership>(with_unknown).is_err());
    }

    #[test]
    fn durable_firewall_generation_is_bound_to_tun_and_process_identity() {
        let first = firewall_owner_generation("qfserver0", "boot", 42, 7);
        let second_tun = firewall_owner_generation("qfserver1", "boot", 42, 7);
        let second_process = firewall_owner_generation("qfserver0", "boot", 42, 8);

        assert_ne!(first, second_tun);
        assert_ne!(first, second_process);
        assert_eq!(
            firewall_identity(crate::firewall::FirewallBackend::Iptables),
            "iptables:filter/QUICFUSCATE_RT,nat/QUICFUSCATE_NAT,ip6tables"
        );
        assert_eq!(
            firewall_identity(crate::firewall::FirewallBackend::Nftables),
            "nftables:inet/quicfuscate_rt"
        );
    }

    #[test]
    fn firewall_claim_rejects_cross_tun_and_fixed_resource_collisions() {
        assert_eq!(
            firewall_claim_decision("qfserver0", Some("qfserver1"), false, false, false),
            FirewallClaimDecision::RejectForeignRoutingOwner
        );
        assert_eq!(
            firewall_claim_decision("qfserver0", Some("qfserver0"), true, true, false),
            FirewallClaimDecision::RejectActiveOwner
        );
        assert_eq!(
            firewall_claim_decision("qfserver0", Some("qfserver0"), false, true, false),
            FirewallClaimDecision::RejectStaleOwner
        );
        assert_eq!(
            firewall_claim_decision("qfserver0", None, false, false, true),
            FirewallClaimDecision::RejectExistingResource
        );
        assert_eq!(
            firewall_claim_decision("qfserver0", None, false, false, false),
            FirewallClaimDecision::Claim
        );
    }

    #[test]
    fn durable_firewall_owner_shape_rejects_generation_tampering() {
        let mut owner = PersistedFirewallOwnership {
            schema: FIREWALL_OWNER_SCHEMA,
            owner_generation: firewall_owner_generation("qfserver0", "boot", 42, 7),
            tun_name: "qfserver0".to_string(),
            firewall_backend: crate::firewall::FirewallBackend::Nftables,
            firewall_identity: firewall_identity(crate::firewall::FirewallBackend::Nftables)
                .to_string(),
            owner_boot_id: "boot".to_string(),
            owner_pid: 42,
            owner_start_time: 7,
            server_ipv4: "10.8.0.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            wan_interface: "eth0".to_string(),
            server_ipv6: None,
            ipv6_prefix_len: 64,
            client_to_client_enabled: false,
        };
        assert!(RoutingManager::validate_firewall_owner_shape(&owner).is_ok());
        owner.owner_generation.push('x');
        assert!(RoutingManager::validate_firewall_owner_shape(&owner).is_err());
    }

    #[test]
    fn nftables_required_fragments_cover_fixed_server_rules() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let fragments = manager.nftables_required_fragments("10.8.0.0/24");
        assert!(fragments.iter().any(|fragment| fragment.contains("masquerade")));
        assert!(fragments.iter().any(|fragment| fragment.contains("established,related")));
        let ruleset = manager.nftables_ruleset_with_owner("10.8.0.0/24", "generation");
        assert!(ruleset.contains("comment \"quicfuscate-owner-generation\""));
        assert_eq!(manager.nftables_expected_rule_count(), 5);
    }

    #[test]
    fn durable_routing_recovery_is_conservative() {
        assert_eq!(recovery_decision(&false, &true, &false), RecoveryDecision::Noop);
        assert_eq!(recovery_decision(&false, &true, &true), RecoveryDecision::Restore);
        assert_eq!(recovery_decision(&"0", &"1", &"2"), RecoveryDecision::Conflict);
    }

    #[test]
    fn durable_routing_owner_identity_rejects_live_and_reused_processes() {
        assert!(active_owner_matches("boot", "boot", 7, Some(7)));
        assert!(!active_owner_matches("boot", "boot", 7, Some(8)));
        assert!(!active_owner_matches("boot", "new-boot", 7, Some(7)));
        assert!(!active_owner_matches("boot", "boot", 7, None));
    }

    #[test]
    fn durable_routing_state_filename_cannot_escape_its_directory() {
        let filename = routing_state_filename("../../tun/with spaces");
        assert!(!filename.contains('/'));
        assert!(!filename.contains('\\'));
        assert!(filename.ends_with(".json"));
        assert_ne!(filename, routing_state_filename("tun/with spaces"));
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
    fn test_nftables_initial_transaction_rejects_existing_table() {
        let manager = RoutingManager::new(
            "qfserver0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        let rules = manager.nftables_ruleset("10.8.0.0/24");
        let existing = RoutingManager::nftables_initial_transaction(&rules, true);
        let initial = RoutingManager::nftables_initial_transaction(&rules, false);

        assert!(existing.is_err());
        assert!(matches!(initial, Ok(value) if value == rules));
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

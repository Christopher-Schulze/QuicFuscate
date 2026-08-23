use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Product default for ordinary circuit configurations.
pub const DEFAULT_PRODUCT_HOPS: u8 = 3;
/// Absolute implementation bound for one circuit.
pub const MAX_CIRCUIT_HOPS: u8 = 8;
/// Maximum operator-visible characters in one hop label.
pub const MAX_CIRCUIT_HOP_LABEL_CHARS: usize = 128;
/// Minimum UDP datagram size that every inner QUIC hop must retain.
pub const MIN_INNER_QUIC_DATAGRAM: u16 = 1200;
/// Maximum FEC wire framing for one protected QUIC datagram.
pub const NESTED_FEC_OVERHEAD: u16 = 36;
/// Maximum QUIC short-header cost: flags, 20-byte DCID, 4-byte PN, and 16-byte tag.
pub const NESTED_QUIC_OVERHEAD: u16 = 41;
/// Maximum HTTP Datagram type plus quarter-stream Flow-ID varints.
pub const NESTED_HTTP_DATAGRAM_OVERHEAD: u16 = 10;
/// Exact worst-case carrier overhead subtracted for every recursive MASQUE layer.
pub const NESTED_MASQUE_OVERHEAD: u16 =
    NESTED_FEC_OVERHEAD + NESTED_QUIC_OVERHEAD + NESTED_HTTP_DATAGRAM_OVERHEAD;

/// Function assigned to one authenticated circuit hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "specta", derive(specta::Type))]
#[serde(rename_all = "kebab-case")]
pub enum HopRole {
    /// Carries the next hop over an authenticated CONNECT-UDP association.
    Relay,
    /// Terminates the circuit through an authenticated CONNECT-IP tunnel.
    Exit,
}

/// Operator-provided route-diversity constraints.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "specta", derive(specta::Type))]
#[serde(default, deny_unknown_fields)]
pub struct CircuitDiversityPolicy {
    /// Require distinct provider labels for every hop.
    pub provider: bool,
    /// Require distinct region labels for every hop.
    pub region: bool,
    /// Require distinct jurisdiction labels for every hop.
    pub jurisdiction: bool,
    /// Require distinct failure-domain labels for every hop.
    pub failure_domain: bool,
}

/// Browser and operating-system persona frozen for one hop generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "specta", derive(specta::Type))]
#[serde(deny_unknown_fields)]
pub struct HopPersonaConfig {
    /// Browser-shaped TLS, QUIC, and HTTP/3 profile.
    pub browser: qf_stealth::BrowserProfile,
    /// Operating-system network fingerprint paired with the browser profile.
    pub os: qf_stealth::OsProfile,
}

/// Optional connection-local policy changes applied only to one circuit hop.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "specta", derive(specta::Type))]
#[serde(default, deny_unknown_fields)]
pub struct HopPolicyOverrides {
    /// Explicit immutable browser/OS persona. Absence inherits the engine policy.
    pub persona: Option<HopPersonaConfig>,
    /// Segment-local FEC policy. Absence inherits the engine policy.
    pub fec_mode: Option<crate::FecMode>,
    /// Segment-local packet padding switch.
    pub enable_traffic_padding: Option<bool>,
    /// Segment-local timing-obfuscation switch.
    pub enable_timing_obfuscation: Option<bool>,
    /// Segment-local cover-PING switch.
    pub enable_cover_ping: Option<bool>,
}

/// One independently authenticated circuit hop.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HopConfig {
    /// Stable operator-facing label. It is never sent to another relay.
    pub label: String,
    /// QUIC endpoint authority in `host:port` or `[ipv6]:port` form.
    pub endpoint: String,
    /// Runtime-pinned entry address shared by firewall and socket ownership. Never serialized.
    #[serde(skip)]
    pub pinned_endpoint: Option<SocketAddr>,
    /// TLS SNI or browser-persona authority for this hop.
    pub sni: String,
    /// Whether the peer certificate must be verified.
    pub verify_peer: bool,
    /// Optional custom CA bundle path.
    pub ca_file: String,
    /// Public QKey identifier for this hop.
    pub qkey_id: String,
    /// Opaque keychain, secret-store, or environment reference. Never the bearer token itself.
    pub qkey_token_ref: String,
    /// Runtime-injected token resolved by a trusted native secret owner. Never serialized.
    #[serde(skip)]
    pub qkey_token: Option<crate::QKeyToken>,
    /// Relay or final-exit role.
    pub role: HopRole,
    /// Optional operator-supplied provider label.
    pub provider: Option<String>,
    /// Optional operator-supplied region label.
    pub region: Option<String>,
    /// Optional operator-supplied jurisdiction label.
    pub jurisdiction: Option<String>,
    /// Optional operator-supplied failure-domain label.
    pub failure_domain: Option<String>,
    /// Per-hop establishment deadline.
    pub connect_timeout_ms: u64,
    /// Per-hop idle deadline.
    pub idle_timeout_ms: u64,
    /// Optional behavior frozen independently for this hop.
    pub policy: HopPolicyOverrides,
}

impl Default for HopConfig {
    fn default() -> Self {
        Self {
            label: String::new(),
            endpoint: String::new(),
            pinned_endpoint: None,
            sni: String::new(),
            verify_peer: true,
            ca_file: String::new(),
            qkey_id: String::new(),
            qkey_token_ref: String::new(),
            qkey_token: None,
            role: HopRole::Exit,
            provider: None,
            region: None,
            jurisdiction: None,
            failure_domain: None,
            connect_timeout_ms: 10_000,
            idle_timeout_ms: 30_000,
            policy: HopPolicyOverrides::default(),
        }
    }
}

/// Canonical ordered multi-hop circuit configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CircuitConfig {
    /// Ordered entry-to-exit hop list.
    pub hops: Vec<HopConfig>,
    /// Configured circuit depth ceiling. The implementation hard limit is eight.
    pub max_hops: u8,
    /// Maximum simultaneously retained primary, rotating, or standby circuits.
    pub max_parallel_circuits: u8,
    /// Permit an explicit VPN-contained one-hop fallback after circuit failure.
    pub allow_single_hop_fallback: bool,
    /// Required route-label diversity.
    pub diversity: CircuitDiversityPolicy,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            hops: Vec::new(),
            max_hops: DEFAULT_PRODUCT_HOPS,
            max_parallel_circuits: 2,
            allow_single_hop_fallback: false,
            diversity: CircuitDiversityPolicy::default(),
        }
    }
}

/// Parsed endpoint authority retained after schema validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopEndpoint {
    /// Hostname or canonical IP literal without IPv6 brackets.
    pub host: String,
    /// UDP port.
    pub port: u16,
}

/// Circuit schema or recursive datagram-budget failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitConfigError(String);

impl std::fmt::Display for CircuitConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CircuitConfigError {}

impl HopConfig {
    /// Parse and validate the configured endpoint authority.
    pub fn parsed_endpoint(&self) -> Result<HopEndpoint, CircuitConfigError> {
        parse_endpoint_authority(&self.endpoint)
    }

    fn validate(&self, index: usize) -> Result<(), CircuitConfigError> {
        let label = self.label.trim();
        if label.is_empty()
            || label.chars().count() > MAX_CIRCUIT_HOP_LABEL_CHARS
            || label.chars().any(char::is_control)
        {
            return Err(CircuitConfigError(format!(
                "circuit.hops[{index}].label must contain 1..={MAX_CIRCUIT_HOP_LABEL_CHARS} visible characters"
            )));
        }
        let endpoint = self.parsed_endpoint().map_err(|error| {
            CircuitConfigError(format!("circuit.hops[{index}].endpoint: {error}"))
        })?;
        if let Some(pinned) = self.pinned_endpoint {
            if pinned.port() != endpoint.port {
                return Err(CircuitConfigError(format!(
                    "circuit.hops[{index}].pinned_endpoint port does not match endpoint"
                )));
            }
            if let Ok(configured_ip) = endpoint.host.parse::<IpAddr>() {
                if pinned.ip() != configured_ip {
                    return Err(CircuitConfigError(format!(
                        "circuit.hops[{index}].pinned_endpoint address does not match endpoint"
                    )));
                }
            }
        }
        if self.sni.trim().is_empty() {
            return Err(CircuitConfigError(format!("circuit.hops[{index}].sni must not be empty")));
        }
        validate_dns_name(self.sni.trim())
            .map_err(|error| CircuitConfigError(format!("circuit.hops[{index}].sni: {error}")))?;
        let qkey_id = self.qkey_id.trim();
        if qkey_id.len() != 12 || !qkey_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CircuitConfigError(format!(
                "circuit.hops[{index}].qkey_id must be 12 hex chars"
            )));
        }
        if self.qkey_token_ref.trim().is_empty() {
            return Err(CircuitConfigError(format!(
                "circuit.hops[{index}].qkey_token_ref must not be empty"
            )));
        }
        if self.connect_timeout_ms == 0 || self.idle_timeout_ms == 0 {
            return Err(CircuitConfigError(format!(
                "circuit.hops[{index}] connect_timeout_ms and idle_timeout_ms must be > 0"
            )));
        }
        if let Some(persona) = self.policy.persona {
            qf_stealth::FingerprintProfile::try_new(persona.browser, persona.os).map_err(
                |error| {
                    CircuitConfigError(format!(
                        "circuit.hops[{index}].policy.persona is unsupported: {error}"
                    ))
                },
            )?;
        }
        Ok(())
    }
}

impl CircuitConfig {
    /// Validate topology, credentials, diversity, resource bounds, and recursive MTU.
    pub fn validate(&self, outer_udp_payload: u16) -> Result<(), CircuitConfigError> {
        if self.hops.is_empty() {
            return Err(CircuitConfigError("circuit.hops must not be empty".to_string()));
        }
        if self.max_hops == 0 || self.max_hops > MAX_CIRCUIT_HOPS {
            return Err(CircuitConfigError(format!(
                "circuit.max_hops must be in 1..={MAX_CIRCUIT_HOPS}, got {}",
                self.max_hops
            )));
        }
        if self.hops.len() > usize::from(self.max_hops) {
            return Err(CircuitConfigError(format!(
                "circuit has {} hops but max_hops is {}",
                self.hops.len(),
                self.max_hops
            )));
        }
        if !(1..=2).contains(&self.max_parallel_circuits) {
            return Err(CircuitConfigError(
                "circuit.max_parallel_circuits must be 1 or 2".to_string(),
            ));
        }
        if self.allow_single_hop_fallback && self.hops.len() < 2 {
            return Err(CircuitConfigError(
                "circuit.allow_single_hop_fallback requires a multi-hop primary circuit"
                    .to_string(),
            ));
        }
        if self.allow_single_hop_fallback && self.max_parallel_circuits != 2 {
            return Err(CircuitConfigError(
                "circuit.allow_single_hop_fallback requires max_parallel_circuits = 2".to_string(),
            ));
        }

        let mut endpoints = HashSet::new();
        let mut identities = HashSet::new();
        let mut token_references = HashSet::new();
        for (index, hop) in self.hops.iter().enumerate() {
            hop.validate(index)?;
            let endpoint = hop.parsed_endpoint()?;
            let endpoint_key = format!("{}:{}", endpoint.host.to_ascii_lowercase(), endpoint.port);
            if !endpoints.insert(endpoint_key) {
                return Err(CircuitConfigError(format!(
                    "circuit.hops[{index}] repeats an endpoint"
                )));
            }
            if !identities.insert(hop.qkey_id.to_ascii_lowercase()) {
                return Err(CircuitConfigError(format!(
                    "circuit.hops[{index}] repeats a QKey identity"
                )));
            }
            if !token_references.insert(hop.qkey_token_ref.trim()) {
                return Err(CircuitConfigError(format!(
                    "circuit.hops[{index}] repeats a QKey token reference"
                )));
            }
            let expected_role =
                if index + 1 == self.hops.len() { HopRole::Exit } else { HopRole::Relay };
            if hop.role != expected_role {
                return Err(CircuitConfigError(format!(
                    "circuit.hops[{index}] must have role {:?}",
                    expected_role
                )));
            }
        }

        validate_diversity(&self.hops, &self.diversity)?;
        self.effective_inner_datagram_budget(outer_udp_payload)?;
        Ok(())
    }

    /// Derive the deepest QUIC datagram budget after every outer relay layer.
    pub fn effective_inner_datagram_budget(
        &self,
        outer_udp_payload: u16,
    ) -> Result<u16, CircuitConfigError> {
        let relay_layers = self.hops.len().saturating_sub(1);
        let overhead = usize::from(NESTED_MASQUE_OVERHEAD).saturating_mul(relay_layers);
        let budget = usize::from(outer_udp_payload).checked_sub(overhead).ok_or_else(|| {
            CircuitConfigError("circuit encapsulation overhead exceeds UDP payload".to_string())
        })?;
        if budget < usize::from(MIN_INNER_QUIC_DATAGRAM) {
            return Err(CircuitConfigError(format!(
                "circuit leaves {budget} bytes for the deepest QUIC datagram; at least {MIN_INNER_QUIC_DATAGRAM} are required"
            )));
        }
        u16::try_from(budget)
            .map_err(|_| CircuitConfigError("circuit datagram budget overflow".to_string()))
    }

    /// Build the explicit VPN-contained direct-to-exit fallback retained beside a multi-hop
    /// primary. The fallback reuses only the authenticated exit identity and never inherits a
    /// recursive fallback or route-diversity claim that no longer applies to a one-hop circuit.
    pub fn single_hop_fallback(&self) -> Option<Self> {
        if !self.allow_single_hop_fallback || self.hops.len() < 2 {
            return None;
        }
        let mut exit = self.hops.last()?.clone();
        exit.pinned_endpoint = None;
        exit.role = HopRole::Exit;
        Some(Self {
            hops: vec![exit],
            max_hops: 1,
            max_parallel_circuits: 2,
            allow_single_hop_fallback: false,
            diversity: CircuitDiversityPolicy::default(),
        })
    }

    /// Compare every operator-controlled circuit property while excluding runtime-only pins and
    /// resolved bearer tokens.
    pub fn has_same_operator_configuration(&self, other: &Self) -> bool {
        self.max_hops == other.max_hops
            && self.max_parallel_circuits == other.max_parallel_circuits
            && self.allow_single_hop_fallback == other.allow_single_hop_fallback
            && self.diversity == other.diversity
            && self.hops.len() == other.hops.len()
            && self.hops.iter().zip(&other.hops).all(|(left, right)| {
                left.label == right.label
                    && left.endpoint.eq_ignore_ascii_case(&right.endpoint)
                    && left.sni.eq_ignore_ascii_case(&right.sni)
                    && left.verify_peer == right.verify_peer
                    && left.ca_file == right.ca_file
                    && left.qkey_id.eq_ignore_ascii_case(&right.qkey_id)
                    && left.qkey_token_ref == right.qkey_token_ref
                    && left.role == right.role
                    && left.provider == right.provider
                    && left.region == right.region
                    && left.jurisdiction == right.jurisdiction
                    && left.failure_domain == right.failure_domain
                    && left.connect_timeout_ms == right.connect_timeout_ms
                    && left.idle_timeout_ms == right.idle_timeout_ms
                    && left.policy == right.policy
            })
    }
}

pub(crate) fn parse_endpoint_authority(value: &str) -> Result<HopEndpoint, CircuitConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CircuitConfigError("must not be empty".to_string()));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(CircuitConfigError("port must be in 1..=65535".to_string()));
        }
        return Ok(HopEndpoint { host: address.ip().to_string(), port: address.port() });
    }
    let (host, port) = value.rsplit_once(':').ok_or_else(|| {
        CircuitConfigError("must use host:port or [ipv6]:port authority syntax".to_string())
    })?;
    if host.contains(':') || host.starts_with('[') || host.ends_with(']') {
        return Err(CircuitConfigError(
            "IPv6 endpoint literals must use [ipv6]:port syntax".to_string(),
        ));
    }
    validate_dns_name(host)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| CircuitConfigError("port must be in 1..=65535".to_string()))?;
    Ok(HopEndpoint { host: host.trim_end_matches('.').to_ascii_lowercase(), port })
}

fn validate_dns_name(value: &str) -> Result<(), CircuitConfigError> {
    if value.len() > 253 || value.is_empty() {
        return Err(CircuitConfigError("hostname length must be in 1..=253".to_string()));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    for label in value.trim_end_matches('.').split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(CircuitConfigError("hostname contains an invalid DNS label".to_string()));
        }
    }
    Ok(())
}

fn validate_diversity(
    hops: &[HopConfig],
    policy: &CircuitDiversityPolicy,
) -> Result<(), CircuitConfigError> {
    validate_unique_labels(hops, "provider", policy.provider, |hop| hop.provider.as_deref())?;
    validate_unique_labels(hops, "region", policy.region, |hop| hop.region.as_deref())?;
    validate_unique_labels(hops, "jurisdiction", policy.jurisdiction, |hop| {
        hop.jurisdiction.as_deref()
    })?;
    validate_unique_labels(hops, "failure_domain", policy.failure_domain, |hop| {
        hop.failure_domain.as_deref()
    })?;
    Ok(())
}

fn validate_unique_labels<'a>(
    hops: &'a [HopConfig],
    name: &str,
    required: bool,
    value: impl Fn(&'a HopConfig) -> Option<&'a str>,
) -> Result<(), CircuitConfigError> {
    if !required {
        return Ok(());
    }
    let mut values = HashSet::new();
    for (index, hop) in hops.iter().enumerate() {
        let label =
            value(hop).map(str::trim).filter(|label| !label.is_empty()).ok_or_else(|| {
                CircuitConfigError(format!("circuit.hops[{index}].{name} is required"))
            })?;
        if !values.insert(label.to_ascii_lowercase()) {
            return Err(CircuitConfigError(format!(
                "circuit diversity requires distinct {name} labels"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(endpoint: &str, qkey_id: &str, role: HopRole) -> HopConfig {
        HopConfig {
            label: endpoint.to_string(),
            endpoint: endpoint.to_string(),
            sni: "relay.example.com".to_string(),
            qkey_id: qkey_id.to_string(),
            qkey_token_ref: format!("keychain:{qkey_id}"),
            role,
            ..HopConfig::default()
        }
    }

    #[test]
    fn one_two_and_three_hop_topologies_validate() {
        for hop_count in 1..=3 {
            let mut hops = Vec::new();
            for index in 0..hop_count {
                let role = if index + 1 == hop_count { HopRole::Exit } else { HopRole::Relay };
                hops.push(hop(
                    &format!("relay{}.example.com:4433", index + 1),
                    &format!("{:012x}", index + 1),
                    role,
                ));
            }
            let circuit = CircuitConfig { hops, ..CircuitConfig::default() };
            circuit.validate(1500).expect("supported product topology");
        }
    }

    #[test]
    fn recursive_budget_uses_the_declared_worst_case_wire_components() {
        assert_eq!(NESTED_FEC_OVERHEAD, 32 + 2 * 2);
        assert_eq!(NESTED_QUIC_OVERHEAD, 1 + 20 + 4 + 16);
        assert_eq!(NESTED_HTTP_DATAGRAM_OVERHEAD, 2 + 8);
        assert_eq!(NESTED_MASQUE_OVERHEAD, 87);

        let circuit = CircuitConfig {
            hops: vec![
                hop("relay.example.com:4433", "000000000001", HopRole::Relay),
                hop("exit.example.com:4433", "000000000002", HopRole::Exit),
            ],
            ..CircuitConfig::default()
        };
        assert_eq!(circuit.effective_inner_datagram_budget(1500).unwrap(), 1413);
    }

    #[test]
    fn topology_rejects_loops_roles_credentials_and_impossible_mtu() {
        let mut circuit = CircuitConfig {
            hops: vec![
                hop("relay.example.com:4433", "000000000001", HopRole::Relay),
                hop("exit.example.com:4433", "000000000002", HopRole::Exit),
            ],
            ..CircuitConfig::default()
        };
        circuit.validate(1500).expect("valid two-hop circuit");

        circuit.hops[1].endpoint = circuit.hops[0].endpoint.clone();
        assert!(circuit
            .validate(1500)
            .expect_err("endpoint loop")
            .to_string()
            .contains("endpoint"));
        circuit.hops[1].endpoint = "exit.example.com:4433".to_string();
        circuit.hops[1].qkey_id = circuit.hops[0].qkey_id.clone();
        assert!(circuit.validate(1500).expect_err("identity loop").to_string().contains("QKey"));
        circuit.hops[1].qkey_id = "000000000002".to_string();
        circuit.hops[1].qkey_token_ref = circuit.hops[0].qkey_token_ref.clone();
        assert!(circuit
            .validate(1500)
            .expect_err("credential reference reuse")
            .to_string()
            .contains("token reference"));
        circuit.hops[1].qkey_token_ref = "keychain:000000000002".to_string();
        circuit.hops[0].role = HopRole::Exit;
        assert!(circuit.validate(1500).expect_err("early exit").to_string().contains("Relay"));

        circuit.hops = (0..7)
            .map(|index| {
                let role = if index == 6 { HopRole::Exit } else { HopRole::Relay };
                hop(
                    &format!("relay{}.example.com:4433", index + 1),
                    &format!("{:012x}", index + 1),
                    role,
                )
            })
            .collect();
        circuit.max_hops = 8;
        assert!(circuit
            .validate(1400)
            .expect_err("impossible nested budget")
            .to_string()
            .contains("deepest QUIC"));
    }

    #[test]
    fn hop_labels_are_bounded_and_log_safe() {
        let mut circuit = CircuitConfig {
            hops: vec![hop("exit.example.com:4433", "000000000001", HopRole::Exit)],
            ..CircuitConfig::default()
        };
        circuit.validate(1500).expect("ordinary label");

        circuit.hops[0].label.clear();
        assert!(circuit.validate(1500).expect_err("empty label").to_string().contains("label"));
        circuit.hops[0].label = "exit\nforged-log-line".to_string();
        assert!(circuit
            .validate(1500)
            .expect_err("control character")
            .to_string()
            .contains("visible"));
        circuit.hops[0].label = "x".repeat(MAX_CIRCUIT_HOP_LABEL_CHARS + 1);
        assert!(circuit.validate(1500).is_err());
    }

    #[test]
    fn operator_configuration_match_covers_security_and_transport_policy() {
        let baseline = CircuitConfig {
            hops: vec![hop("exit.example.com:4433", "000000000001", HopRole::Exit)],
            ..CircuitConfig::default()
        };
        let mut candidate = baseline.clone();
        candidate.hops[0].pinned_endpoint = Some("203.0.113.7:4433".parse().expect("pin"));
        candidate.hops[0].qkey_token = Some(crate::QKeyToken::new("11".repeat(32)));
        assert!(baseline.has_same_operator_configuration(&candidate));

        candidate.hops[0].verify_peer = false;
        assert!(!baseline.has_same_operator_configuration(&candidate));
        candidate.hops[0].verify_peer = true;
        candidate.hops[0].policy.enable_traffic_padding = Some(false);
        assert!(!baseline.has_same_operator_configuration(&candidate));
        candidate.hops[0].policy.enable_traffic_padding = None;
        candidate.diversity.region = true;
        assert!(!baseline.has_same_operator_configuration(&candidate));
    }

    #[test]
    fn explicit_single_hop_fallback_is_bounded_and_derived_from_the_exit() {
        let circuit = CircuitConfig {
            hops: vec![
                hop("entry.example.com:4433", "000000000001", HopRole::Relay),
                hop("exit.example.com:4433", "000000000002", HopRole::Exit),
            ],
            allow_single_hop_fallback: true,
            ..CircuitConfig::default()
        };
        circuit.validate(1500).expect("explicit fallback policy");

        let fallback = circuit.single_hop_fallback().expect("derived fallback");
        fallback.validate(1500).expect("standalone fallback circuit");
        assert_eq!(fallback.hops.len(), 1);
        assert_eq!(fallback.hops[0].endpoint, "exit.example.com:4433");
        assert_eq!(fallback.hops[0].qkey_id, "000000000002");
        assert_eq!(fallback.max_hops, 1);
        assert_eq!(fallback.max_parallel_circuits, 2);
        assert!(!fallback.allow_single_hop_fallback);
        assert_eq!(fallback.diversity, CircuitDiversityPolicy::default());

        let mut invalid = circuit.clone();
        invalid.max_parallel_circuits = 1;
        assert!(invalid
            .validate(1500)
            .expect_err("fallback requires bounded overlap")
            .to_string()
            .contains("max_parallel_circuits"));

        let one_hop = CircuitConfig {
            hops: vec![hop("exit.example.com:4433", "000000000003", HopRole::Exit)],
            allow_single_hop_fallback: true,
            ..CircuitConfig::default()
        };
        assert!(one_hop
            .validate(1500)
            .expect_err("a one-hop primary has no smaller VPN fallback")
            .to_string()
            .contains("multi-hop"));
    }

    #[test]
    fn endpoint_parser_preserves_ipv4_ipv6_and_hostname_semantics() {
        assert_eq!(
            parse_endpoint_authority("203.0.113.1:4433").expect("IPv4"),
            HopEndpoint { host: "203.0.113.1".to_string(), port: 4433 }
        );
        assert_eq!(
            parse_endpoint_authority("[2001:db8::1]:4433").expect("IPv6"),
            HopEndpoint { host: "2001:db8::1".to_string(), port: 4433 }
        );
        assert_eq!(
            parse_endpoint_authority("Relay.Example.com:4433").expect("hostname"),
            HopEndpoint { host: "relay.example.com".to_string(), port: 4433 }
        );
        assert_eq!(
            parse_endpoint_authority("Relay.Example.com.:4433").expect("absolute hostname"),
            HopEndpoint { host: "relay.example.com".to_string(), port: 4433 }
        );
        assert!(parse_endpoint_authority("2001:db8::1:4433").is_err());
    }

    #[test]
    fn per_hop_policy_roundtrips_and_rejects_an_invalid_persona() {
        let mut circuit = CircuitConfig {
            hops: vec![hop("exit.example.com:4433", "000000000001", HopRole::Exit)],
            ..CircuitConfig::default()
        };
        circuit.hops[0].policy = HopPolicyOverrides {
            persona: Some(HopPersonaConfig {
                browser: qf_stealth::BrowserProfile::Firefox,
                os: qf_stealth::OsProfile::Linux,
            }),
            fec_mode: Some(crate::FecMode::Off),
            enable_traffic_padding: Some(false),
            enable_timing_obfuscation: Some(true),
            enable_cover_ping: Some(false),
        };
        circuit.validate(1500).expect("per-hop policy");
        let encoded = toml::to_string(&circuit).expect("serialize circuit");
        let decoded: CircuitConfig = toml::from_str(&encoded).expect("deserialize circuit");
        assert_eq!(decoded.hops[0].policy, circuit.hops[0].policy);

        circuit.hops[0].policy.persona = Some(HopPersonaConfig {
            browser: qf_stealth::BrowserProfile::Safari,
            os: qf_stealth::OsProfile::Windows,
        });
        assert!(circuit.validate(1500).is_err());
    }

    #[test]
    fn runtime_entry_pin_is_not_serialized_and_must_match_literal_authorities() {
        let mut circuit = CircuitConfig {
            hops: vec![hop("203.0.113.7:4433", "000000000001", HopRole::Exit)],
            ..CircuitConfig::default()
        };
        circuit.hops[0].pinned_endpoint = Some("203.0.113.7:4433".parse().expect("pin"));
        circuit.validate(1500).expect("matching runtime pin");
        let encoded = toml::to_string(&circuit).expect("serialize circuit");
        assert!(!encoded.contains("pinned_endpoint"));

        circuit.hops[0].pinned_endpoint = Some("203.0.113.8:4433".parse().expect("wrong pin"));
        assert!(circuit
            .validate(1500)
            .expect_err("mismatched pin")
            .to_string()
            .contains("address"));
    }
}

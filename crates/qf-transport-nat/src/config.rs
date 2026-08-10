//! NAT traversal policy and bounded discovery configuration.

/// Policy that controls when NAT traversal may emit discovery probes.
///
/// NAT traversal is intentionally disabled by default. STUN/ICE traffic can be
/// useful for connectivity, roaming, and mesh scenarios, but it is also an
/// observable protocol surface. The policy therefore treats NAT traversal as a
/// bounded path-discovery tool, not as a default stealth mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatTraversalMode {
    /// Do not emit NAT traversal probes.
    #[default]
    Off,
    /// Probe only after the direct path fails or becomes unreachable.
    ConnectivityFallback,
    /// Probe after direct failure and during local path changes or roaming.
    Roaming,
    /// Probe for direct failure, roaming, and explicit mesh/peer discovery.
    Mesh,
    /// Probe for any explicit discovery reason. Intended for diagnostics only.
    Always,
}

/// Reason a caller wants to run NAT path discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDiscoveryReason {
    /// Direct client-to-server connectivity failed.
    ConnectivityFailure,
    /// The local network path changed, for example WiFi to LTE.
    Roaming,
    /// Mesh or peer-to-peer path establishment needs candidates.
    Mesh,
    /// Explicit operator/test request.
    Manual,
}

/// Engine-facing NAT traversal configuration with string-address wire fields.
///
/// The engine TOML contract intentionally keeps server addresses as strings so
/// malformed operator input can be rejected during configuration validation.
/// Runtime transport code consumes [`NatTraversalConfig`] with parsed socket
/// addresses instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatTraversalSection {
    /// Master switch for NAT traversal. When false, no STUN/TURN/ICE probes are emitted.
    pub enabled: bool,
    /// Discovery policy: off, connectivity-fallback, roaming, mesh, always.
    pub mode: NatTraversalMode,
    /// STUN servers used for server-reflexive candidate discovery.
    pub stun_servers: Vec<String>,
    /// TURN servers reserved for relayed-candidate support.
    pub turn_servers: Vec<String>,
    /// Enable ICE candidate gathering.
    pub ice_enabled: bool,
    /// Minimum interval between discovery probe bursts.
    pub probe_interval_ms: u64,
    /// Maximum candidates returned by one discovery run.
    pub max_candidates: usize,
}

impl Default for NatTraversalSection {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: NatTraversalMode::Off,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            ice_enabled: false,
            probe_interval_ms: NatTraversalConfig::DEFAULT_PROBE_INTERVAL_MS,
            max_candidates: NatTraversalConfig::DEFAULT_MAX_CANDIDATES,
        }
    }
}

impl NatTraversalSection {
    /// Validate the serialized engine contract before runtime conversion.
    pub fn validate(&self) -> Result<(), qf_error::ConnectionError> {
        if self.probe_interval_ms < 1_000 {
            return Err(qf_error::ConnectionError::from(
                "nat_traversal.probe_interval_ms must be at least 1000",
            ));
        }
        if self.max_candidates == 0 {
            return Err(qf_error::ConnectionError::from(
                "nat_traversal.max_candidates must be at least 1",
            ));
        }
        for value in self.stun_servers.iter().chain(self.turn_servers.iter()) {
            NatTraversalConfig::parse_server_addr(value)?;
        }
        if !self.enabled && self.mode != NatTraversalMode::Off {
            return Err(qf_error::ConnectionError::from(
                "nat_traversal.mode must be off when nat_traversal.enabled is false",
            ));
        }
        Ok(())
    }

    /// Convert the validated engine contract into runtime transport settings.
    pub fn to_transport_config(&self) -> Result<NatTraversalConfig, qf_error::ConnectionError> {
        let parse_servers = |values: &[String]| {
            values
                .iter()
                .map(|value| NatTraversalConfig::parse_server_addr(value))
                .collect::<Result<Vec<_>, _>>()
        };

        Ok(NatTraversalConfig {
            enabled: self.enabled,
            mode: self.mode,
            stun_servers: parse_servers(&self.stun_servers)?,
            turn_servers: parse_servers(&self.turn_servers)?,
            ice_enabled: self.ice_enabled,
            probe_interval_ms: self.probe_interval_ms,
            max_candidates: self.max_candidates,
        }
        .normalized())
    }
}

#[cfg(test)]
mod tests {
    use super::{NatTraversalMode, NatTraversalSection};

    #[test]
    fn engine_section_preserves_wire_shape_and_runtime_conversion() {
        let section = NatTraversalSection {
            enabled: true,
            mode: NatTraversalMode::ConnectivityFallback,
            stun_servers: vec!["203.0.113.1:3478".to_string()],
            turn_servers: vec!["203.0.113.2:3478".to_string()],
            ice_enabled: true,
            probe_interval_ms: 30_000,
            max_candidates: 4,
        };

        let encoded = serde_json::to_value(&section).expect("serialize NAT engine section");
        assert_eq!(encoded["mode"], "connectivity-fallback");
        let decoded: NatTraversalSection =
            serde_json::from_value(encoded).expect("deserialize NAT engine section");
        assert_eq!(decoded, section);

        section.validate().expect("valid NAT engine section");
        let runtime = section.to_transport_config().expect("convert NAT runtime section");
        assert_eq!(runtime.stun_servers[0].port(), 3478);
        assert_eq!(runtime.turn_servers[0].port(), 3478);
        assert!(runtime.ice_enabled);
    }

    #[test]
    fn engine_section_validation_preserves_disabled_mode_guard() {
        let section = NatTraversalSection {
            enabled: false,
            mode: NatTraversalMode::Roaming,
            ..NatTraversalSection::default()
        };

        let error = section.validate().expect_err("disabled roaming must fail closed");
        assert_eq!(
            error.to_string(),
            "Transport error: nat_traversal.mode must be off when nat_traversal.enabled is false"
        );
    }

    #[test]
    fn engine_section_validation_rejects_malformed_server_address() {
        let section = NatTraversalSection {
            stun_servers: vec!["not-an-address".to_string()],
            ..NatTraversalSection::default()
        };

        assert!(section.validate().is_err());
        assert!(section.to_transport_config().is_err());
    }
}

/// NAT traversal configuration (TODO-454): STUN/TURN/ICE settings.
///
/// Controls whether the transport attempts NAT traversal via STUN binding
/// requests, TURN relaying, and ICE candidate gathering. Disabled by default.
/// Enabling it provides optional path discovery for direct-connect failures,
/// roaming, or mesh scenarios without turning STUN/ICE into permanent
/// background noise.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct NatTraversalConfig {
    /// Master switch for NAT traversal. When false, STUN/TURN/ICE are skipped.
    pub enabled: bool,
    /// Policy that decides which discovery reasons may emit probes.
    pub mode: NatTraversalMode,
    /// STUN server addresses used to discover server-reflexive candidates.
    pub stun_servers: Vec<std::net::SocketAddr>,
    /// TURN server addresses used to obtain relayed candidates when direct
    /// connectivity is impossible.
    pub turn_servers: Vec<std::net::SocketAddr>,
    /// Whether ICE candidate gathering and pair selection is enabled.
    pub ice_enabled: bool,
    /// Minimum interval between discovery probe bursts.
    pub probe_interval_ms: u64,
    /// Maximum number of candidates returned by one discovery run.
    pub max_candidates: usize,
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl NatTraversalConfig {
    /// Conservative default probe interval. Large enough to avoid STUN chatter
    /// while still reacting quickly to a real direct-path failure.
    pub const DEFAULT_PROBE_INTERVAL_MS: u64 = 30_000;
    /// Default candidate cap. Keeps discovery bounded even with many local
    /// interfaces and STUN/TURN servers.
    pub const DEFAULT_MAX_CANDIDATES: usize = 8;

    /// Create an explicitly disabled config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            mode: NatTraversalMode::Off,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            ice_enabled: false,
            probe_interval_ms: Self::DEFAULT_PROBE_INTERVAL_MS,
            max_candidates: Self::DEFAULT_MAX_CANDIDATES,
        }
    }

    /// Parse a STUN/TURN server address from a string.
    pub fn parse_server_addr(s: &str) -> Result<std::net::SocketAddr, qf_error::ConnectionError> {
        s.parse().map_err(|e| {
            qf_error::ConnectionError::Transport(format!("Invalid NAT server address: {}", e))
        })
    }

    /// Returns true when the configured policy permits discovery for `reason`.
    pub fn allows_discovery(&self, reason: NatDiscoveryReason) -> bool {
        if !self.enabled || self.mode == NatTraversalMode::Off {
            return false;
        }
        match self.mode {
            NatTraversalMode::Off => false,
            NatTraversalMode::ConnectivityFallback => {
                matches!(
                    reason,
                    NatDiscoveryReason::ConnectivityFailure | NatDiscoveryReason::Manual
                )
            }
            NatTraversalMode::Roaming => {
                matches!(
                    reason,
                    NatDiscoveryReason::ConnectivityFailure
                        | NatDiscoveryReason::Roaming
                        | NatDiscoveryReason::Manual
                )
            }
            NatTraversalMode::Mesh => true,
            NatTraversalMode::Always => true,
        }
    }

    /// Returns a normalized copy with production-safe lower bounds.
    pub fn normalized(&self) -> Self {
        let mut out = self.clone();
        out.probe_interval_ms = out.probe_interval_ms.max(1_000);
        out.max_candidates = out.max_candidates.max(1);
        if !out.enabled {
            out.mode = NatTraversalMode::Off;
        }
        out
    }
}

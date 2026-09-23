//! QuicFuscate Engine Configuration
//!
//! This module provides comprehensive configuration structures for the QuicFuscate engine.
//! All settings can be loaded from a TOML configuration file.
//!
//! # Example
//!
//! ```ignore
//! use qf_engine_types::EngineConfig;
//!
//! let config = EngineConfig::from_file("config/quicfuscate.toml")?;
//! config.validate()?;
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{
    AeadPreference, AntiReplaySection, AuditConfig, CcAlgorithm, CircuitConfig, ConfigError,
    ConnectionConfig, CryptoConfig, EngineMode, EngineSection, FecSection,
    FingerprintRotationConfig, InterfaceConfig, LoggingConfig, NatTraversalSection,
    OptimizationConfig, QKeyConfig, SecurityConfig, StealthMode, TelemetryConfig, TransportConfig,
};

/// Complete engine configuration aggregating all subsystems.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// Engine mode and lifecycle settings
    pub engine: EngineSection,
    /// Connection parameters (remote, TLS, streams)
    pub connection: ConnectionConfig,
    /// Canonical multi-hop client circuit. Absence preserves legacy one-hop configuration.
    pub circuit: Option<CircuitConfig>,
    /// Optional distinct circuit authenticated and serviced in parallel after the primary.
    pub alternate_circuit: Option<CircuitConfig>,
    /// Transport layer settings (CC, MTU, pacing)
    pub transport: TransportConfig,
    /// Optional NAT path discovery settings (STUN/TURN/ICE).
    pub nat_traversal: NatTraversalSection,
    /// Cryptographic settings (AEAD, PQ)
    pub crypto: CryptoConfig,
    /// TUN interface settings
    pub interface: InterfaceConfig,
    /// Telemetry and metrics settings
    pub telemetry: TelemetryConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security audit persistence configuration
    pub audit: AuditConfig,
    /// Forward Error Correction settings
    #[serde(rename = "fec")]
    pub fec: FecSection,
    /// Stealth and obfuscation settings
    pub stealth: StealthSection,
    /// Fingerprint rotation settings
    pub fingerprint_rotation: FingerprintRotationConfig,
    /// Performance optimization settings
    pub optimization: OptimizationConfig,
    /// 0-RTT anti-replay protection settings
    pub anti_replay: AntiReplaySection,
    /// Security settings (kill switch, leak prevention)
    #[serde(default)]
    pub security: SecurityConfig,
}

impl EngineConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents =
            std::fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    ///
    /// Normalization runs here so every parse path, including the runtime reload, sees a
    /// configuration whose relative defaults have been reconciled against the operator's values.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.normalize();
        Ok(config)
    }

    /// Reconcile defaults that only make sense relative to another field.
    ///
    /// `pmtu_max_mtu` defaults to 1500 while `transport.mtu` is operator-configurable. Lowering
    /// the MTU to any ordinary value such as 1400 therefore left the DPLPMTUD probe ceiling above
    /// it, and validation rejected the whole configuration even though the operator had set
    /// nothing contradictory. A probe ceiling above the path MTU is meaningless, so it is lowered
    /// to match rather than treated as a conflict.
    ///
    /// Only downward adjustment happens here: a ceiling the operator explicitly set below the MTU
    /// is left alone, and an explicitly raised ceiling that still exceeds the MTU is clamped
    /// with a warning rather than silently accepted.
    pub fn normalize(&mut self) {
        let ceiling = self.transport.mtu.min(self.transport.max_udp_payload);
        if self.transport.pmtu_max_mtu > ceiling {
            log::warn!(
                "transport.pmtu_max_mtu {} exceeds the configured transport limits; lowering to {}",
                self.transport.pmtu_max_mtu,
                ceiling
            );
            self.transport.pmtu_max_mtu = ceiling;
        }
    }

    /// Validate all configuration sections.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.engine.validate().map_err(ConfigError::Validation)?;
        self.connection.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.transport.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        if self.engine.mode == EngineMode::Server
            && (self.circuit.is_some()
                || self.alternate_circuit.is_some()
                || self.connection.outer_hop != crate::OuterHop::None)
        {
            return Err(ConfigError::Validation(
                "circuit, alternate_circuit, and outer_hop are client-only configuration sections"
                    .to_string(),
            ));
        }
        if self.connection.outer_hop != crate::OuterHop::None && self.circuit.is_some() {
            return Err(ConfigError::Validation(
                "connection.outer_hop wraps the direct UDP dial; it cannot be combined with an explicit circuit"
                    .to_string(),
            ));
        }
        if self.connection.outer_hop == crate::OuterHop::Masque
            && self.connection.qkey_token.is_none()
        {
            return Err(ConfigError::Validation(
                "connection.outer_hop = \"masque\" requires connection.qkey_token so the exit hop can authenticate"
                    .to_string(),
            ));
        }
        if let Some(circuit) = self.circuit.as_ref() {
            circuit
                .validate(self.transport.mtu.min(self.transport.max_udp_payload))
                .map_err(|error| ConfigError::Validation(error.to_string()))?;
            let legacy = ConnectionConfig::default();
            if self.connection.remote != legacy.remote
                || self.connection.sni != legacy.sni
                || self.connection.qkey_id.is_some()
                || self.connection.qkey_token.is_some()
            {
                return Err(ConfigError::Validation(
                    "circuit cannot be combined with legacy connection endpoint or QKey fields"
                        .to_string(),
                ));
            }
        }
        if let Some(alternate) = self.alternate_circuit.as_ref() {
            let primary = self.circuit.as_ref().ok_or_else(|| {
                ConfigError::Validation(
                    "alternate_circuit requires a canonical primary circuit".to_string(),
                )
            })?;
            alternate
                .validate(self.transport.mtu.min(self.transport.max_udp_payload))
                .map_err(|error| ConfigError::Validation(error.to_string()))?;
            if primary.max_parallel_circuits != 2 || alternate.max_parallel_circuits != 2 {
                return Err(ConfigError::Validation(
                    "primary and alternate circuits require max_parallel_circuits = 2".to_string(),
                ));
            }
            let primary_endpoints = primary
                .hops
                .iter()
                .map(|hop| {
                    hop.parsed_endpoint()
                        .map(|endpoint| (endpoint.host, endpoint.port))
                        .map_err(|error| ConfigError::Validation(error.to_string()))
                })
                .collect::<Result<std::collections::HashSet<_>, _>>()?;
            let primary_identities = primary
                .hops
                .iter()
                .map(|hop| hop.qkey_id.trim().to_ascii_lowercase())
                .collect::<std::collections::HashSet<_>>();
            let primary_token_references = primary
                .hops
                .iter()
                .map(|hop| hop.qkey_token_ref.trim())
                .collect::<std::collections::HashSet<_>>();
            for (index, hop) in alternate.hops.iter().enumerate() {
                let endpoint = hop
                    .parsed_endpoint()
                    .map_err(|error| ConfigError::Validation(error.to_string()))?;
                if primary_endpoints.contains(&(endpoint.host, endpoint.port)) {
                    return Err(ConfigError::Validation(format!(
                        "alternate_circuit.hops[{index}] reuses a primary endpoint"
                    )));
                }
                if primary_identities.contains(&hop.qkey_id.trim().to_ascii_lowercase()) {
                    return Err(ConfigError::Validation(format!(
                        "alternate_circuit.hops[{index}] reuses a primary QKey identity"
                    )));
                }
                if primary_token_references.contains(hop.qkey_token_ref.trim()) {
                    return Err(ConfigError::Validation(format!(
                        "alternate_circuit.hops[{index}] reuses a primary QKey token reference"
                    )));
                }
            }
        }
        self.nat_traversal
            .validate()
            .map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.crypto.validate().map_err(ConfigError::Validation)?;
        self.interface.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.telemetry.validate().map_err(ConfigError::Validation)?;
        self.logging.validate().map_err(ConfigError::Validation)?;
        self.audit.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.fec.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.fingerprint_rotation.validate().map_err(ConfigError::Validation)?;
        self.optimization.validate().map_err(|error| ConfigError::Validation(error.to_string()))?;
        self.anti_replay.validate().map_err(ConfigError::Validation)?;
        self.stealth
            .to_runtime_config(&self.fingerprint_rotation)
            .map_err(|error| ConfigError::Validation(format!("stealth: {error}")))?;
        let early_data_requested = self.connection.enable_0rtt || self.transport.enable_early_data;
        if early_data_requested
            && self.engine.mode == EngineMode::Server
            && !self.anti_replay.enabled
        {
            return Err(ConfigError::Validation(
                "server 0-RTT requires anti_replay.enabled = true".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a builder for programmatic configuration.
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }
}

impl From<&EngineConfig> for QKeyConfig {
    fn from(config: &EngineConfig) -> Self {
        let stealth = match config.stealth.mode {
            StealthMode::Off => None,
            StealthMode::Performance => Some("performance"),
            StealthMode::Stealth => Some("stealth"),
            StealthMode::StealthMax => Some("Stealth MAX"),
            StealthMode::Manual => Some("manual"),
            StealthMode::Dynamic => Some("dynamic"),
        };
        let fec = match config.fec.mode {
            crate::FecMode::Off => None,
            crate::FecMode::Auto => Some("auto"),
        };

        let mut qkey = Self::new(&config.connection.remote, &config.connection.sni);
        if let Some(mode) = stealth {
            qkey = qkey.with_stealth(mode);
        }
        if let Some(mode) = fec {
            qkey = qkey.with_fec(mode);
        }
        qkey
    }
}

// ============================================================================
// STEALTH SECTION
// ============================================================================

/// Stealth configuration section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StealthSection {
    /// Stealth mode
    pub mode: StealthMode,
    /// The wire image `dynamic` freezes at connect (TODO-1059): `stealth`
    /// (default) keeps persona-trace padding, in-QUIC FEC and cover headers;
    /// `performance` selects the thin image. Shape keys below are inert under
    /// `mode = "dynamic"` - the image preset owns the whole wire shape.
    #[serde(default)]
    pub dynamic_wire_image: qf_stealth::DynamicWireImage,
    /// Optional serialized `maybenot` machine for the wire-defense adapter
    /// (TODO-1061). `None` by default - no machine loads unless an operator
    /// pins one after simulator evidence. Not a shape key: stays effective
    /// under `mode = "dynamic"`.
    #[serde(default)]
    pub maybenot_machine: Option<String>,
    /// Enable uTLS/ClientHello persona spoofing. Effective only when mode is not Off.
    pub use_utls: bool,
    /// Removed wire behavior (TODO-1048): an SNI that differs from the hop's
    /// certificate name. The key stays parseable so existing files still load;
    /// setting it to `true` fails validation with a pointer to
    /// `reality_cover_targets`.
    pub enable_domain_fronting: bool,
    /// Enable HTTP/3 masquerading
    pub enable_http3_masquerading: bool,
    /// Use TLS Cover
    pub use_tls_cover: bool,
    /// Use QPACK headers
    pub use_qpack_headers: bool,
    /// Enable traffic padding
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry
    pub enable_protocol_mimicry: bool,
    /// Enable DNS-over-HTTPS
    pub enable_doh: bool,
    /// DoH provider URL
    pub doh_provider: String,
    /// Padding strategy / wire shape (legacy spellings collapse onto the
    /// TODO-1052 shapes: `persona-trace` or `fixed-cell`).
    pub padding_strategy: String,
    /// Shared wire byte budget: stealth bytes (repairs + padding + cover)
    /// per second. `None` keeps the mode default.
    pub wire_cap_bytes_per_sec: Option<u64>,
    /// Shared wire byte budget: stealth bytes in one drain burst.
    pub wire_cap_bytes_per_burst: Option<u64>,
    /// Maximum padding size
    pub max_padding_size: usize,
    /// Deprecated alias for `reality_cover_targets` (TODO-1048): entries are
    /// treated as cover-target hostnames.
    pub fronting_domains: Vec<String>,
    /// Reality cover targets: `host` or `host:port` entries whose certificate
    /// the selected hop legitimately presents or relays. Probe traffic without
    /// a valid tunnel secret is relayed to these endpoints.
    pub reality_cover_targets: Vec<String>,
    /// Initial browser profile
    pub initial_browser: String,
    /// Initial OS profile
    pub initial_os: String,
    /// Normalize decoded server-side tunnel ingress to the selected OS profile.
    pub enable_network_fingerprint_normalization: bool,
    /// Suppress ICMP destination-unreachable traffic except PMTUD signals.
    pub suppress_icmp_unreachable: bool,
    /// Total size, in bytes, that every 1-RTT packet is padded to when
    /// `padding_strategy = "normalize"`.
    ///
    /// Required by, and only meaningful for, that strategy. It was absent from this schema
    /// entirely, so selecting `normalize` produced a configuration error that named the gap
    /// instead of a working setting: the strategy was visible but unusable, and any path that
    /// skipped this validation would have emitted ordinary variable-sized packets while the
    /// configuration claimed normalization.
    pub normalize_target_size: usize,
}

/// Smallest packet-normalize target that can carry a QUIC datagram.
///
/// Below the 1200-byte QUIC minimum the target could not hold a conformant packet, so padding to
/// it would be meaningless.
pub const MIN_NORMALIZE_TARGET_SIZE: usize = 1200;

/// Largest packet-normalize target, bounded by the maximum UDP payload.
pub const MAX_NORMALIZE_TARGET_SIZE: usize = 65_527;

impl Default for StealthSection {
    fn default() -> Self {
        Self {
            mode: StealthMode::Dynamic,
            dynamic_wire_image: qf_stealth::DynamicWireImage::Stealth,
            maybenot_machine: None,
            use_utls: true,
            enable_domain_fronting: false,
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: true,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            padding_strategy: "persona-trace".to_string(),
            wire_cap_bytes_per_sec: None,
            wire_cap_bytes_per_burst: None,
            normalize_target_size: 0,
            max_padding_size: 256,
            fronting_domains: Vec::new(),
            reality_cover_targets: Vec::new(),
            initial_browser: "chrome".to_string(),
            initial_os: "windows".to_string(),
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
        }
    }
}

impl StealthSection {
    /// Legacy and current padding-strategy spellings collapse onto the
    /// TODO-1052 wire shapes. `random`/`adaptive`/`browser*` map to
    /// `PersonaTrace`; `fixed`/`constant`/`*normalize*` map to `FixedCell`.
    /// In `off`/`performance` modes no ledger is installed, so a mapped
    /// shape there is inert.
    fn parse_wire_shape(value: &str) -> Option<qf_stealth::WireShape> {
        match value.trim().to_ascii_lowercase().as_str() {
            "random" | "1" | "adaptive" | "3" | "browser" | "browser_mimic" | "browser-mimic"
            | "browsermimic" | "mimic" | "4" | "persona-trace" | "persona_trace" | "trace" => {
                Some(qf_stealth::WireShape::PersonaTrace)
            }
            "fixed" | "constant" | "2" | "normalize" | "packet_normalize" | "packet-normalize"
            | "packetnormalize" | "5" | "fixed-cell" | "fixed_cell" | "cell" => {
                Some(qf_stealth::WireShape::FixedCell)
            }
            _ => None,
        }
    }

    /// Convert the engine stealth section and rotation policy into one runtime
    /// configuration. Invalid string enums fail here instead of falling back to
    /// a mode preset inside an adapter.
    pub fn to_runtime_config(
        &self,
        rotation: &FingerprintRotationConfig,
    ) -> Result<qf_stealth::StealthConfig, ConfigError> {
        rotation.validate().map_err(ConfigError::Validation)?;
        let runtime_mode = match self.mode {
            StealthMode::Off => qf_stealth::StealthMode::Off,
            StealthMode::Performance => qf_stealth::StealthMode::Performance,
            StealthMode::Stealth => qf_stealth::StealthMode::Stealth,
            StealthMode::StealthMax => qf_stealth::StealthMode::StealthMax,
            StealthMode::Manual => qf_stealth::StealthMode::Manual,
            StealthMode::Dynamic => qf_stealth::StealthMode::Dynamic,
        };
        if self.enable_domain_fronting {
            return Err(ConfigError::Validation(
                "stealth.enable_domain_fronting was removed in TODO-1048: SNI must equal the certificate name of the hop; set stealth.reality_cover_targets to the Reality cover hosts instead"
                    .into(),
            ));
        }
        let dynamic = runtime_mode == qf_stealth::StealthMode::Dynamic;
        let mut runtime = if dynamic {
            // TODO-1059: the image preset owns the whole wire shape for
            // `dynamic` - padding set, timing, cover schedule and framing are
            // frozen at connect, so the per-key shape overrides below stay
            // inert on this mode (non-Option keys cannot distinguish
            // "operator set false" from the section default).
            qf_stealth::StealthConfig::dynamic_with_image(self.dynamic_wire_image)
        } else {
            qf_stealth::StealthConfig::from_mode(runtime_mode)
        };
        if !dynamic {
            runtime.enable_http3_masquerading = self.enable_http3_masquerading;
            runtime.use_tls_cover = self.use_tls_cover;
            runtime.use_qpack_headers = self.use_qpack_headers;
            runtime.enable_traffic_padding = self.enable_traffic_padding;
            runtime.enable_timing_obfuscation = self.enable_timing_obfuscation;
            runtime.enable_protocol_mimicry = self.enable_protocol_mimicry;
        }
        runtime.enable_network_fingerprint_normalization =
            self.enable_network_fingerprint_normalization;
        runtime.suppress_icmp_unreachable = self.suppress_icmp_unreachable;
        runtime.maybenot_machine = self.maybenot_machine.clone();
        runtime.enable_doh = self.enable_doh;
        runtime.doh_provider = self.doh_provider.clone();
        if !dynamic {
            runtime.max_padding_size = self.max_padding_size;
        }
        // `fronting_domains` survives as a deprecated alias: its entries name
        // cover hosts whose certificate the hop presents or relays.
        runtime.reality_cover_targets = self
            .reality_cover_targets
            .iter()
            .chain(self.fronting_domains.iter())
            .cloned()
            .collect();
        runtime.initial_browser = self.initial_browser.parse().map_err(|_| {
            ConfigError::Validation(format!(
                "stealth.initial_browser has unsupported value '{}'",
                self.initial_browser
            ))
        })?;
        runtime.initial_os = self.initial_os.parse().map_err(|_| {
            ConfigError::Validation(format!(
                "stealth.initial_os has unsupported value '{}'",
                self.initial_os
            ))
        })?;
        qf_stealth::FingerprintProfile::try_new(runtime.initial_browser, runtime.initial_os)
            .map_err(|error| {
                ConfigError::Validation(format!(
                    "stealth.initial_browser/initial_os has unsupported combination '{}@{}': {error}",
                    self.initial_browser, self.initial_os
                ))
            })?;
        if !dynamic {
            runtime.wire_shape =
                Self::parse_wire_shape(&self.padding_strategy).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "stealth.padding_strategy has unsupported value '{}'",
                        self.padding_strategy
                    ))
                })?;
            runtime.normalize_target_size = self.normalize_target_size;
        }
        if let Some(v) = self.wire_cap_bytes_per_sec {
            runtime.wire_cap_bytes_per_sec = v;
        }
        if let Some(v) = self.wire_cap_bytes_per_burst {
            runtime.wire_cap_bytes_per_burst = v;
        }
        if !dynamic {
            if runtime.wire_shape == qf_stealth::WireShape::FixedCell {
                if self.normalize_target_size == 0 {
                    return Err(ConfigError::Validation(
                        "stealth.padding_strategy=fixed-cell requires stealth.normalize_target_size"
                            .into(),
                    ));
                }
                if !(MIN_NORMALIZE_TARGET_SIZE..=MAX_NORMALIZE_TARGET_SIZE)
                    .contains(&self.normalize_target_size)
                {
                    return Err(ConfigError::Validation(format!(
                        "stealth.normalize_target_size must be in {MIN_NORMALIZE_TARGET_SIZE}..={MAX_NORMALIZE_TARGET_SIZE}, got {}",
                        self.normalize_target_size
                    )));
                }
            } else if self.normalize_target_size != 0 {
                // A target with any other shape is a contradiction: it would never be applied, and
                // silently ignoring it is how a configuration comes to claim stealth it does not have.
                return Err(ConfigError::Validation(format!(
                    "stealth.normalize_target_size is only valid with padding_strategy=fixed-cell, but the shape is '{}'",
                    self.padding_strategy
                )));
            }
        }
        if runtime.enable_traffic_padding && runtime.max_padding_size == 0 {
            return Err(ConfigError::Validation(
                "stealth.max_padding_size must be > 0 when traffic padding is enabled".into(),
            ));
        }
        runtime.enable_fingerprint_rotation = rotation.enabled;
        runtime.fingerprint_rotation_interval = rotation.interval_secs;
        runtime.fingerprint_rotation_mode = rotation.mode;
        runtime.fingerprint_rotation_profiles = rotation
            .profile_slots
            .iter()
            .map(|slot| {
                qf_stealth::parse_fingerprint_profile_slot(slot, runtime.initial_os)
                    .map(|profile| (profile.browser, profile.os))
                    .map_err(|error| {
                        ConfigError::Validation(format!(
                            "fingerprint_rotation.profile_slots entry '{slot}': {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        runtime.normalize_protocol_mimicry_bundle();
        runtime.validate().map_err(|error| {
            ConfigError::Validation(format!("stealth runtime projection: {error}"))
        })?;
        Ok(runtime)
    }
}

// ============================================================================
// BUILDER
// ============================================================================

/// Builder for programmatic configuration.
#[derive(Default)]
pub struct EngineConfigBuilder {
    config: EngineConfig,
}

impl EngineConfigBuilder {
    /// Set engine mode.
    pub fn mode(mut self, mode: EngineMode) -> Self {
        self.config.engine.mode = mode;
        self
    }

    /// Set remote address.
    pub fn remote(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.remote = addr.into();
        self
    }

    /// Set local bind address.
    pub fn local(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.local = addr.into();
        self
    }

    /// Enable/disable peer verification.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.connection.verify_peer = verify;
        self
    }

    /// Set stealth mode.
    pub fn stealth_mode(mut self, mode: StealthMode) -> Self {
        self.config.stealth.mode = mode;
        self
    }

    /// Set AEAD preference.
    pub fn aead_preference(mut self, pref: AeadPreference) -> Self {
        self.config.crypto.aead_preference = pref;
        self
    }

    /// Set congestion control algorithm.
    pub fn cc_algorithm(mut self, cc: CcAlgorithm) -> Self {
        self.config.transport.cc_algorithm = cc;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<EngineConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientTunnelIpv4, ClientTunnelIpv6, InterfaceType, LoggingMode, MemoryLockFailurePolicy,
        PacketProtectionMode, PrivateAeadFamily, QuicVersion, RotationMode,
    };
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.transport.quic_versions, [QuicVersion::V2, QuicVersion::V1]);
        assert_eq!(config.transport.cc_algorithm, CcAlgorithm::Bbr3);
        assert_eq!(config.crypto.aead_preference, AeadPreference::Auto);
        assert_eq!(config.crypto.packet_protection_mode, PacketProtectionMode::Standard);
        assert!(config.stealth.enable_network_fingerprint_normalization);
        assert!(!config.stealth.suppress_icmp_unreachable);
    }

    #[test]
    fn qkey_projection_preserves_connection_and_active_modes() {
        let mut config = EngineConfig::default();
        config.connection.remote = "198.51.100.7:443".to_string();
        config.connection.sni = "vpn.example.com".to_string();
        config.stealth.mode = StealthMode::StealthMax;
        config.fec.mode = crate::FecMode::Auto;

        let qkey = QKeyConfig::from(&config);
        assert_eq!(qkey.remote, config.connection.remote);
        assert_eq!(qkey.sni, config.connection.sni);
        assert_eq!(qkey.stealth.as_deref(), Some("Stealth MAX"));
        assert_eq!(qkey.fec.as_deref(), Some("auto"));
        assert!(qkey.validate());

        config.stealth.mode = StealthMode::Off;
        config.fec.mode = crate::FecMode::Off;
        let disabled = QKeyConfig::from(&config);
        assert_eq!(disabled.stealth, None);
        assert_eq!(disabled.fec, None);
        assert!(disabled.validate());
    }

    #[test]
    fn interface_validation_rejects_legacy_non_tun_types() {
        for (interface_type, expected_fragment) in [
            (InterfaceType::Xdp, "AF_XDP was removed"),
            (InterfaceType::Tap, "only \"tun\" is supported"),
            (InterfaceType::RawSocket, "only \"tun\" is supported"),
        ] {
            let interface = InterfaceConfig { interface_type, ..InterfaceConfig::default() };
            let error =
                interface.validate().expect_err("legacy non-TUN interface types must fail closed");
            assert!(
                error.to_string().contains(expected_fragment),
                "unexpected validation error for {interface_type:?}: {error}"
            );
        }
    }

    #[test]
    fn interface_schema_removes_xdp_fields_and_rejects_legacy_input() {
        let encoded = toml::to_string(&EngineConfig::default()).expect("serialize default config");
        assert!(!encoded.contains("xdp_mode"));
        assert!(!encoded.contains("xdp_flags"));

        let error = EngineConfig::from_toml(
            "[interface]\nxdp_mode = \"skb\"\nxdp_flags = [\"update_if_noexist\"]\n",
        )
        .expect_err("removed XDP fields must not remain accepted by the schema");
        assert!(error.to_string().contains("xdp_mode"));

        let config = EngineConfig::from_toml("[interface]\ntype = \"xdp\"\n")
            .expect("legacy XDP type remains parseable for an explicit validation error");
        let error =
            config.validate().expect_err("legacy XDP type must fail closed during validation");
        assert!(error.to_string().contains("AF_XDP was removed"));
    }

    #[test]
    fn network_fingerprint_policy_roundtrips_through_engine_toml() {
        let config = EngineConfig::from_toml(
            r#"
[stealth]
enable_network_fingerprint_normalization = false
suppress_icmp_unreachable = true
"#,
        )
        .unwrap();
        assert!(!config.stealth.enable_network_fingerprint_normalization);
        assert!(config.stealth.suppress_icmp_unreachable);

        let encoded = toml::to_string(&config).unwrap();
        let decoded = EngineConfig::from_toml(&encoded).unwrap();
        assert!(!decoded.stealth.enable_network_fingerprint_normalization);
        assert!(decoded.stealth.suppress_icmp_unreachable);
    }

    /// An ordinary lowered MTU must not be rejected because a relative default outgrew it.
    ///
    /// `pmtu_max_mtu` defaults to 1500 while `transport.mtu` is operator-configurable, so setting
    /// `mtu = 1400`, a completely normal value, left the DPLPMTUD probe ceiling above the MTU and
    /// validation rejected the whole configuration even though nothing contradictory was set.
    #[test]
    fn lowering_transport_mtu_alone_produces_a_valid_configuration() {
        let config = EngineConfig::from_toml("[transport]\nmtu = 1400\n")
            .expect("a lowered MTU alone must parse");
        assert_eq!(
            config.transport.pmtu_max_mtu, 1400,
            "the probe ceiling must follow the configured MTU, not stay at its default"
        );
        config.validate().expect("a lowered MTU alone must validate");

        // max_udp_payload participates in the same ceiling.
        let config = EngineConfig::from_toml("[transport]\nmtu = 1400\nmax_udp_payload = 1300\n")
            .expect("parse");
        assert_eq!(config.transport.pmtu_max_mtu, 1300, "the lower of the two limits wins");
        config.validate().expect("validate");

        // A ceiling the operator deliberately set below the MTU is left alone.
        let config = EngineConfig::from_toml("[transport]\nmtu = 1400\npmtu_max_mtu = 1350\n")
            .expect("parse");
        assert_eq!(config.transport.pmtu_max_mtu, 1350, "an explicit lower ceiling is preserved");
        config.validate().expect("validate");
    }

    /// Validation errors must name the configuration key they are about.
    #[test]
    fn transport_mtu_floor_error_names_the_key() {
        let error = EngineConfig::from_toml("[transport]\nmtu = 100\n")
            .expect("parse succeeds; validation is the gate")
            .validate()
            .expect_err("an MTU below the floor must fail");
        let text = error.to_string().to_ascii_lowercase();
        assert!(
            text.contains("transport.mtu"),
            "an operator cannot act on an error that does not name the key: {error}"
        );
        assert!(text.contains("1200"), "the error must state the floor: {error}");
    }

    /// Selecting packet normalization must produce a working configuration, not an error.
    ///
    /// `stealth.normalize_target_size` did not exist in this schema, so `padding_strategy =
    /// "normalize"` always failed validation with a message that named the missing field. The
    /// strategy was visible and selectable but unusable, and any path that skipped this validation
    /// would have emitted ordinary variable-sized packets while the configuration claimed
    /// normalization.
    #[test]
    fn packet_normalize_requires_and_propagates_a_bounded_target_size() {
        let config = EngineConfig::from_toml(
            "[stealth]\nmode = \"stealth\"\npadding_strategy = \"normalize\"\nnormalize_target_size = 1350\n",
        )
        .expect("parse");
        config.validate().expect("a normalize configuration with a target must validate");

        let runtime = config
            .stealth
            .to_runtime_config(&FingerprintRotationConfig::default())
            .expect("runtime stealth config");
        assert_eq!(
            runtime.wire_shape,
            qf_stealth::WireShape::FixedCell,
            "the legacy normalize spelling must map to the fixed-cell shape"
        );
        assert_eq!(
            runtime.normalize_target_size, 1350,
            "the target must reach the runtime config, otherwise normalization is a no-op"
        );
    }

    /// Missing, undersized, and oversized targets each fail closed with a named key.
    #[test]
    fn packet_normalize_rejects_missing_and_out_of_range_targets() {
        let missing = EngineConfig::from_toml(
            "[stealth]\nmode = \"stealth\"\npadding_strategy = \"normalize\"\n",
        )
        .expect("parse")
        .stealth
        .to_runtime_config(&FingerprintRotationConfig::default())
        .err()
        .expect("normalize without a target must fail");
        assert!(
            missing.to_string().contains("stealth.normalize_target_size"),
            "the error must name the key an operator has to set: {missing}"
        );

        for target in [1usize, MIN_NORMALIZE_TARGET_SIZE - 1, MAX_NORMALIZE_TARGET_SIZE + 1] {
            let error = EngineConfig::from_toml(&format!(
                "[stealth]\nmode = \"stealth\"\npadding_strategy = \"normalize\"\nnormalize_target_size = {target}\n"
            ))
            .expect("parse")
            .stealth
            .to_runtime_config(&FingerprintRotationConfig::default())
            .err()
            .expect("an out-of-range target must fail");
            assert!(
                error.to_string().contains("normalize_target_size"),
                "the error must name the key for target {target}: {error}"
            );
        }

        // The exact bounds are accepted.
        for target in [MIN_NORMALIZE_TARGET_SIZE, MAX_NORMALIZE_TARGET_SIZE] {
            EngineConfig::from_toml(&format!(
                "[stealth]\nmode = \"stealth\"\npadding_strategy = \"normalize\"\nnormalize_target_size = {target}\n"
            ))
            .expect("parse")
            .stealth
            .to_runtime_config(&FingerprintRotationConfig::default())
            .map_err(|error| panic!("boundary target {target} must be accepted: {error}"))
            .ok();
        }
    }

    /// A target set alongside any other strategy is a contradiction, not a harmless leftover.
    #[test]
    fn a_normalize_target_with_another_strategy_is_rejected() {
        let error = EngineConfig::from_toml(
            "[stealth]\nmode = \"stealth\"\npadding_strategy = \"adaptive\"\nnormalize_target_size = 1350\n",
        )
        .expect("parse")
        .stealth
        .to_runtime_config(&FingerprintRotationConfig::default())
        .err()
        .expect("a target without the normalize strategy must fail");
        assert!(
            error.to_string().contains("only valid with padding_strategy=fixed-cell"),
            "silently ignoring the target is how a configuration claims stealth it lacks: {error}"
        );

        // Other strategies without a target remain unaffected.
        EngineConfig::from_toml("[stealth]\nmode = \"stealth\"\npadding_strategy = \"adaptive\"\n")
            .expect("parse")
            .stealth
            .to_runtime_config(&FingerprintRotationConfig::default())
            .map_err(|error| panic!("an ordinary strategy must still work: {error}"))
            .ok();
    }

    #[test]
    fn transport_rejects_empty_or_duplicate_quic_versions() {
        let mut transport = TransportConfig::default();
        transport.quic_versions.clear();
        assert!(transport.validate().is_err());
        transport.quic_versions = vec![QuicVersion::V2, QuicVersion::V2];
        assert!(transport.validate().is_err());
    }

    #[test]
    fn transport_cc_config_roundtrips_canonical_algorithms(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, algorithm) in [
            ("reno", CcAlgorithm::Reno),
            ("cubic", CcAlgorithm::Cubic),
            ("bbr2", CcAlgorithm::Bbr2),
            ("bbr3", CcAlgorithm::Bbr3),
        ] {
            let source = format!("[transport]\ncc_algorithm = \"{name}\"\n");
            let config = EngineConfig::from_toml(&source)?;
            assert_eq!(config.transport.cc_algorithm, algorithm);

            let encoded = toml::to_string(&config)?;
            let decoded = EngineConfig::from_toml(&encoded)?;
            assert_eq!(decoded.transport.cc_algorithm, algorithm);
        }
        Ok(())
    }

    #[test]
    fn test_builder() {
        let config = EngineConfig::builder()
            .mode(EngineMode::Server)
            .remote("0.0.0.0:4433")
            .stealth_mode(StealthMode::StealthMax)
            .build()
            .unwrap();

        assert_eq!(config.engine.mode, EngineMode::Server);
        assert_eq!(config.stealth.mode, StealthMode::StealthMax);
    }

    #[test]
    fn test_nat_traversal_defaults_to_disabled_path_discovery() {
        let config = EngineConfig::default();
        assert!(!config.nat_traversal.enabled);
        assert_eq!(config.nat_traversal.mode, qf_transport_nat::NatTraversalMode::Off);
        assert!(config.nat_traversal.stun_servers.is_empty());
        assert!(config.nat_traversal.turn_servers.is_empty());
    }

    #[test]
    fn test_nat_traversal_toml_maps_to_transport_config() {
        let toml = r#"
[connection]
remote = "127.0.0.1:4433"

[nat_traversal]
enabled = true
mode = "connectivity-fallback"
stun_servers = ["203.0.113.1:3478"]
turn_servers = ["203.0.113.2:3478"]
ice_enabled = true
probe_interval_ms = 30000
max_candidates = 4
"#;
        let config = EngineConfig::from_toml(toml).unwrap();
        config.validate().unwrap();
        let transport_nat = config.nat_traversal.to_transport_config().unwrap();
        assert!(transport_nat.enabled);
        assert_eq!(transport_nat.mode, qf_transport_nat::NatTraversalMode::ConnectivityFallback);
        assert!(transport_nat.ice_enabled);
        assert_eq!(transport_nat.max_candidates, 4);
        assert_eq!(transport_nat.stun_servers.len(), 1);
        assert_eq!(transport_nat.turn_servers.len(), 1);
    }

    #[test]
    fn test_nat_traversal_rejects_enabled_mode_when_disabled() {
        let toml = r#"
[connection]
remote = "127.0.0.1:4433"

[nat_traversal]
enabled = false
mode = "roaming"
"#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_empty_remote() {
        let mut config = EngineConfig::default();
        config.connection.remote = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn migration_policy_toml_roundtrip_and_bounds() {
        let mut config = EngineConfig::default();
        config.connection.migration_cwnd_reduction_factor = 0.25;
        config.connection.migration_cooldown_ms = 0;
        config.connection.migration_probe_target =
            qf_transport_recovery::MigrationProbeTarget::ReducedWindow;
        config.validate().unwrap();

        let encoded = toml::to_string(&config).unwrap();
        let decoded = EngineConfig::from_toml(&encoded).unwrap();
        assert_eq!(decoded.connection.migration_cwnd_reduction_factor, 0.25);
        assert_eq!(decoded.connection.migration_cooldown_ms, 0);
        assert_eq!(
            decoded.connection.migration_probe_target,
            qf_transport_recovery::MigrationProbeTarget::ReducedWindow
        );

        config.connection.migration_cwnd_reduction_factor = 1.01;
        assert!(config.validate().is_err());
        config.connection.migration_cwnd_reduction_factor = 0.5;
        config.connection.migration_cooldown_ms = 60_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn logging_configuration_rejects_invalid_levels_and_file_bounds() {
        let mut config = EngineConfig::default();
        config.logging.level = "loud".to_string();
        assert!(config.validate().is_err());

        config.logging.level = "info".to_string();
        config.logging.log_to_file = true;
        config.logging.log_file_path.clear();
        assert!(config.validate().is_err());

        config.logging.log_file_path = "runtime.log".to_string();
        config.logging.max_file_size_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_configuration_enforces_shared_audit_option_bounds() {
        use qf_audit::{
            MAX_AUDIT_FLUSH_TIMEOUT_MS, MAX_AUDIT_QUEUE_CAPACITY, MAX_AUDIT_SEGMENTS,
            MAX_AUDIT_SEGMENT_BYTES,
        };

        let mut config = EngineConfig::default();
        config.audit.queue_capacity = 0;
        assert!(config.validate().is_err());

        config.audit.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY;
        assert!(config.validate().is_ok());
        config.audit.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY + 1;
        assert!(config.validate().is_err());

        config.audit.queue_capacity = 1;
        config.audit.max_segment_bytes = 0;
        assert!(config.validate().is_err());

        config.audit.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES;
        assert!(config.validate().is_ok());
        config.audit.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES + 1;
        assert!(config.validate().is_err());

        config.audit.max_segment_bytes = 1;
        config.audit.max_segments = 0;
        assert!(config.validate().is_err());

        config.audit.max_segments = MAX_AUDIT_SEGMENTS;
        assert!(config.validate().is_ok());
        config.audit.max_segments = MAX_AUDIT_SEGMENTS + 1;
        assert!(config.validate().is_err());

        config.audit.max_segments = 1;
        config.audit.flush_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.audit.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS;
        assert!(config.validate().is_ok());
        config.audit.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn no_log_mode_removes_every_external_sink_and_filter() {
        let config = LoggingConfig {
            mode: LoggingMode::NoLog,
            log_to_file: true,
            file_path: Some(PathBuf::from("runtime.log")),
            log_to_stdout: true,
            syslog_addr: Some("127.0.0.1:514".parse().unwrap()),
            ..Default::default()
        };
        let effective = config.effective();
        assert_eq!(effective.level, "off");
        assert!(!effective.log_to_file);
        assert!(effective.file_path.is_none());
        assert!(!effective.log_to_stdout);
        assert!(effective.syslog_addr.is_none());
    }

    #[test]
    fn test_crypto_force_aead_rejects_internal_width_backends() {
        for force in ["aegis-128x4", "aegis128x4", "aegis-128x8", "aegis128x8"] {
            let mut config = EngineConfig::default();
            config.crypto.force_aead = force.to_string();
            assert!(config.validate().is_err(), "{force} must stay internal-only");
        }
    }

    #[test]
    fn private_packet_policy_roundtrips_as_typed_config_and_validates() {
        let config = EngineConfig::from_toml(
            "[crypto]\npacket_protection_mode = \"advanced-required\"\naead_preference = \"aegis\"\n",
        )
        .expect("private packet policy parses");
        assert_eq!(config.crypto.packet_protection_mode, PacketProtectionMode::AdvancedRequired);
        assert_eq!(config.crypto.aead_preference, AeadPreference::Aegis128L);
        assert_eq!(
            config.crypto.aead_preference.private_family(),
            Some(PrivateAeadFamily::Aegis128L)
        );
        config.validate().expect("typed private policy is semantically valid");

        let encoded = toml::to_string(&config).expect("private packet policy serializes");
        let decoded = EngineConfig::from_toml(&encoded).expect("private packet policy roundtrips");
        assert_eq!(decoded.crypto.packet_protection_mode, PacketProtectionMode::AdvancedRequired);
        assert_eq!(decoded.crypto.aead_preference, AeadPreference::Aegis128L);
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
            [engine]
            mode = "client"

            [connection]
            remote = "127.0.0.1:4433"
        "#;

        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.connection.remote, "127.0.0.1:4433");
    }

    #[test]
    fn circuit_allows_an_explicit_local_bind_but_rejects_legacy_peer_fields() {
        let hop = crate::HopConfig {
            label: "Entry".to_string(),
            endpoint: "relay.example.com:4433".to_string(),
            sni: "relay.example.com".to_string(),
            qkey_id: "000000000001".to_string(),
            qkey_token_ref: "env:QUICFUSCATE_HOP_1_QKEY".to_string(),
            ..crate::HopConfig::default()
        };
        let mut config = EngineConfig {
            circuit: Some(CircuitConfig { hops: vec![hop], ..CircuitConfig::default() }),
            ..EngineConfig::default()
        };
        config.connection.local = "[::]:0".to_string();
        config.validate().expect("the physical entry still needs an operator-selected local bind");

        config.connection.remote = "198.51.100.7:4433".to_string();
        let error =
            config.validate().expect_err("legacy peer fields make circuit ownership ambiguous");
        assert!(error.to_string().contains("legacy connection endpoint"));
    }

    #[test]
    fn alternate_circuit_requires_distinct_parallel_bounded_routes() {
        let make_hop = |endpoint: &str, qkey_id: &str| crate::HopConfig {
            label: endpoint.to_string(),
            endpoint: endpoint.to_string(),
            sni: "relay.example.com".to_string(),
            qkey_id: qkey_id.to_string(),
            qkey_token_ref: format!("env:QKEY_{qkey_id}"),
            ..crate::HopConfig::default()
        };
        let primary = CircuitConfig {
            hops: vec![make_hop("primary.example.com:4433", "000000000001")],
            ..CircuitConfig::default()
        };
        let alternate = CircuitConfig {
            hops: vec![make_hop("alternate.example.com:4433", "000000000002")],
            ..CircuitConfig::default()
        };
        let mut config = EngineConfig {
            circuit: Some(primary),
            alternate_circuit: Some(alternate),
            ..EngineConfig::default()
        };
        config.validate().expect("distinct alternate circuit");

        config.alternate_circuit.as_mut().unwrap().hops[0].endpoint =
            "PRIMARY.EXAMPLE.COM.:4433".to_string();
        assert!(config.validate().expect_err("endpoint reuse").to_string().contains("endpoint"));

        config.alternate_circuit.as_mut().unwrap().hops[0].endpoint =
            "alternate.example.com:4433".to_string();
        config.alternate_circuit.as_mut().unwrap().hops[0].qkey_token_ref =
            config.circuit.as_ref().unwrap().hops[0].qkey_token_ref.clone();
        assert!(config
            .validate()
            .expect_err("credential reference reuse")
            .to_string()
            .contains("token reference"));
    }

    #[test]
    fn server_mode_rejects_client_circuit_sections() {
        let hop = crate::HopConfig {
            label: "Exit".to_string(),
            endpoint: "exit.example.com:4433".to_string(),
            sni: "exit.example.com".to_string(),
            qkey_id: "000000000001".to_string(),
            qkey_token_ref: "env:QKEY_EXIT".to_string(),
            ..crate::HopConfig::default()
        };
        let mut config = EngineConfig {
            circuit: Some(CircuitConfig { hops: vec![hop], ..CircuitConfig::default() }),
            ..EngineConfig::default()
        };
        config.engine.mode = EngineMode::Server;
        assert!(config.validate().expect_err("server circuit").to_string().contains("client-only"));
    }

    #[test]
    fn zero_rtt_stays_off_by_default_and_server_requires_anti_replay() {
        let defaults = EngineConfig::default();
        assert!(!defaults.connection.enable_0rtt);
        assert!(!defaults.transport.enable_early_data);
        defaults.validate().expect("defaults validate");

        let mut client = EngineConfig::default();
        client.engine.mode = EngineMode::Client;
        client.connection.enable_0rtt = true;
        client.anti_replay.enabled = false;
        client.validate().expect("client early data does not host the replay register");

        let mut server = EngineConfig::default();
        server.engine.mode = EngineMode::Server;
        server.transport.enable_early_data = true;
        server.anti_replay.enabled = false;
        let message = match server.validate() {
            Err(ConfigError::Validation(message)) => message,
            other => panic!("server 0-RTT without replay protection must fail: {other:?}"),
        };
        assert!(message.contains("server 0-RTT requires anti_replay.enabled = true"));

        server.anti_replay = AntiReplaySection::default();
        server.validate().expect("server early data with anti-replay validates");
    }

    #[test]
    fn canonical_engine_document_validates_and_roundtrips_all_sections() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/quicfuscate.toml");
        let config = EngineConfig::from_file(path).expect("canonical engine config parses");
        config.validate().expect("canonical engine config validates");
        assert_eq!(config.transport.traffic_analysis.chaff_size_bytes, 1280);
        assert_eq!(config.fec.window_poor, 50);
        assert_eq!(config.optimization.memory_pool_size, 67_108_864);
        assert!(config.telemetry.enabled);
        assert_eq!(config.audit.max_segments, 8);
        assert_eq!(config.security.memory_lock_failure_policy, MemoryLockFailurePolicy::BestEffort);

        let encoded = toml::to_string(&config).expect("canonical engine config serializes");
        let decoded = EngineConfig::from_toml(&encoded).expect("serialized engine config parses");
        decoded.validate().expect("serialized engine config validates");
        assert_eq!(decoded.transport.quic_versions, config.transport.quic_versions);
        assert_eq!(decoded.transport.cc_algorithm, config.transport.cc_algorithm);
        assert_eq!(decoded.transport.traffic_analysis, config.transport.traffic_analysis);
        assert_eq!(
            decoded.transport.qkey_traffic_analysis_ceiling,
            config.transport.qkey_traffic_analysis_ceiling
        );
        assert_eq!(
            decoded.transport.intelligent_traffic_analysis_ceiling,
            config.transport.intelligent_traffic_analysis_ceiling
        );
        assert_eq!(decoded.fec.window_poor, config.fec.window_poor);
        assert_eq!(decoded.security.kill_switch, config.security.kill_switch);
        assert_eq!(
            decoded.security.memory_lock_failure_policy,
            config.security.memory_lock_failure_policy
        );
        assert_eq!(decoded.security.firewall.backend, config.security.firewall.backend);
    }

    #[test]
    fn canonical_circuit_example_validates_as_the_shared_operator_schema() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/circuit-client.example.toml");
        let config = EngineConfig::from_file(path).expect("canonical circuit example parses");
        config.validate().expect("canonical circuit example validates");

        let circuit = config.circuit.as_ref().expect("canonical circuit section");
        assert_eq!(circuit.hops.len(), 3);
        assert_eq!(circuit.max_hops, 3);
        assert_eq!(circuit.max_parallel_circuits, 2);
        assert!(!circuit.allow_single_hop_fallback);
        assert_eq!(circuit.hops.last().map(|hop| hop.role), Some(crate::HopRole::Exit));
        assert!(config.alternate_circuit.is_none());
    }

    #[test]
    fn strict_engine_schema_rejects_unknown_keys_in_every_section() {
        let sections = [
            "engine",
            "connection",
            "circuit",
            "circuit.diversity",
            "alternate_circuit",
            "alternate_circuit.diversity",
            "transport",
            "transport.traffic_analysis",
            "transport.qkey_traffic_analysis_ceiling",
            "transport.intelligent_traffic_analysis_ceiling",
            "nat_traversal",
            "crypto",
            "interface",
            "telemetry",
            "logging",
            "audit",
            "fec",
            "stealth",
            "fingerprint_rotation",
            "optimization",
            "anti_replay",
            "security",
            "security.firewall",
        ];
        for section in sections {
            let source = format!("[{section}]\nunknown_audit_fixture = true\n");
            let error = EngineConfig::from_toml(&source)
                .expect_err("unknown section keys must not be silently dropped");
            assert!(
                error.to_string().contains("unknown_audit_fixture"),
                "unknown key was not reported for [{section}]: {error}"
            );
        }

        let error = EngineConfig::from_toml("top_level_unknown_audit_fixture = true\n")
            .expect_err("unknown top-level keys must not be silently dropped");
        assert!(error.to_string().contains("top_level_unknown_audit_fixture"));
    }

    #[test]
    fn validation_rejects_invalid_typed_strings_ranges_and_compatibility_values() {
        for source in [
            "[engine]\nmode = \"invalid\"\n",
            "[transport]\ncc_algorithm = \"invalid\"\n",
            "[fingerprint_rotation]\nmode = \"invalid\"\n",
        ] {
            assert!(EngineConfig::from_toml(source).is_err(), "invalid enum accepted: {source}");
        }

        let mut config = EngineConfig::default();
        // `padding_strategy` is inert under `dynamic` (TODO-1059) - validate
        // the legacy spelling on an explicit stealth mode.
        config.stealth.mode = StealthMode::Stealth;
        config.stealth.padding_strategy = "invalid".to_string();
        assert!(config.validate().is_err());
        config.stealth.padding_strategy = "adaptive".to_string();
        config.stealth.initial_browser = "invalid".to_string();
        assert!(config.validate().is_err());
        config.stealth.initial_browser = "chrome".to_string();
        config.fingerprint_rotation.profile_slots = vec!["chrome@invalid".to_string()];
        assert!(config.validate().is_err());

        config.fingerprint_rotation.profile_slots = vec!["chrome:windows".to_string()];
        assert!(config.validate().is_err(), "the legacy ':' slot grammar must be rejected");

        config.fingerprint_rotation.profile_slots = vec!["safari@windows".to_string()];
        assert!(config.validate().is_err(), "unsupported browser/OS pairs must be rejected");

        config.fingerprint_rotation.profile_slots =
            FingerprintRotationConfig::default().profile_slots.clone();
        config.stealth.initial_browser = "safari".to_string();
        config.stealth.initial_os = "windows".to_string();
        assert!(
            config.validate().is_err(),
            "unsupported initial browser/OS pairs must be rejected"
        );
        config.stealth.initial_browser = "chrome".to_string();

        config.fingerprint_rotation.profile_slots =
            FingerprintRotationConfig::default().profile_slots;
        config.transport.max_udp_payload = 1199;
        assert!(config.validate().is_err());
        config.transport.max_udp_payload = 1500;
        config.fec.stream_every = 0;
        assert!(config.validate().is_err());
        config.fec.stream_every = 5;
        config.optimization.memory_pool_alignment = 0;
        assert!(config.validate().is_err());
        config.optimization.memory_pool_alignment = 64;
        config.anti_replay.max_entries = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn fingerprint_rotation_projection_preserves_slots_and_mode_semantics() {
        let mut config = EngineConfig::default();
        config.fingerprint_rotation.enabled = true;
        config.fingerprint_rotation.interval_secs = 17;
        config.fingerprint_rotation.mode = RotationMode::Slots;
        config.fingerprint_rotation.profile_slots =
            vec!["firefox@linux".to_string(), "safari@macos".to_string()];
        config.validate().expect("slot rotation configuration validates");
        let runtime = config
            .stealth
            .to_runtime_config(&config.fingerprint_rotation)
            .expect("slot rotation projects into runtime");
        assert!(runtime.enable_fingerprint_rotation);
        assert_eq!(runtime.fingerprint_rotation_interval, 17);
        assert_eq!(runtime.fingerprint_rotation_mode, qf_stealth::RotationMode::Slots);
        assert_eq!(
            runtime.fingerprint_rotation_profiles,
            vec![
                (qf_stealth::BrowserProfile::Firefox, qf_stealth::OsProfile::Linux),
                (qf_stealth::BrowserProfile::Safari, qf_stealth::OsProfile::MacOS),
            ]
        );
        assert_eq!(runtime.rotation_profile_slots(), runtime.fingerprint_rotation_profiles);

        let mut fixed = config.fingerprint_rotation.clone();
        fixed.mode = RotationMode::Fixed;
        let fixed_runtime = config
            .stealth
            .to_runtime_config(&fixed)
            .expect("fixed rotation configuration projects");
        assert!(fixed_runtime.rotation_profile_slots().is_empty());

        let mut all = config.fingerprint_rotation.clone();
        all.mode = RotationMode::All;
        all.profile_slots.clear();
        let all_runtime =
            config.stealth.to_runtime_config(&all).expect("all rotation configuration projects");
        assert!(!all_runtime.rotation_profile_slots().is_empty());

        config.stealth.initial_os = "macos".to_string();
        config.fingerprint_rotation.profile_slots = vec!["safari".to_string()];
        config.fingerprint_rotation.mode = RotationMode::Slots;
        config.validate().expect("browser-only slots inherit the initial OS");
        let inherited_runtime = config
            .stealth
            .to_runtime_config(&config.fingerprint_rotation)
            .expect("browser-only slot projects with the initial OS");
        assert_eq!(
            inherited_runtime.rotation_profile_slots(),
            vec![(qf_stealth::BrowserProfile::Safari, qf_stealth::OsProfile::MacOS)]
        );

        let mut empty_slots = config.fingerprint_rotation.clone();
        empty_slots.profile_slots.clear();
        empty_slots.mode = RotationMode::Slots;
        assert!(empty_slots.validate().is_err());
    }

    #[test]
    fn test_validation_fails_partial_tun_addressing() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_mixed_tun_address_family() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = Some("ffff:ffff:ffff:ffff::".parse().unwrap());
        assert!(config.validate().is_err());
    }

    #[test]
    fn client_tunnel_addresses_project_ipv4_ipv6_and_roundtrip() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("IPv4 address"));
        config.interface.tun_netmask = Some("255.255.255.0".parse().expect("IPv4 netmask"));
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        config.interface.tun_prefix6 = Some(64);

        let addresses =
            config.interface.client_tunnel_addresses().expect("dual-stack address model");
        assert_eq!(
            addresses.ipv4,
            Some(ClientTunnelIpv4 {
                address: "10.20.30.40".parse().expect("IPv4 address"),
                prefix: 24,
            })
        );
        assert_eq!(
            addresses.ipv6,
            Some(ClientTunnelIpv6 {
                address: "fd00::42".parse().expect("IPv6 address"),
                prefix: 64,
            })
        );

        let encoded = toml::to_string(&config).expect("serialize dual-stack config");
        let decoded = EngineConfig::from_toml(&encoded).expect("parse dual-stack config");
        assert_eq!(decoded.interface.tun_ip6, config.interface.tun_ip6);
        assert_eq!(decoded.interface.tun_prefix6, config.interface.tun_prefix6);
        decoded.validate().expect("round-tripped dual-stack config validates");
    }

    #[test]
    fn client_tunnel_addresses_accept_legacy_ipv6_single_family() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("IPv6 address"));
        config.interface.tun_netmask = Some("ffff:ffff:ffff:ffff::".parse().expect("IPv6 netmask"));

        let addresses =
            config.interface.client_tunnel_addresses().expect("legacy IPv6 address model");
        assert_eq!(addresses.ipv4, None);
        assert_eq!(
            addresses.ipv6,
            Some(ClientTunnelIpv6 {
                address: "2001:db8:42::2".parse().expect("IPv6 address"),
                prefix: 64,
            })
        );
    }

    #[test]
    fn client_tunnel_addresses_reject_non_contiguous_legacy_netmasks() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("IPv4 address"));
        config.interface.tun_netmask = Some("255.0.255.0".parse().expect("IPv4 netmask"));
        assert!(config
            .interface
            .client_tunnel_addresses()
            .expect_err("non-contiguous IPv4 netmask must fail")
            .to_string()
            .contains("contiguous IPv4"));

        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("IPv6 address"));
        config.interface.tun_netmask = Some("ffff:ffff:ffff:fffd::".parse().expect("IPv6 netmask"));
        assert!(config
            .interface
            .client_tunnel_addresses()
            .expect_err("non-contiguous IPv6 netmask must fail")
            .to_string()
            .contains("contiguous IPv6"));
    }

    #[test]
    fn validation_rejects_partial_canonical_ipv6_addressing() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        assert!(config.validate().is_err());

        config.interface.tun_ip6 = None;
        config.interface.tun_prefix6 = Some(64);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_canonical_ipv6_prefix_and_mtu() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        config.interface.tun_prefix6 = Some(129);
        assert!(config.validate().is_err());

        config.interface.tun_prefix6 = Some(64);
        config.interface.tun_mtu = 1279;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_two_ipv6_address_sources() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("legacy IPv6 address"));
        config.interface.tun_netmask =
            Some("ffff:ffff:ffff:ffff::".parse().expect("legacy IPv6 netmask"));
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("canonical IPv6 address"));
        config.interface.tun_prefix6 = Some(64);

        let error = config.validate().expect_err("duplicate IPv6 source must fail closed");
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn test_firewall_config_default_is_auto_detect() {
        let config = EngineConfig::default();
        assert!(config.security.firewall.backend.is_none());
    }

    #[test]
    fn test_firewall_config_explicit_nftables() {
        let toml = r#"
            [security.firewall]
            backend = "nftables"
        "#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(config.security.firewall.backend, Some(qf_firewall::FirewallBackend::Nftables));
    }

    #[test]
    fn test_firewall_config_explicit_iptables() {
        let toml = r#"
            [security.firewall]
            backend = "iptables"
        "#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(config.security.firewall.backend, Some(qf_firewall::FirewallBackend::Iptables));
    }
}

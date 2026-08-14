// Portions derived from Quinn (https://github.com/quinn-rs/quinn)
// Original code licensed under MIT/Apache-2.0
// Modifications: Copyright (c) QuicFuscate Team, MIT License

// # Core Forked Connection Runtime
//
// This module provides the central `QuicFuscateConnection` struct for the
// forked QuicFuscate runtime. It orchestrates crypto, FEC, transport, and
// stealth ownership for the canonical connection lifecycle used by this fork.

mod h3_runtime;
mod private_packet_protection;
mod request_headers;
mod send;
#[cfg(test)]
mod tests;
mod types;

#[cfg(feature = "orchestrator")]
use crate::brain::DeepIntegrationOrchestrator;
use crate::brain::{CombinedObserver, StealthBrain};
use crate::crypto::CryptoManager;
use crate::fec::wire::{self, WireFecReceiver, WirePacketMeta, WireProfile};
use crate::fec::{AdaptiveFec, FecConfig, FecPacket, FecTransportObserver};
use crate::optimize::{AlignedBox, MemoryPool, OptimizationManager, OptimizeConfig, PooledBlock};
use crate::stealth::{
    IcmpUnreachablePolicy, NormalizeResult, OsFingerprintProfile, PacketNormalizer, StealthConfig,
    StealthManager, StealthMode, StealthRuntimeOwner,
};
#[cfg(test)]
use qf_cpu::transport::{self as transport_accel, CongestionSample};
use std::sync::Arc;
#[cfg(feature = "orchestrator")]
use std::sync::OnceLock;
// unused on current code path; keep import minimal
use crate::telemetry;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[cfg(feature = "orchestrator")]
static ORCHESTRATOR: OnceLock<Arc<DeepIntegrationOrchestrator>> = OnceLock::new();
use std::net::SocketAddr;
#[cfg(test)]
use types::MAX_H3_TUNNEL_PENDING_LEN;
pub use types::{ConnectionParams, MasqueRelayHandler, PendingMasqueFlow};
use types::{
    H3TunnelFrameDecoder, Http3PollBindings, MasqueDispatchContext, MasqueFlowBinding,
    OutboundPacer, OutgoingFecPacket, H3_TUNNEL_FRAME_HEADER_LEN, H3_TUNNEL_FRAME_MAGIC,
    IPV6_MINIMUM_LINK_MTU, MAX_BOUND_MASQUE_FLOWS, MAX_INNER_IP_PACKET_LEN,
};

// Type aliases to simplify handler types
pub use qf_fec::ActiveFecPolicyChange;
pub use qf_transport_cc::ConnectionStats;
pub use qf_transport_types::MasqueRelayResponseQueue;
pub use qf_transport_types::{CapsuleHandler, DatagramHandler};
pub use qf_transport_types::{MasqueDownlinkQueue, MasqueDownlinkQueueReject};
pub use qf_transport_types::{MasqueFlowPurpose, MasqueUdpTarget};

/// Private packet-protection control messages are delivered on a dedicated callback so the
/// existing assignment and MASQUE control consumers remain independent.
pub type PrivatePacketProtectionHandler = Arc<std::sync::Mutex<Box<dyn FnMut(&[u8]) + Send>>>;

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    /// Monotonic clock shared by every protocol-facing child owner.
    clock: crate::time_source::ProtocolClock,
    /// Underlying QUIC transport connection handle.
    pub conn: Box<crate::transport::Connection>,
    /// Current peer address (may change on migration).
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,
    qkey_auth_token_hex: Option<qf_engine_types::QKeyToken>,
    /// Secret-free QKey transcript binding set only after the authenticated control gate passes.
    authenticated_qkey_transcript_hash: Option<[u8; 32]>,
    /// Client-selected generation echoed by the server assignment capsule.
    client_connection_generation: Option<u64>,
    circuit_id: Option<[u8; 16]>,
    circuit_hop_budget: Option<u8>,

    // Core Modules
    fec: AdaptiveFec,

    // Stealth & Optimization Modules
    stealth_manager: Arc<StealthManager>,
    optimization_manager: Arc<OptimizationManager>,
    tunnel_ingress_normalizer: PacketNormalizer,

    // State
    stats: ConnectionStats,
    packet_id_counter: u64,
    // Each queued packet retains the wire contract selected when it was encoded.
    // Mode transitions can occur before the queue drains, so framing cannot be
    // derived at dequeue time.
    outgoing_fec_packets: VecDeque<OutgoingFecPacket>,
    // Reused FEC emission scratch to avoid allocating a Vec for every packet on the send path.
    fec_send_scratch: Vec<FecPacket>,
    // Reused FEC recovery scratch to avoid allocating a Vec for every packet on the receive path.
    fec_receive_scratch: Vec<FecPacket>,
    fec_wire_receiver: WireFecReceiver,
    fec_tx_seed: Option<u64>,
    fec_rx_seed: Option<u64>,
    fec_tx_profile: Option<WireProfile>,
    fec_tx_epoch: u32,
    fec_tx_sequence: u64,
    fec_tx_active: bool,
    h3_conn: Option<crate::transport::h3::Connection>,
    /// Reusable pooled buffer for HTTP/3 body reads. The default pool block is 64 KiB.
    h3_body_buffer: Option<AlignedBox<[u8]>>,
    h3_tunnel_rx: HashMap<u64, H3TunnelFrameDecoder>,
    h3_tunnel_tx_frame: Vec<u8>,
    h3_peer_tunnel_stream_id: Option<u64>,
    h3_tunnel_response_started: HashSet<u64>,
    h3_tunnel_uplink_fallback_reported: bool,
    h3_tunnel_downlink_fallback_reported: bool,
    last_telemetry: std::time::Instant,
    // Observer for transport telemetry -> FEC/ACK policy coupling.
    transport_observer: Arc<FecTransportObserver>,
    masque_cb: Option<CapsuleHandler>,
    masque_datagram_cb: Option<DatagramHandler>,
    masque_downlink_queue: Option<Arc<std::sync::Mutex<MasqueDownlinkQueue>>>,
    masque_downlink_retry: Option<Vec<u8>>,
    masque_control_cb: Option<CapsuleHandler>,
    masque_relay_cb: Option<MasqueRelayHandler>,
    private_packet_protection_cb: Option<PrivatePacketProtectionHandler>,
    private_packet_protection_runtime:
        Option<Arc<std::sync::Mutex<private_packet_protection::PrivatePacketProtectionRuntime>>>,
    private_packet_protection_mode: qf_crypto::PacketProtectionMode,
    private_packet_protection_family: Option<qf_crypto::PrivateAeadFamily>,
    masque_relay_response_queue: Option<Arc<std::sync::Mutex<MasqueRelayResponseQueue>>>,
    /// Locally-initiated MASQUE CONNECT-UDP stream id (client side).
    masque_stream_id: Option<u64>,
    /// Purpose-bound local and peer MASQUE flows keyed by quarter stream id.
    masque_local_flows: HashMap<u64, MasqueFlowBinding>,
    masque_peer_flows: HashMap<u64, MasqueFlowBinding>,
    #[cfg(feature = "orchestrator")]
    runtime_cpu_percent: u32,
    #[cfg(feature = "orchestrator")]
    runtime_memory_pressure: u32,
    #[cfg(feature = "orchestrator")]
    runtime_system: sysinfo::System,
    tls_ch_override_template: Option<String>,

    // Async Stealth Scheduler State
    next_packet_release: Option<std::time::Instant>,
    outbound_pacer: OutboundPacer,
}

impl Drop for QuicFuscateConnection {
    fn drop(&mut self) {
        if let Some(buffer) = self.h3_body_buffer.take() {
            self.optimization_manager.free_block(buffer);
        }
    }
}

impl QuicFuscateConnection {
    /// Returns the clock shared by protocol-facing connection state.
    pub fn protocol_clock(&self) -> crate::time_source::ProtocolClock {
        self.clock.clone()
    }

    /// Record the secret-free QKey transcript binding only after the authenticated QKey gate has
    /// succeeded. This does not activate private packet protection by itself.
    pub fn set_authenticated_qkey_transcript_hash(&mut self, hash: [u8; 32]) {
        if hash.iter().any(|byte| *byte != 0) {
            self.authenticated_qkey_transcript_hash = Some(hash);
        }
    }

    /// Return the authenticated QKey transcript binding without exposing credential material.
    pub fn authenticated_qkey_transcript_hash(&self) -> Option<[u8; 32]> {
        self.authenticated_qkey_transcript_hash
    }

    /// Configure the authenticated private packet-protection policy for this connection.
    /// No negotiation is started until TLS, QKey authentication, and the accepted MASQUE flow
    /// are all present.
    pub fn set_private_packet_protection_policy(
        &mut self,
        mode: qf_crypto::PacketProtectionMode,
        family: Option<qf_crypto::PrivateAeadFamily>,
    ) {
        self.private_packet_protection_mode = mode;
        self.private_packet_protection_family = family;
    }

    /// Commit the client-side QKey transcript binding after the server's authenticated
    /// assignment/control response has been accepted.
    pub fn mark_qkey_authenticated_from_token(&mut self) -> bool {
        let Some(hash) = self
            .qkey_auth_token_hex
            .as_ref()
            .and_then(qf_engine_types::QKeyToken::authenticated_transcript_hash)
        else {
            return false;
        };
        self.set_authenticated_qkey_transcript_hash(hash);
        true
    }

    #[cfg(test)]
    fn env_optional_trimmed(name: &str) -> Option<String> {
        std::env::var(name).ok().and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
    }

    /// Creates a new client connection.
    #[allow(clippy::too_many_arguments)]
    pub fn new_client(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        qkey_auth_token_hex: Option<qf_engine_types::QKeyToken>,
        qkey_initial_token: Option<Vec<u8>>,
        use_utls: bool,
    ) -> Result<Self, String> {
        Self::new_client_with_runtime(
            server_name,
            local_addr,
            remote_addr,
            config,
            stealth_config,
            fec_config,
            opt_cfg,
            qkey_auth_token_hex,
            qkey_initial_token,
            use_utls,
            None,
            None,
        )
    }

    /// Creates a new client connection attached to a runtime-owned stealth service.
    #[allow(clippy::too_many_arguments)]
    pub fn new_client_with_runtime(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        qkey_auth_token_hex: Option<qf_engine_types::QKeyToken>,
        qkey_initial_token: Option<Vec<u8>>,
        use_utls: bool,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        http_authority: Option<&str>,
    ) -> Result<Self, String> {
        Self::new_client_with_runtime_and_clock(
            server_name,
            local_addr,
            remote_addr,
            config,
            stealth_config,
            fec_config,
            opt_cfg,
            qkey_auth_token_hex,
            qkey_initial_token,
            use_utls,
            runtime_owner,
            http_authority,
            crate::time_source::ProtocolClock::default(),
        )
    }

    /// Creates a new client connection with an explicit protocol clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new_client_with_runtime_and_clock(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        qkey_auth_token_hex: Option<qf_engine_types::QKeyToken>,
        qkey_initial_token: Option<Vec<u8>>,
        use_utls: bool,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        http_authority: Option<&str>,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new_with_runtime_owner_and_clock(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
            runtime_owner,
            clock.clone(),
        ));

        if use_utls {
            stealth_manager.apply_utls_profile(&mut config);
        }

        // Each client connection should use a fresh, unpredictable SCID to avoid linkability.
        let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
        crate::transport::rand::rand_bytes(&mut scid_bytes);
        let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);

        let (sni, default_host_header) = stealth_manager.get_connection_headers(server_name);
        let host_header =
            http_authority.map(|authority| authority.to_owned()).unwrap_or(default_host_header);

        // When a QKey is provided, embed its 12-char hex ID as the QUIC Initial packet
        // token so the server can look up the QKey record during connection acceptance.
        if let Some(token_bytes) = qkey_initial_token {
            config.set_initial_token(Some(token_bytes));
        }

        let conn = crate::transport::packet::connect_with_clock(
            Some(&sni),
            scid.as_ref(),
            local_addr,
            remote_addr,
            &mut config,
            clock.clone(),
        )
        .map_err(|e| format!("Failed to create QUIC connection: {}", e))?;

        Ok(Self::new(ConnectionParams {
            clock,
            conn: Box::new(conn),
            local_addr,
            peer_addr: remote_addr,
            host_header,
            sni_host: Some(sni),
            qkey_auth_token_hex,
            stealth_manager,
            optimization_manager,
            fec_config,
            tunnel_ingress_normalizer: PacketNormalizer::new(OsFingerprintProfile::Disabled),
            private_packet_protection_mode: qf_crypto::PacketProtectionMode::Auto,
            private_packet_protection_family: None,
        }))
    }

    /// Creates a new server-side connection accepted from a remote client.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        scid: &crate::transport::ConnectionId,
        initial_key_dcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
    ) -> Result<Self, String> {
        Self::new_server_with_runtime(
            scid,
            initial_key_dcid,
            local_addr,
            remote_addr,
            config,
            stealth_config,
            fec_config,
            opt_cfg,
            None,
        )
    }

    /// Creates a new server-side connection attached to a runtime-owned stealth service.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server_with_runtime(
        scid: &crate::transport::ConnectionId,
        initial_key_dcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
    ) -> Result<Self, String> {
        Self::new_server_with_runtime_and_clock(
            scid,
            initial_key_dcid,
            local_addr,
            remote_addr,
            config,
            stealth_config,
            fec_config,
            opt_cfg,
            runtime_owner,
            crate::time_source::ProtocolClock::default(),
        )
    }

    /// Creates a new server-side connection with an explicit protocol clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server_with_runtime_and_clock(
        scid: &crate::transport::ConnectionId,
        initial_key_dcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        Self::new_server_with_runtime_and_clock_and_original(
            scid,
            initial_key_dcid,
            None,
            local_addr,
            remote_addr,
            config,
            stealth_config,
            fec_config,
            opt_cfg,
            runtime_owner,
            clock,
        )
    }

    /// Creates a server-side connection while retaining the original client DCID separately from
    /// the Retry-selected Initial key-derivation DCID.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server_with_runtime_and_clock_and_original(
        scid: &crate::transport::ConnectionId,
        initial_key_dcid: Option<&crate::transport::ConnectionId>,
        original_dcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        let tunnel_ingress_profile = if !stealth_config.enable_network_fingerprint_normalization
            || matches!(stealth_config.mode, StealthMode::Off)
        {
            OsFingerprintProfile::Disabled
        } else {
            OsFingerprintProfile::from_stealth_os(stealth_config.initial_os)
        };
        let icmp_unreachable_policy = if stealth_config.suppress_icmp_unreachable {
            IcmpUnreachablePolicy::SuppressNonPmtud
        } else {
            IcmpUnreachablePolicy::Preserve
        };
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new_with_runtime_owner_and_clock(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
            runtime_owner,
            clock.clone(),
        ));

        let conn = crate::transport::packet::accept_with_clock_and_original(
            scid.as_ref(),
            initial_key_dcid.as_ref().map(|id| id.as_ref()),
            original_dcid.as_ref().map(|id| id.as_ref()),
            local_addr,
            remote_addr,
            config,
            clock.clone(),
        )
        .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;

        Ok(Self::new(ConnectionParams {
            clock,
            conn: Box::new(conn),
            local_addr,
            peer_addr: remote_addr,
            host_header: String::new(),
            sni_host: None,
            qkey_auth_token_hex: None,
            stealth_manager,
            optimization_manager,
            fec_config,
            tunnel_ingress_normalizer: PacketNormalizer::with_icmp_unreachable_policy(
                tunnel_ingress_profile,
                icmp_unreachable_policy,
            ),
            private_packet_protection_mode: qf_crypto::PacketProtectionMode::Auto,
            private_packet_protection_family: None,
        }))
    }

    fn new(params: ConnectionParams) -> Self {
        let clock = params.clock.clone();
        let environment = params.stealth_manager.environment_snapshot();
        let obs = FecTransportObserver::new_with_snapshot(&environment);
        let fec_mem_pool = params.optimization_manager.memory_pool().clone();
        let h3_body_buffer = params.optimization_manager.alloc_block();
        let mut s = Self {
            clock: clock.clone(),
            conn: params.conn,
            peer_addr: params.peer_addr,
            local_addr: params.local_addr,
            host_header: params.host_header,
            qkey_auth_token_hex: params.qkey_auth_token_hex,
            authenticated_qkey_transcript_hash: None,
            client_connection_generation: None,
            circuit_id: None,
            circuit_hop_budget: None,
            fec: qf_fec::AdaptiveFec::new_with_snapshot_and_pool(
                params.fec_config,
                &environment,
                crate::optimize::global_pool(),
            ),
            stealth_manager: params.stealth_manager,
            optimization_manager: params.optimization_manager,
            tunnel_ingress_normalizer: params.tunnel_ingress_normalizer,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            fec_send_scratch: Vec::with_capacity(1),
            fec_receive_scratch: Vec::with_capacity(1),
            fec_wire_receiver: WireFecReceiver::new(fec_mem_pool),
            fec_tx_seed: None,
            fec_rx_seed: None,
            fec_tx_profile: None,
            fec_tx_epoch: 0,
            fec_tx_sequence: 0,
            fec_tx_active: false,
            h3_conn: None,
            h3_body_buffer: Some(h3_body_buffer),
            h3_tunnel_rx: HashMap::new(),
            h3_tunnel_tx_frame: Vec::new(),
            h3_peer_tunnel_stream_id: None,
            h3_tunnel_response_started: HashSet::new(),
            h3_tunnel_uplink_fallback_reported: false,
            h3_tunnel_downlink_fallback_reported: false,
            last_telemetry: clock.now(),
            transport_observer: obs.clone(),
            masque_cb: None,
            masque_datagram_cb: None,
            masque_downlink_queue: None,
            masque_downlink_retry: None,
            masque_control_cb: None,
            masque_relay_cb: None,
            private_packet_protection_cb: None,
            private_packet_protection_runtime: None,
            private_packet_protection_mode: params.private_packet_protection_mode,
            private_packet_protection_family: params.private_packet_protection_family,
            masque_relay_response_queue: None,
            masque_stream_id: None,
            masque_local_flows: HashMap::new(),
            masque_peer_flows: HashMap::new(),
            #[cfg(feature = "orchestrator")]
            runtime_cpu_percent: 0,
            #[cfg(feature = "orchestrator")]
            runtime_memory_pressure: 0,
            #[cfg(feature = "orchestrator")]
            runtime_system: sysinfo::System::new(),
            tls_ch_override_template: environment.first(["QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE"]),
            next_packet_release: None,
            outbound_pacer: OutboundPacer::default(),
        };
        s.fec.enable_simd_acceleration();
        s.conn.set_intelligent_stealth_runtime(s.stealth_manager.is_intelligent_runtime());
        s.conn.set_brain_runtime_permissions(s.stealth_manager.brain_runtime_permissions());
        // Attach observers to transport for live telemetry callbacks
        // Combine FEC observer with StealthBrain when enabled (default on, disable via QUICFUSCATE_BRAIN=0|false)
        let obs_dyn: Arc<dyn crate::transport::TransportObserver> = obs.clone();
        let brain_enabled = environment.flag("QUICFUSCATE_BRAIN", true);
        if brain_enabled {
            let brain = StealthBrain::new_with_level_hints(
                crate::brain::StealthBrainConfig::from_env_with_snapshot(&environment),
                s.stealth_manager.intelligent_level_hints(),
            );
            obs.attach_brain_hints(brain.fec_hints());
            let brain_dyn: Arc<dyn crate::transport::TransportObserver> = brain.clone();
            let combined = CombinedObserver::new(vec![obs_dyn.clone(), brain_dyn]);
            let combined_dyn: Arc<dyn crate::transport::TransportObserver> = combined.clone();
            s.conn.set_observer(Some(combined_dyn));
        } else {
            s.conn.set_observer(Some(obs_dyn));
        }

        // Enable and configure RealTLS (always on, including Performance mode)
        // Map stealth fingerprint to TLS profile and apply SNI from fronting
        s.conn.set_environment_snapshot(environment.clone());
        if let Err(e) = s.conn.enable_tls("unified") {
            warn!("Failed to enable unified TLS provider: {:?}", e);
        }
        let tls_prof = s.stealth_manager.runtime_tls_profile(params.sni_host.as_deref());
        let sni_str = tls_prof.sni.as_deref().unwrap_or(s.host_header.as_str());
        if let Err(e) = s.conn.configure_tls(&tls_prof, sni_str) {
            warn!("Failed to configure TLS profile for SNI {}: {:?}", sni_str, e);
        }

        // Initialize DeepIntegrationOrchestrator if feature enabled
        #[cfg(feature = "orchestrator")]
        {
            let orchestrator_enabled = environment.flag("QUICFUSCATE_ORCHESTRATOR", true);
            if orchestrator_enabled {
                let orchestrator = DeepIntegrationOrchestrator::new(
                    crate::brain::StealthBrainConfig::from_env_with_snapshot(&environment),
                    1024,  // pool capacity
                    65536, // block size
                );
                // Store globally for later use in HTTP/3 loop.
                if ORCHESTRATOR.set(orchestrator).is_ok() {
                    info!("DeepIntegrationOrchestrator activated for advanced coordination");
                    // Enable Server Push coordination in Intelligent mode (brain will throttle)
                    if s.stealth_manager.is_intelligent_runtime() {
                        if let Some(orch) = ORCHESTRATOR.get() {
                            orch.enable_server_push(true);
                        }
                    }
                } else {
                    debug!(
                        "DeepIntegrationOrchestrator already initialized, reusing existing instance"
                    );
                }
            }
        }

        s
    }

    #[cfg(feature = "orchestrator")]
    fn update_orchestrator_resource_signals(&mut self) {
        use sysinfo::{MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate};

        if ORCHESTRATOR.get().is_none() {
            return;
        }
        let Ok(pid) = sysinfo::get_current_pid() else {
            return;
        };
        self.runtime_system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory().without_tasks(),
        );
        self.runtime_system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        if let Some(process) = self.runtime_system.process(pid) {
            self.runtime_cpu_percent = process.cpu_usage().round().clamp(0.0, 100.0) as u32;
            let total = self.runtime_system.total_memory();
            let used = process.memory();
            self.runtime_memory_pressure = if total > 0 {
                ((used as f64 * 100.0) / total as f64).round().clamp(0.0, 100.0) as u32
            } else {
                0
            };
        }
    }

    fn ensure_masque_tunnel(
        &mut self,
        host: &str,
    ) -> Result<Option<u64>, crate::transport::h3::Error> {
        self.ensure_masque_tunnel_with_requirement(host, false)
    }

    fn ensure_masque_tunnel_with_requirement(
        &mut self,
        host: &str,
        required: bool,
    ) -> Result<Option<u64>, crate::transport::h3::Error> {
        // When TUN bridging is active (a MASQUE datagram sink is installed),
        // always use MASQUE CONNECT-IP as the tunnel transport regardless of
        // the stealth escalation state. Without this, TUN traffic would fall
        // back to H3 DATA frames (Option B) and the downlink MASQUE path would
        // be inconsistent with the uplink.
        let tun_bridging = self.masque_datagram_cb.is_some();
        if !required && !self.stealth_manager.masque_preferred_runtime() && !tun_bridging {
            return Ok(None);
        }

        if let Some(sid) = self.masque_stream_id {
            return Ok(Some(sid));
        }

        // For TUN bridging, fall back to the connection's host header as the
        // MASQUE proxy authority when the stealth manager has no explicit
        // MASQUE proxy / fronting-domain config. The proxy authority is just
        // the H3 :authority header - the server validates it against itself.
        let proxy = self.stealth_manager.masque_proxy().unwrap_or_else(|| format!("{}:443", host));

        let extra_headers = self.build_masque_request_headers();
        let Some(ref mut h3) = self.h3_conn else {
            return Ok(None);
        };

        let sid = h3.connect_ip_with_headers(&mut self.conn, &proxy, &extra_headers)?;
        info!("MASQUE CONNECT-IP opened (proxy={}, sid={})", proxy, sid);
        crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);

        match h3.enable_masque_datagram(&mut self.conn, sid) {
            Ok(flow_id) => {
                self.masque_local_flows.insert(
                    flow_id,
                    MasqueFlowBinding {
                        stream_id: sid,
                        target: None,
                        purpose: MasqueFlowPurpose::TunIp,
                        generation: self.client_connection_generation,
                        circuit_id: self.circuit_id,
                        hop_budget: self.circuit_hop_budget,
                        accepted: true,
                        control_sent: false,
                    },
                );
                debug!("MASQUE DATAGRAM enabled (flow-id={flow_id}, ctx=0)");
            }
            Err(e) => {
                warn!("MASQUE DATAGRAM enable failed: {:?}", e);
            }
        }

        self.masque_stream_id = Some(sid);
        Ok(Some(sid))
    }

    fn sync_intelligent_runtime_controls(&self, intelligent_level: u32) {
        self.stealth_manager.sync_intelligent_runtime_controls(intelligent_level);
    }

    fn sync_poll_intelligent_runtime_controls(&self, intelligent_level: u32) {
        self.sync_intelligent_runtime_controls(intelligent_level);

        if self.stealth_manager.is_intelligent_runtime() {
            #[cfg(feature = "orchestrator")]
            {
                if intelligent_level >= 1 {
                    if let Some(orchestrator) = ORCHESTRATOR.get() {
                        let stats = self.conn.stats();
                        let sent = stats.sent as u64;
                        let lost = stats.lost as u64;
                        let loss_rate_permille = lost
                            .saturating_mul(1000)
                            .checked_div(sent)
                            .map_or(0, |rate| rate.min(1000))
                            as u32;
                        let delivery_rate_bps =
                            self.conn.delivery_rate().max(self.stats.congestion_delivery_rate);
                        let stealth_active = self.stealth_manager.runtime_stealth_active();
                        orchestrator.update_runtime_signals(
                            loss_rate_permille,
                            self.runtime_cpu_percent,
                            self.runtime_memory_pressure,
                            delivery_rate_bps,
                            stealth_active,
                        );
                    }
                    if let Some(orchestrator) = ORCHESTRATOR.get() {
                        if orchestrator.should_trigger_server_push() {
                            let mut intensity = orchestrator.get_server_push_intensity();
                            if intelligent_level >= 2 {
                                intensity = intensity.max(0.9);
                            }
                            self.stealth_manager
                                .sync_orchestrator_server_push_controls(true, intensity);
                        }
                    }
                }
            }
        }
    }

    fn ensure_masque_tunnel_for_send(
        &mut self,
    ) -> Result<Option<u64>, crate::transport::h3::Error> {
        let host = self.host_header.clone();
        match self.ensure_masque_tunnel(&host) {
            Ok(sid) => Ok(sid),
            Err(e) => {
                crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Starts the locally initiated CONNECT-UDP flow without sending tunnel data.
    pub fn begin_masque_tunnel(&mut self) -> Result<u64, crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        self.ensure_masque_tunnel_for_send()?.ok_or_else(|| "MASQUE tunnel unavailable".into())
    }

    /// Starts the canonical MASQUE flow required for authenticated control exchange.
    pub fn begin_masque_control_tunnel(&mut self) -> Result<u64, crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        let host = self.host_header.clone();
        self.ensure_masque_tunnel_with_requirement(&host, true)?.ok_or_else(|| {
            crate::error::ConnectionError::Transport(
                "MASQUE control tunnel unavailable".to_string(),
            )
        })
    }

    /// Returns true only after the peer acknowledged CONNECT-UDP with a 2xx response.
    pub fn masque_tunnel_established(&self) -> bool {
        let Some(stream_id) = self.masque_stream_id else {
            return false;
        };
        self.h3_conn.as_ref().is_some_and(|h3| h3.masque_established(stream_id))
    }

    pub fn masque_stream_established(&self, stream_id: u64) -> bool {
        self.h3_conn.as_ref().is_some_and(|h3| h3.masque_established(stream_id))
    }

    /// Accepts the recorded peer CONNECT-UDP flow after application authentication.
    pub fn accept_peer_masque_tunnel(&mut self) -> Result<bool, crate::error::ConnectionError> {
        let Some(stream_id) = self
            .masque_peer_flows
            .values()
            .find(|flow| flow.purpose == MasqueFlowPurpose::TunIp)
            .map(|flow| flow.stream_id)
        else {
            return Ok(false);
        };
        self.accept_peer_masque_flow(stream_id)
    }

    fn emit_server_push_cover_burst(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &crate::stealth::StealthManager,
        stats: &crate::transport::Stats,
        intelligent_level: u32,
    ) {
        let Some((base_path, intensity)) = stealth_manager.server_push_cover_plan() else {
            return;
        };

        match h3.generate_stealth_cover_burst(&base_path) {
            Ok(ids) => {
                let sent = stats.sent as u64;
                let lost = stats.lost as u64;
                let loss_rate_permille =
                    lost.saturating_mul(1000).checked_div(sent).unwrap_or(0).min(1000) as u32;
                stealth_manager.observe_server_push_burst(
                    &base_path,
                    ids.len(),
                    intensity,
                    loss_rate_permille,
                    intelligent_level,
                );
                if !conn.is_server() {
                    if let Some((authority, path)) = stealth_manager.webtransport_cover_plan() {
                        match h3.open_webtransport_cover_session(conn, &authority, &path) {
                            Ok(sid) => {
                                debug!("WebTransport cover session opened: sid={sid}");
                            }
                            Err(e) => warn!("WebTransport cover session failed: {:?}", e),
                        }
                    }
                }
                debug!("Server Push burst emitted: {} promises", ids.len());
            }
            Err(e) => warn!("Server Push burst generation failed: {:?}", e),
        }
    }

    fn prepare_http3_poll_iteration(&self) -> (u32, crate::transport::Stats) {
        let intelligent_level = self.stealth_manager.intelligent_runtime_level();
        self.sync_poll_intelligent_runtime_controls(intelligent_level);
        let stats = self.conn.stats().clone();
        (intelligent_level, stats)
    }

    /// Processes an incoming raw buffer, parsing it into an FEC packet and handling recovery.
    /// This now avoids any serialization overhead.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, crate::error::ConnectionError> {
        self.recv_on_path(data, self.peer_addr, self.local_addr)
    }

    /// Processes an incoming raw datagram on its observed network path.
    pub fn recv_on_path(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<usize, crate::error::ConnectionError> {
        let mut block = self.optimization_manager.alloc_block();
        if data.len() > block.len() {
            // Avoid silent truncation; return a clear error and recycle the block.
            self.optimization_manager.free_block(block);
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let copy_len = data.len();
        block[..copy_len].copy_from_slice(&data[..copy_len]);
        self.recv_pooled_block_on_path(block, copy_len, from, to)
    }

    /// Processes an incoming packet that already resides in a pooled block.
    pub fn recv_pooled_block(
        &mut self,
        block: AlignedBox<[u8]>,
        len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        self.recv_pooled_block_on_path(block, len, self.peer_addr, self.local_addr)
    }

    /// Processes a pooled incoming datagram on its observed network path.
    pub fn recv_pooled_block_on_path(
        &mut self,
        block: AlignedBox<[u8]>,
        len: usize,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<usize, crate::error::ConnectionError> {
        if len > block.len() {
            self.optimization_manager.free_block(block);
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        let wire_framed = wire::is_framed(&block[..len]);
        let mut recovered_packets = std::mem::take(&mut self.fec_receive_scratch);
        let receive_report = if wire_framed {
            if self.fec_rx_seed.is_none() {
                if let Some(seed) = self.conn.fec_receive_fountain_seed() {
                    self.fec_wire_receiver.set_fountain_seed(seed);
                    self.fec_rx_seed = Some(seed);
                }
            }
            let result = if self.fec.control_policy() == crate::fec::FecControlPolicy::Off {
                self.fec_wire_receiver.receive_source_only(&block[..len], &mut recovered_packets)
            } else {
                self.fec_wire_receiver.receive(&block[..len], &mut recovered_packets)
            };
            self.optimization_manager.free_block(block);
            match result {
                Ok(report) => report,
                Err(error) => {
                    debug!("dropping malformed or unsupported FEC wire datagram: {error}");
                    self.fec_receive_scratch = recovered_packets;
                    return Ok(len);
                }
            }
        } else {
            let mem_pool = self.optimization_manager.memory_pool().clone();
            let data = match PooledBlock::from_pool_block(Arc::clone(&mem_pool), block) {
                Ok(data) => data,
                Err(block) => {
                    self.optimization_manager.free_block(block);
                    return Err(crate::error::ConnectionError::BufferTooShort);
                }
            };
            let packet = FecPacket::from_pooled_blocks(
                self.packet_id_counter,
                Some(data),
                len,
                true,
                None,
                0,
                mem_pool,
            )
            .map_err(|_| crate::error::ConnectionError::BufferTooShort)?;
            self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
            recovered_packets.clear();
            recovered_packets.push(packet);
            wire::WireReceiveReport::raw_source(len)
        };
        if self.fec.telemetry_enabled() {
            self.fec.observe_wire_receive(receive_report);
        }

        let mut terminal_receive_error = None;
        for mut packet in recovered_packets.drain(..) {
            // payload_mut_unique() returns None when the FEC decoder still
            // holds an Arc clone of the shared buffer. In that case, copy the
            // payload into a fresh pooled buffer so conn.recv() can mutate it
            // (header protection removal + AEAD decryption are in-place).
            if let Some(data) = packet.payload_mut_unique() {
                self.stealth_manager.process_incoming_packet(data, from);
                let recv_info = crate::transport::RecvInfo { from, to, ecn: None };
                if let Err(error) = self.conn.recv(data, &recv_info) {
                    if matches!(
                        error,
                        crate::error::ConnectionError::TlsError(_)
                            | crate::error::ConnectionError::TlsAlert(_)
                            | crate::error::ConnectionError::PeerCertificateUnsupported
                    ) {
                        terminal_receive_error = Some(error);
                        break;
                    }
                    debug!(
                        "transport::recv failed (possible probe) len={}: {:?}",
                        data.len(),
                        error
                    );
                    self.stealth_manager.handle_fallback(data, from);
                }
            } else if let Some(slice) = packet.payload_slice() {
                let mut buf = PooledBlock::new(self.optimization_manager.memory_pool());
                let n = slice.len().min(buf.len());
                buf[..n].copy_from_slice(&slice[..n]);
                let data = &mut buf[..n];
                self.stealth_manager.process_incoming_packet(data, from);
                let recv_info = crate::transport::RecvInfo { from, to, ecn: None };
                if let Err(error) = self.conn.recv(data, &recv_info) {
                    if matches!(
                        error,
                        crate::error::ConnectionError::TlsError(_)
                            | crate::error::ConnectionError::TlsAlert(_)
                            | crate::error::ConnectionError::PeerCertificateUnsupported
                    ) {
                        terminal_receive_error = Some(error);
                        break;
                    }
                    debug!(
                        "transport::recv failed (possible probe) len={}: {:?}",
                        data.len(),
                        error
                    );
                    self.stealth_manager.handle_fallback(data, from);
                }
            }
        }
        self.fec_receive_scratch = recovered_packets;

        if let Some(error) = terminal_receive_error {
            return Err(error);
        }

        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;

        Ok(len)
    }

    /// Shared receive-side memory pool for socket fast paths.
    pub fn recv_memory_pool(&self) -> Arc<MemoryPool> {
        self.optimization_manager.memory_pool().clone()
    }

    /// Starts validation for connection migration to a new network path.
    /// Triggers migration probing toward a new peer address.
    ///
    /// The underlying QUIC connection emits a new path candidate immediately,
    /// sends PATH_CHALLENGE probing on that candidate path, and only switches
    /// the active path after a matching PATH_RESPONSE validates it.
    pub fn migrate_connection(
        &mut self,
        new_peer: SocketAddr,
    ) -> Result<u64, crate::transport::Error> {
        // Initiate path migration using the transport API. The local address remains
        // unchanged, but a new peer address is supplied. The transport handles sending
        // the probing packets required for validation.
        self.conn
            .migrate(self.local_addr, new_peer)
            .map_err(|_| crate::transport::Error::NoViablePath)
    }

    /// Returns the Host header that should be used for HTTP requests when domain
    /// fronting is active.
    pub fn host_header(&self) -> &str {
        &self.host_header
    }

    /// Returns the stealth manager for dynamic profile updates.
    pub fn stealth_manager(&self) -> Arc<StealthManager> {
        self.stealth_manager.clone()
    }

    /// Returns the network-stack profile frozen with this connection persona.
    pub fn tunnel_ingress_profile(&self) -> OsFingerprintProfile {
        self.tunnel_ingress_normalizer.profile
    }

    fn apply_fec_transport_feedback(
        fec: &mut AdaptiveFec,
        feedback: crate::transport::connection::FecCallbackFeedback,
        transport_loss_rate: f32,
        diagnostics_enabled: bool,
    ) {
        // A send callback only establishes that a packet entered recovery. It
        // cannot establish loss or delivery, and replaying the congestion
        // controller's current smoothed rate for each send turns stale loss
        // into self-amplifying FEC pressure. ACK and loss callbacks are the
        // only admissible controller evidence.
        if feedback.acked_packets == 0 && feedback.lost_packets == 0 {
            return;
        }

        let sent_packets = feedback.sent_packets.min(usize::MAX as u64) as usize;
        let acknowledged_packets = feedback.acked_packets.min(usize::MAX as u64) as usize;
        let lost_packets = feedback.lost_packets.min(usize::MAX as u64) as usize;
        if diagnostics_enabled {
            fec.report_transport_loss_with_slow_phase_diagnostics(
                sent_packets,
                acknowledged_packets,
                lost_packets,
                transport_loss_rate,
            );
        } else {
            fec.report_transport_loss(
                sent_packets,
                acknowledged_packets,
                lost_packets,
                transport_loss_rate,
            );
        }
    }

    fn run_update_state_phase<T>(
        clock: &crate::time_source::ProtocolClock,
        diagnostics_enabled: bool,
        phase: &'static str,
        operation: impl FnOnce() -> T,
    ) -> T {
        if !diagnostics_enabled {
            return operation();
        }
        let started = clock.now();
        let result = operation();
        let elapsed = clock.elapsed_since(started);
        if elapsed >= std::time::Duration::from_millis(100) {
            info!(
                "Connection update_state slow phase: phase={phase} duration_ms={}",
                elapsed.as_millis()
            );
        }
        result
    }

    /// Update internal state, e.g., FEC mode based on statistics.
    pub fn update_state(&mut self) {
        self.update_state_inner(false);
    }

    /// Update internal state while retaining opt-in slow-subphase diagnostics.
    pub fn update_state_with_slow_phase_diagnostics(&mut self) {
        self.update_state_inner(true);
    }

    fn update_state_inner(&mut self, diagnostics_enabled: bool) {
        let clock = self.clock.clone();
        Self::run_update_state_phase(&clock, diagnostics_enabled, "transport-stats", || {
            let stats = self.conn.stats();
            let rtt_seconds =
                self.conn.path_stats().next().map(|ps| ps.rtt.as_secs_f32()).unwrap_or(0.0);
            self.stats.update_from_transport_stats(stats, rtt_seconds);
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "resource-telemetry", || {
            if clock.elapsed_since(self.last_telemetry) >= std::time::Duration::from_secs(1) {
                telemetry!(telemetry::refresh_resource_metrics_if_due());
                #[cfg(feature = "orchestrator")]
                self.update_orchestrator_resource_signals();
                self.last_telemetry = clock.now();
            }
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "path-events", || {
            while let Some(event) = self.conn.path_event_next() {
                match event {
                    crate::transport::PathEvent::New(local, peer) => {
                        info!("New path detected: {local}->{peer}");
                    }
                    crate::transport::PathEvent::Validated(local, peer) => {
                        info!("Path validated: {local}->{peer}");
                        self.peer_addr = peer;
                        self.local_addr = local;
                        telemetry!(telemetry::PATH_MIGRATIONS.inc());
                    }
                    crate::transport::PathEvent::FailedValidation(local, peer) => {
                        warn!("Path validation failed: {local}->{peer}");
                    }
                    crate::transport::PathEvent::Closed(local, peer) => {
                        info!("Path closed: {local}->{peer}");
                    }
                    crate::transport::PathEvent::ReusedSourceConnectionId(seq, old, new) => {
                        info!("CID {seq} reused from {old:?} to {new:?}");
                    }
                    crate::transport::PathEvent::PeerMigrated(old_peer, peer) => {
                        info!("Peer migrated: {old_peer}->{peer}");
                    }
                }
            }
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "masque-state", || {
            if self.masque_flow_active() {
                crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                self.masque_stream_id = None;
                self.masque_local_flows.clear();
                self.masque_peer_flows.clear();
            }
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-observer-sync", || {
            self.transport_observer.sync_runtime_hints(&mut self.conn);
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-observer-interval", || {
            let interval = self.transport_observer.compute_streaming_interval() as usize;
            if (1..=32).contains(&interval) {
                self.conn.set_fec_stream_every(interval);
            }
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-control-delta", || {
            let delta = self.conn.take_fec_control_delta();
            if let Some(every) = delta.stream_every {
                self.fec.set_stream_every(every);
            }
            if delta.force_streaming {
                self.fec.force_streaming_mode();
            }
            if let Some(ppm) = delta.redundancy_ppm {
                self.fec.set_redundancy_ppm(ppm);
            }
        });

        let (feedback, transport_loss_rate) =
            Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-feedback-read", || {
                (self.conn.take_fec_callback_feedback(), self.conn.recovery_loss_rate())
            });
        Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-feedback-apply", || {
            Self::apply_fec_transport_feedback(
                &mut self.fec,
                feedback,
                transport_loss_rate,
                diagnostics_enabled,
            );
        });
        Self::run_update_state_phase(&clock, diagnostics_enabled, "fec-rtt-hint", || {
            let rtt_ms = self.stats.rtt.max(0.0) as u32;
            self.fec.set_rtt_hint(rtt_ms);
        });

        Self::run_update_state_phase(&clock, diagnostics_enabled, "stealth-intelligence", || {
            self.stealth_manager.sync_intelligent_level();
            let level = self.stealth_manager.intelligent_runtime_level();
            if let Err(error) = self.conn.apply_intelligent_traffic_analysis_level(level) {
                warn!("Intelligent traffic-analysis policy transition failed: {error}");
            }
        });
    }

    /// Returns the current estimated RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        self.stats.rtt
    }

    /// Returns the current estimated packet loss rate in [0.0, 1.0].
    pub fn loss_rate(&self) -> f32 {
        self.stats.loss_rate
    }

    /// Return exact connection-local FEC policy, mode, and wire evidence.
    pub fn fec_telemetry_snapshot(&self) -> crate::fec::FecTelemetrySnapshot {
        self.fec.telemetry_snapshot()
    }

    /// Returns current stealth mode for this connection.
    pub fn stealth_mode(&self) -> StealthMode {
        self.stealth_manager.mode()
    }

    /// Returns the effective TLS SNI currently configured on the live transport connection.
    pub fn server_name(&self) -> Option<String> {
        self.conn.server_name().map(|name| name.to_string())
    }
}

// Portions derived from Quinn (https://github.com/quinn-rs/quinn)
// Original code licensed under MIT/Apache-2.0
// Modifications: Copyright (c) QuicFuscate Team, MIT License

// # Core Forked Connection Runtime
//
// This module provides the central `QuicFuscateConnection` struct for the
// forked QuicFuscate runtime. It orchestrates crypto, FEC, transport, and
// stealth ownership for the canonical connection lifecycle used by this fork.

use crate::accelerate::transport::{self as transport_accel, CongestionSample};
#[cfg(feature = "orchestrator")]
use crate::brain::DeepIntegrationOrchestrator;
use crate::brain::{CombinedObserver, StealthBrain};
use crate::crypto::CryptoManager;
use crate::fec::wire::{self, WireFecReceiver, WirePacketMeta, WireProfile};
use crate::fec::{AdaptiveFec, FecConfig, FecPacket, FecTransportObserver};
use crate::optimize::{AlignedBox, MemoryPool, OptimizationManager, OptimizeConfig};
use crate::stealth::{
    IcmpUnreachablePolicy, NormalizeResult, OsFingerprintProfile, PacketNormalizer, StealthConfig,
    StealthManager, StealthMode,
};
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

// Type aliases to simplify handler types
pub type CapsuleHandler = Arc<std::sync::Mutex<Box<dyn FnMut(u64, &[u8]) + Send>>>;
pub type DatagramHandler = Arc<std::sync::Mutex<Box<dyn FnMut(&[u8]) + Send>>>;

const H3_TUNNEL_FRAME_MAGIC: &[u8; 4] = b"QFT1";
const H3_TUNNEL_FRAME_HEADER_LEN: usize = 6;
const MAX_INNER_IP_PACKET_LEN: usize = u16::MAX as usize;
const MAX_H3_TUNNEL_PENDING_LEN: usize = 2 * (H3_TUNNEL_FRAME_HEADER_LEN + MAX_INNER_IP_PACKET_LEN);
const IPV6_MINIMUM_LINK_MTU: usize = 1280;

/// Bounded FIFO for server-generated MASQUE response packets.
///
/// The queue is shared with DNS resolution workers, while one dequeued packet
/// can remain owned by the connection for a retry after QUIC DATAGRAM pressure.
#[derive(Debug)]
pub struct MasqueDownlinkQueue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasqueDownlinkQueueReject {
    PacketCapacity,
    ByteCapacity,
}

impl MasqueDownlinkQueue {
    pub fn new(max_packets: usize, max_bytes: usize) -> Self {
        Self { packets: VecDeque::new(), bytes: 0, max_packets, max_bytes }
    }

    pub fn enqueue(&mut self, packet: Vec<u8>) -> Result<(), MasqueDownlinkQueueReject> {
        if self.packets.len() >= self.max_packets {
            return Err(MasqueDownlinkQueueReject::PacketCapacity);
        }
        if self.bytes.saturating_add(packet.len()) > self.max_bytes {
            return Err(MasqueDownlinkQueueReject::ByteCapacity);
        }
        self.bytes = self.bytes.saturating_add(packet.len());
        self.packets.push_back(packet);
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.len());
        Some(packet)
    }

    pub fn discard_all(&mut self) -> (usize, usize) {
        let packets = self.packets.len();
        let bytes = self.bytes;
        self.packets.clear();
        self.bytes = 0;
        (packets, bytes)
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Default)]
struct H3TunnelFrameDecoder {
    pending: Vec<u8>,
}

impl H3TunnelFrameDecoder {
    fn push<F>(&mut self, data: &[u8], mut on_packet: F) -> Result<(), &'static str>
    where
        F: FnMut(&mut [u8]),
    {
        if self.pending.len().saturating_add(data.len()) > MAX_H3_TUNNEL_PENDING_LEN {
            self.pending.clear();
            return Err("H3 tunnel frame buffer exceeded its bounded capacity");
        }
        self.pending.extend_from_slice(data);

        let mut consumed = 0usize;
        while self.pending.len().saturating_sub(consumed) >= H3_TUNNEL_FRAME_HEADER_LEN {
            let header = &self.pending[consumed..consumed + H3_TUNNEL_FRAME_HEADER_LEN];
            if &header[..H3_TUNNEL_FRAME_MAGIC.len()] != H3_TUNNEL_FRAME_MAGIC {
                self.pending.clear();
                return Err("invalid H3 tunnel frame magic");
            }
            let packet_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if packet_len == 0 {
                self.pending.clear();
                return Err("empty H3 tunnel packet");
            }
            let frame_len = H3_TUNNEL_FRAME_HEADER_LEN + packet_len;
            if self.pending.len() - consumed < frame_len {
                break;
            }
            let packet_start = consumed + H3_TUNNEL_FRAME_HEADER_LEN;
            let packet_end = consumed + frame_len;
            let packet = &mut self.pending[packet_start..packet_end];
            if !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) {
                self.pending.clear();
                return Err("H3 tunnel frame does not contain an IP packet");
            }
            on_packet(packet);
            consumed = packet_end;
        }

        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        Ok(())
    }
}

struct Http3PollBindings {
    masque_datagram_cb: Option<DatagramHandler>,
    masque_control_cb: Option<CapsuleHandler>,
    masque_cb: Option<CapsuleHandler>,
    memory_pool: Arc<crate::optimize::MemoryPool>,
}

struct OutgoingFecPacket {
    packet: FecPacket,
    wire_meta: Option<WirePacketMeta>,
    send_info: crate::transport::SendInfo,
    congestion_controlled: bool,
}

impl OutgoingFecPacket {
    fn write_to(&self, buf: &mut [u8]) -> Result<usize, String> {
        let Some(meta) = self.wire_meta else {
            return self.packet.to_raw(buf);
        };
        let symbol = self.packet.payload_slice().ok_or_else(|| "No data available".to_string())?;
        let payload = if meta.systematic {
            wire::source_symbol_payload(symbol).map_err(|error| error.to_string())?
        } else {
            symbol
        };
        wire::write_packet(meta, payload, buf).map_err(|error| error.to_string())
    }

    fn telemetry_shape(&self) -> (bool, usize) {
        match self.wire_meta {
            None => (true, self.packet.data_len),
            Some(meta) if meta.systematic => {
                (true, self.packet.data_len.saturating_sub(2 * wire::SOURCE_LENGTH_LEN))
            }
            Some(_) => (false, 0),
        }
    }
}

/// Atomic active-connection FEC policy acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveFecPolicyChange {
    /// Controller-level policy and mode transition.
    pub controller: crate::fec::FecPolicyChange,
    /// Source datagrams preserved across the command boundary.
    pub queued_sources_preserved: usize,
    /// Repair-only datagrams discarded before acknowledgement.
    pub queued_repairs_discarded: usize,
}

#[derive(Default)]
struct OutboundPacer {
    next_release: Option<Instant>,
    burst_bytes: usize,
}

impl OutboundPacer {
    fn next_release(&self) -> Option<Instant> {
        self.next_release
    }

    fn is_blocked(&mut self, now: Instant) -> bool {
        let Some(release) = self.next_release else {
            return false;
        };
        if now < release {
            return true;
        }
        self.next_release = None;
        false
    }

    fn record_send(
        &mut self,
        now: Instant,
        bytes: usize,
        send_quantum: usize,
        rate_bytes_per_second: u64,
    ) {
        if bytes == 0 || rate_bytes_per_second == 0 {
            return;
        }
        self.burst_bytes = self.burst_bytes.saturating_add(bytes);
        if self.burst_bytes < send_quantum.max(1) {
            return;
        }

        let paced_bytes = std::mem::take(&mut self.burst_bytes);
        let numerator = (paced_bytes as u128).saturating_mul(1_000_000_000);
        let denominator = rate_bytes_per_second as u128;
        let delay_nanos = numerator.div_ceil(denominator).max(1).min(u64::MAX as u128) as u64;
        self.next_release = Some(now + Duration::from_nanos(delay_nanos));
    }

    fn reset(&mut self) {
        self.next_release = None;
        self.burst_bytes = 0;
    }
}

/// Parameters for creating a new QuicFuscateConnection.
pub struct ConnectionParams {
    /// Underlying QUIC transport connection.
    pub conn: Box<crate::transport::Connection>,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Remote peer socket address.
    pub peer_addr: SocketAddr,
    /// HTTP Host header value (may differ from SNI when domain fronting).
    pub host_header: String,
    /// TLS SNI hostname override (None uses host_header).
    pub sni_host: Option<String>,
    /// QKey authentication token in hex (client mode only).
    pub qkey_auth_token_hex: Option<crate::engine::qkey::QKeyToken>,
    /// Shared stealth manager for obfuscation and fingerprint control.
    pub stealth_manager: Arc<StealthManager>,
    /// Shared optimization manager for memory pool and CPU feature detection.
    pub optimization_manager: Arc<OptimizationManager>,
    /// Forward error correction configuration.
    pub fec_config: FecConfig,
    /// Frozen raw-IP normalizer for decoded tunnel ingress.
    pub tunnel_ingress_normalizer: PacketNormalizer,
}

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    /// Underlying QUIC transport connection handle.
    pub conn: Box<crate::transport::Connection>,
    /// Current peer address (may change on migration).
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,
    qkey_auth_token_hex: Option<crate::engine::qkey::QKeyToken>,

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
    fec_tx_profile: Option<WireProfile>,
    fec_tx_epoch: u32,
    fec_tx_sequence: u64,
    fec_tx_active: bool,
    h3_conn: Option<crate::transport::h3::Connection>,
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
    /// Locally-initiated MASQUE CONNECT-UDP stream id (client side).
    masque_stream_id: Option<u64>,
    /// Peer-initiated MASQUE CONNECT-UDP stream id (server side: the client opened
    /// the flow; we reuse its stream id for downlink datagram sends).
    masque_peer_stream_id: Option<u64>,
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

/// Tracks performance and reliability metrics for a connection.
#[derive(Debug)]
pub struct ConnectionStats {
    /// Smoothed round-trip time in seconds.
    pub rtt: f32,
    /// Packet loss rate in [0.0, 1.0].
    pub loss_rate: f32,
    /// Total packets sent on this connection.
    pub packets_sent: u64,
    /// Total packets lost (detected by transport).
    pub packets_lost: u64,
    /// Current congestion window in bytes.
    pub congestion_cwnd: u64,
    /// Bytes currently in flight (unacknowledged).
    pub congestion_bytes_in_flight: u64,
    /// Estimated delivery rate in bytes per second.
    pub congestion_delivery_rate: u64,
    /// Total packets lost as tracked by congestion controller.
    pub congestion_lost: u64,
    /// Aggregate congestion score (higher = more congested).
    pub congestion_score: u64,
    congestion_samples: VecDeque<CongestionSample>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            rtt: 0.0,
            loss_rate: 0.0,
            packets_sent: 0,
            packets_lost: 0,
            congestion_cwnd: 0,
            congestion_bytes_in_flight: 0,
            congestion_delivery_rate: 0,
            congestion_lost: 0,
            congestion_score: 0,
            congestion_samples: VecDeque::with_capacity(transport_accel::CONGESTION_WINDOW_SIZE),
        }
    }
}

impl ConnectionStats {
    fn update_congestion(&mut self, sample: CongestionSample) {
        if self.congestion_samples.len() == transport_accel::CONGESTION_WINDOW_SIZE {
            self.congestion_samples.pop_front();
        }
        self.congestion_samples.push_back(sample);
        let summary =
            transport_accel::aggregate_congestion(self.congestion_samples.make_contiguous());
        self.congestion_cwnd = summary.total_cwnd;
        self.congestion_bytes_in_flight = summary.total_bytes_in_flight;
        self.congestion_delivery_rate = summary.total_delivery_rate;
        self.congestion_lost = summary.total_lost_packets;
        self.congestion_score = summary.congestion_score;
    }
}

impl QuicFuscateConnection {
    fn env_optional_trimmed(name: &str) -> Option<String> {
        std::env::var(name).ok().and_then(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
    }

    /// Creates a new client connection.
    #[allow(clippy::too_many_arguments)]
    pub fn new_client(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        qkey_auth_token_hex: Option<crate::engine::qkey::QKeyToken>,
        qkey_initial_token: Option<Vec<u8>>,
        use_utls: bool,
    ) -> Result<Self, String> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
        ));

        if use_utls {
            stealth_manager.apply_utls_profile(&mut config, None);
        }

        // Each client connection should use a fresh, unpredictable SCID to avoid linkability.
        let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
        crate::transport::rand::rand_bytes(&mut scid_bytes);
        let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);

        let (sni, host_header) = stealth_manager.get_connection_headers(server_name);

        // When a QKey is provided, embed its 12-char hex ID as the QUIC Initial packet
        // token so the server can look up the QKey record during connection acceptance.
        if let Some(token_bytes) = qkey_initial_token {
            config.set_initial_token(Some(token_bytes));
        }

        let conn = crate::transport::packet::connect(
            Some(&sni),
            scid.as_ref(),
            local_addr,
            remote_addr,
            &mut config,
        )
        .map_err(|e| format!("Failed to create QUIC connection: {}", e))?;

        Ok(Self::new(ConnectionParams {
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
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
        ));

        let conn = crate::transport::packet::accept(
            scid.as_ref(),
            initial_key_dcid.as_ref().map(|id| id.as_ref()),
            local_addr,
            remote_addr,
            config,
        )
        .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;

        Ok(Self::new(ConnectionParams {
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
        }))
    }

    fn new(params: ConnectionParams) -> Self {
        let obs = FecTransportObserver::new();
        let fec_mem_pool = params.optimization_manager.memory_pool().clone();
        let mut s = Self {
            conn: params.conn,
            peer_addr: params.peer_addr,
            local_addr: params.local_addr,
            host_header: params.host_header,
            qkey_auth_token_hex: params.qkey_auth_token_hex,
            fec: AdaptiveFec::new(params.fec_config),
            stealth_manager: params.stealth_manager,
            optimization_manager: params.optimization_manager,
            tunnel_ingress_normalizer: params.tunnel_ingress_normalizer,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            fec_send_scratch: Vec::with_capacity(1),
            fec_receive_scratch: Vec::with_capacity(1),
            fec_wire_receiver: WireFecReceiver::new(fec_mem_pool),
            fec_tx_profile: None,
            fec_tx_epoch: 0,
            fec_tx_sequence: 0,
            fec_tx_active: false,
            h3_conn: None,
            h3_tunnel_rx: HashMap::new(),
            h3_tunnel_tx_frame: Vec::new(),
            h3_peer_tunnel_stream_id: None,
            h3_tunnel_response_started: HashSet::new(),
            h3_tunnel_uplink_fallback_reported: false,
            h3_tunnel_downlink_fallback_reported: false,
            last_telemetry: std::time::Instant::now(),
            transport_observer: obs.clone(),
            masque_cb: None,
            masque_datagram_cb: None,
            masque_downlink_queue: None,
            masque_downlink_retry: None,
            masque_control_cb: None,
            masque_stream_id: None,
            masque_peer_stream_id: None,
            #[cfg(feature = "orchestrator")]
            runtime_cpu_percent: 0,
            #[cfg(feature = "orchestrator")]
            runtime_memory_pressure: 0,
            #[cfg(feature = "orchestrator")]
            runtime_system: sysinfo::System::new(),
            tls_ch_override_template: Self::env_optional_trimmed(
                "QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE",
            ),
            next_packet_release: None,
            outbound_pacer: OutboundPacer::default(),
        };
        s.fec.enable_simd_acceleration();
        s.conn.set_intelligent_stealth_runtime(s.stealth_manager.is_intelligent_runtime());
        s.conn.set_brain_runtime_permissions(s.stealth_manager.brain_runtime_permissions());
        // Attach observers to transport for live telemetry callbacks
        // Combine FEC observer with StealthBrain when enabled (default on, disable via QUICFUSCATE_BRAIN=0|false)
        let obs_dyn: Arc<dyn crate::transport::TransportObserver> = obs.clone();
        let brain_enabled = crate::env_utils::env_flag("QUICFUSCATE_BRAIN", true);
        if brain_enabled {
            let brain = StealthBrain::new_default();
            let brain_dyn: Arc<dyn crate::transport::TransportObserver> = brain.clone();
            let combined = CombinedObserver::new(vec![obs_dyn.clone(), brain_dyn]);
            let combined_dyn: Arc<dyn crate::transport::TransportObserver> = combined.clone();
            s.conn.set_observer(Some(combined_dyn));
        } else {
            s.conn.set_observer(Some(obs_dyn));
        }

        // Enable and configure RealTLS (always on, including Performance mode)
        // Map stealth fingerprint to TLS profile and apply SNI from fronting
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
            let orchestrator_enabled = crate::env_utils::env_flag("QUICFUSCATE_ORCHESTRATOR", true);
            if orchestrator_enabled {
                let orchestrator = DeepIntegrationOrchestrator::new(
                    crate::brain::StealthBrainConfig::from_env(),
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

    fn inject_qkey_auth_header(
        token: Option<&str>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        let Some(token) = token else {
            return;
        };
        let token = token.trim();
        if token.is_empty() {
            return;
        }
        headers.retain(|h| h.name() != b"x-qf-auth");
        headers.push(crate::transport::h3::Header::new(b"x-qf-auth", token.as_bytes()));
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
        // When TUN bridging is active (a MASQUE datagram sink is installed),
        // always use MASQUE CONNECT-UDP as the tunnel transport regardless of
        // the stealth escalation state. Without this, TUN traffic would fall
        // back to H3 DATA frames (Option B) and the downlink MASQUE path would
        // be inconsistent with the uplink.
        let tun_bridging = self.masque_datagram_cb.is_some();
        if !self.stealth_manager.masque_preferred_runtime() && !tun_bridging {
            return Ok(None);
        }

        if let Some(sid) = self.masque_stream_id {
            return Ok(Some(sid));
        }

        // For TUN bridging, fall back to the connection's host header as the
        // MASQUE proxy authority when the stealth manager has no MASQUE config
        // (no masque_manager / fronting domains). The proxy authority is just
        // the H3 :authority header - the server validates it against itself.
        let proxy = self.stealth_manager.masque_proxy().unwrap_or_else(|| format!("{}:443", host));

        let target = format!("{}:443", host);
        let mut extra_headers = Vec::new();
        Self::inject_qkey_auth_header(self.qkey_auth_token_hex.as_deref(), &mut extra_headers);
        let Some(ref mut h3) = self.h3_conn else {
            return Ok(None);
        };

        let sid = h3.connect_udp_with_headers(&mut self.conn, &proxy, &target, &extra_headers)?;
        info!("MASQUE CONNECT-UDP opened (proxy={}, target={}, sid={})", proxy, target, sid);
        crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);

        match h3.enable_masque_datagram(&mut self.conn, sid) {
            Ok(_) => {
                if let Err(e) = h3.register_datagram_context(&mut self.conn, sid, 1, 0) {
                    warn!("MASQUE DATAGRAM context registration failed: {:?}", e);
                } else {
                    debug!("MASQUE DATAGRAM enabled (flow-id=1, ctx=0)");
                }
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
                        let loss_rate_permille = if sent > 0 {
                            (((lost.saturating_mul(1000)) / sent).min(1000)) as u32
                        } else {
                            0
                        };
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

    /// Returns true only after the peer acknowledged CONNECT-UDP with a 2xx response.
    pub fn masque_tunnel_established(&self) -> bool {
        let Some(stream_id) = self.masque_stream_id else {
            return false;
        };
        self.h3_conn.as_ref().is_some_and(|h3| h3.masque_established(stream_id))
    }

    /// Accepts the recorded peer CONNECT-UDP flow after application authentication.
    pub fn accept_peer_masque_tunnel(&mut self) -> Result<bool, crate::error::ConnectionError> {
        let Some(stream_id) = self.masque_peer_stream_id else {
            return Ok(false);
        };
        let Some(h3) = self.h3_conn.as_mut() else {
            return Ok(false);
        };
        h3.accept_masque_connect(&mut self.conn, stream_id).map_err(Into::into)
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
                if let Some((authority, path)) = stealth_manager.webtransport_cover_plan() {
                    match h3.open_webtransport_cover_session(conn, &authority, &path) {
                        Ok(sid) => {
                            debug!("WebTransport cover session opened: sid={sid}");
                        }
                        Err(e) => warn!("WebTransport cover session failed: {:?}", e),
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

    fn ensure_http3_ready_for_poll(&mut self, context: &str) -> bool {
        if self.h3_conn.is_none() && self.conn.is_established() {
            if let Err(e) = self.init_http3() {
                debug!("Deferred HTTP/3 init failed during {}: {:?}", context, e);
            }
        }
        self.h3_conn.is_some()
    }

    fn ensure_http3_initialized(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3_conn.is_none() {
            self.init_http3()?;
        }
        Ok(())
    }

    fn http3_poll_bindings(&self) -> Http3PollBindings {
        Http3PollBindings {
            masque_datagram_cb: self.masque_datagram_cb.clone(),
            masque_control_cb: self.masque_control_cb.clone(),
            masque_cb: self.masque_cb.clone(),
            memory_pool: self.optimization_manager.memory_pool(),
        }
    }

    fn build_http3_request_headers(
        &self,
        method: &'static [u8],
        path: &str,
    ) -> Vec<crate::transport::h3::Header> {
        let host = self.host_header.as_str();
        let mut headers =
            self.stealth_manager.get_http3_header_list(host, path).unwrap_or_default();

        headers.retain(|h| {
            h.name() != b":method"
                && h.name() != b":scheme"
                && h.name() != b":authority"
                && h.name() != b":path"
        });
        headers.insert(0, crate::transport::h3::Header::new(b":path", path.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":authority", host.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":scheme", b"https"));
        headers.insert(0, crate::transport::h3::Header::new(b":method", method));
        Self::inject_qkey_auth_header(self.qkey_auth_token_hex.as_deref(), &mut headers);
        headers
    }

    fn send_http3_request_headers(
        &mut self,
        method: &'static [u8],
        path: &str,
        fin: bool,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        let headers = self.build_http3_request_headers(method, path);
        let h3 = self.h3_conn.as_mut().ok_or("h3 not initialized")?;
        h3.send_request(&mut self.conn, &headers, fin).map_err(Into::into)
    }

    fn poll_http3_event_loop<FH, FB>(
        &mut self,
        context: &str,
        verbose_events: bool,
        mut on_headers: FH,
        mut on_body: FB,
    ) -> Result<(), crate::error::ConnectionError>
    where
        FH: FnMut(u64, &[crate::transport::h3::Header]),
        FB: FnMut(u64, &[u8]),
    {
        if self.ensure_http3_ready_for_poll(context) {
            let start = std::time::Instant::now();
            let bindings = self.http3_poll_bindings();
            loop {
                let (intelligent_level, stats) = self.prepare_http3_poll_iteration();
                let Some(ref mut h3) = self.h3_conn else {
                    break;
                };
                Self::emit_due_cover_headers(h3, &mut self.conn, &self.stealth_manager);
                Self::emit_server_push_cover_burst(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &stats,
                    intelligent_level,
                );
                match h3.poll(&mut self.conn) {
                    Ok(Some((sid, crate::transport::h3::Event::Headers { list, .. }))) => {
                        // Detect peer-initiated MASQUE CONNECT-UDP requests (server side:
                        // the client opens the flow). Record the stream id and provision
                        // QUIC DATAGRAM queues so downlink sends work. Inlined here
                        // because h3 is borrowed from self.h3_conn while we also need
                        // &mut self.conn - a helper taking &mut self would conflict.
                        if Self::is_connect_udp_request(&list)
                            && self.masque_peer_stream_id.is_none()
                        {
                            self.masque_peer_stream_id = Some(sid);
                            let _ = h3.enable_masque_datagram(&mut self.conn, sid);
                            crate::telemetry::MASQUE_ACTIVE
                                .store(1, std::sync::atomic::Ordering::Relaxed);
                            info!("MASQUE peer CONNECT-UDP flow recorded (stream={})", sid);
                        }
                        if list
                            .iter()
                            .any(|header| header.name() == b":path" && header.value() == b"/tun")
                        {
                            self.h3_tunnel_rx.entry(sid).or_default();
                            self.h3_peer_tunnel_stream_id.get_or_insert(sid);
                        }
                        on_headers(sid, &list);
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Data))) => {
                        let mut buf = [0; 65535];
                        while let Ok(read) = h3.recv_body(&mut self.conn, sid, &mut buf) {
                            if read == 0 {
                                break;
                            }
                            if let Some(decoder) = self.h3_tunnel_rx.get_mut(&sid) {
                                let normalizer = &self.tunnel_ingress_normalizer;
                                decoder
                                    .push(&buf[..read], |packet| {
                                        let required = normalizer.required_capacity(packet);
                                        if required > packet.len()
                                            && required <= MAX_INNER_IP_PACKET_LEN
                                        {
                                            let mut expanded = [0u8; MAX_INNER_IP_PACKET_LEN];
                                            expanded[..packet.len()].copy_from_slice(packet);
                                            let outcome = normalizer.normalize_with_capacity(
                                                &mut expanded,
                                                packet.len(),
                                            );
                                            if outcome.result != NormalizeResult::Dropped {
                                                on_body(sid, &expanded[..outcome.packet_len]);
                                            }
                                        } else {
                                            let outcome = normalizer
                                                .normalize_with_capacity(packet, packet.len());
                                            if outcome.result != NormalizeResult::Dropped {
                                                on_body(sid, &packet[..outcome.packet_len]);
                                            }
                                        }
                                    })
                                    .map_err(crate::error::ConnectionError::from)?;
                            } else {
                                on_body(sid, &buf[..read]);
                            }
                        }
                    }
                    Ok(Some((
                        _sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, mut payload },
                    ))) => {
                        Self::handle_masque_capsule_event(
                            capsule_type,
                            &mut payload,
                            &bindings.masque_datagram_cb,
                            &bindings.masque_control_cb,
                            &bindings.masque_cb,
                            &bindings.memory_pool,
                            &self.tunnel_ingress_normalizer,
                        );
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Reset(err)))) => {
                        self.h3_tunnel_rx.remove(&sid);
                        self.h3_tunnel_response_started.remove(&sid);
                        crate::optimize::telemetry::STEALTH_SIGNAL_RST
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if verbose_events {
                            warn!("H3 stream reset: {:?}", err);
                        }
                    }
                    Ok(Some((_id, crate::transport::h3::Event::PriorityUpdate))) => {
                        if verbose_events {
                            debug!("H3 priority update received");
                        }
                    }
                    Ok(Some((_id, crate::transport::h3::Event::GoAway))) => {
                        if verbose_events {
                            info!("H3 GOAWAY received");
                        }
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Finished))) => {
                        self.h3_tunnel_rx.remove(&sid);
                        self.h3_tunnel_response_started.remove(&sid);
                        if self.h3_peer_tunnel_stream_id == Some(sid) {
                            self.h3_peer_tunnel_stream_id = None;
                        }
                    }
                    Ok(Some((
                        _id,
                        crate::transport::h3::Event::PushPromise { push_id, headers },
                    ))) => {
                        if verbose_events {
                            info!(
                                "Received stealth push promise {} with {} headers",
                                push_id,
                                headers.len()
                            );
                        }
                    }
                    Ok(None) => break,
                    Err(crate::transport::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &bindings.masque_datagram_cb,
                    &bindings.masque_cb,
                    &self.tunnel_ingress_normalizer,
                );
            }
            // Always drain MASQUE datagrams after the H3 event loop exits.
            // QUIC DATAGRAM frames (carrying MASQUE CONNECT-UDP payloads) are
            // NOT H3 events: they sit in the QUIC datagram recv queue and are
            // never returned by h3.poll(). Without this post-loop drain, TUN
            // uplink packets would be silently dropped whenever the H3 event
            // queue is empty (the common case after handshake).
            if let Some(ref mut h3) = self.h3_conn {
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &bindings.masque_datagram_cb,
                    &bindings.masque_cb,
                    &self.tunnel_ingress_normalizer,
                );
            }
            log::trace!("HTTP/3 events processed in {} ms", start.elapsed().as_millis());
        }
        Ok(())
    }

    fn emit_due_cover_headers(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &StealthManager,
    ) {
        if let Some(headers) = stealth_manager.cover_headers_due() {
            if let Err(e) = h3.send_request(conn, &headers, true) {
                crate::optimize::telemetry::STEALTH_SIGNAL_RST
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("Cover traffic send failed: {:?}", e);
            } else {
                debug!("Cover traffic request emitted");
            }
        }
    }

    fn dispatch_masque_datagram_payload(
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        payload: &[u8],
    ) {
        if let Some(cb) = masque_datagram_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(payload);
            }
        } else if let Some(cb) = masque_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(0x00, payload);
            }
        }
    }

    fn dispatch_masque_capsule_payload(
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        capsule_type: u64,
        payload: &[u8],
    ) {
        if let Some(cb) = masque_control_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(capsule_type, payload);
            }
        } else if let Some(cb) = masque_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(capsule_type, payload);
            }
        }
    }

    fn dispatch_masque_compressed_datagram(
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        pool: &Arc<crate::optimize::MemoryPool>,
        payload: &[u8],
        dict: Option<&[u8]>,
        normalizer: &PacketNormalizer,
    ) {
        let decoded = match dict {
            Some(dict_bytes) => crate::compress::decompress_with_dict(pool, payload, dict_bytes),
            None => crate::compress::CompressionManager::new(Default::default())
                .decompress_to_pool(pool, payload),
        };
        if let Some((mut blk, used)) = decoded {
            let outcome = normalizer.normalize_with_capacity(&mut blk, used);
            if outcome.result != NormalizeResult::Dropped {
                Self::dispatch_masque_datagram_payload(
                    masque_datagram_cb,
                    masque_cb,
                    &blk[..outcome.packet_len],
                );
            }
            pool.free(blk);
        }
    }

    fn handle_masque_capsule_event(
        capsule_type: u64,
        payload: &mut Vec<u8>,
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        memory_pool: &Arc<crate::optimize::MemoryPool>,
        normalizer: &PacketNormalizer,
    ) {
        match capsule_type {
            0x00 => {
                if normalizer.normalize_vec(payload) != NormalizeResult::Dropped {
                    Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, payload);
                }
            }
            0x21 => {
                Self::dispatch_masque_compressed_datagram(
                    masque_datagram_cb,
                    masque_cb,
                    memory_pool,
                    payload,
                    None,
                    normalizer,
                );
            }
            0x22 => {
                if payload.len() >= 9 && payload[0] == 0x5D {
                    let mut hb = [0u8; 2];
                    hb.copy_from_slice(&payload[1..3]);
                    let hash = u16::from_be_bytes(hb);
                    let mut vb = [0u8; 2];
                    vb.copy_from_slice(&payload[3..5]);
                    let ver = u16::from_be_bytes(vb);
                    if let Some(dict) = crate::compress::get_dict_by_id(hash, ver) {
                        Self::dispatch_masque_compressed_datagram(
                            masque_datagram_cb,
                            masque_cb,
                            memory_pool,
                            payload,
                            Some(&dict),
                            normalizer,
                        );
                    }
                }
            }
            _ => {
                Self::dispatch_masque_capsule_payload(
                    masque_control_cb,
                    masque_cb,
                    capsule_type,
                    payload,
                );
            }
        }
    }

    fn drain_masque_datagrams(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &StealthManager,
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        normalizer: &PacketNormalizer,
    ) {
        // Drain whenever a sink is present (TUN bridge) or the stealth runtime
        // explicitly enabled MASQUE datagrams. Without this, MASQUE-framed
        // datagrams would be left in the QUIC datagram queue and either dropped
        // or consumed as corrupted raw bytes by a bare dgram_recv loop.
        let has_sink = masque_datagram_cb.is_some() || masque_cb.is_some();
        if stealth_manager.masque_datagram_enabled() || has_sink {
            while let Some((_fid, mut payload)) = h3.try_recv_masque_datagram(conn) {
                if normalizer.normalize_vec(&mut payload) != NormalizeResult::Dropped {
                    Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, &payload);
                }
            }
        }
    }

    /// Returns true if the H3 headers describe a MASQUE CONNECT-UDP request
    /// (`:method: CONNECT` + `:protocol: connect-udp`).
    fn is_connect_udp_request(headers: &[crate::transport::h3::Header]) -> bool {
        let mut method_connect = false;
        let mut protocol_connect_udp = false;
        for h in headers {
            if h.name().eq_ignore_ascii_case(b":method")
                && h.value().eq_ignore_ascii_case(b"CONNECT")
            {
                method_connect = true;
            }
            if h.name().eq_ignore_ascii_case(b":protocol")
                && h.value().eq_ignore_ascii_case(b"connect-udp")
            {
                protocol_connect_udp = true;
            }
        }
        method_connect && protocol_connect_udp
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
            let packet = FecPacket::new(
                self.packet_id_counter,
                Some(block),
                len,
                true,
                None,
                0,
                self.optimization_manager.memory_pool().clone(),
            );
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
                let mut buf = self.optimization_manager.alloc_block();
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
                        self.optimization_manager.free_block(buf);
                        break;
                    }
                    debug!(
                        "transport::recv failed (possible probe) len={}: {:?}",
                        data.len(),
                        error
                    );
                    self.stealth_manager.handle_fallback(data, from);
                }
                self.optimization_manager.free_block(buf);
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

    /// Earliest outgoing release imposed by the pacing or stealth scheduler.
    pub fn next_outbound_release_deadline(&self) -> Option<Instant> {
        [self.outbound_pacer.next_release(), self.next_packet_release].into_iter().flatten().min()
    }

    /// Earliest instant the caller should poll `send` again.
    ///
    /// This merges outer pacing, stealth release, QUIC recovery, and the one
    /// transport-owned traffic-analysis deadline.
    pub fn next_send_deadline(&self) -> Option<Instant> {
        [
            self.next_outbound_release_deadline(),
            self.conn.recovery_deadline(),
            self.conn.traffic_analysis_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Queue one ack-eliciting transport keepalive for the next send poll.
    pub fn queue_keepalive_ping(&mut self) {
        self.conn.queue_cover_ping();
    }

    /// Atomically change the operator-owned FEC policy for this live connection.
    ///
    /// The existing connection mutex serializes this command with lifecycle,
    /// Brain feedback, loss feedback, send, and receive. Source datagrams already
    /// owned by the output queue remain byte-identical; repair-only datagrams are
    /// retired before the command is acknowledged. Both codec directions restart
    /// from empty state so Auto never inherits stale Off-era or prior-Auto evidence.
    pub fn set_fec_control_policy(
        &mut self,
        policy: crate::fec::FecControlPolicy,
    ) -> ActiveFecPolicyChange {
        let previous_policy = self.fec.control_policy();
        if previous_policy == policy {
            return ActiveFecPolicyChange {
                controller: self.fec.set_control_policy(policy),
                queued_sources_preserved: self
                    .outgoing_fec_packets
                    .iter()
                    .filter(|packet| packet.wire_meta.is_none_or(|meta| meta.systematic))
                    .count(),
                queued_repairs_discarded: 0,
            };
        }

        let queued_before = self.outgoing_fec_packets.len();
        self.outgoing_fec_packets
            .retain(|packet| packet.wire_meta.is_none_or(|meta| meta.systematic));
        let queued_sources_preserved = self.outgoing_fec_packets.len();
        let queued_repairs_discarded = queued_before.saturating_sub(queued_sources_preserved);

        self.fec_send_scratch.clear();
        self.fec_receive_scratch.clear();
        self.fec_wire_receiver =
            WireFecReceiver::new(self.optimization_manager.memory_pool().clone());
        self.fec_tx_profile = None;
        self.fec_tx_sequence = 0;
        self.fec_tx_active = false;

        ActiveFecPolicyChange {
            controller: self.fec.set_control_policy(policy),
            queued_sources_preserved,
            queued_repairs_discarded,
        }
    }

    fn prepare_fec_wire_profile(
        &mut self,
    ) -> Result<Option<WireProfile>, crate::error::ConnectionError> {
        let candidate = match self.fec.wire_profile(self.fec_tx_epoch.max(1)) {
            Ok(profile) => profile,
            Err(wire::WireError::ZeroModeMustRemainRaw) => {
                self.fec_tx_active = false;
                return Ok(None);
            }
            Err(error) => {
                return Err(crate::error::ConnectionError::Transport(error.to_string()));
            }
        };
        let shape_changed = self.fec_tx_profile.is_some_and(|previous| {
            previous.codec != candidate.codec
                || previous.source_count != candidate.source_count
                || previous.total_count != candidate.total_count
                || previous.interleave_depth != candidate.interleave_depth
        });
        let window_space_exhausted =
            self.fec_tx_sequence / candidate.source_count as u64 > u32::MAX as u64;
        if !self.fec_tx_active || shape_changed || window_space_exhausted {
            self.fec_tx_epoch = self.fec_tx_epoch.wrapping_add(1).max(1);
            self.fec_tx_sequence = 0;
        }
        self.fec_tx_active = true;
        let profile = WireProfile { epoch: self.fec_tx_epoch, ..candidate };
        self.fec_tx_profile = Some(profile);
        Ok(Some(profile))
    }

    fn bypass_fec_for_path_control(
        wire_profile: Option<WireProfile>,
        send_info: &crate::transport::SendInfo,
        send_buffer: &mut [u8],
        write: usize,
    ) -> Result<Option<WireProfile>, crate::error::ConnectionError> {
        if wire_profile.is_none() || !send_info.path_control {
            return Ok(wire_profile);
        }

        let quic_offset = 2 * wire::SOURCE_LENGTH_LEN;
        let quic_end = quic_offset
            .checked_add(write)
            .filter(|end| *end <= send_buffer.len())
            .ok_or(crate::error::ConnectionError::BufferTooShort)?;
        send_buffer.copy_within(quic_offset..quic_end, 0);
        Ok(None)
    }

    /// Prepares one wire datagram and discards its address metadata.
    ///
    /// Connected-socket callers can use this compatibility API. Multipath and
    /// unconnected-socket runtimes must use [`Self::send_with_info`] so targeted
    /// path-validation frames reach the address selected by the transport.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        self.send_with_info(buf).map(|(len, _)| len)
    }

    /// Prepares one wire datagram together with its exact transport-selected path.
    pub fn send_with_info(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, crate::transport::SendInfo), crate::error::ConnectionError> {
        let now = Instant::now();

        // --- LOSS/PTO RECOVERY TIMER ---
        // RFC 9002 §6.1.2/§6.2.1: event loops drive the recovery timer.  When the
        // deadline has passed, run loss detection (time-threshold or PTO probe)
        // before the pacing/stealth scheduler so probes never wait on shaping.
        if self.conn.recovery_deadline().is_some_and(|recovery_deadline| now >= recovery_deadline) {
            self.conn.on_recovery_timeout(now);
            // Recovery takes precedence over pacing/stealth release; force
            // an immediate send attempt so PTO probes can emit.
            if self.next_packet_release.is_some_and(|r| r > now) {
                self.next_packet_release = None;
            }
        }

        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
        let established = self.conn.is_established();
        if established {
            self.conn.on_traffic_analysis_timeout(now);
        }
        let fec_wire_ready = self
            .conn
            .post_handshake_datagram_ready()
            .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
        let path_control_pending = self.conn.has_sendable_path_control();

        // --- REALITY FALLBACK RESPONSE POLLING ---
        // Check if there are any responses from upstream to send back (bypass stealth scheduler)
        if let Some(resp) = self.stealth_manager.poll_fallback() {
            if buf.len() < resp.data.len() {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            buf[..resp.data.len()].copy_from_slice(&resp.data);
            return Ok((
                resp.data.len(),
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        // --- ASYNC STEALTH SCHEDULER ---
        // If we are currently throttled by the StealthManager (Brain), yield immediately.
        //
        // Production invariant:
        // Never delay Initial/Handshake flights. Delaying them can stall the connection setup and
        // makes short-lived clients (like E2E) time out. Stealth timing only applies post-handshake.
        if !established {
            self.next_packet_release = None;
            self.outbound_pacer.reset();
        } else if !path_control_pending {
            if let Some(release_time) = self.next_packet_release {
                if now < release_time {
                    log::trace!(
                        "connection.send: next_packet_release blocks until {:?}",
                        release_time
                    );
                    return Ok((
                        0,
                        crate::transport::SendInfo {
                            from: self.local_addr,
                            to: self.peer_addr,
                            at: now,
                            congestion_controlled: false,
                            path_control: false,
                        },
                    )); // WouldBlock / Yield
                }
                // Timer expired, clear block and proceed
                self.next_packet_release = None;
            }
        }
        if established && !path_control_pending && self.outbound_pacer.is_blocked(now) {
            log::trace!("connection.send: outbound_pacer blocked dgram_queue={} out_fec={} bytes_in_flight={} cwnd={}",
                self.conn.dgram_send_queue_len(), self.outgoing_fec_packets.len(), self.conn.bytes_in_flight(), self.conn.cwnd());
            return Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        // If there are buffered FEC packets, send one directly. These packets
        // were already generated in a previous send() call but could not be
        // emitted because of pacing or stealth scheduling. Flushing them first
        // prevents an accumulation deadlock: if has_pending_app_data stayed true
        // (e.g. a MASQUE datagram was queued but conn.send was blocked), every
        // new send() call would generate another FEC packet and push it onto
        // outgoing_fec_packets without ever draining the buffer.
        if !path_control_pending {
            if let Some(packet) = self.outgoing_fec_packets.pop_front() {
                let len = packet.write_to(buf)?;
                let mut send_info = packet.send_info;
                send_info.at = now;
                if self.fec.telemetry_enabled() {
                    let (systematic, source_payload_bytes) = packet.telemetry_shape();
                    self.fec.observe_wire_send(systematic, source_payload_bytes, len);
                }
                self.record_paced_packet(now, len, packet.congestion_controlled);
                // Drop handles pool recycling automatically.
                return Ok((len, send_info));
            }
        }

        // Cover PING: inject post-handshake keepalive if the interval has elapsed.
        // The PING lands in pending_control and is flushed by flush_pending_control_frames()
        // inside conn.send(), requiring no extra round-trip through this function.
        if established && !path_control_pending && self.stealth_manager.should_send_cover_ping() {
            self.conn.queue_cover_ping();
        }

        let wire_profile = if fec_wire_ready { self.prepare_fec_wire_profile()? } else { None };

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = self.optimization_manager.alloc_block();
        let send_result = if wire_profile.is_some() {
            if send_buffer.len() <= 2 * wire::SOURCE_LENGTH_LEN {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            self.conn.send_with_datagram_overhead(
                &mut send_buffer[2 * wire::SOURCE_LENGTH_LEN..],
                wire::MAX_DATAGRAM_OVERHEAD,
            )
        } else {
            self.conn.send(&mut send_buffer)
        };
        let (write, send_info) = match send_result {
            Ok(v) => v,
            Err(crate::error::ConnectionError::Done) => {
                log::trace!("connection.send: conn.send returned Done dgram_queue={} out_fec={} bytes_in_flight={} cwnd={}",
                    self.conn.dgram_send_queue_len(), self.outgoing_fec_packets.len(), self.conn.bytes_in_flight(), self.conn.cwnd());
                // No packet currently pending is a normal state for polling loops.
                drop(send_buffer);
                return Ok((
                    0,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                    },
                ));
            }
            Err(crate::error::ConnectionError::BufferTooShort) => {
                drop(send_buffer);
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            Err(e) => {
                // The buffer is recycled automatically via FecPacket Drop.
                drop(send_buffer);
                return Err(crate::error::ConnectionError::Transport(e.to_string()));
            }
        };

        if write == 0 {
            log::trace!("connection.send: conn.send returned write=0");
            // The buffer is recycled automatically via Drop.
            drop(send_buffer);
            return Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        let bypass_fec_for_path_control = send_info.path_control;
        let wire_profile =
            Self::bypass_fec_for_path_control(wire_profile, &send_info, &mut send_buffer, write)?;

        // The buffer may be larger than the written data; the length is tracked separately.
        // Stealth padding may be applied by the transport configuration; do not mutate the
        // sealed datagram here to preserve AEAD integrity and FEC compatibility.

        // Obfuscate payload if enabled (includes timing/flow shaping)
        // NON-BLOCKING: If delay needed, we schedule it and yield zero bytes.
        let quic_range = if wire_profile.is_some() {
            2 * wire::SOURCE_LENGTH_LEN..2 * wire::SOURCE_LENGTH_LEN + write
        } else {
            0..write
        };
        let delay_opt = if bypass_fec_for_path_control {
            None
        } else {
            self.stealth_manager.process_outgoing_packet(&mut send_buffer[quic_range.clone()])
        };

        let (packet_id, fec_data_len) = if wire_profile.is_some() {
            let quic_len =
                u16::try_from(write).map_err(|_| crate::error::ConnectionError::BufferTooShort)?;
            let source_len = quic_len
                .checked_add(wire::SOURCE_LENGTH_LEN as u16)
                .ok_or(crate::error::ConnectionError::BufferTooShort)?;
            send_buffer[..wire::SOURCE_LENGTH_LEN].copy_from_slice(&source_len.to_be_bytes());
            send_buffer[wire::SOURCE_LENGTH_LEN..2 * wire::SOURCE_LENGTH_LEN]
                .copy_from_slice(&quic_len.to_be_bytes());
            (self.fec_tx_sequence, write + 2 * wire::SOURCE_LENGTH_LEN)
        } else {
            (self.packet_id_counter, write)
        };

        // Create a source (systematic) FEC packet, passing ownership of the buffer.
        let mut fec_packet = FecPacket::new(
            packet_id,
            Some(send_buffer),
            fec_data_len,
            true,
            None,
            0,
            // Use the same pool the buffer was allocated from to avoid cross-pool leaks
            self.optimization_manager.memory_pool().clone(),
        );
        fec_packet.seq = packet_id;

        // Initial and Handshake datagrams must remain raw because the server parses
        // the first Initial before a Core connection exists. FEC starts only after
        // this endpoint has entered 1-RTT. Zero mode retains raw zero-overhead output.
        if let Some(profile) = wire_profile {
            let source_sequence = self.fec_tx_sequence;
            let window = (source_sequence / profile.source_count as u64) as u32;
            self.fec.on_send_into(fec_packet, &mut self.fec_send_scratch);
            for packet in self.fec_send_scratch.drain(..) {
                let (sequence, repair_index, block_index) = if packet.is_systematic {
                    (
                        source_sequence,
                        wire::SYSTEMATIC_REPAIR_INDEX,
                        (source_sequence % profile.interleave_depth as u64) as u8,
                    )
                } else {
                    (
                        packet.id,
                        u16::try_from(packet.seq >> 4).map_err(|_| {
                            crate::error::ConnectionError::Transport(
                                "FEC repair ordinal exceeds wire range".to_string(),
                            )
                        })?,
                        (packet.seq & 0x0F) as u8,
                    )
                };
                self.outgoing_fec_packets.push_back(OutgoingFecPacket {
                    wire_meta: Some(WirePacketMeta {
                        profile,
                        window,
                        sequence,
                        repair_index,
                        block_index,
                        systematic: packet.is_systematic,
                    }),
                    packet,
                    send_info,
                    congestion_controlled: send_info.congestion_controlled,
                });
            }
            self.fec_tx_sequence = self.fec_tx_sequence.wrapping_add(1);
        } else {
            self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
            let outgoing = OutgoingFecPacket {
                packet: fec_packet,
                wire_meta: None,
                send_info,
                congestion_controlled: send_info.congestion_controlled,
            };
            if send_info.path_control {
                self.outgoing_fec_packets.push_front(outgoing);
            } else {
                self.outgoing_fec_packets.push_back(outgoing);
            }
        }

        // Single outbound stealth timing owner: core merges StealthManager shaping delay
        // with transport jitter (when enabled) into one release deadline. Connection::send
        // no longer maintains a parallel next_send_at gate.
        if established && !bypass_fec_for_path_control {
            let transport_jitter = self.conn.transport_stealth_jitter_delay();
            if let Some(release_at) =
                Self::compute_outbound_stealth_release(now, delay_opt, transport_jitter)
            {
                self.next_packet_release = Some(release_at);
                return Ok((
                    0,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                    },
                )); // Yield immediately, do not send the just-generated packets yet.
            }
        }

        // Pop the first packet from the buffer to send it now.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            let len = packet.write_to(buf)?;
            let mut send_info = packet.send_info;
            send_info.at = now;
            log::trace!(
                "connection.send: emitting packet len={} dgram_queue_after={} remaining_fec={}",
                len,
                self.conn.dgram_send_queue_len(),
                self.outgoing_fec_packets.len()
            );
            if self.fec.telemetry_enabled() {
                let (systematic, source_payload_bytes) = packet.telemetry_shape();
                self.fec.observe_wire_send(systematic, source_payload_bytes, len);
            }
            self.record_paced_packet(now, len, packet.congestion_controlled);
            // Drop handles pool recycling automatically.
            Ok((len, send_info))
        } else {
            Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ))
        }
    }

    fn record_paced_packet(&mut self, now: Instant, bytes: usize, congestion_controlled: bool) {
        if !congestion_controlled {
            return;
        }
        let Some(rate) = self.conn.pacing_rate() else {
            return;
        };
        self.outbound_pacer.record_send(now, bytes, self.conn.send_quantum(), rate);
    }

    /// Merges StealthManager delay and transport jitter into one release instant.
    /// When both apply, the later deadline wins (no stacked duplicate yields).
    pub(crate) fn compute_outbound_stealth_release(
        now: Instant,
        stealth_manager_delay: Option<Duration>,
        transport_jitter: Option<Duration>,
    ) -> Option<Instant> {
        let mut release = stealth_manager_delay.map(|delay| now + delay);
        if let Some(jitter) = transport_jitter {
            let candidate = now + jitter;
            release = Some(match release {
                Some(current) => current.max(candidate),
                None => candidate,
            });
        }
        release
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

    /// Initializes the HTTP/3 connection if it hasn't been created yet.
    pub fn init_http3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3_conn.is_none() {
            // Enable a modest QPACK dynamic table to improve compression.
            let mut h3_cfg = crate::transport::h3::Config::new()
                .map_err(|_| crate::transport::h3::Error::InternalError)?;
            // Select capacities based on the active persona.
            let (qpack_capacity, qpack_blocked_streams) =
                self.stealth_manager.qpack_runtime_profile();
            h3_cfg.set_qpack_max_table_capacity(qpack_capacity);
            h3_cfg.set_qpack_blocked_streams(qpack_blocked_streams);

            let h3 = crate::transport::h3::Connection::with_transport(&mut self.conn, &h3_cfg)?;
            let mut h3 = h3;
            // Set persona QPACK index policy
            h3.set_qpack_index_policy(self.stealth_manager.qpack_index_policy());
            self.h3_conn = Some(h3);
            // Notify the compression layer about the persona (dictionary selection).
            let persona = self.stealth_manager.current_persona_name();
            crate::compress::set_current_persona(&persona);
        }
        Ok(())
    }

    /// Sends a masqueraded HTTP/3 GET request using the stealth manager.
    pub fn send_http3_request(&mut self, path: &str) -> Result<(), crate::error::ConnectionError> {
        let intelligent_level = self.stealth_manager.intelligent_runtime_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        if let Err(e) = self.ensure_masque_tunnel_for_send() {
            warn!("MASQUE CONNECT-UDP open failed: {:?}", e);
        }
        let start = std::time::Instant::now();
        if let Err(e) = self.send_http3_request_headers(b"GET", path, true) {
            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(e);
        }
        info!("HTTP/3 request sent in {} ms", start.elapsed().as_millis());
        Ok(())
    }

    /// Initializes HTTP/3 if not yet initialized and returns a writable POST stream id.
    pub fn open_http3_stream_post(
        &mut self,
        path: &str,
    ) -> Result<u64, crate::error::ConnectionError> {
        let stream_id = self.send_http3_request_headers(b"POST", path, false)?;
        if path == "/tun" {
            self.h3_tunnel_rx.entry(stream_id).or_default();
        }
        Ok(stream_id)
    }

    /// Sends a HTTP/3 request body chunk on an existing stream.
    pub fn http3_send_body_chunk(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let intelligent_level = self.stealth_manager.intelligent_runtime_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, data, fin)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Sends one raw IP packet through the fastest safe tunnel carrier.
    ///
    /// Packets that fit the confirmed MASQUE datagram budget use the datagram
    /// fast path. IPv6-minimum packets that do not fit that budget use an
    /// explicitly length-framed HTTP/3 body so arbitrary stream segmentation
    /// cannot merge or split IP packets at the receiver.
    pub fn send_tunnel_packet(
        &mut self,
        stream_id: u64,
        packet: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if packet.is_empty()
            || packet.len() > self.effective_tunnel_mtu()
            || !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6))
        {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        if packet.len() <= self.effective_masque_mtu() {
            match self.ensure_masque_tunnel_for_send() {
                Ok(Some(sid)) => {
                    if let Some(ref mut h3) = self.h3_conn {
                        match h3.send_masque_datagram(&mut self.conn, sid, packet) {
                            Ok(()) => {
                                log::trace!("MASQUE TX: sid={} {}B", sid, packet.len());
                                return Ok(());
                            }
                            Err(crate::transport::h3::Error::DgramQueueFull) => {
                                return Err(crate::error::ConnectionError::DgramQueueFull);
                            }
                            Err(error) => {
                                warn!(
                                    "MASQUE datagram send failed, using framed H3 fallback: {:?}",
                                    error
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    warn!("MASQUE setup failed, using framed H3 fallback: {:?}", error);
                }
            }
        }

        self.prepare_h3_tunnel_frame(packet)?;
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, &self.h3_tunnel_tx_frame, false)?;
            if !self.h3_tunnel_uplink_fallback_reported {
                info!(
                    "framed H3 tunnel uplink active: sid={} packet={}B masque_limit={}B",
                    stream_id,
                    packet.len(),
                    self.effective_masque_mtu()
                );
                self.h3_tunnel_uplink_fallback_reported = true;
            }
            debug!("framed H3 tunnel uplink TX: sid={} {}B", stream_id, packet.len());
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    fn prepare_h3_tunnel_frame(
        &mut self,
        packet: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let packet_len = u16::try_from(packet.len())
            .map_err(|_| crate::error::ConnectionError::BufferTooShort)?;
        self.h3_tunnel_tx_frame.clear();
        self.h3_tunnel_tx_frame.reserve(H3_TUNNEL_FRAME_HEADER_LEN.saturating_add(packet.len()));
        self.h3_tunnel_tx_frame.extend_from_slice(H3_TUNNEL_FRAME_MAGIC);
        self.h3_tunnel_tx_frame.extend_from_slice(&packet_len.to_be_bytes());
        self.h3_tunnel_tx_frame.extend_from_slice(packet);
        Ok(())
    }

    /// Sends one UDP payload over the active MASQUE DATAGRAM tunnel.
    pub fn send_masque_udp_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        let host = self.host_header.clone();
        let Some(sid) = self.ensure_masque_tunnel(&host)? else {
            return Err("masque tunnel unavailable".into());
        };
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_masque_datagram(&mut self.conn, sid, payload)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Sends a raw IP packet downlink through the fastest safe peer carrier.
    ///
    /// A bare QUIC datagram fallback was intentionally removed: the client only
    /// drains MASQUE-framed datagrams via `drain_masque_datagrams` and would
    /// never consume a bare dgram, causing silent data loss and queue growth.
    pub fn send_masque_downlink(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if payload.is_empty()
            || payload.len() > self.effective_tunnel_mtu()
            || !matches!(payload.first().map(|byte| byte >> 4), Some(4 | 6))
        {
            debug!(
                "send_masque_downlink: rejected payload len={} first={:?}",
                payload.len(),
                payload.first()
            );
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        log::trace!("send_masque_downlink: payload len={} masque_mtu={} masque_peer_stream_id={:?} h3_conn={}",
            payload.len(), self.effective_masque_mtu(), self.masque_peer_stream_id, self.h3_conn.is_some());

        if payload.len() <= self.effective_masque_mtu() {
            if let Some(sid) = self.masque_peer_stream_id {
                if let Some(ref mut h3) = self.h3_conn {
                    match h3.send_masque_datagram(&mut self.conn, sid, payload) {
                        Ok(()) => {
                            log::trace!(
                                "MASQUE downlink TX: sid={} {}B dgram_queue={}",
                                sid,
                                payload.len(),
                                self.conn.dgram_send_queue_len()
                            );
                            return Ok(());
                        }
                        Err(crate::transport::h3::Error::DgramQueueFull) => {
                            return Err(crate::error::ConnectionError::DgramQueueFull);
                        }
                        Err(error) => {
                            warn!("MASQUE downlink failed, using framed H3 fallback: {:?}", error);
                        }
                    }
                } else {
                    debug!("send_masque_downlink: no h3_conn for datagram");
                }
            } else {
                debug!("send_masque_downlink: no masque_peer_stream_id");
            }
        } else {
            debug!("send_masque_downlink: payload too large for masque datagram, fallback to H3 stream");
        }

        let Some(stream_id) = self.h3_peer_tunnel_stream_id else {
            debug!("send_masque_downlink: no h3_peer_tunnel_stream_id, returning Done");
            return Err(crate::error::ConnectionError::Done);
        };
        self.prepare_h3_tunnel_frame(payload)?;
        let response_started = self.h3_tunnel_response_started.contains(&stream_id);
        let Some(ref mut h3) = self.h3_conn else {
            return Err(crate::error::ConnectionError::Done);
        };
        if !response_started {
            let headers = [
                crate::transport::h3::Header::new(b":status", b"200"),
                crate::transport::h3::Header::new(
                    b"content-type",
                    b"application/quicfuscate-tunnel",
                ),
            ];
            h3.send_response(&mut self.conn, stream_id, &headers, false)?;
            self.h3_tunnel_response_started.insert(stream_id);
        }
        h3.send_body(&mut self.conn, stream_id, &self.h3_tunnel_tx_frame, false)?;
        if !self.h3_tunnel_downlink_fallback_reported {
            info!(
                "framed H3 tunnel downlink active: sid={} packet={}B masque_limit={}B",
                stream_id,
                payload.len(),
                self.effective_masque_mtu()
            );
            self.h3_tunnel_downlink_fallback_reported = true;
        }
        debug!("framed H3 tunnel downlink TX: sid={} {}B", stream_id, payload.len());
        Ok(())
    }

    /// Maximum raw IP packet that fits the confirmed QUIC/FEC MASQUE path.
    pub fn effective_masque_mtu(&self) -> usize {
        const QUIC_AND_MASQUE_OVERHEAD: usize = 64;
        self.conn
            .effective_path_mtu()
            .min(self.conn.max_send_udp_payload_size())
            .saturating_sub(wire::MAX_DATAGRAM_OVERHEAD + QUIC_AND_MASQUE_OVERHEAD)
    }

    /// Maximum inner IP packet supported by the complete tunnel carrier set.
    /// HTTP/3 framing preserves the IPv6 minimum even when the current MASQUE
    /// datagram payload budget is smaller.
    pub fn effective_tunnel_mtu(&self) -> usize {
        self.effective_masque_mtu().max(IPV6_MINIMUM_LINK_MTU)
    }

    /// Installs a sink for decoded MASQUE datagram payloads (raw IP packets).
    /// Used by both server (uplink: MASQUE → TUN) and client (downlink: MASQUE → TUN).
    pub fn set_masque_datagram_cb(&mut self, cb: DatagramHandler) {
        self.masque_datagram_cb = Some(cb);
    }

    /// Returns true if a MASQUE datagram sink has been installed.
    pub fn has_masque_datagram_cb(&self) -> bool {
        self.masque_datagram_cb.is_some()
    }

    /// Installs a queue for raw IP packets that must be sent back to the peer
    /// on the peer-initiated MASQUE flow after callback dispatch returns.
    pub fn set_masque_downlink_queue(&mut self, queue: Arc<std::sync::Mutex<MasqueDownlinkQueue>>) {
        self.masque_downlink_queue = Some(queue);
    }

    /// Returns the installed MASQUE downlink queue, if present.
    pub fn masque_downlink_queue(&self) -> Option<Arc<std::sync::Mutex<MasqueDownlinkQueue>>> {
        self.masque_downlink_queue.as_ref().cloned()
    }

    /// Returns true if the MASQUE downlink response queue has been installed.
    pub fn has_masque_downlink_queue(&self) -> bool {
        self.masque_downlink_queue.is_some()
    }

    /// Returns the next queued MASQUE downlink packet, preserving a packet that
    /// previously hit QUIC DATAGRAM backpressure ahead of later responses.
    pub fn pop_masque_downlink_packet(&mut self) -> Option<Vec<u8>> {
        if let Some(packet) = self.masque_downlink_retry.take() {
            return Some(packet);
        }
        let queue = self.masque_downlink_queue.as_ref()?;
        match queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(poisoned) => poisoned.into_inner().pop_front(),
        }
    }

    /// Retains a dequeued MASQUE response for the next send attempt.
    ///
    /// This slot is intentionally separate from the shared bounded queue so a
    /// concurrent DNS producer cannot consume its released capacity and force
    /// the oldest response to be dropped or reordered.
    pub fn retry_masque_downlink_packet(&mut self, packet: Vec<u8>) {
        debug_assert!(self.masque_downlink_retry.is_none());
        self.masque_downlink_retry = Some(packet);
    }

    /// Drops all locally owned MASQUE response packets during terminal teardown.
    pub fn discard_masque_downlink_packets(&mut self) -> (usize, usize) {
        let retry = self.masque_downlink_retry.take();
        let retry_bytes = retry.as_ref().map_or(0, Vec::len);
        let retry_packets = usize::from(retry.is_some());
        let Some(queue) = self.masque_downlink_queue.as_ref() else {
            return (retry_packets, retry_bytes);
        };
        let (queued_packets, queued_bytes) = match queue.lock() {
            Ok(mut guard) => guard.discard_all(),
            Err(poisoned) => poisoned.into_inner().discard_all(),
        };
        (retry_packets.saturating_add(queued_packets), retry_bytes.saturating_add(queued_bytes))
    }

    pub fn poll_http3(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.poll_http3_event_loop(
            "poll_http3",
            true,
            |_sid, list| {
                let mut status_opt: Option<u16> = None;
                for h in list {
                    if h.name() == b":status" {
                        if let Ok(s) = std::str::from_utf8(h.value()) {
                            status_opt = s.parse::<u16>().ok();
                        }
                    }
                }
                if let Some(st) = status_opt {
                    if !(200..300).contains(&st) {
                        warn!("H3 non-2xx status: {}", st);
                    }
                }
                for h in list {
                    debug!(
                        "{}: {}",
                        String::from_utf8_lossy(h.name()),
                        String::from_utf8_lossy(h.value())
                    );
                }
            },
            |sid, data| {
                debug!("Received {} bytes on stream {}", data.len(), sid);
                debug!("{}", String::from_utf8_lossy(data));
            },
        )
    }

    /// Polls HTTP/3 events and forwards received HEADERS/DATA frames to the provided sinks.
    pub fn poll_http3_with_headers<FH, FB>(
        &mut self,
        on_headers: FH,
        on_body: FB,
    ) -> Result<(), crate::error::ConnectionError>
    where
        FH: FnMut(u64, &[crate::transport::h3::Header]),
        FB: FnMut(u64, &[u8]),
    {
        self.poll_http3_event_loop("poll_http3_with_headers", false, on_headers, on_body)
    }

    /// Polls HTTP/3 events and forwards received DATA frames to the provided sink.
    pub fn poll_http3_with<F>(
        &mut self,
        mut on_body: F,
    ) -> Result<(), crate::error::ConnectionError>
    where
        F: FnMut(&[u8]),
    {
        self.poll_http3_with_headers(|_sid, _headers| {}, |_sid, data| on_body(data))?;
        Ok(())
    }

    /// Returns true if a MASQUE CONNECT-UDP flow is currently registered.
    pub fn masque_flow_active(&self) -> bool {
        self.h3_conn.as_ref().map(|h| h.masque_flow_active()).unwrap_or(false)
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
        diagnostics_enabled: bool,
        phase: &'static str,
        operation: impl FnOnce() -> T,
    ) -> T {
        if !diagnostics_enabled {
            return operation();
        }
        let started = std::time::Instant::now();
        let result = operation();
        let elapsed = started.elapsed();
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
        Self::run_update_state_phase(diagnostics_enabled, "transport-stats", || {
            let stats = self.conn.stats();
            self.stats.packets_sent = stats.sent as u64;
            self.stats.rtt =
                self.conn.path_stats().next().map(|ps| ps.rtt.as_secs_f32()).unwrap_or(0.0);
            self.stats.packets_lost = stats.lost as u64;
            self.stats.loss_rate =
                if stats.sent > 0 { stats.lost as f32 / stats.sent as f32 } else { 0.0 };
            self.stats.update_congestion(CongestionSample::from_transport_stats(stats));
        });

        Self::run_update_state_phase(diagnostics_enabled, "resource-telemetry", || {
            if self.last_telemetry.elapsed() >= std::time::Duration::from_secs(1) {
                telemetry!(telemetry::refresh_resource_metrics_if_due());
                #[cfg(feature = "orchestrator")]
                self.update_orchestrator_resource_signals();
                self.last_telemetry = std::time::Instant::now();
            }
        });

        Self::run_update_state_phase(diagnostics_enabled, "path-events", || {
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

        Self::run_update_state_phase(diagnostics_enabled, "masque-state", || {
            if self.masque_flow_active() {
                crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                self.masque_stream_id = None;
                self.masque_peer_stream_id = None;
            }
        });

        Self::run_update_state_phase(diagnostics_enabled, "fec-observer-sync", || {
            self.transport_observer.sync_runtime_hints(&mut self.conn);
        });

        Self::run_update_state_phase(diagnostics_enabled, "fec-observer-interval", || {
            let interval = self.transport_observer.compute_streaming_interval() as usize;
            if (1..=32).contains(&interval) {
                self.conn.set_fec_stream_every(interval);
            }
        });

        Self::run_update_state_phase(diagnostics_enabled, "fec-control-delta", || {
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
            Self::run_update_state_phase(diagnostics_enabled, "fec-feedback-read", || {
                (self.conn.take_fec_callback_feedback(), self.conn.recovery_loss_rate())
            });
        Self::run_update_state_phase(diagnostics_enabled, "fec-feedback-apply", || {
            Self::apply_fec_transport_feedback(
                &mut self.fec,
                feedback,
                transport_loss_rate,
                diagnostics_enabled,
            );
        });
        Self::run_update_state_phase(diagnostics_enabled, "fec-rtt-hint", || {
            let rtt_ms = self.stats.rtt.max(0.0) as u32;
            self.fec.set_rtt_hint(rtt_ms);
        });

        Self::run_update_state_phase(diagnostics_enabled, "stealth-intelligence", || {
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

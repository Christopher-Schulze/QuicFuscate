// Portions derived from Quinn (https://github.com/quinn-rs/quinn)
// Original code licensed under MIT/Apache-2.0
// Modifications: Copyright (c) QuicFuscate Team, MIT License

//! # Core Forked Connection Runtime
//!
//! This module provides the central `QuicFuscateConnection` struct for the
//! forked QuicFuscate runtime. It orchestrates crypto, FEC, transport, and
//! stealth ownership for the canonical connection lifecycle used by this fork.

use crate::accelerate::transport::{self as transport_accel, CongestionSample};
#[cfg(feature = "orchestrator")]
use crate::brain::DeepIntegrationOrchestrator;
use crate::brain::{CombinedObserver, StealthBrain};
use crate::crypto::CryptoManager;
use crate::fec::{AdaptiveFec, FecConfig, FecPacket, FecTransportObserver};
use crate::optimize::{AlignedBox, MemoryPool, OptimizationManager, OptimizeConfig};
use crate::stealth::{StealthConfig, StealthManager, StealthMode};
use std::sync::Arc;
#[cfg(feature = "orchestrator")]
use std::sync::OnceLock;
// unused on current code path; keep import minimal
use crate::telemetry;
use log::{debug, info, warn};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[cfg(feature = "orchestrator")]
static ORCHESTRATOR: OnceLock<Arc<DeepIntegrationOrchestrator>> = OnceLock::new();
use std::net::SocketAddr;

// Type aliases to simplify handler types
pub type CapsuleHandler = Arc<std::sync::Mutex<Box<dyn FnMut(u64, &[u8]) + Send>>>;
pub type DatagramHandler = Arc<std::sync::Mutex<Box<dyn FnMut(&[u8]) + Send>>>;

struct Http3PollBindings {
    masque_datagram_cb: Option<DatagramHandler>,
    masque_control_cb: Option<CapsuleHandler>,
    masque_cb: Option<CapsuleHandler>,
    memory_pool: Arc<crate::optimize::MemoryPool>,
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
    pub qkey_auth_token_hex: Option<String>,
    /// Shared stealth manager for obfuscation and fingerprint control.
    pub stealth_manager: Arc<StealthManager>,
    /// Shared optimization manager for memory pool and CPU feature detection.
    pub optimization_manager: Arc<OptimizationManager>,
    /// Forward error correction configuration.
    pub fec_config: FecConfig,
}

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    /// Underlying QUIC transport connection handle.
    pub conn: Box<crate::transport::Connection>,
    /// Current peer address (may change on migration).
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,
    qkey_auth_token_hex: Option<String>,

    // Core Modules
    fec: AdaptiveFec,

    // Stealth & Optimization Modules
    stealth_manager: Arc<StealthManager>,
    optimization_manager: Arc<OptimizationManager>,

    // State
    stats: ConnectionStats,
    packet_id_counter: u64,
    // The outgoing buffer now holds fully formed FEC packets, ready for direct sending.
    // This eliminates the serialization overhead entirely.
    outgoing_fec_packets: VecDeque<FecPacket>,
    // Reused FEC emission scratch to avoid allocating a Vec for every packet on the send path.
    fec_send_scratch: Vec<FecPacket>,
    // Reused FEC recovery scratch to avoid allocating a Vec for every packet on the receive path.
    fec_receive_scratch: Vec<FecPacket>,
    h3_conn: Option<crate::transport::h3::Connection>,
    last_telemetry: std::time::Instant,
    // Observer for transport telemetry -> FEC/ACK policy coupling.
    transport_observer: Arc<FecTransportObserver>,
    masque_cb: Option<CapsuleHandler>,
    masque_datagram_cb: Option<DatagramHandler>,
    masque_downlink_queue: Option<Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>>,
    masque_control_cb: Option<CapsuleHandler>,
    /// Locally-initiated MASQUE CONNECT-UDP stream id (client side).
    masque_stream_id: Option<u64>,
    /// Peer-initiated MASQUE CONNECT-UDP stream id (server side: the client opened
    /// the flow; we reuse its stream id for downlink datagram sends).
    masque_peer_stream_id: Option<u64>,
    fec_last_report_sent: u64,
    fec_last_report_lost: u64,
    #[cfg(feature = "orchestrator")]
    runtime_cpu_percent: u32,
    #[cfg(feature = "orchestrator")]
    runtime_memory_pressure: u32,
    tls_ch_override_template: Option<String>,

    // Async Stealth Scheduler State
    next_packet_release: Option<std::time::Instant>,
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
        qkey_auth_token_hex: Option<String>,
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
        }))
    }

    /// Creates a new server-side connection accepted from a remote client.
    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        scid: &crate::transport::ConnectionId,
        odcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
    ) -> Result<Self, String> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
        ));

        let conn = crate::transport::packet::accept(
            scid.as_ref(),
            odcid.as_ref().map(|id| id.as_ref()),
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
        }))
    }

    fn new(params: ConnectionParams) -> Self {
        let obs = FecTransportObserver::new();
        let mut s = Self {
            conn: params.conn,
            peer_addr: params.peer_addr,
            local_addr: params.local_addr,
            host_header: params.host_header,
            qkey_auth_token_hex: params.qkey_auth_token_hex,
            fec: AdaptiveFec::new(params.fec_config),
            stealth_manager: params.stealth_manager,
            optimization_manager: params.optimization_manager,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            fec_send_scratch: Vec::with_capacity(1),
            fec_receive_scratch: Vec::with_capacity(1),
            h3_conn: None,
            last_telemetry: std::time::Instant::now(),
            transport_observer: obs.clone(),
            masque_cb: None,
            masque_datagram_cb: None,
            masque_downlink_queue: None,
            masque_control_cb: None,
            masque_stream_id: None,
            masque_peer_stream_id: None,
            fec_last_report_sent: 0,
            fec_last_report_lost: 0,
            #[cfg(feature = "orchestrator")]
            runtime_cpu_percent: 0,
            #[cfg(feature = "orchestrator")]
            runtime_memory_pressure: 0,
            tls_ch_override_template: Self::env_optional_trimmed(
                "QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE",
            ),
            next_packet_release: None,
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
        use sysinfo::ProcessesToUpdate;

        let mut sys = sysinfo::System::new_all();
        let Ok(pid) = sysinfo::get_current_pid() else {
            return;
        };
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        sys.refresh_memory();
        if let Some(proc_) = sys.process(pid) {
            self.runtime_cpu_percent = proc_.cpu_usage().round().clamp(0.0, 100.0) as u32;
            let total = sys.total_memory();
            let used = proc_.memory();
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
                        on_headers(sid, &list);
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Data))) => {
                        let mut buf = [0; 65535];
                        while let Ok(read) = h3.recv_body(&mut self.conn, sid, &mut buf) {
                            if read == 0 {
                                break;
                            }
                            on_body(sid, &buf[..read]);
                        }
                    }
                    Ok(Some((
                        sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, payload },
                    ))) => {
                        Self::handle_masque_capsule_event(
                            h3,
                            &mut self.conn,
                            sid,
                            capsule_type,
                            &payload,
                            &bindings.masque_datagram_cb,
                            &bindings.masque_control_cb,
                            &bindings.masque_cb,
                            &bindings.memory_pool,
                        );
                    }
                    Ok(Some((_id, crate::transport::h3::Event::Reset(err)))) => {
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
                    Ok(Some((_id, crate::transport::h3::Event::Finished))) => {}
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
                );
            }
            debug!("HTTP/3 events processed in {} ms", start.elapsed().as_millis());
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
    ) {
        let decoded = match dict {
            Some(dict_bytes) => crate::compress::decompress_with_dict(pool, payload, dict_bytes),
            None => crate::compress::CompressionManager::new(Default::default())
                .decompress_to_pool(pool, payload),
        };
        if let Some((blk, used)) = decoded {
            Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, &blk[..used]);
            pool.free(blk);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_masque_capsule_event(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        sid: u64,
        capsule_type: u64,
        payload: &[u8],
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        memory_pool: &Arc<crate::optimize::MemoryPool>,
    ) {
        if !h3.masque_established(sid) {
            h3.mark_masque_established(sid);
            let ack = crate::transport::h3::Connection::encode_capsule(0x02, b"established");
            if let Err(e) = h3.send_capsule(conn, sid, &ack, false) {
                warn!("MASQUE establishment ACK capsule send failed on stream {}: {:?}", sid, e);
            }
        }

        match capsule_type {
            0x00 => {
                Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, payload);
            }
            0x21 => {
                Self::dispatch_masque_compressed_datagram(
                    masque_datagram_cb,
                    masque_cb,
                    memory_pool,
                    payload,
                    None,
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
    ) {
        // Drain whenever a sink is present (TUN bridge) or the stealth runtime
        // explicitly enabled MASQUE datagrams. Without this, MASQUE-framed
        // datagrams would be left in the QUIC datagram queue and either dropped
        // or consumed as corrupted raw bytes by a bare dgram_recv loop.
        let has_sink = masque_datagram_cb.is_some() || masque_cb.is_some();
        if stealth_manager.masque_datagram_enabled() || has_sink {
            while let Some((_fid, pl)) = h3.try_recv_masque_datagram(conn) {
                Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, &pl[..]);
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
        let mut block = self.optimization_manager.alloc_block();
        if data.len() > block.len() {
            // Avoid silent truncation; return a clear error and recycle the block.
            self.optimization_manager.free_block(block);
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let copy_len = data.len();
        block[..copy_len].copy_from_slice(&data[..copy_len]);
        self.recv_pooled_block(block, copy_len)
    }

    /// Processes an incoming packet that already resides in a pooled block.
    pub fn recv_pooled_block(
        &mut self,
        block: AlignedBox<[u8]>,
        len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if len > block.len() {
            self.optimization_manager.free_block(block);
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        let fec_packet = FecPacket::new(
            self.packet_id_counter,
            Some(block),
            len,
            true,
            None,
            0,
            self.optimization_manager.memory_pool().clone(),
        );
        // Ensure unique IDs for subsequent packets
        self.packet_id_counter = self.packet_id_counter.wrapping_add(1);

        let mut recovered_packets = std::mem::take(&mut self.fec_receive_scratch);
        if let Err(e) = self.fec.on_receive_into(fec_packet, &mut recovered_packets) {
            self.fec_receive_scratch = recovered_packets;
            return Err(crate::error::ConnectionError::Transport(format!(
                "FEC decoding failed: {}",
                e
            )));
        }

        for mut packet in recovered_packets.drain(..) {
            // payload_mut_unique() returns None when the FEC decoder still
            // holds an Arc clone of the shared buffer. In that case, copy the
            // payload into a fresh pooled buffer so conn.recv() can mutate it
            // (header protection removal + AEAD decryption are in-place).
            if let Some(data) = packet.payload_mut_unique() {
                self.stealth_manager.process_incoming_packet(data, self.peer_addr);
                let recv_info = crate::transport::RecvInfo {
                    from: self.peer_addr,
                    to: self.local_addr,
                    ecn: None,
                };
                if let Err(e) = self.conn.recv(data, &recv_info) {
                    debug!("transport::recv failed (possible probe): {}", e);
                    self.stealth_manager.handle_fallback(data, self.peer_addr);
                }
            } else if let Some(slice) = packet.payload_slice() {
                let mut buf = self.optimization_manager.alloc_block();
                let n = slice.len().min(buf.len());
                buf[..n].copy_from_slice(&slice[..n]);
                let data = &mut buf[..n];
                self.stealth_manager.process_incoming_packet(data, self.peer_addr);
                let recv_info = crate::transport::RecvInfo {
                    from: self.peer_addr,
                    to: self.local_addr,
                    ecn: None,
                };
                if let Err(e) = self.conn.recv(data, &recv_info) {
                    debug!("transport::recv failed (possible probe): {}", e);
                    self.stealth_manager.handle_fallback(data, self.peer_addr);
                }
                self.optimization_manager.free_block(buf);
            }
        }
        self.fec_receive_scratch = recovered_packets;

        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;

        Ok(len)
    }

    /// Shared receive-side memory pool for socket fast paths.
    pub fn recv_memory_pool(&self) -> Arc<MemoryPool> {
        self.optimization_manager.memory_pool().clone()
    }

    /// Prepares QUIC packets for sending, wraps them in FEC, and buffers them.
    /// This has been completely refactored to eliminate serialization and copies.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        let now = Instant::now();
        let established = self.conn.is_established();
        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;

        // --- REALITY FALLBACK RESPONSE POLLING ---
        // Check if there are any responses from upstream to send back (bypass stealth scheduler)
        if let Some(resp) = self.stealth_manager.poll_fallback() {
            if buf.len() < resp.data.len() {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            buf[..resp.data.len()].copy_from_slice(&resp.data);
            return Ok(resp.data.len());
        }

        // --- ASYNC STEALTH SCHEDULER ---
        // If we are currently throttled by the StealthManager (Brain), yield immediately.
        //
        // Production invariant:
        // Never delay Initial/Handshake flights. Delaying them can stall the connection setup and
        // makes short-lived clients (like E2E) time out. Stealth timing only applies post-handshake.
        if !established {
            self.next_packet_release = None;
        } else if let Some(release_time) = self.next_packet_release {
            if now < release_time {
                return Ok(0); // WouldBlock / Yield
            }
            // Timer expired, clear block and proceed
            self.next_packet_release = None;
        }

        // If there are buffered FEC packets, send one directly - but only if
        // there is no pending stream/datagram data that would be starved by
        // FEC draining. Without this guard, a burst of FEC repair packets can
        // fill the outgoing queue and block new QUIC packets (carrying stream
        // data or DATAGRAM frames) from being generated, causing a liveness
        // deadlock where the peer never receives application data.
        let has_pending_app_data =
            self.conn.writable_streams_count() > 0 || self.conn.dgram_send_queue_len() > 0;
        if !has_pending_app_data {
            if let Some(packet) = self.outgoing_fec_packets.pop_front() {
                let len = packet.to_raw(buf)?;
                // Drop handles pool recycling automatically.
                return Ok(len);
            }
        } else if self.outgoing_fec_packets.len() > 4 {
            // Drain excess FEC packets when the queue grows too large, even
            // with pending app data, to avoid unbounded memory growth.
            // But still fall through to generate a new QUIC packet this turn.
            self.outgoing_fec_packets.drain(4..);
        }

        // Cover PING: inject post-handshake keepalive if the interval has elapsed.
        // The PING lands in pending_control and is flushed by flush_pending_control_frames()
        // inside conn.send(), requiring no extra round-trip through this function.
        if established && self.stealth_manager.should_send_cover_ping() {
            self.conn.queue_cover_ping();
        }
        // Cover stream: inject fake APPLICATION_DATA on a dedicated stream to simulate
        // idle HTTP/3 traffic patterns beyond what PINGs alone can achieve.
        if established && self.stealth_manager.should_inject_cover_stream_frame() {
            let data = self.stealth_manager.generate_cover_stream_data();
            let _ = self.conn.stream_send(StealthManager::COVER_STREAM_ID, &data, false);
        }

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = self.optimization_manager.alloc_block();
        let (write, _send_info) = match self.conn.send(&mut send_buffer) {
            Ok(v) => v,
            Err(crate::error::ConnectionError::Done) => {
                // No packet currently pending is a normal state for polling loops.
                drop(send_buffer);
                return Ok(0);
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
            // The buffer is recycled automatically via Drop.
            drop(send_buffer);
            return Ok(0);
        }

        // The buffer may be larger than the written data; the length is tracked separately.
        // Stealth padding may be applied by the transport configuration; do not mutate the
        // sealed datagram here to preserve AEAD integrity and FEC compatibility.

        // Obfuscate payload if enabled (includes timing/flow shaping)
        // NON-BLOCKING: If delay needed, we schedule it and yield zero bytes.
        let delay_opt = self.stealth_manager.process_outgoing_packet(&mut send_buffer[..write]);

        // Create a source (systematic) FEC packet, passing ownership of the buffer.
        let fec_packet = FecPacket::new(
            self.packet_id_counter,
            Some(send_buffer),
            write,
            true,
            None,
            0,
            // Use the same pool the buffer was allocated from to avoid cross-pool leaks
            self.optimization_manager.memory_pool().clone(),
        );
        self.packet_id_counter += 1;

        // Pass to FEC encoder to get original + repair packets.
        // Reuse the scratch Vec so the common Zero/no-repair path stays allocation-free.
        self.fec.on_send_into(fec_packet, &mut self.fec_send_scratch);
        for pkt in self.fec_send_scratch.drain(..) {
            self.outgoing_fec_packets.push_back(pkt);
        }

        // Single outbound stealth timing owner: core merges StealthManager shaping delay
        // with transport jitter (when enabled) into one release deadline. Connection::send
        // no longer maintains a parallel next_send_at gate.
        if established {
            let transport_jitter = self.conn.transport_stealth_jitter_delay();
            if let Some(release_at) =
                Self::compute_outbound_stealth_release(now, delay_opt, transport_jitter)
            {
                self.next_packet_release = Some(release_at);
                return Ok(0); // Yield immediately, do not send the just-generated packets yet.
            }
        }

        // Pop the first packet from the buffer to send it now.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            let len = packet.to_raw(buf)?;
            // Drop handles pool recycling automatically.
            Ok(len)
        } else {
            Ok(0)
        }
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
        self.send_http3_request_headers(b"POST", path, false)
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
        // Compatibility-only MASQUE path for UDP-like payload forwarding.
        if !data.is_empty() {
            match self.ensure_masque_tunnel_for_send() {
                Ok(Some(sid)) => {
                    if let Some(ref mut h3) = self.h3_conn {
                        match h3.send_masque_datagram(&mut self.conn, sid, data) {
                            Ok(()) => {
                                debug!("MASQUE TX: sid={} {}B", sid, data.len());
                                return Ok(());
                            }
                            Err(e) => {
                                warn!(
                                    "MASQUE datagram send failed, falling back to H3 body: {:?}",
                                    e
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("MASQUE tunnel setup failed, falling back to H3 body: {:?}", e),
            }
        }

        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, data, fin)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
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

    /// Sends a raw IP packet downlink to the peer over the peer-initiated MASQUE
    /// CONNECT-UDP flow (server side: client opened the flow, we reuse its stream
    /// id for the datagram flow-id mapping). Returns `Done` if no MASQUE flow has
    /// been established yet - the packet is dropped, which is acceptable for
    /// best-effort IP traffic; subsequent packets will succeed once the client's
    /// CONNECT-UDP request is processed and `masque_peer_stream_id` is set.
    ///
    /// A bare QUIC datagram fallback was intentionally removed: the client only
    /// drains MASQUE-framed datagrams via `drain_masque_datagrams` and would
    /// never consume a bare dgram, causing silent data loss and queue growth.
    pub fn send_masque_downlink(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if let Some(sid) = self.masque_peer_stream_id {
            if let Some(ref mut h3) = self.h3_conn {
                h3.send_masque_datagram(&mut self.conn, sid, payload)?;
                debug!("MASQUE downlink TX: sid={} {}B", sid, payload.len());
                return Ok(());
            }
        }
        // No MASQUE flow yet - drop the packet. The client's CONNECT-UDP
        // request is processed asynchronously in poll_http3_event_loop, which
        // sets masque_peer_stream_id. Retrying is unnecessary: the TUN reader
        // thread sends the next packet immediately, and IP traffic is
        // best-effort (lost packets are retransmitted by higher layers).
        Err(crate::error::ConnectionError::Done)
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
    pub fn set_masque_downlink_queue(&mut self, queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>) {
        self.masque_downlink_queue = Some(queue);
    }

    /// Returns the installed MASQUE downlink queue, if present.
    pub fn masque_downlink_queue(&self) -> Option<Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>> {
        self.masque_downlink_queue.as_ref().cloned()
    }

    /// Returns true if the MASQUE downlink response queue has been installed.
    pub fn has_masque_downlink_queue(&self) -> bool {
        self.masque_downlink_queue.is_some()
    }

    /// Drains queued MASQUE downlink raw IP packets.
    pub fn drain_masque_downlink_queue(&mut self) -> Vec<Vec<u8>> {
        let Some(queue) = self.masque_downlink_queue.as_ref() else {
            return Vec::new();
        };
        match queue.lock() {
            Ok(mut guard) => guard.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        }
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

    /// Update internal state, e.g., FEC mode based on statistics.
    pub fn update_state(&mut self) {
        // Update stats
        let stats = self.conn.stats();
        self.stats.packets_sent = stats.sent as u64;
        self.stats.rtt =
            self.conn.path_stats().next().map(|ps| ps.rtt.as_secs_f32()).unwrap_or(0.0);
        self.stats.packets_lost = stats.lost as u64;
        self.stats.loss_rate =
            if stats.sent > 0 { stats.lost as f32 / stats.sent as f32 } else { 0.0 };
        self.stats.update_congestion(CongestionSample::from_transport_stats(stats));

        if self.last_telemetry.elapsed() >= std::time::Duration::from_secs(1) {
            telemetry!(telemetry::update_memory_usage());
            telemetry!(telemetry::flush());
            #[cfg(feature = "orchestrator")]
            self.update_orchestrator_resource_signals();
            self.last_telemetry = std::time::Instant::now();
        }

        // Handle path events for connection migration
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

        if self.masque_flow_active() {
            crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
            self.masque_stream_id = None;
            self.masque_peer_stream_id = None;
        }

        // Sync FEC-owned runtime hints only. Generic transport actuators are driven
        // through the live transport observer path, not duplicated here.
        self.transport_observer.sync_runtime_hints(&mut self.conn);
        // Opportunistic FEC streaming interval from observer (independent of brain)
        let ivl = self.transport_observer.compute_streaming_interval() as usize;
        if (1..=32).contains(&ivl) {
            self.conn.set_fec_stream_every(ivl);
        }

        // Consume FEC control deltas from transport and apply to core AdaptiveFec
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

        // Drive AdaptiveFec loss estimator using callback feedback first, then transport deltas.
        let (cb_sent_pkts, cb_lost_pkts, _cb_sent_bytes, _cb_lost_bytes) =
            self.conn.take_fec_callback_feedback();
        if cb_sent_pkts > 0 || cb_lost_pkts > 0 {
            let total_obs = cb_sent_pkts.saturating_add(cb_lost_pkts).max(cb_lost_pkts);
            self.fec.report_loss(
                cb_lost_pkts.min(usize::MAX as u64) as usize,
                total_obs.min(usize::MAX as u64) as usize,
            );
        } else {
            let sent_total = self.stats.packets_sent;
            let lost_total = self.stats.packets_lost;
            let sent_delta = sent_total.saturating_sub(self.fec_last_report_sent);
            let lost_delta = lost_total.saturating_sub(self.fec_last_report_lost);
            if sent_delta > 0 {
                self.fec.report_loss(
                    lost_delta.min(usize::MAX as u64) as usize,
                    sent_delta.min(usize::MAX as u64) as usize,
                );
                self.fec_last_report_sent = sent_total;
                self.fec_last_report_lost = lost_total;
            }
        }

        // Feed RTT estimate to FEC controller for stream_every scaling.
        let rtt_ms = self.stats.rtt.max(0.0) as u32;
        self.fec.set_rtt_hint(rtt_ms);

        // Sync stealth runtime level with brain's intelligent level hint.
        self.stealth_manager.sync_intelligent_level();
    }

    /// Returns the current estimated RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        self.stats.rtt
    }

    /// Returns the current estimated packet loss rate in [0.0, 1.0].
    pub fn loss_rate(&self) -> f32 {
        self.stats.loss_rate
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_stats_default_zeroed() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.rtt, 0.0);
        assert_eq!(stats.loss_rate, 0.0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.congestion_cwnd, 0);
        assert_eq!(stats.congestion_bytes_in_flight, 0);
        assert_eq!(stats.congestion_delivery_rate, 0);
        assert_eq!(stats.congestion_lost, 0);
        assert_eq!(stats.congestion_score, 0);
        assert!(stats.congestion_samples.is_empty());
    }

    #[test]
    fn connection_stats_congestion_update_window_rotation() {
        let mut stats = ConnectionStats::default();
        let cap = transport_accel::CONGESTION_WINDOW_SIZE;
        for i in 0..(cap + 5) {
            let sample = CongestionSample {
                cwnd: (i as u32) * 1000,
                bytes_in_flight: (i as u32) * 500,
                delivery_rate: (i as u32) * 100,
                lost_packets: i as u32,
            };
            stats.update_congestion(sample);
        }
        assert_eq!(stats.congestion_samples.len(), cap);
    }

    #[test]
    fn env_optional_trimmed_returns_none_for_missing() {
        let result =
            QuicFuscateConnection::env_optional_trimmed("QUICFUSCATE_TEST_NONEXISTENT_VAR_XYZ");
        assert!(result.is_none());
    }

    #[test]
    fn env_optional_trimmed_trims_whitespace() {
        let key = "QUICFUSCATE_TEST_TRIM_WS";
        std::env::set_var(key, "  hello  ");
        let result = QuicFuscateConnection::env_optional_trimmed(key);
        assert_eq!(result, Some("hello".to_string()));
        std::env::remove_var(key);
    }

    #[test]
    fn env_optional_trimmed_returns_none_for_empty() {
        let key = "QUICFUSCATE_TEST_TRIM_EMPTY";
        std::env::set_var(key, "   ");
        let result = QuicFuscateConnection::env_optional_trimmed(key);
        assert!(result.is_none());
        std::env::remove_var(key);
    }

    #[test]
    fn inject_qkey_auth_header_adds_header() {
        let mut headers = vec![];
        QuicFuscateConnection::inject_qkey_auth_header(Some("abc123"), &mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name(), b"x-qf-auth");
        assert_eq!(headers[0].value(), b"abc123");
    }

    #[test]
    fn inject_qkey_auth_header_skips_empty_token() {
        let mut headers = vec![];
        QuicFuscateConnection::inject_qkey_auth_header(Some("  "), &mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn inject_qkey_auth_header_replaces_existing() {
        let mut headers = vec![
            crate::transport::h3::Header::new(b"x-qf-auth", b"old"),
            crate::transport::h3::Header::new(b"content-type", b"text"),
        ];
        QuicFuscateConnection::inject_qkey_auth_header(Some("new_token"), &mut headers);
        assert_eq!(headers.len(), 2);
        let auth = headers.iter().find(|h| h.name() == b"x-qf-auth").unwrap();
        assert_eq!(auth.value(), b"new_token");
    }

    #[test]
    fn inject_qkey_auth_header_noop_without_token() {
        let mut headers = vec![crate::transport::h3::Header::new(b"host", b"example.com")];
        QuicFuscateConnection::inject_qkey_auth_header(None, &mut headers);
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn outbound_stealth_release_merges_to_single_latest_deadline() {
        let now = Instant::now();
        let manager_delay = Duration::from_millis(8);
        let transport_jitter = Duration::from_millis(3);
        let release = QuicFuscateConnection::compute_outbound_stealth_release(
            now,
            Some(manager_delay),
            Some(transport_jitter),
        )
        .expect("both delays should produce a release");
        assert_eq!(release, now + manager_delay);

        let jitter_only = QuicFuscateConnection::compute_outbound_stealth_release(
            now,
            None,
            Some(transport_jitter),
        )
        .expect("transport jitter alone should schedule release");
        assert_eq!(jitter_only, now + transport_jitter);
    }

    #[test]
    fn outbound_stealth_release_none_when_no_delays() {
        let now = Instant::now();
        assert!(QuicFuscateConnection::compute_outbound_stealth_release(now, None, None).is_none());
    }
}

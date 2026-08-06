#[cfg(all(target_os = "linux", feature = "io_uring"))]
type LiveUringWorker = crate::optimize::uring_batch::UringBatchWorker;
#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
type LiveUringWorker = ();

pub fn load_server_identity(
    config: &mut crate::transport::Config,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    lock_memory: bool,
) -> std::io::Result<()> {
    let cert_str = cert_path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid certificate path")
    })?;
    if let Err(e) = config.load_cert_chain_from_pem_file(cert_str) {
        log::error!("Failed to load server cert {}: {}", cert_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid certificate path",
        ));
    }

    let key_str = key_path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid private key path")
    })?;
    if let Err(e) = config.load_priv_key_from_pem_file(key_str) {
        log::error!("Failed to load server key {}: {}", key_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid private key path",
        ));
    }

    let preload_status = crate::qftls::preload_tls_server_identity(cert_str, key_str, lock_memory)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()))?;
    log::info!("Preloaded TLS server identity: {:?}", preload_status);
    Ok(())
}

pub fn start_runtime_profile_rotation(
    runtime_owner: &Arc<StealthRuntimeOwner>,
    stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    profiles: Vec<FingerprintProfile>,
    profile_interval_secs: u64,
) -> Result<(), String> {
    runtime_owner.start(Some(stealth_config), profiles, profile_interval_secs)
}

pub fn start_standalone_metrics_service(runtime: &mut ServerRuntime, port: u16) {
    let server = self::metrics::MetricsServer::new(port, runtime.standalone_metrics());
    runtime.register_metrics_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown is handled via the
    // registered shutdown signal above. Errors are logged inside the task.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("metrics server failed: {}", e);
        }
    });
}

#[cfg(unix)]
pub fn start_standalone_admin_service(
    runtime: &mut ServerRuntime,
    path: std::path::PathBuf,
    core: ServerAdminCore,
) {
    let handler = ServerAdminRuntimeHandler::new(core);
    let server = AdminServer::new(path, Arc::new(handler));
    runtime.register_admin_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown via registered signal.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("admin server failed: {}", e);
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_standalone_admin_web_service(
    runtime: &mut ServerRuntime,
    addr: std::net::SocketAddr,
    web_root: std::path::PathBuf,
    auth: AdminAuth,
    auth_path: std::path::PathBuf,
    max_connections: usize,
    operation_timeout_ms: u64,
    handler: ServerAdminHttpRuntimeHandler,
    operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
) -> std::io::Result<()> {
    let server = AdminHttpServer::new_with_max_connections_and_operation_timeout_and_diagnostics_and_clock(
        addr,
        web_root,
        Some(auth),
        Some(auth_path),
        Arc::new(handler),
        max_connections,
        operation_timeout_ms,
        operation_diagnostics,
        runtime.clock.clone(),
    )?;
    runtime.register_admin_web_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown via registered signal.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("admin web server failed: {}", e);
        }
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn start_configured_standalone_admin_web_service(
    runtime: &mut ServerRuntime,
    addr: std::net::SocketAddr,
    web_root: std::path::PathBuf,
    max_connections: usize,
    operation_timeout_ms: u64,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    config_path: Option<&std::path::Path>,
    blocked_ips_path: Option<std::path::PathBuf>,
    initial_logging_mode: String,
    mut admin_core: ServerAdminCore,
    admin_log_buffer: Arc<self::admin_logs::AdminLogBuffer>,
) -> std::io::Result<()> {
    let auth = resolve_admin_web_auth(admin_web_user, admin_web_password)?;
    let operation_diagnostics = AdminHttpOperationDiagnostics::new(operation_timeout_ms)?;
    admin_core.set_admin_http_operation_diagnostics(Arc::clone(&operation_diagnostics));
    let logging_mode = Arc::new(parking_lot::RwLock::new(initial_logging_mode));
    let handler = ServerAdminHttpRuntimeHandler::new(
        admin_core,
        blocked_ips_path,
        config_path.map(std::path::Path::to_path_buf),
        logging_mode,
        admin_log_buffer,
    );
    let auth_path = resolve_admin_auth_store_path(config_path);
    start_standalone_admin_web_service(
        runtime,
        addr,
        web_root,
        auth,
        auth_path,
        max_connections,
        operation_timeout_ms,
        handler,
        operation_diagnostics,
    )?;
    Ok(())
}

pub fn find_live_client_by_dcid(
    clients: &std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    from: SocketAddr,
    packet: &[u8],
) -> Option<SocketAddr> {
    clients.iter().find_map(|(addr, conn)| {
        if *addr == from {
            return None;
        }
        let source_id = conn.conn.source_id();
        let (header, _) =
            crate::transport::packet::parse_header(packet, source_id.as_ref().len()).ok()?;
        (source_id.as_ref() == header.dcid.as_slice()).then_some(*addr)
    })
}

pub fn reconcile_live_clients(
    clients: &mut std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    qkey_auth: &mut std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    accept_loop: &AcceptLoop,
    metrics: &Metrics,
) -> Vec<SocketAddr> {
    let closed_addrs: Vec<_> =
        clients.iter().filter_map(|(addr, conn)| conn.conn.is_closed().then_some(*addr)).collect();
    for addr in &closed_addrs {
        accept_loop.record_closed(*addr);
    }
    clients.retain(|_, conn| !conn.conn.is_closed());
    qkey_auth.retain(|conn_id, _| {
        clients.values().any(|conn| conn.conn.source_id().as_ref() == conn_id.as_slice())
    });
    metrics.clients_active.store(clients.len() as u64, Ordering::Relaxed);
    closed_addrs
}

pub struct LiveInitialAuthContext {
    pub initial_key_dcid: crate::transport::ConnectionId,
    pub version: u32,
    pub qkey_record: Option<QKeyRecord>,
    pub pending_qkey_auth: Option<QKeyAuthState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveInitialAuthError {
    MalformedPacket,
    MissingCredential,
    InvalidCredential,
    RevokedCredential,
}

impl LiveInitialAuthError {
    pub fn is_auth_failure(self) -> bool {
        !matches!(self, Self::MalformedPacket)
    }
}

pub(crate) fn parse_live_server_initial_auth(
    packet: &[u8],
    remote_ip: IpAddr,
    retry_token_manager: Option<&crate::implementations::server::ddos::RetryTokenManager>,
    qkey_registry: &std::sync::Mutex<QKeyRegistry>,
    revocation_manager: &crate::implementations::server::revocation::RevocationManager,
    auth_attempt: crate::implementations::server::limits::AuthAttempt,
) -> Result<LiveInitialAuthContext, LiveInitialAuthError> {
    let (mut initial_hdr, _) = match crate::transport::packet::parse_header(packet, 0) {
        Ok(value) => value,
        Err(_) => return Err(LiveInitialAuthError::MalformedPacket),
    };
    if initial_hdr.ty != crate::transport::PacketType::Initial {
        return Err(LiveInitialAuthError::MalformedPacket);
    }

    let version = initial_hdr.version;
    let initial_key_dcid = crate::transport::ConnectionId::from_ref(&initial_hdr.dcid);
    let mut initial_token = initial_hdr.token.take();
    if initial_token
        .as_deref()
        .is_some_and(crate::implementations::server::ddos::RetryTokenManager::is_retry_token)
    {
        let Some(manager) = retry_token_manager else {
            return Err(LiveInitialAuthError::InvalidCredential);
        };
        let claims = manager
            .validate(initial_token.as_deref().unwrap_or_default(), remote_ip, &initial_hdr.dcid)
            .map_err(|_| LiveInitialAuthError::InvalidCredential)?;
        initial_token = Some(claims.credential);
    }
    let require_qkey = require_qkey_for_new_clients();
    let mut qkey_record = None;
    let mut pending_qkey_auth = None;

    if require_qkey {
        let token = match initial_token {
            Some(token) if !token.is_empty() => token,
            _ => return Err(LiveInitialAuthError::MissingCredential),
        };
        let record = {
            let mut registry = qkey_registry.lock().unwrap_or_else(|error| error.into_inner());
            registry.lookup_initial_id_token(&token)
        };
        let Some(record) = record else {
            return Err(LiveInitialAuthError::InvalidCredential);
        };
        if revocation_manager.is_revoked(&record.id) {
            return Err(LiveInitialAuthError::RevokedCredential);
        }
        pending_qkey_auth = Some(QKeyAuthState {
            key_id: record.id.clone(),
            expected_token_sha256: record.token_sha256.clone(),
            bandwidth_policy: record.bandwidth_policy.clone(),
            traffic_analysis_policy: record.traffic_analysis_policy,
            authed: false,
            post_handshake_started_at: None,
            auth_attempt: Some(auth_attempt),
        });
        qkey_record = Some(record);
    }

    Ok(LiveInitialAuthContext { initial_key_dcid, version, qkey_record, pending_qkey_auth })
}

pub fn apply_qkey_policy_overrides(
    record: &QKeyRecord,
    stealth_config: &mut crate::stealth::StealthConfig,
    fec_config: &mut crate::fec::FecConfig,
) {
    if let Some(mode_raw) = record.stealth.as_deref() {
        let mode = mode_raw.trim().to_ascii_lowercase();
        let mapped = match mode.as_str() {
            "off" => Some(crate::stealth::StealthMode::Off),
            "performance" => Some(crate::stealth::StealthMode::Performance),
            "stealth" => Some(crate::stealth::StealthMode::Stealth),
            "anti-dpi" | "antidpi" | "max" => Some(crate::stealth::StealthMode::AntiDpi),
            "manual" => Some(crate::stealth::StealthMode::Manual),
            "auto" | "intelligent" => Some(crate::stealth::StealthMode::Intelligent),
            _ => None,
        };
        if let Some(mapped) = mapped {
            stealth_config.mode = mapped;
        }
    }
    if let Some(fec_raw) = record.fec.as_deref() {
        match normalize_qkey_fec(Some(fec_raw)) {
            Ok("off") => {
                fec_config.apply_engine_mode(crate::engine::FecMode::Off);
            }
            Ok("auto") => {
                fec_config.apply_engine_mode(crate::engine::FecMode::Auto);
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

pub fn create_live_server_connection(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_config: &mut crate::transport::Config,
    stealth_config: crate::stealth::StealthConfig,
    fec_config: crate::fec::FecConfig,
    opt_params: crate::optimize::OptimizeConfig,
    initial_key_dcid: &crate::transport::ConnectionId,
) -> Result<QuicFuscateConnection, String> {
    create_live_server_connection_with_runtime(
        local_addr,
        remote_addr,
        transport_config,
        stealth_config,
        fec_config,
        opt_params,
        initial_key_dcid,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_live_server_connection_with_runtime(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_config: &mut crate::transport::Config,
    stealth_config: crate::stealth::StealthConfig,
    fec_config: crate::fec::FecConfig,
    opt_params: crate::optimize::OptimizeConfig,
    initial_key_dcid: &crate::transport::ConnectionId,
    runtime_owner: Option<Arc<StealthRuntimeOwner>>,
) -> Result<QuicFuscateConnection, String> {
    create_live_server_connection_with_runtime_and_clock(
        local_addr,
        remote_addr,
        transport_config,
        stealth_config,
        fec_config,
        opt_params,
        initial_key_dcid,
        runtime_owner,
        crate::time_source::ProtocolClock::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_live_server_connection_with_runtime_and_clock(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_config: &mut crate::transport::Config,
    stealth_config: crate::stealth::StealthConfig,
    fec_config: crate::fec::FecConfig,
    opt_params: crate::optimize::OptimizeConfig,
    initial_key_dcid: &crate::transport::ConnectionId,
    runtime_owner: Option<Arc<StealthRuntimeOwner>>,
    clock: crate::time_source::ProtocolClock,
) -> Result<QuicFuscateConnection, String> {
    let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut scid_bytes);
    let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);
    QuicFuscateConnection::new_server_with_runtime_and_clock(
        &scid,
        Some(initial_key_dcid),
        local_addr,
        remote_addr,
        transport_config,
        stealth_config,
        fec_config,
        opt_params,
        runtime_owner,
        clock,
    )
}

pub enum QKeyHeaderAuthOutcome {
    Unchanged,
    Authenticated,
    Reject(&'static [u8]),
}

pub fn evaluate_qkey_http3_headers(
    headers: &[crate::transport::h3::Header],
    expected_token_sha256: Option<&str>,
    already_authed: bool,
) -> QKeyHeaderAuthOutcome {
    let Some(expected) = expected_token_sha256 else {
        return QKeyHeaderAuthOutcome::Unchanged;
    };
    if already_authed {
        return QKeyHeaderAuthOutcome::Unchanged;
    }

    let mut provided: Option<&[u8]> = None;
    for header in headers {
        if header.name().eq_ignore_ascii_case(b"x-qf-auth") {
            provided = Some(header.value());
            break;
        }
    }

    let Some(provided) = provided else {
        return QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied");
    };
    let provided = match std::str::from_utf8(provided) {
        Ok(value) => value.trim(),
        Err(_) => return QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied"),
    };
    if crate::implementations::server::qkey_registry::token_matches_hash(provided, expected.trim())
    {
        QKeyHeaderAuthOutcome::Authenticated
    } else {
        QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied")
    }
}

#[inline]
fn qkey_payload_allowed(require_auth: bool, authenticated: bool) -> bool {
    !require_auth || authenticated
}

pub fn close_live_client_for_qkey_auth_failure(
    conn: &mut QuicFuscateConnection,
    remote_addr: SocketAddr,
    reason: &'static [u8],
) {
    if let Err(error) = conn.conn.close(true, 0x0, reason) {
        log::warn!("Client close after QKey auth failure failed for {}: {:?}", remote_addr, error);
    }
}

fn record_live_snapshot_bytes_out(
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    addr: SocketAddr,
    bytes_out: u64,
    session_id: Option<SessionId>,
) {
    if bytes_out == 0 {
        return;
    }
    if let Ok(mut guard) = client_snapshots.lock() {
        if let Some(snapshot) = guard.get_mut(&addr) {
            if let Some(session_id) = session_id {
                snapshot.set_session_id(session_id);
            }
            snapshot.record_bytes_out(bytes_out);
        }
    }
}

fn record_live_snapshot_bytes_in(
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    addr: SocketAddr,
    bytes_in: u64,
    stealth_mode: String,
    session_id: Option<SessionId>,
    connected_at: std::time::Instant,
) {
    if bytes_in == 0 {
        return;
    }
    let mut snapshots_guard = match client_snapshots.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let snap = snapshots_guard
        .entry(addr)
        .or_insert_with(|| ClientSnapshot::new_at(stealth_mode.clone(), connected_at));
    if let Some(session_id) = session_id {
        snap.set_session_id(session_id);
    }
    snap.record_bytes_in(bytes_in, stealth_mode);
}

pub struct LiveClientDatagramResult {
    pub auth_result: Option<(Vec<u8>, bool)>,
    pub remove_auth_conn_id: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QKeyDatagramAuthProgress {
    Pending,
    Authenticated,
    Rejected,
}

fn qkey_datagram_auth_result(
    conn_id: &[u8],
    progress: QKeyDatagramAuthProgress,
) -> Option<(Vec<u8>, bool)> {
    match progress {
        QKeyDatagramAuthProgress::Pending => None,
        QKeyDatagramAuthProgress::Authenticated => Some((conn_id.to_vec(), true)),
        QKeyDatagramAuthProgress::Rejected => Some((conn_id.to_vec(), false)),
    }
}

#[cfg(unix)]
pub async fn send_live_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    // Use `async_io` to avoid edge-triggered busy-loop (same fix as recv).
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::WRITABLE, || {
            let zc = ZeroCopyBuffer::new(&[data]).map_err(std::io::Error::from)?;
            let transfer = zc.send_to(fd, *addr).map_err(std::io::Error::from)?;
            if transfer.is_complete() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send_to",
                ))
            }
        })
        .await
}

#[cfg(not(unix))]
pub async fn send_live_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    use tokio::io::Interest;

    loop {
        socket.ready(Interest::WRITABLE).await?;
        match socket.try_send_to(data, *addr) {
            Ok(len) if len == data.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send_to",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn flush_live_server_outgoing(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    conn: &mut QuicFuscateConnection,
    out: &mut [u8],
    metrics: &Metrics,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    session_stats: Option<Arc<SessionStats>>,
    session_id: Option<SessionId>,
    uring_worker: Option<&LiveUringWorker>,
) -> Result<(u64, u64), DataPlaneFault> {
    let mut bytes_sent = 0u64;
    let mut packets_sent = 0u64;

    // Collect all outgoing packets from this connection before sending.
    // This lets us submit them as a single io_uring batch (one io_uring_enter
    // syscall instead of one sendmsg per packet).
    let mut staging: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    while staging.len() < crate::transport::UDP_DATAGRAM_BURST_LIMIT {
        match conn.send_with_info(out) {
            Ok((len, send_info)) if len > 0 => {
                crate::telemetry::BYTES_SENT.inc_by(len as u64);
                metrics.record_egress_datagram(len);
                if let Some(stats) = session_stats.as_ref() {
                    stats.record_sent(len as u64);
                }
                bytes_sent = bytes_sent.saturating_add(len as u64);
                packets_sent = packets_sent.saturating_add(1);
                staging.push((send_info.to, out[..len].to_vec()));
            }
            Ok(_) => break,
            Err(crate::error::ConnectionError::Done) => break,
            Err(error) => {
                log::error!("Send failed to {}: {:?}", addr, error);
                return Err(DataPlaneFault::TransportSend {
                    component: format!("server connection send to {addr}"),
                    error: error.to_string(),
                });
            }
        }
    }
    if staging.len() == crate::transport::UDP_DATAGRAM_BURST_LIMIT {
        log::debug!(
            "Outgoing flush for {} reached the {} datagram burst limit",
            addr,
            crate::transport::UDP_DATAGRAM_BURST_LIMIT
        );
    }

    if !staging.is_empty() {
        // Try io_uring batch on Linux when the feature is compiled in.
        // Full success returns early; partial success falls through for the unsent tail.
        let already_sent = {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                use std::os::unix::io::AsRawFd;
                let fd = socket.as_raw_fd();
                let packets: Vec<(SocketAddr, &[u8])> =
                    staging.iter().map(|(target, packet)| (*target, packet.as_slice())).collect();
                match uring_worker {
                    Some(worker) => match worker.send_batch_to(fd, &packets).await {
                        Ok(sent) => sent.min(staging.len()),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            log::debug!("io_uring server worker busy, using async tail: {error}");
                            0
                        }
                        Err(error) => {
                            return Err(DataPlaneFault::TransportSend {
                                component: "server io_uring blocking worker".to_string(),
                                error: error.to_string(),
                            });
                        }
                    },
                    None => 0,
                }
            }

            #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
            {
                0usize
            }
        };
        #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
        let _ = uring_worker;
        if already_sent == staging.len() {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
                return Ok((bytes_sent, packets_sent));
            }
        }
        // io_uring unavailable, failed, or partially sent: finish via individual async calls.
        for (target, packet) in staging.iter().skip(already_sent) {
            send_live_datagram_to(socket, target, packet).await.map_err(|error| {
                DataPlaneFault::TransportSend {
                    component: format!("server UDP send to {target}"),
                    error: error.to_string(),
                }
            })?;
        }
    }

    record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
    Ok((bytes_sent, packets_sent))
}

#[derive(Debug)]
struct ClientFanoutPacket {
    source: SocketAddr,
    destination: IpAddr,
    packet: Vec<u8>,
}

const MAX_CLIENT_FANOUT_ENTRIES: usize = 256;
const MAX_CLIENT_FANOUT_BYTES: usize = 384 * 1024;
const MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE: usize = 32;
const MAX_CLIENT_FANOUT_BYTES_PER_SOURCE: usize = 64 * 1024;
const MAX_CLIENT_FANOUT_DRAIN_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
struct ClientFanoutSourceUsage {
    entries: usize,
    bytes: usize,
}

#[derive(Debug)]
struct ClientFanoutQueueState {
    packets: std::collections::VecDeque<ClientFanoutPacket>,
    bytes: usize,
    source_usage: std::collections::HashMap<SocketAddr, ClientFanoutSourceUsage>,
    max_entries: usize,
    max_bytes: usize,
    max_source_entries: usize,
    max_source_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientFanoutReject {
    Queue,
    Bytes,
    PerSource,
    PerSourceBytes,
}

impl ClientFanoutQueueState {
    fn new() -> Self {
        Self::with_limits(
            MAX_CLIENT_FANOUT_ENTRIES,
            MAX_CLIENT_FANOUT_BYTES,
            MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE,
            MAX_CLIENT_FANOUT_BYTES_PER_SOURCE,
        )
    }

    fn with_limits(
        max_entries: usize,
        max_bytes: usize,
        max_source_entries: usize,
        max_source_bytes: usize,
    ) -> Self {
        Self {
            packets: std::collections::VecDeque::new(),
            bytes: 0,
            source_usage: std::collections::HashMap::new(),
            max_entries,
            max_bytes,
            max_source_entries,
            max_source_bytes,
        }
    }

    fn enqueue(
        &mut self,
        source: SocketAddr,
        destination: IpAddr,
        packet: &[u8],
    ) -> Result<(), ClientFanoutReject> {
        let packet_bytes = packet.len();
        if self.packets.len() >= self.max_entries {
            return Err(ClientFanoutReject::Queue);
        }
        if packet_bytes > self.max_bytes.saturating_sub(self.bytes) {
            return Err(ClientFanoutReject::Bytes);
        }
        let source_usage = self.source_usage.get(&source).copied().unwrap_or_default();
        if source_usage.entries >= self.max_source_entries {
            return Err(ClientFanoutReject::PerSource);
        }
        if packet_bytes > self.max_source_bytes.saturating_sub(source_usage.bytes) {
            return Err(ClientFanoutReject::PerSourceBytes);
        }

        self.packets.push_back(ClientFanoutPacket {
            source,
            destination,
            packet: packet.to_vec(),
        });
        self.bytes += packet_bytes;
        let source_usage = self.source_usage.entry(source).or_default();
        source_usage.entries += 1;
        source_usage.bytes += packet_bytes;
        Ok(())
    }

    fn pop_front(&mut self) -> Option<ClientFanoutPacket> {
        let fanout = self.packets.pop_front()?;
        let packet_bytes = fanout.packet.len();
        self.bytes = self.bytes.saturating_sub(packet_bytes);
        let remove_source = if let Some(source_usage) = self.source_usage.get_mut(&fanout.source) {
            source_usage.entries = source_usage.entries.saturating_sub(1);
            source_usage.bytes = source_usage.bytes.saturating_sub(packet_bytes);
            source_usage.entries == 0
        } else {
            false
        };
        if remove_source {
            self.source_usage.remove(&fanout.source);
        }
        Some(fanout)
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.packets.len()
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.bytes
    }
}

type ClientFanoutQueue = Arc<std::sync::Mutex<ClientFanoutQueueState>>;

fn new_client_fanout_queue() -> ClientFanoutQueue {
    Arc::new(std::sync::Mutex::new(ClientFanoutQueueState::new()))
}

fn enqueue_client_fanout(
    queue: &ClientFanoutQueue,
    metrics: &Metrics,
    source: SocketAddr,
    route: UplinkRoute,
    packet: &[u8],
) {
    let destination = match route {
        UplinkRoute::Broadcast { destination, .. } => IpAddr::V4(destination),
        UplinkRoute::Multicast { destination, .. } => destination,
        UplinkRoute::Local { .. } | UplinkRoute::Internet { .. } | UplinkRoute::Client { .. } => {
            return;
        }
    };
    let mut queue = match queue.lock() {
        Ok(queue) => queue,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Err(reject) = queue.enqueue(source, destination, packet) {
        metrics.record_client_fanout_drop();
        log::debug!("Client fan-out packet dropped before queue admission: {:?}", reject);
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn allow_client_uplink(
    forwarding_policy: &ClientIsolationManager,
    metrics: &Metrics,
    assigned_ips: Option<AssignedClientIps>,
    packet: &[u8],
    fingerprint_profile: OsFingerprintProfile,
    server_ips: ServerTunIps,
    tun_mtu: u16,
    response_queue: &Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
) -> Option<UplinkRoute> {
    let route = match forwarding_policy.evaluate_uplink(packet, assigned_ips) {
        Ok(route) => route,
        Err(reason) => {
            metrics.record_uplink_drop(reason);
            log::debug!("Client uplink dropped by forwarding policy: {:?}", reason);
            return None;
        }
    };
    let route = match route {
        UplinkRoute::Internet { source, destination }
            if destination == IpAddr::V4(server_ips.ipv4)
                || server_ips.ipv6.is_some_and(|ipv6| destination == IpAddr::V6(ipv6)) =>
        {
            UplinkRoute::Local { source, destination }
        }
        route => route,
    };
    metrics.record_uplink_route(route);

    let is_forwarded_unicast =
        matches!(route, UplinkRoute::Internet { .. } | UplinkRoute::Client { .. });
    if is_forwarded_unicast && packet.first().is_some_and(|byte| byte >> 4 == 4) && packet[8] <= 1 {
        let response = icmp::build_icmpv4_error_with_ttl(
            packet,
            server_ips.ipv4,
            icmp::icmp_type::TIME_EXCEEDED,
            0,
            None,
            fingerprint_profile.ttl(),
        );
        enqueue_routing_response(response_queue, metrics, response);
        metrics.record_routing_outcome(RoutingOutcome::TimeExceeded);
        return None;
    }
    if is_forwarded_unicast && packet.first().is_some_and(|byte| byte >> 4 == 6) && packet[7] <= 1 {
        if let Some(server_ipv6) = server_ips.ipv6 {
            let response = icmp::build_icmpv6_error_with_hop_limit(
                packet,
                server_ipv6,
                icmp::icmpv6_type::TIME_EXCEEDED,
                None,
                fingerprint_profile.ttl(),
            );
            enqueue_routing_response(response_queue, metrics, response);
            metrics.record_routing_outcome(RoutingOutcome::TimeExceeded);
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
        }
        return None;
    }

    if packet.len() > usize::from(tun_mtu) && packet.first().is_some_and(|byte| byte >> 4 == 4) {
        // Reject both DF states before either TUN write path. The server does
        // not perform userspace IPv4 fragmentation, so the packet must never
        // reach a platform-specific oversized-write boundary.
        let response = icmp::build_icmpv4_error_with_ttl(
            packet,
            server_ips.ipv4,
            icmp::icmp_type::DESTINATION_UNREACHABLE,
            icmp::icmp_code::FRAGMENTATION_NEEDED,
            Some(tun_mtu),
            fingerprint_profile.ttl(),
        );
        enqueue_routing_response(response_queue, metrics, response);
        metrics.record_routing_outcome(RoutingOutcome::PacketTooBig);
        return None;
    }
    if packet.len() > usize::from(tun_mtu) && packet.first().is_some_and(|byte| byte >> 4 == 6) {
        if let Some(server_ipv6) = server_ips.ipv6 {
            let response = icmp::build_icmpv6_error_with_hop_limit(
                packet,
                server_ipv6,
                icmp::icmpv6_type::PACKET_TOO_BIG,
                Some(u32::from(tun_mtu)),
                fingerprint_profile.ttl(),
            );
            enqueue_routing_response(response_queue, metrics, response);
            metrics.record_routing_outcome(RoutingOutcome::PacketTooBig);
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
        }
        return None;
    }

    Some(route)
}

fn admit_session_bandwidth(
    sessions: &Arc<RwLock<SessionManager>>,
    metrics: &Metrics,
    session_id: Option<SessionId>,
    direction: BandwidthDirection,
    bytes: usize,
) -> BandwidthDecision {
    let Some(session_id) = session_id else {
        metrics.record_bandwidth_decision(direction, BandwidthDecision::RateLimited, bytes);
        return BandwidthDecision::RateLimited;
    };
    let decision = sessions.write().check_bandwidth(session_id, direction, bytes);
    metrics.record_bandwidth_decision(direction, decision, bytes);
    decision
}

fn enqueue_routing_response(
    queue: &Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
    metrics: &Metrics,
    response: Vec<u8>,
) {
    if response.is_empty() {
        return;
    }
    let admission = match queue.lock() {
        Ok(mut pending) => pending.enqueue(response),
        Err(poisoned) => poisoned.into_inner().enqueue(response),
    };
    if let Err(reason) = admission {
        metrics.record_masque_downlink_response_drop(reason);
    }
}

fn drain_masque_downlink_responses(
    conn: &mut QuicFuscateConnection,
    addr: SocketAddr,
    metrics: &Metrics,
) {
    let mut terminal_drops = 0usize;
    while let Some(packet) = conn.pop_masque_downlink_packet() {
        match conn.send_masque_downlink(&packet) {
            Ok(()) => {}
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                conn.retry_masque_downlink_packet(packet);
                metrics.record_masque_downlink_response_retry();
                break;
            }
            Err(error) => {
                metrics.record_masque_downlink_response_terminal_drop(1);
                terminal_drops = terminal_drops.saturating_add(1);
                log::trace!(
                    "MASQUE queued downlink to {} reached terminal send outcome: {:?}",
                    addr,
                    error
                );
            }
        }
    }
    if terminal_drops > 0 {
        log::debug!(
            "dropped {} MASQUE queued downlinks to {} after terminal send outcomes",
            terminal_drops,
            addr
        );
    }
}

fn send_client_assignment(
    conn: &mut QuicFuscateConnection,
    session_id: Option<SessionId>,
    assigned_ips: Option<AssignedClientIps>,
    settings: &ServerAssignmentSettings,
    tun_enabled: bool,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let Some(generation) = conn.masque_peer_generation() else {
        log::warn!(
            "authenticated MASQUE client {} did not provide a valid connection generation",
            session_id
        );
        return;
    };
    let assignment = if tun_enabled {
        let Some(assigned_ips) = assigned_ips else {
            log::warn!("authenticated MASQUE client {} has no assigned IPs", session_id);
            return;
        };
        crate::control_plane::ClientAssignment::enabled(
            session_id.as_u64(),
            generation,
            Some(crate::control_plane::AssignedIpv4 {
                address: assigned_ips.ipv4,
                prefix: settings.ipv4_prefix,
            }),
            assigned_ips.ipv6.map(|address| crate::control_plane::AssignedIpv6 {
                address,
                prefix: settings.ipv6_prefix,
            }),
            settings.mtu,
            settings.dns_servers.clone(),
        )
    } else {
        crate::control_plane::ClientAssignment::disabled(session_id.as_u64(), generation)
    };
    let assignment = match assignment {
        Ok(assignment) => assignment,
        Err(error) => {
            log::warn!("client assignment for {} rejected locally: {}", session_id, error);
            return;
        }
    };
    let payload = match assignment.encode() {
        Ok(payload) => payload,
        Err(error) => {
            log::warn!("client assignment for {} could not be encoded: {}", session_id, error);
            return;
        }
    };
    match conn.send_masque_control_once(
        crate::control_plane::CLIENT_ASSIGNMENT_CAPSULE_TYPE,
        &payload,
    ) {
        Ok(true) => log::info!(
            "authenticated client assignment sent: session={} generation={} enabled={}",
            session_id,
            generation,
            tun_enabled
        ),
        Ok(false) => {}
        Err(error) => log::warn!(
            "client assignment send failed: session={} generation={} error={:?}",
            session_id,
            generation,
            error
        ),
    }
}

fn record_live_tun_fault(
    fault_slot: &Arc<Mutex<Option<DataPlaneFault>>>,
    notify: &Arc<tokio::sync::Notify>,
    shutdown: &AtomicBool,
    fault: DataPlaneFault,
) {
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    let mut stored = fault_slot.lock();
    if stored.is_none() {
        *stored = Some(fault);
        notify.notify_one();
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_live_server_client_datagram(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    runtime_client: LiveClientRuntime<'_>,
    packet: &[u8],
    out: &mut [u8],
    metrics: &Arc<Metrics>,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    server_tun: Option<&Arc<TunInterface>>,
    server_ips: ServerTunIps,
    assignment_settings: ServerAssignmentSettings,
    tun_enable: bool,
    dns_upstream_resolvers: Arc<Vec<Ipv4Addr>>,
    dns_intercept_admission: Arc<crate::dns::DnsAdmission>,
    dns_intercept_workers: Arc<DnsInterceptWorkerOwner>,
    tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    tun_notify: Arc<tokio::sync::Notify>,
    runtime_shutdown: Arc<AtomicBool>,
    uring_worker: Option<&LiveUringWorker>,
) -> Result<LiveClientDatagramResult, DataPlaneFault> {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    let LiveClientRuntime {
        connection: conn,
        conn_id,
        qkey_auth,
        session_stats,
        session_id,
        assigned_ips,
        forwarding_policy,
        sessions,
        fanout_queue,
        migration_from,
        ..
    } = runtime_client;
    let fingerprint_profile = conn.tunnel_ingress_profile();
    let logical_addr = migration_from.unwrap_or(addr);
    record_live_snapshot_bytes_in(
        client_snapshots,
        logical_addr,
        packet.len() as u64,
        format!("{:?}", conn.stealth_mode()),
        session_id,
        conn.protocol_clock().now(),
    );
    if let Some(stats) = session_stats.as_ref() {
        stats.record_received(packet.len() as u64);
    }

    let local_addr = socket.local_addr().map_err(|error| DataPlaneFault::TransportReceive {
        component: "server local socket address".to_string(),
        error: error.to_string(),
    })?;
    match conn.recv_on_path(packet, addr, local_addr) {
        Ok(_) => {}
        Err(error) => {
            log::error!("QUIC recv failed for {}: {:?}", addr, error);
        }
    }

    let require_auth = qkey_auth.is_some();
    let expected_token_sha256 = qkey_auth.as_ref().map(|state| state.expected_token_sha256.clone());
    let auth_gate =
        Arc::new(AtomicBool::new(qkey_auth.as_ref().map(|state| state.authed).unwrap_or(true)));
    let auth_progress = Cell::new(QKeyDatagramAuthProgress::Pending);
    let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

    // Install the MASQUE→TUN sink when TUN bridging is active. Decoded MASQUE
    // CONNECT-UDP datagram payloads (raw IP packets) are written to the server
    // TUN interface by this callback, invoked from drain_masque_datagrams
    // inside poll_http3_event_loop. The callback is rebound on each packet
    // processing pass so it always captures the current QKey auth gate; keeping
    // the first unauthenticated gate forever would silently drop later valid
    // MASQUE datagrams.
    if tun_enable {
        if let Some(tun) = server_tun {
            if !conn.has_masque_downlink_queue() {
                conn.set_masque_downlink_queue(Arc::new(std::sync::Mutex::new(
                    crate::core::MasqueDownlinkQueue::new(
                        MAX_MASQUE_DOWNLINK_RESPONSES,
                        MAX_MASQUE_DOWNLINK_RESPONSE_BYTES,
                    ),
                )));
            }
            let tun_sink = Arc::clone(tun);
            let tun_fault_for_masque = Arc::clone(&tun_fault);
            let tun_notify_for_masque = Arc::clone(&tun_notify);
            let shutdown_for_masque = Arc::clone(&runtime_shutdown);
            let masque_forwarding_policy = Arc::clone(&forwarding_policy);
            let masque_sessions = Arc::clone(&sessions);
            let masque_fanout_queue = Arc::clone(&fanout_queue);
            let masque_metrics = Arc::clone(metrics);
            let dns_resolvers = Arc::clone(&dns_upstream_resolvers);
            let dns_admission = Arc::clone(&dns_intercept_admission);
            let dns_workers = Arc::clone(&dns_intercept_workers);
            let dns_downlink_queue = conn
                .masque_downlink_queue()
                .expect("MASQUE downlink queue installed before callback");
            let masque_response_queue = Arc::clone(&dns_downlink_queue);
            let tun_mtu = tun.mtu();
            let datagram_auth_gate = Arc::clone(&auth_gate);
            conn.set_masque_datagram_cb(Arc::new(std::sync::Mutex::new(Box::new(
                move |payload: &[u8]| {
                    if !qkey_payload_allowed(
                        require_auth,
                        datagram_auth_gate.load(AtomicOrdering::Relaxed),
                    ) {
                        return;
                    }
                    let bandwidth_decision = admit_session_bandwidth(
                        &masque_sessions,
                        &masque_metrics,
                        session_id,
                        BandwidthDirection::Uplink,
                        payload.len(),
                    );
                    if bandwidth_decision != BandwidthDecision::Allowed {
                        log::debug!(
                            "Client uplink denied by bandwidth policy: {:?}",
                            bandwidth_decision
                        );
                        return;
                    }
                    let Some(route) = allow_client_uplink(
                        &masque_forwarding_policy,
                        &masque_metrics,
                        assigned_ips,
                        payload,
                        fingerprint_profile,
                        server_ips,
                        tun_mtu,
                        &masque_response_queue,
                    ) else {
                        return;
                    };
                    if spawn_dns_intercept(
                        payload,
                        Arc::clone(&dns_resolvers),
                        Arc::clone(&dns_downlink_queue),
                        Arc::clone(&masque_metrics),
                        Arc::clone(&dns_admission),
                        Arc::clone(&dns_workers),
                        session_id,
                        fingerprint_profile,
                    ) {
                        return;
                    }
                    enqueue_client_fanout(
                        &masque_fanout_queue,
                        masque_metrics.as_ref(),
                        logical_addr,
                        route,
                        payload,
                    );
                    if let Err(error) = tun_sink.write(payload) {
                        log::warn!("Server TUN write (MASQUE) failed: {:?}", error);
                        record_live_tun_fault(
                            &tun_fault_for_masque,
                            &tun_notify_for_masque,
                            &shutdown_for_masque,
                            DataPlaneFault::TunWrite {
                                component: "server MASQUE downlink".to_string(),
                                error: error.to_string(),
                            },
                        );
                    }
                },
            ))));
        }
    }

    let stream_response_queue = conn.masque_downlink_queue();

    let tun_fault_for_stream = Arc::clone(&tun_fault);
    let tun_notify_for_stream = Arc::clone(&tun_notify);
    let shutdown_for_stream = Arc::clone(&runtime_shutdown);
    if let Err(error) = conn.poll_http3_with_headers(
        |_sid, headers| match evaluate_qkey_http3_headers(
            headers,
            expected_token_sha256.as_deref(),
            auth_gate.load(AtomicOrdering::Relaxed),
        ) {
            QKeyHeaderAuthOutcome::Unchanged => {}
            QKeyHeaderAuthOutcome::Authenticated => {
                auth_gate.store(true, AtomicOrdering::Relaxed);
                auth_progress.set(QKeyDatagramAuthProgress::Authenticated);
            }
            QKeyHeaderAuthOutcome::Reject(reason) => {
                auth_progress.set(QKeyDatagramAuthProgress::Rejected);
                should_close.set(Some(reason));
            }
        },
        |_sid, data| {
            if !qkey_payload_allowed(require_auth, auth_gate.load(AtomicOrdering::Relaxed)) {
                return;
            }
            if tun_enable {
                if let Some(tun) = server_tun {
                    // Only write to TUN if the data looks like a valid IP packet
                    // (version 4 or 6 in the high nibble of the first byte).
                    // This filters out CONNECT-UDP capsule protocol data on the
                    // MASQUE stream, which is not a raw IP packet and would cause
                    // EINVAL on TUN write.
                    if !data.is_empty() && (data[0] >> 4 == 4 || data[0] >> 4 == 6) {
                        let bandwidth_decision = admit_session_bandwidth(
                            &sessions,
                            metrics,
                            session_id,
                            BandwidthDirection::Uplink,
                            data.len(),
                        );
                        if bandwidth_decision != BandwidthDecision::Allowed {
                            log::debug!(
                                "Client framed uplink denied by bandwidth policy: {:?}",
                                bandwidth_decision
                            );
                            return;
                        }
                        let Some(response_queue) = stream_response_queue.as_ref() else {
                            return;
                        };
                        let Some(route) = allow_client_uplink(
                            &forwarding_policy,
                            metrics,
                            assigned_ips,
                            data,
                            fingerprint_profile,
                            server_ips,
                            tun.mtu(),
                            response_queue,
                        ) else {
                            return;
                        };
                        enqueue_client_fanout(
                            &fanout_queue,
                            metrics.as_ref(),
                            logical_addr,
                            route,
                            data,
                        );
                        if let Err(error) = tun.write(data) {
                            log::warn!("Server TUN write failed: {:?}", error);
                            record_live_tun_fault(
                                &tun_fault_for_stream,
                                &tun_notify_for_stream,
                                &shutdown_for_stream,
                                DataPlaneFault::TunWrite {
                                    component: "server HTTP/3 downlink".to_string(),
                                    error: error.to_string(),
                                },
                            );
                        }
                    }
                }
            }
        },
    ) {
        log::warn!("HTTP/3 header/body poll failed for {}: {:?}", addr, error);
    }

    // A successful CONNECT response is the client-visible data-plane barrier.
    // For QKey clients it is queued only after the CONNECT headers authenticated;
    // the caller commits bandwidth ownership synchronously before receiving the
    // client's next datagram.
    if should_close.get().is_none() && auth_gate.load(AtomicOrdering::Relaxed) {
        let masque_ready = match conn.accept_peer_masque_tunnel() {
            Ok(true) => {
                log::info!("Authenticated MASQUE data plane accepted for {}", addr);
                true
            }
            Ok(false) => conn.masque_flow_active(),
            Err(error) => {
                log::warn!("MASQUE CONNECT response failed for {}: {:?}", addr, error);
                false
            }
        };
        if masque_ready {
            send_client_assignment(
                conn,
                session_id,
                assigned_ips,
                &assignment_settings,
                tun_enable && server_tun.is_some(),
            );
        }
    }

    // MASQUE CONNECT-UDP uplink datagrams are drained and written to the TUN by
    // drain_masque_datagrams (inside poll_http3_with_headers above) via the
    // masque_datagram_cb sink installed earlier. The previous bare dgram_recv
    // loop was either redundant (datagrams already drained) or wrote corrupted
    // bytes (MASQUE flow-id varint prefix not stripped) and has been removed.

    let auth_result = qkey_datagram_auth_result(&conn_id, auth_progress.get());
    let mut remove_auth_conn_id = None;
    if let Some(reason) = should_close.get() {
        close_live_client_for_qkey_auth_failure(conn, addr, reason);
        remove_auth_conn_id = Some(conn_id.clone());
    }

    drain_masque_downlink_responses(conn, addr, metrics);

    flush_live_server_outgoing(
        socket,
        logical_addr,
        conn,
        out,
        metrics,
        client_snapshots,
        session_stats,
        session_id,
        uring_worker,
    )
    .await?;

    Ok(LiveClientDatagramResult { auth_result, remove_auth_conn_id })
}

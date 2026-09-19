use super::*;

mod fanout;
pub(super) use fanout::{
    new_client_fanout_queue, ClientFanoutQueue, MAX_CLIENT_FANOUT_DRAIN_BATCH,
};
#[cfg(test)]
pub(super) use fanout::{
    ClientFanoutQueueState, ClientFanoutReject, MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE,
};

#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub(super) type LiveUringWorker = crate::optimize::uring_batch::UringBatchWorker;
#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
pub(super) type LiveUringWorker = ();

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
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
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

pub(crate) fn start_runtime_profile_rotation_with_generation(
    runtime_owner: &Arc<StealthRuntimeOwner>,
    stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    profiles: Vec<FingerprintProfile>,
    profile_interval_secs: u64,
    runtime_policy_generation: RuntimePolicyGeneration,
) -> Result<(), String> {
    runtime_owner.start_with_policy_generation(
        Some(stealth_config),
        profiles,
        profile_interval_secs,
        Some(runtime_policy_generation),
    )
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
    let server =
        AdminHttpServer::new_with_max_connections_and_operation_timeout_and_diagnostics_and_clock(
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
    // Server-issued SCIDs are always MAX_CONN_ID_LEN bytes, so the wire DCID
    // can be sliced out directly - no per-client header parse (which also
    // allocates two Vecs) is needed.
    let first = *packet.first()?;
    let dcid: &[u8] = if first & crate::transport::packet::FORM_BIT == 0 {
        packet.get(1..1 + crate::transport::MAX_CONN_ID_LEN)?
    } else {
        let dlen = *packet.get(5)? as usize;
        if dlen > crate::transport::MAX_CONN_ID_LEN {
            return None;
        }
        packet.get(6..6 + dlen)?
    };
    clients.iter().find_map(|(addr, conn)| {
        if *addr == from {
            return None;
        }
        (conn.conn.source_id().as_ref() == dcid).then_some(*addr)
    })
}

pub fn reconcile_live_clients(
    clients: &mut std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    qkey_auth: &mut std::collections::HashMap<crate::transport::ConnectionId, QKeyAuthState>,
    accept_loop: &AcceptLoop,
    metrics: &Metrics,
) -> Vec<SocketAddr> {
    let closed_addrs: Vec<_> =
        clients.iter().filter_map(|(addr, conn)| conn.conn.is_closed().then_some(*addr)).collect();
    for addr in &closed_addrs {
        accept_loop.record_closed(*addr);
    }
    clients.retain(|_, conn| !conn.conn.is_closed());
    // One O(clients) set build instead of O(qkey x clients) rescan per entry.
    let active_conn_ids: std::collections::HashSet<&[u8]> =
        clients.values().map(|conn| conn.conn.source_id().as_ref()).collect();
    qkey_auth.retain(|conn_id, _| active_conn_ids.contains(conn_id.as_ref()));
    metrics.clients_active.store(clients.len() as u64, Ordering::Relaxed);
    closed_addrs
}

pub struct LiveInitialAuthContext {
    pub initial_key_dcid: crate::transport::ConnectionId,
    pub original_dcid: crate::transport::ConnectionId,
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
    let mut original_dcid = initial_key_dcid;
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
        original_dcid = crate::transport::ConnectionId::from_ref(&claims.original_dcid);
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

    Ok(LiveInitialAuthContext {
        initial_key_dcid,
        original_dcid,
        version,
        qkey_record,
        pending_qkey_auth,
    })
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
                fec_config.apply_engine_mode(qf_engine_types::FecMode::Off);
            }
            Ok("auto") => {
                fec_config.apply_engine_mode(qf_engine_types::FecMode::Auto);
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
    create_live_server_connection_with_runtime_and_clock_and_original(
        local_addr,
        remote_addr,
        transport_config,
        stealth_config,
        fec_config,
        opt_params,
        initial_key_dcid,
        None,
        runtime_owner,
        clock,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_live_server_connection_with_runtime_and_clock_and_original(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_config: &mut crate::transport::Config,
    stealth_config: crate::stealth::StealthConfig,
    fec_config: crate::fec::FecConfig,
    opt_params: crate::optimize::OptimizeConfig,
    initial_key_dcid: &crate::transport::ConnectionId,
    original_dcid: Option<&crate::transport::ConnectionId>,
    runtime_owner: Option<Arc<StealthRuntimeOwner>>,
    clock: crate::time_source::ProtocolClock,
) -> Result<QuicFuscateConnection, String> {
    let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut scid_bytes);
    let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);
    QuicFuscateConnection::new_server_with_runtime_and_clock_and_original(
        &scid,
        Some(initial_key_dcid),
        original_dcid,
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
    headers: &[qf_transport_types::h3::Header],
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
pub(super) fn qkey_payload_allowed(require_auth: bool, authenticated: bool) -> bool {
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
    stealth_mode: &'static str,
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
        .or_insert_with(|| ClientSnapshot::new_at(stealth_mode, connected_at));
    if let Some(session_id) = session_id {
        snap.set_session_id(session_id);
    }
    snap.record_bytes_in(bytes_in, stealth_mode);
}

pub struct LiveClientDatagramResult {
    pub auth_result: Option<(crate::transport::ConnectionId, bool)>,
    pub remove_auth_conn_id: Option<crate::transport::ConnectionId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QKeyDatagramAuthProgress {
    Pending,
    Authenticated,
    Rejected,
}

pub(super) fn qkey_datagram_auth_result(
    conn_id: &[u8],
    progress: QKeyDatagramAuthProgress,
) -> Option<(crate::transport::ConnectionId, bool)> {
    match progress {
        QKeyDatagramAuthProgress::Pending => None,
        QKeyDatagramAuthProgress::Authenticated => {
            Some((crate::transport::ConnectionId::from_ref(conn_id), true))
        }
        QKeyDatagramAuthProgress::Rejected => {
            Some((crate::transport::ConnectionId::from_ref(conn_id), false))
        }
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
                Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "partial datagram send_to"))
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

/// Detect a GSO-coalescable run in `staging` starting at `start`.
///
/// Returns `(end, segment_size)` when at least two contiguous, unsent packets
/// share the same target and every interior packet is exactly `segment_size`
/// bytes (the kernel splits the super-buffer on `segment_size` boundaries, so
/// only the final packet may be shorter). Runs are capped at 64 segments and
/// `max_payload` bytes. `None` when the run has fewer than two packets or GSO
/// was already ruled out for this socket.
#[cfg(target_os = "linux")]
pub(in crate::implementations::server) fn plan_gso_run(
    staging: &[(SocketAddr, usize, usize)],
    sent: &[bool],
    start: usize,
    max_payload: usize,
    max_seg: usize,
) -> Option<(usize, u16)> {
    const MAX_GSO_SEGMENTS: usize = 64;
    let (target, _, first_len) = staging[start];
    let seg = first_len;
    // A GSO segment must itself fit a single wire datagram — the kernel
    // rejects `gso_size > route_mtu - header` with EMSGSIZE, so `max_seg`
    // carries the route/payload ceiling probed by the caller.
    if seg == 0 || seg > max_seg.min(u16::MAX as usize) {
        return None;
    }
    let mut end = start + 1;
    let mut total = seg;
    while end < staging.len()
        && !sent[end]
        && staging[end].0 == target
        && end - start < MAX_GSO_SEGMENTS
        && total + staging[end].2 <= max_payload
    {
        let len = staging[end].2;
        if len == seg {
            total += len;
            end += 1;
            continue;
        }
        // A shorter same-target packet may only close the run.
        if len < seg {
            end += 1;
        }
        break;
    }
    (end - start >= 2).then_some((end, seg as u16))
}

/// Kernel-wide UDP GSO probe cached per process; `UDP_SEGMENT` support is a
/// socket option uniform across UDP sockets on this host.
#[cfg(target_os = "linux")]
fn udp_gso_capable(fd: std::os::unix::io::RawFd) -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static STATE: AtomicU8 = AtomicU8::new(0);
    match STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let capable = qf_transport_udp::probe_udp_gso(fd);
            STATE.store(if capable { 1 } else { 2 }, Ordering::Relaxed);
            capable
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
    // syscall instead of one sendmsg per packet). Payloads stage into one
    // flat buffer plus a span table - one allocation per flush instead of one
    // `Vec` per datagram, and a GSO run is already contiguous in `flat`.
    // Both buffers are pre-sized for a full burst so the growth-doubling chain
    // (and its memcpy churn) never runs on the hot path; all per-packet
    // telemetry accumulates into locals and lands as one atomic batch below.
    let mut staging_flat: Vec<u8> =
        Vec::with_capacity(crate::transport::UDP_DATAGRAM_BURST_LIMIT * 1_500);
    let mut staging_spans: Vec<(SocketAddr, usize, usize)> =
        Vec::with_capacity(crate::transport::UDP_DATAGRAM_BURST_LIMIT);
    while staging_spans.len() < crate::transport::UDP_DATAGRAM_BURST_LIMIT {
        match conn.send_with_info(out) {
            Ok((len, send_info)) if len > 0 => {
                bytes_sent = bytes_sent.saturating_add(len as u64);
                packets_sent = packets_sent.saturating_add(1);
                let start = staging_flat.len();
                staging_flat.extend_from_slice(&out[..len]);
                staging_spans.push((send_info.to, start, len));
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
    if staging_spans.len() == crate::transport::UDP_DATAGRAM_BURST_LIMIT {
        log::debug!(
            "Outgoing flush for {} reached the {} datagram burst limit",
            addr,
            crate::transport::UDP_DATAGRAM_BURST_LIMIT
        );
    }

    // Telemetry lands once per staged burst instead of per datagram.
    if packets_sent > 0 {
        crate::telemetry::BYTES_SENT.inc_by(bytes_sent);
        metrics.record_egress_batch(bytes_sent, packets_sent);
        if let Some(stats) = session_stats.as_ref() {
            stats.record_sent_batch(bytes_sent, packets_sent);
        }
    }

    if !staging_spans.is_empty() {
        // Try io_uring batch on Linux when the feature is compiled in.
        // Every fallback candidate is selected from the exact per-slot result;
        // an out-of-order CQE can never make a later successful datagram part
        // of a retried contiguous prefix.
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        let mut sent = vec![false; staging_spans.len()];
        // `mut` even without io_uring: the Linux GSO fallback marks slots.
        #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
        #[allow(unused_mut)]
        let mut sent = vec![false; staging_spans.len()];
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let packets: Vec<(SocketAddr, &[u8])> = staging_spans
                .iter()
                .map(|&(target, start, len)| (target, &staging_flat[start..start + len]))
                .collect();
            if let Some(worker) = uring_worker {
                match worker.send_batch_to_with_disposition(fd, &packets).await {
                    Ok(result) => {
                        for (index, sent_slot) in sent.iter_mut().enumerate() {
                            *sent_slot = result.is_sent(index);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        log::debug!("io_uring server worker busy, using async tail: {error}");
                    }
                    Err(error) => {
                        return Err(DataPlaneFault::TransportSend {
                            component: "server io_uring blocking worker".to_string(),
                            error: error.to_string(),
                        });
                    }
                }
            }
        }

        #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
        let _ = uring_worker;
        if sent.iter().all(|slot| *slot) {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
                return Ok((bytes_sent, packets_sent));
            }
        }
        // io_uring unavailable or partial: finish only slots not accepted by
        // the batch operation via individual async calls. On Linux, contiguous
        // unsent same-target runs with uniform interior length go out as one
        // UDP_SEGMENT sendmsg (one syscall per run) - the flat staging already
        // holds the run back-to-back, so no second concatenation is needed.
        let mut index = 0usize;
        #[cfg(target_os = "linux")]
        let mut gso_ok = {
            use std::os::unix::io::AsRawFd;
            udp_gso_capable(socket.as_raw_fd())
        };
        // Segment ceiling: GSO only pays when a segment still fits one wire
        // datagram. The server socket is unconnected, so `IP_MTU` rarely
        // reports a route — the conservative Ethernet payload ceiling stands.
        #[cfg(target_os = "linux")]
        let gso_seg_cap = {
            use std::os::unix::io::AsRawFd;
            qf_transport_udp::udp_gso_segment_mtu(socket.as_raw_fd()).unwrap_or(1472)
        };
        while index < staging_spans.len() {
            if sent[index] {
                index += 1;
                continue;
            }
            #[cfg(target_os = "linux")]
            if gso_ok && !conn.udp_gso_path_blocked {
                if let Some((end, seg_size)) = plan_gso_run(
                    &staging_spans,
                    &sent,
                    index,
                    qf_transport_udp::UDP_GSO_MAX_PAYLOAD,
                    gso_seg_cap,
                ) {
                    let run_start = staging_spans[index].1;
                    let run_end = staging_spans[end - 1].1 + staging_spans[end - 1].2;
                    let target = staging_spans[index].0;
                    let gso_result = {
                        use std::os::unix::io::AsRawFd;
                        qf_transport_udp::send_udp_segment(
                            socket.as_raw_fd(),
                            target,
                            &staging_flat[run_start..run_end],
                            seg_size,
                        )
                    };
                    match gso_result {
                        Ok(_) => {
                            for slot in sent.iter_mut().take(end).skip(index) {
                                *slot = true;
                            }
                            index = end;
                            continue;
                        }
                        Err(error) => {
                            // Kernel rejected GSO (or backpressure): do not
                            // retry GSO this flush; packets go out individually.
                            log::debug!("UDP GSO send to {target} failed, per-packet: {error}");
                            gso_ok = false;
                            // EMSGSIZE means the segment outlives the route's
                            // payload ceiling — a stable path property, so stop
                            // probing GSO to this peer for the connection's life.
                            if error.raw_os_error() == Some(libc::EMSGSIZE) {
                                conn.udp_gso_path_blocked = true;
                            }
                        }
                    }
                }
            }
            let &(target, start, len) = &staging_spans[index];
            send_live_datagram_to(socket, &target, &staging_flat[start..start + len])
                .await
                .map_err(|error| DataPlaneFault::TransportSend {
                    component: format!("server UDP send to {target}"),
                    error: error.to_string(),
                })?;
            index += 1;
        }
    }

    record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
    Ok((bytes_sent, packets_sent))
}

pub(super) fn enqueue_client_fanout(
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
pub(super) fn allow_client_uplink(
    forwarding_policy: &ClientIsolationManager,
    metrics: &Metrics,
    assigned_ips: Option<AssignedClientIps>,
    packet: &[u8],
    fingerprint_profile: OsFingerprintProfile,
    server_ips: ServerTunIps,
    tun_mtu: u16,
    response_queue: &Arc<std::sync::Mutex<qf_transport_types::MasqueDownlinkQueue>>,
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
    sessions: &SessionManager,
    metrics: &Metrics,
    session_id: Option<SessionId>,
    direction: BandwidthDirection,
    bytes: usize,
) -> BandwidthDecision {
    let Some(session_id) = session_id else {
        metrics.record_bandwidth_decision(direction, BandwidthDecision::RateLimited, bytes);
        return BandwidthDecision::RateLimited;
    };
    let decision = sessions.check_bandwidth(session_id, direction, bytes);
    metrics.record_bandwidth_decision(direction, decision, bytes);
    decision
}

pub(super) fn enqueue_routing_response(
    queue: &Arc<std::sync::Mutex<qf_transport_types::MasqueDownlinkQueue>>,
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

pub(super) fn drain_masque_downlink_responses(
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
    if conn.peer_connect_ip_control_sent() {
        return;
    }
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
    let connect_ip_capsules = match assignment.encode_connect_ip_capsules() {
        Ok(capsules) => capsules,
        Err(error) => {
            log::warn!("RFC 9484 assignment for {} could not be encoded: {}", session_id, error);
            return;
        }
    };
    for (capsule_type, capsule_payload) in connect_ip_capsules {
        if let Err(error) = conn.send_peer_connect_ip_capsule(capsule_type, &capsule_payload) {
            log::warn!(
                "RFC 9484 capsule send failed: session={} type={} error={:?}",
                session_id,
                capsule_type,
                error
            );
            return;
        }
    }
    match conn
        .send_masque_control_once(crate::control_plane::CLIENT_ASSIGNMENT_CAPSULE_TYPE, &payload)
    {
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

pub(super) fn record_live_tun_fault(
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
pub(super) async fn process_live_server_client_datagram(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    runtime_client: LiveClientRuntime<'_>,
    packet: &mut [u8],
    out: &mut [u8],
    metrics: &Arc<Metrics>,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    server_tun: Option<&Arc<TunInterface>>,
    server_ips: ServerTunIps,
    assignment_settings: &ServerAssignmentSettings,
    tun_enable: bool,
    dns_upstream_resolvers: &Arc<Vec<Ipv4Addr>>,
    dns_intercept_admission: &Arc<crate::dns::DnsAdmission>,
    dns_intercept_workers: &Arc<DnsInterceptWorkerOwner>,
    tun_fault: &Arc<Mutex<Option<DataPlaneFault>>>,
    tun_notify: &Arc<tokio::sync::Notify>,
    runtime_shutdown: &Arc<AtomicBool>,
    masque_relay_owner: Option<&crate::implementations::server::masque_relay::MasqueRelayOwner>,
    uring_worker: Option<&LiveUringWorker>,
) -> Result<LiveClientDatagramResult, DataPlaneFault> {
    use std::cell::Cell;
    use std::sync::atomic::Ordering as AtomicOrdering;

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
    conn.set_masque_logical_addr(logical_addr);
    record_live_snapshot_bytes_in(
        client_snapshots,
        logical_addr,
        packet.len() as u64,
        conn.stealth_mode().as_str(),
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
    match conn.recv_on_path_mut(packet, addr, local_addr) {
        Ok(_) => {}
        Err(error) => {
            log::error!("QUIC recv failed for {}: {:?}", addr, error);
        }
    }

    let require_auth = qkey_auth.is_some();
    let expected_token_sha256 = qkey_auth.map(|state| state.expected_token_sha256.as_str());
    // The datagram sink is installed once and reads this persistent gate;
    // refreshing the flag per pass replaces the old per-packet rebind.
    conn.set_masque_datagram_auth(qkey_auth.map(|state| state.authed).unwrap_or(true));
    let auth_gate = conn.masque_datagram_auth_gate();
    let auth_progress = Cell::new(QKeyDatagramAuthProgress::Pending);
    let authenticated_transcript = Cell::new(false);
    let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

    if let (Some(relay_owner), Some(relay_session_id)) = (masque_relay_owner, session_id) {
        if conn.masque_relay_response_queue().is_none() {
            let queue =
                Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueRelayResponseQueue::new(
                    MAX_MASQUE_DOWNLINK_RESPONSES,
                    MAX_MASQUE_DOWNLINK_RESPONSE_BYTES,
                )));
            conn.set_masque_relay_response_queue(Arc::clone(&queue));
        }
        // The owner callback carries a session lease. Install it once per
        // connection: replacing it on every packet would drop the previous
        // lease and enqueue session teardown while the connection is active.
        if !conn.has_masque_relay_cb() {
            conn.set_masque_relay_cb(relay_owner.handler(relay_session_id.as_u64()));
        }
    }

    // Install the MASQUE->TUN sink when TUN bridging is active. Decoded MASQUE
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
                    qf_transport_types::MasqueDownlinkQueue::new(
                        MAX_MASQUE_DOWNLINK_RESPONSES,
                        MAX_MASQUE_DOWNLINK_RESPONSE_BYTES,
                    ),
                )));
            }
            // The sink is installed once per connection. Values that used to
            // be refreshed by the per-packet rebind now live in persistent
            // connection state (auth gate, logical addr) or are resolved fresh
            // inside the callback (session, assigned IPs).
            if !conn.has_masque_datagram_cb() {
                let tun_sink = Arc::clone(tun);
                let tun_fault_for_masque = Arc::clone(tun_fault);
                let tun_notify_for_masque = Arc::clone(tun_notify);
                let shutdown_for_masque = Arc::clone(runtime_shutdown);
                let masque_forwarding_policy = Arc::clone(forwarding_policy);
                let masque_sessions = Arc::clone(sessions);
                let masque_fanout_queue = Arc::clone(fanout_queue);
                let masque_metrics = Arc::clone(metrics);
                let dns_resolvers = Arc::clone(dns_upstream_resolvers);
                let dns_admission = Arc::clone(dns_intercept_admission);
                let dns_workers = Arc::clone(dns_intercept_workers);
                let Some(dns_downlink_queue) = conn.masque_downlink_queue() else {
                    return Err(DataPlaneFault::TransportReceive {
                        component: "MASQUE downlink queue installation".to_string(),
                        error: "queue was absent after installation".to_string(),
                    });
                };
                let masque_response_queue = Arc::clone(&dns_downlink_queue);
                let masque_logical_addr = conn.masque_logical_addr();
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
                        let logical_addr = **masque_logical_addr.load();
                        // One read guard covers both the session lookup and
                        // the bandwidth admission below.
                        let sessions = masque_sessions.read();
                        let (session_id, assigned_ips) =
                            match sessions.get_by_remote_addr(logical_addr) {
                                Some(session) => (
                                    Some(session.id()),
                                    Some(AssignedClientIps {
                                        ipv4: session.client_ip(),
                                        ipv6: session.client_ipv6(),
                                    }),
                                ),
                                None => (None, None),
                            };
                        let bandwidth_decision = admit_session_bandwidth(
                            &sessions,
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
                            // TODO-896: WouldBlock is transient backpressure, not a fault.
                            if error.kind() == std::io::ErrorKind::WouldBlock {
                                masque_metrics.record_tun_write_backpressure();
                                return;
                            }
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
    }

    let stream_response_queue = conn.masque_downlink_queue();

    if let Err(error) = conn.poll_http3_with_headers(
        |_sid, headers| match evaluate_qkey_http3_headers(
            headers,
            expected_token_sha256,
            auth_gate.load(AtomicOrdering::Relaxed),
        ) {
            QKeyHeaderAuthOutcome::Unchanged => {}
            QKeyHeaderAuthOutcome::Authenticated => {
                auth_gate.store(true, AtomicOrdering::Relaxed);
                authenticated_transcript.set(true);
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
                            &sessions.read(),
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
                            forwarding_policy,
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
                            fanout_queue,
                            metrics.as_ref(),
                            logical_addr,
                            route,
                            data,
                        );
                        if let Err(error) = tun.write(data) {
                            // TODO-896: transient backpressure (EAGAIN/WouldBlock on a
                            // non-blocking TUN fd) is NOT a data-plane fault. The packet is
                            // already fanned out to the client socket; dropping only the TUN
                            // copy under kernel ring pressure beats tearing down every live
                            // tunnel. Real faults (EBADF, EINVAL, ENODEV) keep the hard path.
                            if error.kind() == std::io::ErrorKind::WouldBlock {
                                metrics.record_tun_write_backpressure();
                                return;
                            }
                            log::warn!("Server TUN write failed: {:?}", error);
                            record_live_tun_fault(
                                tun_fault,
                                tun_notify,
                                runtime_shutdown,
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
    if authenticated_transcript.get() {
        if let Some(transcript_hash) = expected_token_sha256
            .and_then(qf_engine_types::authenticated_transcript_hash_from_verifier_hash_hex)
        {
            conn.set_authenticated_qkey_transcript_hash(transcript_hash);
        }
    }

    // A successful CONNECT response is the client-visible data-plane barrier.
    // For QKey clients it is queued only after the CONNECT headers authenticated;
    // the caller commits bandwidth ownership synchronously before receiving the
    // client's next datagram.
    if should_close.get().is_none() && auth_gate.load(AtomicOrdering::Relaxed) {
        for (stream_id, target, purpose, circuit_id, hop_budget) in conn.pending_peer_masque_flows()
        {
            let admitted = match purpose {
                crate::transport::h3::MasqueFlowPurpose::TunIp => false,
                crate::transport::h3::MasqueFlowPurpose::Control => true,
                crate::transport::h3::MasqueFlowPurpose::NextHopUdp => {
                    let (Some(circuit_id), Some(hop_budget)) = (circuit_id, hop_budget) else {
                        log::warn!(
                            "Rejecting MASQUE relay flow for {} without a valid circuit context",
                            addr
                        );
                        continue;
                    };
                    let Some(relay_owner) = masque_relay_owner else {
                        log::warn!(
                            "Rejecting MASQUE relay flow for {} because relay mode is disabled",
                            addr
                        );
                        continue;
                    };
                    let (Some(relay_session_id), Some(target), Some(responses)) =
                        (session_id, target, conn.masque_relay_response_queue())
                    else {
                        log::warn!("Rejecting incomplete MASQUE relay flow for {}", addr);
                        continue;
                    };
                    match relay_owner
                        .authorize_flow(
                            relay_session_id.as_u64(),
                            stream_id / 4,
                            target,
                            circuit_id,
                            hop_budget,
                            responses,
                        )
                        .await
                    {
                        Ok(()) => true,
                        Err(error) => {
                            log::warn!(
                                "Rejecting MASQUE relay flow for {} on stream {}: {}",
                                addr,
                                stream_id,
                                error
                            );
                            false
                        }
                    }
                }
            };
            if admitted {
                match conn.accept_peer_masque_flow(stream_id) {
                    Ok(true) => log::info!(
                        "Authenticated MASQUE {:?} flow accepted for {} on stream {}",
                        purpose,
                        addr,
                        stream_id
                    ),
                    Ok(false) => {}
                    Err(error) => {
                        log::warn!("MASQUE {:?} response failed for {}: {:?}", purpose, addr, error)
                    }
                }
            }
        }
        let masque_ready = match conn.accept_peer_masque_tunnel() {
            Ok(true) => {
                log::info!("Authenticated MASQUE data plane accepted for {}", addr);
                true
            }
            Ok(false) => conn.peer_connect_ip_flow_active(),
            Err(error) => {
                log::warn!("MASQUE CONNECT response failed for {}: {:?}", addr, error);
                false
            }
        };
        // The first private-protection proposal can arrive on the next UDP datagram. Prime the
        // authenticated control owner now that any peer flow, including NextHopUdp relay flows,
        // is accepted. Otherwise the H3 dispatcher would consume that proposal before a callback
        // exists. The call is intentionally outside the TunIp-only `masque_ready` branch.
        if let Err(error) = conn.private_packet_protection_control_tick() {
            log::warn!(
                "Private packet-protection control bootstrap failed for {}: {:?}",
                addr,
                error
            );
        }
        if masque_ready {
            send_client_assignment(
                conn,
                session_id,
                assigned_ips,
                assignment_settings,
                tun_enable && server_tun.is_some(),
            );
        }
    }

    // MASQUE CONNECT-UDP uplink datagrams are drained and written to the TUN by
    // drain_masque_datagrams (inside poll_http3_with_headers above) via the
    // masque_datagram_cb sink installed earlier. The previous bare dgram_recv
    // loop was either redundant (datagrams already drained) or wrote corrupted
    // bytes (MASQUE flow-id varint prefix not stripped) and has been removed.

    let auth_result = qkey_datagram_auth_result(conn_id.as_ref(), auth_progress.get());
    let mut remove_auth_conn_id = None;
    if let Some(reason) = should_close.get() {
        close_live_client_for_qkey_auth_failure(conn, addr, reason);
        remove_auth_conn_id = Some(conn_id);
    }

    drain_masque_downlink_responses(conn, addr, metrics);
    if let Err(error) = conn.flush_masque_relay_responses() {
        log::warn!("MASQUE relay response flush failed for {}: {:?}", addr, error);
    }

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

#[cfg(all(test, target_os = "linux"))]
mod gso_plan_tests {
    use super::*;

    fn span(addr: SocketAddr, start: usize, len: usize) -> (SocketAddr, usize, usize) {
        (addr, start, len)
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    #[test]
    fn uniform_same_target_run_coalesces() {
        let a = addr(1000);
        let staging = vec![span(a, 0, 600), span(a, 600, 600), span(a, 1200, 250)];
        let sent = vec![false; 3];
        let (end, seg) =
            plan_gso_run(&staging, &sent, 0, qf_transport_udp::UDP_GSO_MAX_PAYLOAD, usize::MAX)
                .expect("run");
        assert_eq!((end, seg), (3, 600), "short tail must close the run");
    }

    #[test]
    fn mixed_targets_and_sent_slots_break_runs() {
        let a = addr(1000);
        let b = addr(2000);
        // Different target ends the run before b.
        let staging = vec![span(a, 0, 600), span(b, 600, 600), span(a, 1200, 600)];
        let sent = vec![false; 3];
        assert!(plan_gso_run(
            &staging,
            &sent,
            0,
            qf_transport_udp::UDP_GSO_MAX_PAYLOAD,
            usize::MAX
        )
        .is_none());

        // An already-sent middle slot splits the run; index 1 is the start.
        let staging = vec![span(a, 0, 600), span(a, 600, 600), span(a, 1200, 600)];
        let sent = vec![false, true, false];
        let (end, seg) =
            plan_gso_run(&staging, &sent, 2, qf_transport_udp::UDP_GSO_MAX_PAYLOAD, usize::MAX)
                .unwrap_or((0, 0));
        assert_eq!((end, seg), (0, 0), "single packet is not a run");
    }

    #[test]
    fn run_caps_at_segment_count_and_payload_limit() {
        let a = addr(1000);
        let staging: Vec<_> = (0..80).map(|i| span(a, i * 600, 600)).collect();
        let sent = vec![false; staging.len()];
        let (end, seg) =
            plan_gso_run(&staging, &sent, 0, qf_transport_udp::UDP_GSO_MAX_PAYLOAD, usize::MAX)
                .expect("run");
        assert_eq!(seg, 600);
        assert!(end <= 64, "run must respect the 64-segment cap");
        // ~65.5K/600 = 109 segments fit by bytes; the 64-segment cap binds.
        assert_eq!(end, 64);

        // Tight payload cap cuts the run earlier.
        let (end, _) = plan_gso_run(&staging, &sent, 0, 1_800, usize::MAX).expect("run");
        assert_eq!(end, 3, "1800-byte cap admits exactly three 600-byte segments");
    }

    #[test]
    fn interior_longer_packet_rejects_run() {
        let a = addr(1000);
        // A same-target packet LONGER than the first segment cannot join the
        // run (it is not a valid tail either) - run collapses to a singleton.
        let staging = vec![span(a, 0, 600), span(a, 600, 900), span(a, 1500, 600)];
        let sent = vec![false; 3];
        assert!(plan_gso_run(
            &staging,
            &sent,
            0,
            qf_transport_udp::UDP_GSO_MAX_PAYLOAD,
            usize::MAX
        )
        .is_none());
    }

    #[test]
    fn segment_above_route_mtu_ceiling_skips_run() {
        let a = addr(1000);
        // Wire datagrams of 1500 bytes cannot be GSO segments on a 1500-MTU
        // route (UDP payload ceiling 1472) — the kernel answers EMSGSIZE.
        let staging = vec![span(a, 0, 1500), span(a, 1500, 1500), span(a, 3000, 1500)];
        let sent = vec![false; 3];
        assert!(
            plan_gso_run(&staging, &sent, 0, qf_transport_udp::UDP_GSO_MAX_PAYLOAD, 1472).is_none()
        );
        // The same run coalesces when the route ceiling admits the segment.
        let (end, seg) =
            plan_gso_run(&staging, &sent, 0, qf_transport_udp::UDP_GSO_MAX_PAYLOAD, usize::MAX)
                .expect("run");
        assert_eq!((end, seg), (3, 1500));
    }
}

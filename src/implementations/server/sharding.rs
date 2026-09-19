use super::masque_relay::MasqueRelayOwner;
use super::*;

/// Inbound message routed to a dataplane shard over its bounded channel.
///
/// `Datagram` carries an already-admitted forwarded packet (migration or
/// post-commit foreign addr); the owning shard runs the acquire/process
/// path directly. `Downlink` carries a TUN/fanout payload for one target
/// client. The remaining variants are shard commands posted by the
/// coordinator (admin, session lifecycle, shutdown).
pub(super) enum ShardMessage {
    Datagram {
        packet: Vec<u8>,
        from: SocketAddr,
    },
    Downlink {
        target: SocketAddr,
        session_id: SessionId,
        packet: PendingTunPacket,
        kind: DownlinkKind,
    },
    Kick {
        addr: SocketAddr,
    },
    CloseSessions {
        addrs: Vec<SocketAddr>,
    },
    ExpireRemotes {
        remotes: Vec<(SocketAddr, SessionId)>,
    },
    /// Successful standalone reload swapped the construction transport
    /// profile; shards replace their spawn-time copy for subsequent
    /// `acquire` calls (scope stays `NextConnectionOnly`).
    ReloadTransport {
        transport: Box<crate::transport::Config>,
    },
    Shutdown {
        reason: &'static [u8],
    },
}

/// Which admission semantics the owning shard applies to a downlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DownlinkKind {
    /// TUN-originated payload: MTU check with PacketTooBig ICMP for
    /// unicast, bandwidth decision, then direct send or scheduled queue.
    Tun { unicast: bool, profile: OsFingerprintProfile },
    /// Client fanout payload: qkey-auth gate, MTU and weight resolution all
    /// happen owner-side via `deliver_fanout_target`.
    Fanout,
}

#[derive(Default)]
struct ShardRouterInner {
    /// Current client remote addr -> owning shard. Kept in lockstep with the
    /// union of all shard `clients` maps (insert on accept, rebind on path
    /// commit, remove on teardown).
    addr_owner: std::collections::HashMap<SocketAddr, usize>,
    /// Server-issued SCID -> owning shard for pre-commit migration
    /// candidates whose new addr is not yet registered.
    conn_owner: std::collections::HashMap<crate::transport::ConnectionId, usize>,
    /// Frozen tunnel ingress profile per client addr (needed for ICMP error
    /// composition on shards that do not own the source client).
    profiles: std::collections::HashMap<SocketAddr, OsFingerprintProfile>,
}

/// Routes datagrams, downlinks, and commands to the shard that owns the
/// target client. Read lookups only run on local-map misses: established
/// traffic hits the shard-local `clients` map first, keeping the shared
/// lock off the steady-state path.
pub(super) struct ShardRouter {
    inner: parking_lot::RwLock<ShardRouterInner>,
    channels: Vec<tokio::sync::mpsc::Sender<ShardMessage>>,
}

impl ShardRouter {
    pub(super) fn new(channels: Vec<tokio::sync::mpsc::Sender<ShardMessage>>) -> Arc<Self> {
        Arc::new(Self { inner: parking_lot::RwLock::new(ShardRouterInner::default()), channels })
    }

    pub(super) fn shard_count(&self) -> usize {
        self.channels.len()
    }

    /// Register a freshly accepted client under `addr` for `shard`.
    pub(super) fn register(
        &self,
        addr: SocketAddr,
        conn_id: crate::transport::ConnectionId,
        shard: usize,
        profile: OsFingerprintProfile,
    ) {
        let mut inner = self.inner.write();
        inner.addr_owner.insert(addr, shard);
        inner.conn_owner.insert(conn_id, shard);
        inner.profiles.insert(addr, profile);
    }

    /// Drop all routing state for `addr` owned by `shard`. The conn-id entry
    /// is retained lazily by `retain_conn_ids` during reconcile.
    pub(super) fn unregister(&self, addr: SocketAddr, shard: usize) {
        let mut inner = self.inner.write();
        if inner.addr_owner.get(&addr) == Some(&shard) {
            inner.addr_owner.remove(&addr);
        }
        inner.profiles.remove(&addr);
    }

    /// Re-key a client after a validated path commit: the owning shard is
    /// unchanged (ownership follows the connection, not the addr).
    pub(super) fn rebind(&self, old_addr: SocketAddr, new_addr: SocketAddr, shard: usize) {
        let mut inner = self.inner.write();
        if inner.addr_owner.get(&old_addr) == Some(&shard) {
            inner.addr_owner.remove(&old_addr);
            inner.addr_owner.insert(new_addr, shard);
            if let Some(profile) = inner.profiles.remove(&old_addr) {
                inner.profiles.insert(new_addr, profile);
            }
        }
    }

    /// Refresh this shard's conn-id registrations: drop stale entries and
    /// upsert the current server SCID of every live client. Server SCIDs can
    /// rotate over a connection's life; without the upsert a post-rotation
    /// migration candidate would miss `conn_owner` and be admitted as a new
    /// connection on the wrong shard.
    pub(super) fn sync_conn_ids(
        &self,
        shard: usize,
        active: &std::collections::HashSet<crate::transport::ConnectionId>,
    ) {
        let mut inner = self.inner.write();
        inner.conn_owner.retain(|conn_id, owner| *owner != shard || active.contains(conn_id));
        for conn_id in active {
            inner.conn_owner.insert(*conn_id, shard);
        }
    }

    pub(super) fn owner_of(&self, addr: &SocketAddr) -> Option<usize> {
        self.inner.read().addr_owner.get(addr).copied()
    }

    pub(super) fn conn_owner_of(&self, dcid: &[u8]) -> Option<usize> {
        self.inner.read().conn_owner.get(dcid).copied()
    }

    pub(super) fn profile_of(&self, addr: &SocketAddr) -> Option<OsFingerprintProfile> {
        self.inner.read().profiles.get(addr).copied()
    }

    /// Union of all current client addrs across shards (snapshot retain).
    pub(super) fn addr_keyset(&self) -> std::collections::HashSet<SocketAddr> {
        self.inner.read().addr_owner.keys().copied().collect()
    }

    /// Global client count across shards.
    pub(super) fn len(&self) -> usize {
        self.inner.read().addr_owner.len()
    }

    /// Whether any shard currently owns a client address.
    pub(super) fn is_empty(&self) -> bool {
        self.inner.read().addr_owner.is_empty()
    }

    /// Non-blocking post to `shard`; `Err(msg)` when the channel is full or
    /// closed. Callers convert the reject into the drop metric matching the
    /// message kind (UDP loss semantics).
    pub(super) fn send(&self, shard: usize, msg: ShardMessage) -> Result<(), ShardMessage> {
        match self.channels.get(shard) {
            Some(tx) => tx.try_send(msg).map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(msg)
                | tokio::sync::mpsc::error::TrySendError::Closed(msg) => msg,
            }),
            None => Err(msg),
        }
    }
}

/// Per-shard bounded channel pair: the sender half lives in the router,
/// the receiver half is consumed by the shard task.
pub(super) fn shard_channels(
    count: usize,
    capacity: usize,
) -> (Vec<tokio::sync::mpsc::Sender<ShardMessage>>, Vec<tokio::sync::mpsc::Receiver<ShardMessage>>)
{
    let mut senders = Vec::with_capacity(count);
    let mut receivers = Vec::with_capacity(count);
    for _ in 0..count {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        senders.push(tx);
        receivers.push(rx);
    }
    (senders, receivers)
}

/// Slice the destination connection id out of a datagram without a full
/// header parse (same offsets as `find_live_client_by_dcid`).
fn datagram_dcid(packet: &[u8]) -> Option<&[u8]> {
    let first = *packet.first()?;
    if first & crate::transport::packet::FORM_BIT == 0 {
        packet.get(1..1 + crate::transport::MAX_CONN_ID_LEN)
    } else {
        let dlen = *packet.get(5)? as usize;
        if dlen > crate::transport::MAX_CONN_ID_LEN {
            return None;
        }
        packet.get(6..6 + dlen)
    }
}

/// Bounded per-shard channel capacity; a full queue drops routed payloads
/// with UDP loss semantics rather than unbounded memory growth.
pub(super) const SHARD_MESSAGE_CAPACITY: usize = 4096;
/// Sentinel `shard_id` for the coordinator's `LiveServerState` fork: never a
/// valid worker index, so every owner lookup routes off the coordinator and
/// global housekeeping runs exactly once (workers use ids `0..N`).
pub(super) const COORDINATOR_SHARD_ID: usize = usize::MAX;
/// Messages handled per select wakeup so the channel cannot starve RX.
const SHARD_MESSAGE_DRAIN_CAP: usize = 64;

/// Owned handles a dataplane shard needs for its `'static` task. Built once
/// on the coordinator before `tokio::spawn`; every field is either owned,
/// `Arc`-shared, or `Copy`.
pub(super) struct ShardWorkerCtx {
    pub(super) shard_id: usize,
    pub(super) router: Arc<ShardRouter>,
    pub(super) socket: Arc<UdpSocket>,
    pub(super) local_addr: SocketAddr,
    pub(super) accept_loop: Arc<AcceptLoop>,
    /// Per-shard admission budget (`accept_max_clients / N`).
    pub(super) accept_max_clients: usize,
    pub(super) metrics: Arc<Metrics>,
    pub(super) blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    pub(super) qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
    pub(super) dns_intercept_admission: Arc<crate::dns::DnsAdmission>,
    pub(super) dns_intercept_workers: Arc<DnsInterceptWorkerOwner>,
    pub(super) dns_upstream_resolvers: Arc<Vec<Ipv4Addr>>,
    pub(super) tun_ctx: ServerTunContext,
    pub(super) tun_enable: bool,
    pub(super) assignment_settings: ServerAssignmentSettings,
    pub(super) tun_notify: Arc<tokio::sync::Notify>,
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) stealth_runtime: Option<Arc<StealthRuntimeOwner>>,
    pub(super) stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    pub(super) fec_cfg_shared: Arc<std::sync::Mutex<FecConfig>>,
    pub(super) opt_params_shared: Arc<std::sync::Mutex<OptimizeConfig>>,
    pub(super) transport: crate::transport::Config,
    pub(super) runtime_policy_generation: RuntimePolicyGeneration,
    pub(super) crypto_config: qf_crypto::CryptoConfig,
    #[cfg(feature = "rate_limiter")]
    pub(super) retry_token_manager:
        Option<Arc<crate::implementations::server::ddos::RetryTokenManager>>,
    pub(super) clock: crate::time_source::ProtocolClock,
    pub(super) masque_relay_owner: Option<Arc<MasqueRelayOwner>>,
    /// First dataplane fault posted by any shard; the coordinator observes
    /// it on its housekeeping tick and tears the runtime down.
    pub(super) shard_fault: Arc<Mutex<Option<DataPlaneFault>>>,
}

/// Route an inbound datagram to its owning shard, or `None` when it belongs
/// here (unknown addr → local admission/migration path).
fn route_inbound(
    state: &LiveServerState,
    ctx: &ShardWorkerCtx,
    from: &SocketAddr,
    packet: &[u8],
) -> Option<usize> {
    if state.clients.contains_key(from) {
        return None;
    }
    if let Some(owner) = ctx.router.owner_of(from) {
        return (owner != ctx.shard_id).then_some(owner);
    }
    // Pre-commit migration candidate: the new addr hashes to us but the conn
    // lives elsewhere. Registered conn ids route directly; everything else
    // falls through to the local candidate/admission path.
    datagram_dcid(packet).and_then(|dcid| ctx.router.conn_owner_of(dcid))
}

/// One `ShardMessage` applied on the owning shard. Datagrams re-enter the
/// acquire/process path pre-admitted; commands map onto the same
/// `LiveServerState` helpers the coordinator calls locally when unsharded.
async fn handle_shard_message(
    state: &mut LiveServerState,
    ctx: &mut ShardWorkerCtx,
    msg: ShardMessage,
    out: &mut [u8],
    direct_sends: &mut smallvec::SmallVec<[SocketAddr; 8]>,
) -> Result<Option<DataPlaneFault>, &'static [u8]> {
    match msg {
        ShardMessage::Shutdown { reason } => return Err(reason),
        ShardMessage::ReloadTransport { transport } => {
            ctx.transport = *transport;
        }
        ShardMessage::Kick { addr } => {
            state.kick_remote(addr, &ctx.accept_loop, &ctx.metrics);
        }
        ShardMessage::CloseSessions { addrs } => {
            for addr in addrs {
                state.close_revoked_remote(addr);
            }
        }
        ShardMessage::ExpireRemotes { remotes } => {
            for (addr, session_id) in remotes {
                state.expire_remote(addr, session_id, &ctx.accept_loop, &ctx.metrics);
            }
        }
        ShardMessage::Downlink { target, session_id, packet, kind } => {
            match handle_shard_downlink(
                state,
                &ctx.tun_ctx,
                target,
                session_id,
                packet,
                kind,
                &ctx.metrics,
            ) {
                Ok(true) => direct_sends.push(target),
                Ok(false) => {}
                Err(fault) => return Ok(Some(fault)),
            }
        }
        ShardMessage::Datagram { packet, from } => {
            let mut packet = packet;
            let len = packet.len();
            return process_shard_datagram(state, ctx, &mut packet, len, from, out, true)
                .await
                .map_err(|_| b"datagram processing terminated" as &'static [u8]);
        }
    }
    Ok(None)
}

/// The per-datagram pipeline shared by socket RX (`routed = false`) and
/// forwarded `ShardMessage::Datagram` (`true`): blocked-IP gate, stateless
/// version negotiation, rate-limit admission, acquire, transport process,
/// migration reconcile and QKey-auth commit. Mirrors the legacy select arm
/// in `run_loop`; forwarded datagrams keep full admission semantics, only
/// the routing hop is skipped.
async fn process_shard_datagram(
    state: &mut LiveServerState,
    ctx: &ShardWorkerCtx,
    datagram: &mut [u8],
    len: usize,
    from: SocketAddr,
    out: &mut [u8],
    routed: bool,
) -> Result<Option<DataPlaneFault>, &'static str> {
    let metrics = &*ctx.metrics;

    if ctx.blocked_ips.read().contains(&from.ip()) {
        metrics.record_connection_rejected();
        return Ok(None);
    }
    let version_negotiation = stateless_version_negotiation_response(
        &datagram[..len],
        ctx.transport.supported_versions(),
    )
    .ok()
    .flatten();
    // Ownership check before admission: packets for foreign-owned addrs
    // or registered conn ids are forwarded untouched (migrated clients
    // keep hitting the shard their new 4-tuple hashes to).
    if !routed {
        if let Some(owner) = route_inbound(state, ctx, &from, &datagram[..len]) {
            if ctx
                .router
                .send(owner, ShardMessage::Datagram { packet: datagram[..len].to_vec(), from })
                .is_err()
            {
                ctx.metrics.record_shard_forward_drop();
            }
            return Ok(None);
        }
    }
    #[cfg(feature = "rate_limiter")]
    {
        use crate::implementations::server::ddos::IncomingDatagramAdmission;
        let established = state.is_established_datagram(from, &datagram[..len]);
        match state.admit_incoming_datagram(
            from,
            &datagram[..len],
            established,
            version_negotiation.is_none(),
            metrics,
        ) {
            IncomingDatagramAdmission::Allow => {}
            IncomingDatagramAdmission::RetryValidated => {
                metrics.record_ddos_retry_validated();
            }
            IncomingDatagramAdmission::Drop(reason) => {
                metrics.record_ddos_drop(reason);
                return Ok(None);
            }
            IncomingDatagramAdmission::Retry(response) => {
                metrics.record_ddos_retry_issued();
                match ctx.socket.send_to(&response, from).await {
                    Ok(sent) => metrics.record_egress_datagram(sent),
                    Err(error) => {
                        log::warn!("failed to send QUIC Retry to {}: {}", from, error);
                    }
                }
                return Ok(None);
            }
        }
    }
    if let Some(response) = version_negotiation {
        match ctx.socket.send_to(&response, from).await {
            Ok(sent) => metrics.record_egress_datagram(sent),
            Err(error) => {
                log::warn!("failed to send version negotiation to {}: {}", from, error);
            }
        }
        return Ok(None);
    }

    let client_snapshots = state.client_snapshots().clone();
    let auth_rate_limiter = state.auth_rate_limiter.clone();
    let revocation_manager = Arc::clone(&state.revocation_manager);
    let uring_worker = state.uring_worker.clone();
    let runtime_client = match state.acquire_runtime_client_with(
        from,
        &datagram[..len],
        &ctx.accept_loop,
        ctx.accept_max_clients,
        metrics,
        || {
            build_live_server_client_init(LiveClientBuildRequest {
                packet: &datagram[..len],
                local_addr: ctx.local_addr,
                remote_addr: from,
                qkey_registry: ctx.qkey_registry.as_ref(),
                revocation_manager: revocation_manager.as_ref(),
                metrics,
                stealth_config: &ctx.stealth_config,
                fec_cfg_shared: &ctx.fec_cfg_shared,
                opt_params_shared: &ctx.opt_params_shared,
                transport_config: &ctx.transport,
                runtime_policy_generation: &ctx.runtime_policy_generation,
                stealth_runtime: ctx.stealth_runtime.clone(),
                auth_rate_limiter: auth_rate_limiter.clone(),
                #[cfg(feature = "rate_limiter")]
                retry_token_manager: ctx.retry_token_manager.clone(),
                #[cfg(not(feature = "rate_limiter"))]
                retry_token_manager: None,
                clock: ctx.clock.clone(),
                crypto_config: &ctx.crypto_config,
            })
        },
    ) {
        LiveClientAcquire::Ready(v) => v,
        LiveClientAcquire::Backpressure => {
            tokio::time::sleep(ctx.accept_loop.backpressure_delay()).await;
            return Ok(None);
        }
        LiveClientAcquire::Rejected => return Ok(None),
    };
    let migration_from = runtime_client.migration_from;

    let datagram_result = match process_live_server_client_datagram(
        &ctx.socket,
        from,
        runtime_client,
        &mut datagram[..len],
        out,
        &ctx.metrics,
        &client_snapshots,
        ctx.tun_ctx.server_tun.as_ref(),
        ctx.tun_ctx.server_ips,
        &ctx.assignment_settings,
        ctx.tun_enable,
        &ctx.dns_upstream_resolvers,
        &ctx.dns_intercept_admission,
        &ctx.dns_intercept_workers,
        &ctx.tun_ctx.tun_fault,
        &ctx.tun_notify,
        &ctx.shutdown,
        ctx.masque_relay_owner.as_deref(),
        uring_worker.as_deref(),
    )
    .await
    {
        Ok(result) => result,
        Err(fault) => return Ok(Some(fault)),
    };
    if let Some(old_addr) = migration_from {
        state.reconcile_incoming_path_update(old_addr, from, ctx.local_addr, &ctx.accept_loop);
    }
    state.commit_qkey_auth_result(
        datagram_result.remove_auth_conn_id,
        datagram_result.auth_result,
        &ctx.accept_loop,
        metrics,
    );
    state.drain_client_fanout(metrics);
    Ok(None)
}

/// Dataplane shard task: one `SO_REUSEPORT` socket, one bounded message
/// channel, one `LiveServerState` fork. The select loop mirrors the legacy
/// run loop minus coordinator concerns (admin/signals/TUN reader).
pub(super) async fn run_shard_worker(
    mut state: LiveServerState,
    mut ctx: ShardWorkerCtx,
    mut shard_rx: tokio::sync::mpsc::Receiver<ShardMessage>,
) -> Result<(), DataPlaneFault> {
    let mut out = Box::new([0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE]);
    let mut ingress_pool: Vec<Vec<u8>> = Vec::new();
    let mut batch: Vec<(Vec<u8>, usize, SocketAddr)> = Vec::new();
    let mut housekeeping = tokio::time::interval(Duration::from_millis(5));
    housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut fatal: Option<DataPlaneFault> = None;
    let mut closing = false;
    // Hard close requested via `ShardMessage::Shutdown`: leave the loop even
    // with clients still connected; `force_close_and_flush` runs below.
    let mut force_close = false;
    let mut close_reason: &'static [u8] = b"server_shutdown";

    while fatal.is_none() && !force_close {
        if ctx.shutdown.load(Ordering::Relaxed) && !closing {
            closing = true;
        }
        tokio::select! {
            batch_res = recv_datagram_batch(&ctx.socket, 64, &mut ingress_pool, &mut batch), if !closing => {
                match batch_res {
                    Ok(()) => {
                        let metrics = &*ctx.metrics;
                        let mut ingress_bytes = 0u64;
                        let mut ingress_pkts = 0u64;
                        for (mut datagram, len, from) in batch.drain(..) {
                            ingress_bytes += len as u64;
                            ingress_pkts += 1;
                            match process_shard_datagram(
                                &mut state, &ctx, datagram.as_mut_slice(), len, from, &mut out[..], false,
                            )
                            .await
                            {
                                Ok(None) => {}
                                Ok(Some(fault)) => {
                                    fatal = Some(fault);
                                    ingress_pool.push(datagram);
                                    break;
                                }
                                Err(_) => {
                                    ingress_pool.push(datagram);
                                    break;
                                }
                            }
                            ingress_pool.push(datagram);
                        }
                        crate::telemetry!(crate::telemetry::BYTES_RECEIVED.inc_by(ingress_bytes));
                        metrics.record_ingress_batch(ingress_bytes, ingress_pkts);
                    }
                    Err(error) => {
                        log::error!("shard {} socket read failed: {}", ctx.shard_id, error);
                    }
                }
            }
            msg = shard_rx.recv() => {
                match msg {
                    Some(msg) => {
                        let mut direct_sends = smallvec::SmallVec::<[SocketAddr; 8]>::new();
                        let mut messages = smallvec::SmallVec::<[ShardMessage; SHARD_MESSAGE_DRAIN_CAP]>::new();
                        messages.push(msg);
                        for _ in 1..SHARD_MESSAGE_DRAIN_CAP {
                            match shard_rx.try_recv() {
                                Ok(msg) => messages.push(msg),
                                Err(_) => break,
                            }
                        }
                        for msg in messages {
                            match handle_shard_message(
                                &mut state, &mut ctx, msg, &mut out[..], &mut direct_sends,
                            )
                            .await
                            {
                                Ok(_) => {}
                                // Shutdown is a hard close: leave the loop and
                                // let `force_close_and_flush` emit CLOSE frames.
                                Err(reason) => {
                                    closing = true;
                                    force_close = true;
                                    close_reason = reason;
                                    break;
                                }
                            }
                            if closing || fatal.is_some() {
                                break;
                            }
                        }
                        if !direct_sends.is_empty() {
                            if let Err(fault) = flush_tun_downlink_queue(
                                &mut state, &direct_sends, &mut out[..], &ctx.socket, &ctx.metrics,
                            ) {
                                fatal = Some(fault);
                            }
                        }
                        if let Err(fault) =
                            drain_pending_tun_downlinks(&mut state, &mut out[..], &ctx.socket, &ctx.metrics)
                        {
                            fatal = Some(fault);
                        }
                    }
                    None => closing = true,
                }
            }
            _ = housekeeping.tick() => {
                if let Err(fault) = state
                    .run_housekeeping_tick(&ctx.socket, &mut out[..], &ctx.metrics, &ctx.accept_loop)
                    .await
                {
                    fatal = Some(fault);
                }
                if fatal.is_none() {
                    if let Err(fault) = drain_pending_tun_downlinks(
                        &mut state, &mut out[..], &ctx.socket, &ctx.metrics,
                    ) {
                        fatal = Some(fault);
                    }
                }
            }
        }
        if closing && (force_close || state.clients.is_empty()) {
            break;
        }
    }

    if let Some(fault) = fatal {
        *ctx.shard_fault.lock() = Some(fault.clone());
        return Err(fault);
    }
    // Graceful exit: close every client and flush CONNECTION_CLOSE frames.
    state
        .force_close_and_flush(
            &ctx.socket,
            &mut out[..],
            &ctx.metrics,
            &ctx.accept_loop,
            close_reason,
        )
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(n: usize) -> (Arc<ShardRouter>, Vec<tokio::sync::mpsc::Receiver<ShardMessage>>) {
        let (senders, receivers) = shard_channels(n, 4);
        (ShardRouter::new(senders), receivers)
    }

    fn conn_id(byte: u8) -> crate::transport::ConnectionId {
        crate::transport::ConnectionId::from_ref(&[byte; crate::transport::MAX_CONN_ID_LEN])
    }

    #[test]
    fn register_owner_lookup_and_unregister() {
        let (router, _rx) = router(2);
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let id = conn_id(7);
        router.register(addr, id, 1, OsFingerprintProfile::default());
        assert_eq!(router.owner_of(&addr), Some(1));
        assert_eq!(router.conn_owner_of(id.as_ref()), Some(1));
        assert_eq!(router.len(), 1);
        router.unregister(addr, 1);
        assert_eq!(router.owner_of(&addr), None);
        assert_eq!(router.len(), 0);
    }

    #[test]
    fn unregister_from_wrong_shard_is_ignored() {
        let (router, _rx) = router(2);
        let addr: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        router.register(addr, conn_id(1), 0, OsFingerprintProfile::default());
        router.unregister(addr, 1);
        assert_eq!(router.owner_of(&addr), Some(0));
    }

    #[test]
    fn rebind_keeps_ownership_and_moves_profile() {
        let (router, _rx) = router(2);
        let old_addr: SocketAddr = "10.0.0.1:5002".parse().unwrap();
        let new_addr: SocketAddr = "10.0.0.1:5003".parse().unwrap();
        let profile = OsFingerprintProfile::default();
        router.register(old_addr, conn_id(2), 1, profile);
        router.rebind(old_addr, new_addr, 1);
        assert_eq!(router.owner_of(&old_addr), None);
        assert_eq!(router.owner_of(&new_addr), Some(1));
        assert_eq!(router.profile_of(&new_addr), Some(profile));
    }

    #[test]
    fn retain_conn_ids_drops_only_stale_entries_of_owning_shard() {
        let (router, _rx) = router(2);
        let mine = conn_id(3);
        let foreign = conn_id(4);
        let stale = conn_id(5);
        let addr: SocketAddr = "10.0.0.1:5004".parse().unwrap();
        router.register(addr, mine, 0, OsFingerprintProfile::default());
        router.register(addr, foreign, 1, OsFingerprintProfile::default());
        router.register(addr, stale, 0, OsFingerprintProfile::default());
        let active: std::collections::HashSet<crate::transport::ConnectionId> =
            [mine].into_iter().collect();
        router.sync_conn_ids(0, &active);
        assert_eq!(router.conn_owner_of(mine.as_ref()), Some(0));
        assert_eq!(router.conn_owner_of(foreign.as_ref()), Some(1));
        assert_eq!(router.conn_owner_of(stale.as_ref()), None);
    }

    #[tokio::test]
    async fn send_full_channel_returns_message_for_drop_accounting() {
        let (router, mut receivers) = router(1);
        for _ in 0..4 {
            assert!(router
                .send(0, ShardMessage::Kick { addr: "10.0.0.1:1".parse().unwrap() })
                .is_ok());
        }
        assert!(router
            .send(0, ShardMessage::Kick { addr: "10.0.0.1:2".parse().unwrap() })
            .is_err());
        let mut received = 0;
        while receivers[0].try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 4);
    }
}

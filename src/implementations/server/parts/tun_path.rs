impl Default for LiveServerState {
    fn default() -> Self {
        Self::new(ServerConfig::default())
    }
}

struct ServerRuntimeLiveParts<'a> {
    live_state: &'a mut LiveServerState,
    accept_loop: &'a AcceptLoop,
    accept_max_clients: usize,
    server_tun: Option<&'a Arc<TunInterface>>,
    server_ips: ServerTunIps,
}

struct ServerLiveRuntime {
    live_state: LiveServerState,
    accept_loop: AcceptLoop,
    accept_max_clients: usize,
    admin_actions_tx: mpsc::UnboundedSender<AdminAction>,
    admin_actions_rx: Option<mpsc::UnboundedReceiver<AdminAction>>,
    metrics: Arc<Metrics>,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    server_tun: Option<Arc<TunInterface>>,
    routing: Option<RoutingManager>,
    /// Server TUN IP for ICMP echo reply handling.
    server_tun_ip: Option<Ipv4Addr>,
    server_tun_ipv6: Option<Ipv6Addr>,
    /// Channel receiving packets read from the server TUN interface (spawned reader thread).
    /// Forwarded to the appropriate client via QUIC datagrams in the run_loop.
    tun_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
    admin_web_bootstrap: StandaloneAdminWebBootstrap,
    standalone_runtime_metadata: Option<StandaloneRuntimeMetadata>,
    service_signals: StandaloneServiceSignals,
}

#[derive(Clone)]
struct StandaloneReloadPolicy {
    fec_mode_override: Option<crate::engine::FecMode>,
    stealth_policy: OwnedRuntimeStealthPolicy,
}

#[derive(Clone)]
struct StandaloneRuntimeMetadata {
    front_domain: Vec<String>,
    config_path: Option<std::path::PathBuf>,
    reload_policy: StandaloneReloadPolicy,
}

/// Runtime scope of a successful standalone configuration reload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StandaloneReloadScope {
    /// Construction profiles changed, while every existing session stayed immutable.
    NextConnectionOnly,
}

/// Truthful standalone reload acknowledgement retained in logs and audit evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandaloneReloadOutcome {
    pub scope: StandaloneReloadScope,
    pub active_sessions_unchanged: usize,
}

#[derive(Default)]
struct StandaloneServiceSignals {
    admin: Option<Arc<AtomicBool>>,
    admin_web: Option<Arc<AtomicBool>>,
    metrics: Option<Arc<AtomicBool>>,
}

fn write_tun_control_packet(tun: &TunInterface, packet: &[u8], context: &str) {
    if packet.is_empty() {
        return;
    }
    if let Err(error) = tun.write(packet) {
        log::warn!("{} write to server TUN failed: {:?}", context, error);
    }
}

fn handle_local_tun_packet(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    fingerprint_profile: OsFingerprintProfile,
    metrics: &Metrics,
) -> bool {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if destination != server_ips.ipv4 {
            return false;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if let Some(header) = icmp::parse_icmpv4(header_len, packet) {
            if header.icmp_type == icmp::icmp_type::ECHO_REQUEST {
                let reply = icmp::build_echo_reply_with_ttl(packet, fingerprint_profile.ttl());
                write_tun_control_packet(tun, &reply, "ICMPv4 echo reply");
            }
        }
        metrics.record_routing_outcome(RoutingOutcome::Local);
        return true;
    }

    let Some(server_ipv6) = server_ips.ipv6 else {
        return false;
    };
    let Some(header) = icmp::parse_icmpv6(packet) else {
        return false;
    };
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap_or([0; 16]));
    let response = if header.icmp_type == icmp::icmpv6_type::NEIGHBOR_SOLICITATION {
        icmp::build_neighbor_advertisement(packet, server_ipv6)
    } else if destination == server_ipv6 && header.icmp_type == icmp::icmpv6_type::ECHO_REQUEST {
        icmp::build_icmpv6_echo_reply(packet, fingerprint_profile.ttl())
    } else if destination == server_ipv6 {
        Vec::new()
    } else {
        return false;
    };
    write_tun_control_packet(tun, &response, "ICMPv6 local response");
    metrics.record_routing_outcome(RoutingOutcome::Local);
    metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
    true
}

fn write_downlink_error(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    outcome: RoutingOutcome,
    mtu: Option<usize>,
    metrics: &Metrics,
) {
    let response = match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let (icmp_type, code) = match outcome {
                RoutingOutcome::PacketTooBig => (
                    icmp::icmp_type::DESTINATION_UNREACHABLE,
                    icmp::icmp_code::FRAGMENTATION_NEEDED,
                ),
                RoutingOutcome::TimeExceeded => (icmp::icmp_type::TIME_EXCEEDED, 0),
                _ => (icmp::icmp_type::DESTINATION_UNREACHABLE, icmp::icmp_code::HOST_UNREACHABLE),
            };
            let next_hop_mtu = mtu.map(|value| value.min(usize::from(u16::MAX)) as u16);
            icmp::build_icmpv4_error(packet, server_ips.ipv4, icmp_type, code, next_hop_mtu)
        }
        Some(6) => {
            let Some(server_ipv6) = server_ips.ipv6 else {
                return;
            };
            let icmp_type = match outcome {
                RoutingOutcome::PacketTooBig => icmp::icmpv6_type::PACKET_TOO_BIG,
                RoutingOutcome::TimeExceeded => icmp::icmpv6_type::TIME_EXCEEDED,
                _ => icmp::icmpv6_type::DESTINATION_UNREACHABLE,
            };
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
            icmp::build_icmpv6_error(
                packet,
                server_ipv6,
                icmp_type,
                mtu.map(|value| value.min(u32::MAX as usize) as u32),
            )
        }
        _ => return,
    };
    write_tun_control_packet(tun, &response, "routing ICMP response");
    metrics.record_routing_outcome(outcome);
}

/// Retry downlink packets that were deferred because a client's QUIC DATAGRAM
/// queue was full. Successfully enqueued packets are flushed to the socket;
/// entries that are still backpressured remain in the pending queue.
fn drain_pending_tun_downlinks(
    live: &mut ServerLiveRuntime,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) {
    let mut still_pending = std::collections::VecDeque::new();
    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    let now = Instant::now();
    while let Some(entry) = live.live_state.pending_tun_downlinks.pop_front() {
        if entry.is_expired(now) {
            metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);
            log::warn!(
                "dropping expired pending TUN downlink for {} after {} ms",
                entry.target,
                now.duration_since(entry.queued_at).as_millis()
            );
            continue;
        }
        let target = entry.target;
        let send_result = {
            let Some(connection) = live.live_state.clients.get_mut(&target) else {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!(
                    "dropping pending TUN downlink for {} because its connection no longer exists",
                    target
                );
                continue;
            };
            connection.send_masque_downlink(&entry.packet)
        };
        match send_result {
            Ok(()) => queued.push(target),
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                log::debug!("pending TUN downlink for {} still backpressured", target);
                metrics.record_tun_downlink_backpressure_retry();
                still_pending.push_back(entry);
            }
            Err(error) => {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!("pending TUN downlink for {} failed: {:?}", target, error);
            }
        }
    }

    // Return still-pending entries to the queue in their original order.
    for entry in still_pending {
        live.live_state.pending_tun_downlinks.requeue(entry);
    }
    metrics.set_tun_downlink_backpressure_pending(
        live.live_state.pending_tun_downlinks.len(),
        live.live_state.pending_tun_downlinks.bytes(),
    );

    flush_tun_downlink_queue(live, &queued, out, socket, metrics);
}

fn enqueue_pending_tun_downlink(
    pending: &mut PendingTunDownlinks,
    target: SocketAddr,
    packet: Vec<u8>,
    queued_at: Instant,
    metrics: &Metrics,
) -> Result<(), PendingTunDownlinkReject> {
    let admission = pending.enqueue(target, packet, queued_at);
    match admission {
        Ok(()) => metrics.record_tun_downlink_backpressure_enqueued(),
        Err(reject) => metrics.record_tun_downlink_backpressure_drop(reject.into()),
    }
    metrics.set_tun_downlink_backpressure_pending(pending.len(), pending.bytes());
    admission
}

/// Flush a list of client connections whose downlink datagrams have been
/// enqueued. Callers are responsible for collecting `queued` addresses.
fn flush_tun_downlink_queue(
    live: &mut ServerLiveRuntime,
    queued: &[SocketAddr],
    out: &mut [u8],
    socket: &UdpSocket,
    _metrics: &Metrics,
) {
    for target in queued {
        let Some(connection) = live.live_state.clients.get_mut(target) else {
            continue;
        };
        loop {
            let written = match connection.send(out) {
                Ok(0) => {
                    log::debug!("TUN to socket send to {}: connection.send returned 0", target);
                    break;
                }
                Ok(written) => written,
                Err(error) => {
                    log::warn!(
                        "TUN to socket send to {}: connection.send failed: {:?}",
                        target,
                        error
                    );
                    break;
                }
            };
            if let Err(error) = socket.try_send_to(&out[..written], *target) {
                log::warn!("TUN to socket send to {} failed: {:?}", target, error);
                break;
            }
            log::debug!("TUN to socket send to {}: sent {}B", target, written);
        }
    }
}

fn process_server_tun_packet(
    live: &mut ServerLiveRuntime,
    packet: &[u8],
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
    fingerprint_profile: OsFingerprintProfile,
) {
    let Some(tun) = live.server_tun.clone() else {
        return;
    };
    let server_ips = ServerTunIps {
        ipv4: live.server_tun_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ipv6: live.server_tun_ipv6,
    };
    if handle_local_tun_packet(packet, &tun, server_ips, fingerprint_profile, metrics) {
        return;
    }

    let policy = Arc::clone(&live.live_state.domain.shared.forwarding_policy);
    let route = policy.classify_downlink(packet, server_ips.ipv4, server_ips.ipv6);
    log::debug!(
        "process_server_tun_packet: {}B route={:?} assigned_count={}",
        packet.len(),
        route,
        policy.assigned_address_count()
    );
    let expired = matches!(route, DownlinkRoute::Unicast { .. })
        && match packet.first().map(|byte| byte >> 4) {
            Some(4) => packet.get(8).is_some_and(|ttl| *ttl == 0),
            Some(6) => packet.get(7).is_some_and(|hop_limit| *hop_limit == 0),
            _ => false,
        };
    if expired {
        write_downlink_error(packet, &tun, server_ips, RoutingOutcome::TimeExceeded, None, metrics);
        return;
    }
    let mut targets = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    {
        let sessions = live.live_state.domain.shared.sessions.read();
        match route {
            DownlinkRoute::Unicast { destination, .. } => {
                let target = match destination {
                    std::net::IpAddr::V4(ipv4) => sessions.get_by_client_ip(ipv4),
                    std::net::IpAddr::V6(ipv6) => sessions.get_by_client_ipv6(ipv6),
                };
                if let Some(session) = target {
                    targets.push(session.remote_addr());
                }
                metrics.record_routing_outcome(RoutingOutcome::Unicast);
            }
            DownlinkRoute::Fanout { source, destination } => {
                for (_, session) in sessions.iter() {
                    let owns_source = match source {
                        std::net::IpAddr::V4(ipv4) => session.client_ip() == ipv4,
                        std::net::IpAddr::V6(ipv6) => session.client_ipv6() == Some(ipv6),
                    };
                    let supports_family = destination.is_ipv4() || session.client_ipv6().is_some();
                    if !owns_source && supports_family {
                        targets.push(session.remote_addr());
                    }
                }
                metrics.record_routing_outcome(RoutingOutcome::Fanout);
            }
            DownlinkRoute::Unknown { .. } => {
                drop(sessions);
                write_downlink_error(
                    packet,
                    &tun,
                    server_ips,
                    RoutingOutcome::Unknown,
                    None,
                    metrics,
                );
                return;
            }
            DownlinkRoute::Malformed => {
                metrics.routing_drop_malformed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            DownlinkRoute::Local { .. } => return,
        }
    }

    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    log::debug!(
        "process_server_tun_packet: targets={} clients_count={}",
        targets.len(),
        live.live_state.clients.len()
    );
    for target in targets {
        let send_result = {
            let Some(connection) = live.live_state.clients.get_mut(&target) else {
                log::debug!("process_server_tun_packet: no connection for target {}", target);
                continue;
            };
            let effective_mtu = connection.effective_tunnel_mtu().min(usize::from(tun.mtu()));
            if packet.len() > effective_mtu {
                if matches!(route, DownlinkRoute::Unicast { .. }) {
                    write_downlink_error(
                        packet,
                        &tun,
                        server_ips,
                        RoutingOutcome::PacketTooBig,
                        Some(effective_mtu),
                        metrics,
                    );
                }
                continue;
            }
            connection.send_masque_downlink(packet)
        };
        match send_result {
            Ok(()) => queued.push(target),
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                if let Err(reject) = enqueue_pending_tun_downlink(
                    &mut live.live_state.pending_tun_downlinks,
                    target,
                    packet.to_vec(),
                    Instant::now(),
                    metrics,
                ) {
                    log::warn!(
                        "dropping TUN downlink for {} after bounded backpressure rejection: {:?}",
                        target,
                        reject
                    );
                }
            }
            Err(error) => {
                log::warn!("TUN to MASQUE queue for {} failed: {:?}", target, error);
            }
        }
    }

    flush_tun_downlink_queue(live, &queued, out, socket, metrics);
}

impl StandaloneServiceSignals {
    fn shutdown_all(&mut self) {
        if let Some(sig) = self.admin.take() {
            sig.store(true, Ordering::SeqCst);
        }
        if let Some(sig) = self.admin_web.take() {
            sig.store(true, Ordering::SeqCst);
        }
        if let Some(sig) = self.metrics.take() {
            sig.store(true, Ordering::SeqCst);
        }
    }
}

pub const QKEY_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const FINAL_CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_millis(500);
pub const DF_SNI_MODE_FIXED: &str = "fixed";
pub const DF_SNI_MODE_AUTO_ROTATING: &str = "auto_rotating";

const BUILTIN_FRONTING_SNI_ALLOWLIST: &[&str] = &[
    "cdn.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "warp.plus",
    "workers.dev",
    "cdn.fastly.net",
    "fastly.com",
    "fastlylb.net",
    "fsly.net",
    "akamaized.net",
    "akamai.net",
    "akamaihd.net",
    "akamaitechnologies.com",
    "edgesuite.net",
    "cloudfront.net",
    "amazonaws.com",
    "aws.amazon.com",
    "awsstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "google.com",
    "azureedge.net",
    "azure.microsoft.com",
    "windows.net",
    "msecnd.net",
    "stackpathdns.com",
    "stackpathcdn.com",
    "bootstrapcdn.com",
    "kxcdn.com",
    "keycdn.com",
    "b-cdn.net",
    "bunnycdn.com",
    "incapdns.net",
    "imperva.com",
];

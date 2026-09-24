use super::sharding::{DownlinkKind, ShardMessage, ShardRouter};
use super::*;

fn masque_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("QUICFUSCATE_MASQUE_TRACE").is_some())
}

impl Default for LiveServerState {
    // `ServerConfig::default()` is validated by the fallible constructor; the
    // legacy Default API has no error channel, so preserve its infallible
    // contract with a narrow disposition rather than hiding the failure.
    #[allow(clippy::panic)]
    fn default() -> Self {
        Self::try_new(ServerConfig::default()).unwrap_or_else(|error| {
            panic!("default live server state construction failed: {error}")
        })
    }
}

pub(super) struct ServerRuntimeLiveParts<'a> {
    pub(super) live_state: &'a mut LiveServerState,
    pub(super) accept_loop: &'a AcceptLoop,
    pub(super) accept_max_clients: usize,
    pub(super) server_tun: Option<&'a Arc<TunInterface>>,
    pub(super) server_ips: ServerTunIps,
    pub(super) assignment_settings: ServerAssignmentSettings,
    pub(super) tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    pub(super) tun_notify: Arc<tokio::sync::Notify>,
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) uring_worker: Option<Arc<LiveUringWorker>>,
}

pub(super) struct ServerLiveRuntime {
    pub(super) live_state: LiveServerState,
    pub(super) accept_loop: Arc<AcceptLoop>,
    pub(super) accept_max_clients: usize,
    pub(super) admin_actions_tx: mpsc::UnboundedSender<AdminAction>,
    pub(super) admin_actions_rx: Option<mpsc::UnboundedReceiver<AdminAction>>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) socket: Arc<UdpSocket>,
    pub(super) local_addr: SocketAddr,
    pub(super) server_tun: Option<Arc<TunInterface>>,
    pub(super) routing: Option<RoutingManager>,
    /// Server TUN IP for ICMP echo reply handling.
    pub(super) server_tun_ip: Option<Ipv4Addr>,
    pub(super) server_tun_ipv6: Option<Ipv6Addr>,
    /// TUN uplink ingress: reactor-integrated fd read (unix) or the
    /// wave-batched reader channel (fd-less backends). Replaces the bare
    /// receiver so the run loop sees one source abstraction.
    pub(super) tun_ingress: ServerTunIngress,
    /// Cooperative cancellation for the standalone TUN reader.
    pub(super) tun_reader_shutdown: Option<Arc<AtomicBool>>,
    /// Owned reader handle. `stop()` joins it before releasing the TUN device.
    pub(super) tun_reader_handle: Option<std::thread::JoinHandle<()>>,
    /// Wakes the run loop as soon as the reader queues a TUN frame.
    pub(super) tun_notify: Arc<tokio::sync::Notify>,
    /// First terminal server TUN data-plane fault for this runtime generation.
    pub(super) tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    /// All dataplane sockets (`len > 1` => SO_REUSEPORT sharding active).
    /// `socket` stays `shard_sockets[0]` for legacy consumers.
    pub(super) shard_sockets: Vec<Arc<UdpSocket>>,
    /// Worker-side message receivers, taken by the run loop when spawning
    /// shard tasks. `Some` iff sharding is active.
    pub(super) shard_receivers:
        Option<Vec<tokio::sync::mpsc::Receiver<super::sharding::ShardMessage>>>,
    /// Global address/conn-id -> shard-owner routing table.
    pub(super) shard_router: Option<Arc<super::sharding::ShardRouter>>,
    /// First dataplane fault reported by any shard worker.
    pub(super) shard_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    pub(super) blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    pub(super) qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
    pub(super) admin_web_bootstrap: StandaloneAdminWebBootstrap,
    pub(super) standalone_runtime_metadata: Option<StandaloneRuntimeMetadata>,
    pub(super) service_signals: StandaloneServiceSignals,
}

#[derive(Clone)]
pub(super) struct StandaloneReloadPolicy {
    pub(super) fec_mode_override: Option<qf_engine_types::FecMode>,
    pub(super) stealth_policy: OwnedRuntimeStealthPolicy,
}

#[derive(Clone)]
pub(super) struct StandaloneRuntimeMetadata {
    pub(super) cover_targets: Vec<String>,
    pub(super) config_path: Option<std::path::PathBuf>,
    pub(super) reload_policy: StandaloneReloadPolicy,
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
    pub runtime_generation: u64,
}

#[derive(Default)]
pub(super) struct StandaloneServiceSignals {
    pub(super) admin: Option<Arc<AtomicBool>>,
    pub(super) admin_web: Option<Arc<AtomicBool>>,
    pub(super) metrics: Option<Arc<AtomicBool>>,
}

fn write_tun_control_packet(
    tun: &TunInterface,
    packet: &[u8],
    context: &str,
) -> Result<(), DataPlaneFault> {
    if packet.is_empty() {
        return Ok(());
    }
    if let Err(error) = tun.write(packet) {
        log::warn!("{} write to server TUN failed: {:?}", context, error);
        return Err(DataPlaneFault::TunWrite {
            component: context.to_string(),
            error: error.to_string(),
        });
    }
    Ok(())
}

fn handle_local_tun_packet(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    fingerprint_profile: OsFingerprintProfile,
    metrics: &Metrics,
) -> Result<bool, DataPlaneFault> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if destination != server_ips.ipv4 {
            return Ok(false);
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if let Some(header) = icmp::parse_icmpv4(header_len, packet) {
            if header.icmp_type == icmp::icmp_type::ECHO_REQUEST {
                let reply = icmp::build_echo_reply_with_ttl(packet, fingerprint_profile.ttl());
                write_tun_control_packet(tun, &reply, "ICMPv4 echo reply")?;
            }
        }
        if masque_trace_enabled() {
            log::info!(
                "server TUN ingress consumed locally dst={} icmp={:?}",
                destination,
                icmp::parse_icmpv4(header_len, packet).map(|header| header.icmp_type)
            );
        }
        metrics.record_routing_outcome(RoutingOutcome::Local);
        return Ok(true);
    }

    let Some(server_ipv6) = server_ips.ipv6 else {
        return Ok(false);
    };
    let Some(header) = icmp::parse_icmpv6(packet) else {
        return Ok(false);
    };
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap_or([0; 16]));
    let response = if header.icmp_type == icmp::icmpv6_type::NEIGHBOR_SOLICITATION {
        icmp::build_neighbor_advertisement(packet, server_ipv6)
    } else if destination == server_ipv6 && header.icmp_type == icmp::icmpv6_type::ECHO_REQUEST {
        icmp::build_icmpv6_echo_reply(packet, fingerprint_profile.ttl())
    } else if destination == server_ipv6 {
        Vec::new()
    } else {
        return Ok(false);
    };
    write_tun_control_packet(tun, &response, "ICMPv6 local response")?;
    metrics.record_routing_outcome(RoutingOutcome::Local);
    metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
    Ok(true)
}

fn write_downlink_error(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    fingerprint_profile: OsFingerprintProfile,
    outcome: RoutingOutcome,
    mtu: Option<usize>,
    metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
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
            icmp::build_icmpv4_error_with_ttl(
                packet,
                server_ips.ipv4,
                icmp_type,
                code,
                next_hop_mtu,
                fingerprint_profile.ttl(),
            )
        }
        Some(6) => {
            let Some(server_ipv6) = server_ips.ipv6 else {
                return Ok(());
            };
            let icmp_type = match outcome {
                RoutingOutcome::PacketTooBig => icmp::icmpv6_type::PACKET_TOO_BIG,
                RoutingOutcome::TimeExceeded => icmp::icmpv6_type::TIME_EXCEEDED,
                _ => icmp::icmpv6_type::DESTINATION_UNREACHABLE,
            };
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
            icmp::build_icmpv6_error_with_hop_limit(
                packet,
                server_ipv6,
                icmp_type,
                mtu.map(|value| value.min(u32::MAX as usize) as u32),
                fingerprint_profile.ttl(),
            )
        }
        _ => return Ok(()),
    };
    write_tun_control_packet(tun, &response, "routing ICMP response")?;
    metrics.record_routing_outcome(outcome);
    Ok(())
}

/// Retry downlink packets that were deferred because a client's QUIC DATAGRAM
/// queue was full. Successfully enqueued packets are flushed to the socket;
/// entries that are still backpressured remain in the pending queue.
pub(super) fn drain_pending_tun_downlinks(
    live_state: &mut LiveServerState,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    let mut deferred_sessions = std::collections::HashSet::new();
    let sessions = Arc::clone(&live_state.domain.shared.sessions);
    // One read guard covers stats lookups and token-bucket checks for every
    // drained entry; the bandwidth manager serializes per client internally.
    // `sessions` is an independent Arc here, so the guard conflicts with
    // nothing else in `live`.
    let sessions = sessions.read();
    let now = live_state.clock.now();
    while let Some(mut entry) = live_state.pending_tun_downlinks.pop_next(&deferred_sessions) {
        if entry.is_expired(now) {
            metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);
            log::warn!(
                "dropping expired pending TUN downlink for {} after {} ms",
                entry.target,
                now.saturating_duration_since(entry.queued_at).as_millis()
            );
            continue;
        }
        let Some(stats) = sessions.bandwidth_stats(entry.session_id) else {
            metrics.record_tun_downlink_backpressure_drop(
                TunDownlinkBackpressureDrop::TerminalTransportError,
            );
            continue;
        };
        let weight = stats.policy.weight;
        if !live_state.pending_tun_downlinks.reserve_capacity(entry.packet.len()) {
            metrics.record_tun_downlink_backpressure_retry();
            live_state.pending_tun_downlinks.requeue_front(entry, weight);
            break;
        }
        {
            if !entry.bandwidth_accounted {
                let decision = sessions.check_bandwidth(
                    entry.session_id,
                    BandwidthDirection::Downlink,
                    entry.packet.len(),
                );
                metrics.record_bandwidth_decision(
                    BandwidthDirection::Downlink,
                    decision,
                    entry.packet.len(),
                );
                match decision {
                    BandwidthDecision::Allowed => entry.bandwidth_accounted = true,
                    BandwidthDecision::RateLimited => {
                        live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                        metrics.record_tun_downlink_backpressure_retry();
                        deferred_sessions.insert(entry.session_id);
                        live_state.pending_tun_downlinks.requeue_front(entry, weight);
                        continue;
                    }
                    BandwidthDecision::DailyQuotaExceeded
                    | BandwidthDecision::MonthlyQuotaExceeded
                    | BandwidthDecision::ClockUnavailable => {
                        live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                        continue;
                    }
                }
            }
        }
        let target = entry.target;
        let send_result = {
            let Some(connection) = live_state.clients.get_mut(&target) else {
                live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!(
                    "dropping pending TUN downlink for {} because its connection no longer exists",
                    target
                );
                continue;
            };
            connection.send_masque_downlink(entry.packet.as_slice())
        };
        match send_result {
            Ok(()) => {
                metrics.record_bandwidth_scheduler_delivery(entry.packet.len());
                queued.push(target);
            }
            Err(crate::error::ConnectionError::DgramQueueFull)
            | Err(crate::error::ConnectionError::PrivatePayloadGateClosed) => {
                live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                log::debug!("pending TUN downlink for {} still backpressured", target);
                metrics.record_tun_downlink_backpressure_retry();
                deferred_sessions.insert(entry.session_id);
                live_state.pending_tun_downlinks.requeue_front(entry, weight);
            }
            Err(error) => {
                live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!("pending TUN downlink for {} failed: {:?}", target, error);
                return Err(DataPlaneFault::TransportSend {
                    component: format!("server pending TUN downlink to {target}"),
                    error: error.to_string(),
                });
            }
        }
    }

    metrics.set_tun_downlink_backpressure_pending(
        live_state.pending_tun_downlinks.len(),
        live_state.pending_tun_downlinks.bytes(),
    );
    metrics
        .set_bandwidth_scheduler_active_clients(live_state.pending_tun_downlinks.active_clients());

    flush_tun_downlink_queue(live_state, &queued, out, socket, metrics)
}

#[cfg(test)]
pub(super) fn enqueue_pending_tun_downlink(
    pending: &mut PendingTunDownlinks,
    target: SocketAddr,
    session_id: SessionId,
    weight: u16,
    packet: Vec<u8>,
    queued_at: Instant,
    metrics: &Metrics,
) -> Result<(), PendingTunDownlinkReject> {
    enqueue_pending_tun_downlink_with_accounting(
        pending,
        PendingTunDownlink {
            target,
            session_id,
            packet: PendingTunPacket::from_vec(packet),
            queued_at,
            bandwidth_accounted: false,
        },
        weight,
        PendingTunDownlinkAdmission::TransportBackpressure,
        metrics,
    )
}

pub(super) fn enqueue_scheduled_tun_downlink(
    pending: &mut PendingTunDownlinks,
    target: SocketAddr,
    session_id: SessionId,
    weight: u16,
    packet: PendingTunPacket,
    queued_at: Instant,
    metrics: &Metrics,
) -> Result<(), PendingTunDownlinkReject> {
    enqueue_pending_tun_downlink_with_accounting(
        pending,
        PendingTunDownlink { target, session_id, packet, queued_at, bandwidth_accounted: false },
        weight,
        PendingTunDownlinkAdmission::BandwidthScheduler,
        metrics,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingTunDownlinkAdmission {
    TransportBackpressure,
    BandwidthScheduler,
}

fn enqueue_pending_tun_downlink_with_accounting(
    pending: &mut PendingTunDownlinks,
    entry: PendingTunDownlink,
    weight: u16,
    admission_kind: PendingTunDownlinkAdmission,
    metrics: &Metrics,
) -> Result<(), PendingTunDownlinkReject> {
    let admission = pending.enqueue_with_accounting(
        entry.target,
        entry.session_id,
        weight,
        entry.packet,
        entry.queued_at,
        entry.bandwidth_accounted,
    );
    match admission {
        Ok(()) => match admission_kind {
            PendingTunDownlinkAdmission::TransportBackpressure => {
                metrics.record_tun_downlink_backpressure_enqueued();
            }
            PendingTunDownlinkAdmission::BandwidthScheduler => {
                metrics.record_bandwidth_scheduler_enqueue();
            }
        },
        Err(reject) => metrics.record_tun_downlink_backpressure_drop(reject.into()),
    }
    metrics.set_tun_downlink_backpressure_pending(pending.len(), pending.bytes());
    metrics.set_bandwidth_scheduler_active_clients(pending.active_clients());
    admission
}

/// Flush a list of client connections whose downlink datagrams have been
/// enqueued. Callers are responsible for collecting `queued` addresses.
pub(super) fn flush_tun_downlink_queue(
    live_state: &mut LiveServerState,
    queued: &[SocketAddr],
    out: &mut [u8],
    socket: &UdpSocket,
    _metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
    // Linux: drain all targets into the persistent flat staging, then emit the
    // burst through sendmmsg with per-packet addresses - GSO runs coalesce
    // contiguous same-target uniform segments into one sendmsg first. A burst
    // no longer costs one sendto syscall per produced packet.
    #[cfg(target_os = "linux")]
    {
        let _ = out;
        use std::os::fd::AsRawFd;
        const TX_STAGED_MAX: usize = 256;
        const TX_FLAT_BYTES: usize = 4 * 1024 * 1024;
        const SEND_WINDOW: usize = 65_535;

        let fd = socket.as_raw_fd();
        // A GSO segment must fit one wire datagram — the kernel rejects
        // `gso_size > route_mtu - header` with EMSGSIZE. The unconnected
        // server socket rarely reports a route MTU, so the conservative
        // Ethernet payload ceiling stands in when probing fails.
        let gso_seg_cap = qf_transport_udp::udp_gso_segment_mtu(fd).unwrap_or(1472);
        let flat = &mut live_state.downlink_tx_flat;
        let staging = &mut live_state.downlink_tx_staging;
        if flat.len() < TX_FLAT_BYTES {
            flat.resize(TX_FLAT_BYTES, 0);
        }

        let mut ti = 0usize;
        while ti < queued.len() {
            // Phase 1: drain connections into flat staging until drained or full.
            staging.clear();
            let mut watermark = 0usize;
            while ti < queued.len()
                && staging.len() < TX_STAGED_MAX
                && flat.len() - watermark >= SEND_WINDOW
            {
                let target = queued[ti];
                let Some(connection) = live_state.clients.get_mut(&target) else {
                    ti += 1;
                    continue;
                };
                match connection.send(&mut flat[watermark..]) {
                    Ok(0) => {
                        log::debug!("TUN to socket send to {}: connection.send returned 0", target);
                        ti += 1;
                    }
                    Ok(written) => {
                        staging.push((target, watermark, written));
                        watermark += written;
                    }
                    Err(crate::error::ConnectionError::Done) => {
                        log::debug!(
                            "TUN to socket send to {}: connection.send returned Done",
                            target
                        );
                        ti += 1;
                    }
                    Err(error) => {
                        log::warn!(
                            "TUN to socket send to {}: connection.send failed: {:?}",
                            target,
                            error
                        );
                        return Err(DataPlaneFault::TransportSend {
                            component: format!("server TUN downlink connection to {target}"),
                            error: error.to_string(),
                        });
                    }
                }
            }
            if staging.is_empty() {
                break;
            }

            // Phase 2: dispatch staged packets in order. GSO runs first - the
            // run's spans are contiguous in `flat` by construction. Everything
            // else accumulates into sendmmsg groups flushed before each GSO
            // segment so per-target ordering is preserved.
            let mut sent = [false; TX_STAGED_MAX];
            let n_staged = staging.len();
            let mut pending: smallvec::SmallVec<[usize; 64]> = smallvec::SmallVec::new();
            let mut i = 0usize;
            while i < n_staged {
                if sent[i] {
                    i += 1;
                    continue;
                }
                let gso_blocked = live_state
                    .clients
                    .get(&staging[i].0)
                    .map(|c| c.udp_gso_path_blocked)
                    .unwrap_or(false);
                if let Some((end, seg)) = if gso_blocked {
                    None
                } else {
                    super::live_auth::plan_gso_run(
                        staging,
                        &sent[..n_staged],
                        i,
                        qf_transport_udp::UDP_GSO_MAX_PAYLOAD,
                        gso_seg_cap,
                    )
                } {
                    if !pending.is_empty() {
                        let refs: smallvec::SmallVec<[(&[u8], SocketAddr); 64]> = pending
                            .iter()
                            .map(|&idx| {
                                let (t, off, len) = staging[idx];
                                (&flat[off..off + len], t)
                            })
                            .collect();
                        match qf_transport_udp::send_batch_fd(fd, &refs) {
                            Ok(n) => {
                                for &idx in pending.iter().take(n.min(pending.len())) {
                                    sent[idx] = true;
                                }
                            }
                            Err(error) => {
                                log::debug!("TUN downlink sendmmsg fallback: {}", error);
                            }
                        }
                        pending.clear();
                    }
                    let (target, start_off, _) = staging[i];
                    let end_off = staging[end - 1].1 + staging[end - 1].2;
                    match qf_transport_udp::send_udp_segment(
                        fd,
                        target,
                        &flat[start_off..end_off],
                        seg,
                    ) {
                        Ok(_) => {
                            for flag in &mut sent[i..end] {
                                *flag = true;
                            }
                        }
                        Err(error) => {
                            log::debug!("TUN downlink GSO fallback: {}", error);
                            // EMSGSIZE is a stable route property — stop
                            // probing GSO to this peer for the connection.
                            if error.raw_os_error() == Some(libc::EMSGSIZE) {
                                if let Some(client) = live_state.clients.get_mut(&target) {
                                    client.udp_gso_path_blocked = true;
                                }
                            }
                        }
                    }
                    i = end;
                } else {
                    pending.push(i);
                    i += 1;
                }
            }
            if !pending.is_empty() {
                let refs: smallvec::SmallVec<[(&[u8], SocketAddr); 64]> = pending
                    .iter()
                    .map(|&idx| {
                        let (t, off, len) = staging[idx];
                        (&flat[off..off + len], t)
                    })
                    .collect();
                match qf_transport_udp::send_batch_fd(fd, &refs) {
                    Ok(n) => {
                        for &idx in pending.iter().take(n.min(pending.len())) {
                            sent[idx] = true;
                        }
                    }
                    Err(error) => {
                        log::debug!("TUN downlink sendmmsg fallback: {}", error);
                    }
                }
            }

            // Sequential tail: whatever sendmmsg/GSO left unsent goes out with
            // the original per-packet semantics and error propagation.
            for (idx, &(target, off, len)) in staging.iter().enumerate() {
                if sent[idx] {
                    continue;
                }
                if let Err(error) = socket.try_send_to(&flat[off..off + len], target) {
                    log::warn!("TUN to socket send to {} failed: {:?}", target, error);
                    return Err(DataPlaneFault::TransportSend {
                        component: format!("server UDP downlink to {target}"),
                        error: error.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    for target in queued {
        let Some(connection) = live_state.clients.get_mut(target) else {
            continue;
        };
        loop {
            let written = match connection.send(out) {
                Ok(0) => {
                    log::debug!("TUN to socket send to {}: connection.send returned 0", target);
                    break;
                }
                Ok(written) => written,
                Err(crate::error::ConnectionError::Done) => {
                    log::debug!("TUN to socket send to {}: connection.send returned Done", target);
                    break;
                }
                Err(error) => {
                    log::warn!(
                        "TUN to socket send to {}: connection.send failed: {:?}",
                        target,
                        error
                    );
                    return Err(DataPlaneFault::TransportSend {
                        component: format!("server TUN downlink connection to {target}"),
                        error: error.to_string(),
                    });
                }
            };
            if let Err(error) = socket.try_send_to(&out[..written], *target) {
                log::warn!("TUN to socket send to {} failed: {:?}", target, error);
                return Err(DataPlaneFault::TransportSend {
                    component: format!("server UDP downlink to {target}"),
                    error: error.to_string(),
                });
            }
            log::debug!("TUN to socket send to {}: sent {}B", target, written);
        }
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

/// Retain the frame's pool block for a pending-queue entry. The first enqueue
/// converts the `TunPacket` into a `PendingTunPacket::Shared`; subsequent
/// targets get an Arc clone of the same block instead of another copy.
fn retain_tun_frame(
    packet: &mut Option<crate::interface::TunPacket>,
    shared_frame: &mut Option<PendingTunPacket>,
) -> PendingTunPacket {
    if let Some(shared) = shared_frame.as_ref() {
        return shared.clone();
    }
    let pending = PendingTunPacket::from_tun_packet(
        packet.take().expect("TUN frame owned until first enqueue"),
    );
    *shared_frame = Some(pending.clone());
    pending
}

/// TUN-side handles and identity shared by the unsharded packet path and
/// the sharded coordinator/worker split. Owned `Arc`s keep the context
/// independent of `ServerLiveRuntime` borrows; everything is `&self`-safe:
/// TUN writes are atomic per frame, ICMP composition is pure.
#[derive(Clone)]
pub(super) struct ServerTunContext {
    pub(super) server_tun: Option<Arc<TunInterface>>,
    pub(super) server_ips: ServerTunIps,
    pub(super) tun_reader_shutdown: Option<Arc<AtomicBool>>,
    pub(super) tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    pub(super) fingerprint_profile: OsFingerprintProfile,
}

/// Admit downlink frames against the opened inner TUN MTU.
///
/// `effective_tunnel_mtu()` floors at 1280 until DPLPMTUD confirms the path.
/// The server TUN is already opened at `inner_tun_mtu(path)` (1413 on a 1500
/// path). Re-clamping to the pre-confirm floor rejects the kernel's MSS-sized
/// segments and blackholes TCP downlink.
pub(super) fn tun_downlink_admit_mtu(tun_mtu: Option<u16>, connection_effective: usize) -> usize {
    tun_mtu.map(usize::from).unwrap_or(connection_effective)
}

/// One downlink target processed on the shard that owns the connection:
/// MTU gate (+ PacketTooBig ICMP for unicast), bandwidth decision, then
/// direct send or bounded scheduled enqueue. Returns `true` when the packet
/// was queued into the connection and the caller should flush it.
#[allow(clippy::too_many_arguments)]
fn deliver_tun_downlink_target(
    live_state: &mut LiveServerState,
    tun: Option<&Arc<TunInterface>>,
    server_ips: ServerTunIps,
    target: SocketAddr,
    session_id: SessionId,
    packet: &mut Option<crate::interface::TunPacket>,
    shared_frame: &mut Option<PendingTunPacket>,
    unicast: bool,
    source_profile: OsFingerprintProfile,
    sessions: &SessionManager,
    metrics: &Metrics,
) -> Result<bool, DataPlaneFault> {
    let Some(connection) = live_state.clients.get(&target) else {
        log::debug!("downlink target {} has no local connection", target);
        return Ok(false);
    };
    let frame_len = match shared_frame.as_ref() {
        Some(shared) => shared.len(),
        None => packet.as_ref().expect("TUN frame owned until first enqueue").len(),
    };
    let effective_mtu =
        tun_downlink_admit_mtu(tun.map(|tun| tun.mtu()), connection.effective_tunnel_mtu());
    if frame_len > effective_mtu {
        if unicast {
            if let Some(tun) = tun {
                let frame: &[u8] = match shared_frame.as_ref() {
                    Some(shared) => shared.as_slice(),
                    None => packet.as_ref().expect("frame").as_slice(),
                };
                write_downlink_error(
                    frame,
                    tun,
                    server_ips,
                    source_profile,
                    RoutingOutcome::PacketTooBig,
                    Some(effective_mtu),
                    metrics,
                )?;
            }
        }
        return Ok(false);
    }
    let requires_scheduler = live_state.pending_tun_downlinks.uses_shared_capacity()
        || live_state.pending_tun_downlinks.contains_session(session_id);
    // The sessions guard held by the caller covers the stats lookup and (on
    // the fast path) the token-bucket check.
    let Some(stats) = sessions.bandwidth_stats(session_id) else {
        return Ok(false);
    };
    let weight = stats.policy.weight;
    let decision = if requires_scheduler {
        None
    } else {
        Some(sessions.check_bandwidth(session_id, BandwidthDirection::Downlink, frame_len))
    };
    if let Some(decision) = decision {
        metrics.record_bandwidth_decision(BandwidthDirection::Downlink, decision, frame_len);
        match decision {
            BandwidthDecision::Allowed => {
                let masque_mtu = live_state
                    .clients
                    .get(&target)
                    .map(QuicFuscateConnection::effective_masque_mtu);
                let send_result = {
                    let frame: &[u8] = match shared_frame.as_ref() {
                        Some(shared) => shared.as_slice(),
                        None => packet.as_ref().expect("frame").as_slice(),
                    };
                    live_state
                        .clients
                        .get_mut(&target)
                        .map(|connection| connection.send_masque_downlink(frame))
                };
                match send_result {
                    Some(Ok(())) => {
                        metrics.record_bandwidth_scheduler_delivery(frame_len);
                        return Ok(true);
                    }
                    Some(Err(
                        crate::error::ConnectionError::BufferTooShort
                        | crate::error::ConnectionError::Done,
                    )) => {
                        if unicast {
                            if let Some(tun) = tun {
                                let frame: &[u8] = match shared_frame.as_ref() {
                                    Some(shared) => shared.as_slice(),
                                    None => packet.as_ref().expect("frame").as_slice(),
                                };
                                write_downlink_error(
                                    frame,
                                    tun,
                                    server_ips,
                                    source_profile,
                                    RoutingOutcome::PacketTooBig,
                                    masque_mtu,
                                    metrics,
                                )?;
                            }
                        }
                        return Ok(false);
                    }
                    Some(Err(crate::error::ConnectionError::DgramQueueFull))
                    | Some(Err(crate::error::ConnectionError::PrivatePayloadGateClosed)) => {
                        let pending_packet = retain_tun_frame(packet, shared_frame);
                        if let Err(reject) = enqueue_pending_tun_downlink_with_accounting(
                            &mut live_state.pending_tun_downlinks,
                            PendingTunDownlink {
                                target,
                                session_id,
                                packet: pending_packet,
                                queued_at: live_state.clock.now(),
                                bandwidth_accounted: true,
                            },
                            weight,
                            PendingTunDownlinkAdmission::TransportBackpressure,
                            metrics,
                        ) {
                            log::warn!(
                                "dropping admitted TUN downlink for {} after bounded transport backpressure rejection: {:?}",
                                target,
                                reject
                            );
                        }
                        return Ok(false);
                    }
                    Some(Err(error)) => {
                        metrics.record_tun_downlink_backpressure_drop(
                            TunDownlinkBackpressureDrop::TerminalTransportError,
                        );
                        log::warn!("TUN downlink for {} failed: {:?}", target, error);
                        return Err(DataPlaneFault::TransportSend {
                            component: format!("server TUN downlink to {target}"),
                            error: error.to_string(),
                        });
                    }
                    None => return Ok(false),
                }
            }
            BandwidthDecision::RateLimited => {
                metrics.record_tun_downlink_backpressure_retry();
            }
            BandwidthDecision::DailyQuotaExceeded
            | BandwidthDecision::MonthlyQuotaExceeded
            | BandwidthDecision::ClockUnavailable => return Ok(false),
        }
    }
    let enqueue_result = enqueue_scheduled_tun_downlink(
        &mut live_state.pending_tun_downlinks,
        target,
        session_id,
        weight,
        retain_tun_frame(packet, shared_frame),
        live_state.clock.now(),
        metrics,
    );
    if let Err(reject) = enqueue_result {
        log::warn!(
            "dropping TUN downlink for {} after bounded scheduler rejection: {:?}",
            target,
            reject
        );
    }
    Ok(false)
}

/// Resolve the source client's frozen ingress profile for ICMP composition.
/// Local `clients` first (unsharded); the `profile_lookup` fallback lets a
/// sharded coordinator consult the router's profile registry.
fn resolve_source_profile(
    live_state: &LiveServerState,
    packet_slice: &[u8],
    profile_lookup: &dyn Fn(&SocketAddr) -> Option<OsFingerprintProfile>,
) -> Option<OsFingerprintProfile> {
    let remote_addr = match packet_slice.first().map(|byte| byte >> 4) {
        Some(4) if packet_slice.len() >= 20 => {
            let source = Ipv4Addr::new(
                packet_slice[12],
                packet_slice[13],
                packet_slice[14],
                packet_slice[15],
            );
            live_state
                .domain
                .shared
                .sessions
                .read()
                .get_by_client_ip(source)
                .map(Session::remote_addr)
        }
        Some(6) if packet_slice.len() >= 40 => {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet_slice[8..24]).ok()?);
            live_state
                .domain
                .shared
                .sessions
                .read()
                .get_by_client_ipv6(source)
                .map(Session::remote_addr)
        }
        _ => None,
    }?;
    live_state
        .clients
        .get(&remote_addr)
        .map(QuicFuscateConnection::tunnel_ingress_profile)
        .or_else(|| profile_lookup(&remote_addr))
}

/// Resolved downlink classification: unicast flag, ordered (addr, session)
/// targets, and the source client's frozen ingress profile for ICMP
/// composition.
struct ClassifiedDownlink {
    unicast: bool,
    targets: smallvec::SmallVec<[(SocketAddr, SessionId); 4]>,
    source_profile: OsFingerprintProfile,
}

/// Shared prelude of the TUN downlink path: local handling, route
/// classification, TTL expiry, and target resolution. `Ok(None)` means the
/// packet was fully handled here (local/unknown/malformed/expired).
fn classify_server_tun_downlink(
    live_state: &LiveServerState,
    tun: &Arc<TunInterface>,
    server_ips: ServerTunIps,
    packet_slice: &[u8],
    profile_lookup: &dyn Fn(&SocketAddr) -> Option<OsFingerprintProfile>,
    fingerprint_profile: OsFingerprintProfile,
    metrics: &Metrics,
) -> Result<Option<ClassifiedDownlink>, DataPlaneFault> {
    let source_profile = resolve_source_profile(live_state, packet_slice, profile_lookup)
        .unwrap_or(fingerprint_profile);
    if handle_local_tun_packet(packet_slice, tun, server_ips, source_profile, metrics)? {
        return Ok(None);
    }

    let policy = &live_state.domain.shared.forwarding_policy;
    let route = policy.classify_downlink(packet_slice, server_ips.ipv4, server_ips.ipv6);
    log::debug!(
        "server TUN downlink: {}B route={:?} assigned_count={}",
        packet_slice.len(),
        route,
        policy.assigned_address_count()
    );
    let expired = matches!(route, DownlinkRoute::Unicast { .. })
        && match packet_slice.first().map(|byte| byte >> 4) {
            Some(4) => packet_slice.get(8).is_some_and(|ttl| *ttl == 0),
            Some(6) => packet_slice.get(7).is_some_and(|hop_limit| *hop_limit == 0),
            _ => false,
        };
    if expired {
        write_downlink_error(
            packet_slice,
            tun,
            server_ips,
            source_profile,
            RoutingOutcome::TimeExceeded,
            None,
            metrics,
        )?;
        return Ok(None);
    }
    let sessions = live_state.domain.shared.sessions.read();
    let mut targets = smallvec::SmallVec::<[(SocketAddr, SessionId); 4]>::new();
    match route {
        DownlinkRoute::Unicast { destination, .. } => {
            let target = match destination {
                std::net::IpAddr::V4(ipv4) => sessions.get_by_client_ip(ipv4),
                std::net::IpAddr::V6(ipv6) => sessions.get_by_client_ipv6(ipv6),
            };
            if let Some(session) = target {
                targets.push((session.remote_addr(), session.id()));
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
                    targets.push((session.remote_addr(), session.id()));
                }
            }
            metrics.record_routing_outcome(RoutingOutcome::Fanout);
        }
        DownlinkRoute::Unknown { .. } => {
            drop(sessions);
            write_downlink_error(
                packet_slice,
                tun,
                server_ips,
                source_profile,
                RoutingOutcome::Unknown,
                None,
                metrics,
            )?;
            return Ok(None);
        }
        DownlinkRoute::Malformed => {
            metrics.routing_drop_malformed.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        DownlinkRoute::Local { .. } => return Ok(None),
    }
    Ok(Some(ClassifiedDownlink {
        unicast: matches!(route, DownlinkRoute::Unicast { .. }),
        targets,
        source_profile,
    }))
}

fn process_server_tun_packet(
    live_state: &mut LiveServerState,
    tun_ctx: &ServerTunContext,
    packet: crate::interface::TunPacket,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
    let Some(tun) = tun_ctx.server_tun.as_ref() else {
        return Ok(());
    };
    let server_ips = tun_ctx.server_ips;
    let packet_slice: &[u8] = packet.as_slice();
    let Some(ClassifiedDownlink { unicast, targets, source_profile }) =
        classify_server_tun_downlink(
            live_state,
            tun,
            server_ips,
            packet_slice,
            &|_| None,
            tun_ctx.fingerprint_profile,
            metrics,
        )?
    else {
        return Ok(());
    };

    // Arc-cloned so the read guard borrows the local Arc, not `live_state`
    // - `&mut live_state` stays usable while the guard is held.
    let sessions = Arc::clone(&live_state.domain.shared.sessions);
    let sessions = sessions.read();
    let mut direct_send_targets = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    // The frame stays owned until the first enqueue retains it; direct sends
    // never pay for retention and additional queued targets share the block
    // via an Arc bump instead of copying the frame again.
    let mut packet = Some(packet);
    let mut shared_frame: Option<PendingTunPacket> = None;
    for (target, session_id) in targets {
        if deliver_tun_downlink_target(
            live_state,
            Some(tun),
            server_ips,
            target,
            session_id,
            &mut packet,
            &mut shared_frame,
            unicast,
            source_profile,
            &sessions,
            metrics,
        )? {
            direct_send_targets.push(target);
        }
    }

    drop(sessions);
    flush_tun_downlink_queue(live_state, &direct_send_targets, out, socket, metrics)?;
    drain_pending_tun_downlinks(live_state, out, socket, metrics)
}

/// Coordinator-side TUN packet handling under sharding: classification and
/// ICMP/local work stay here; each resolved target is shipped to its owning
/// shard as `ShardMessage::Downlink` with a shared-retained frame.
fn route_server_tun_packet(
    live_state: &LiveServerState,
    tun_ctx: &ServerTunContext,
    router: &ShardRouter,
    packet: crate::interface::TunPacket,
    metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
    let Some(tun) = tun_ctx.server_tun.as_ref() else {
        return Ok(());
    };
    let packet_slice: &[u8] = packet.as_slice();
    let Some(ClassifiedDownlink { unicast, targets, source_profile }) =
        classify_server_tun_downlink(
            live_state,
            tun,
            tun_ctx.server_ips,
            packet_slice,
            &|addr| router.profile_of(addr),
            tun_ctx.fingerprint_profile,
            metrics,
        )?
    else {
        return Ok(());
    };

    let mut shared_frame: Option<PendingTunPacket> = None;
    let mut packet = Some(packet);
    for (target, session_id) in targets {
        let Some(owner) = router.owner_of(&target) else {
            continue;
        };
        let pending = retain_tun_frame(&mut packet, &mut shared_frame);
        if router
            .send(
                owner,
                ShardMessage::Downlink {
                    target,
                    session_id,
                    packet: pending,
                    kind: DownlinkKind::Tun { unicast, profile: source_profile },
                },
            )
            .is_err()
        {
            metrics
                .record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::QueueCapacity);
            log::debug!("dropping routed TUN downlink for {}: shard queue full", target);
        }
    }
    Ok(())
}

/// Owning-shard half of `ShardMessage::Downlink`. `Tun` payloads run the
/// identical per-target semantics as the unsharded path (returns `true`
/// when the packet was queued for direct flush); `Fanout` payloads go
/// through the scheduled-queue helper only.
pub(super) fn handle_shard_downlink(
    live_state: &mut LiveServerState,
    tun_ctx: &ServerTunContext,
    target: SocketAddr,
    session_id: SessionId,
    packet: PendingTunPacket,
    kind: DownlinkKind,
    metrics: &Metrics,
) -> Result<bool, DataPlaneFault> {
    match kind {
        DownlinkKind::Fanout => {
            if live_state.deliver_fanout_target(target, session_id, packet, metrics) {
                metrics.record_routing_outcome(RoutingOutcome::Fanout);
            }
            Ok(false)
        }
        DownlinkKind::Tun { unicast, profile } => {
            let sessions = Arc::clone(&live_state.domain.shared.sessions);
            let sessions = sessions.read();
            let mut packet_slot = None;
            let mut shared_frame = Some(packet);
            deliver_tun_downlink_target(
                live_state,
                tun_ctx.server_tun.as_ref(),
                tun_ctx.server_ips,
                target,
                session_id,
                &mut packet_slot,
                &mut shared_frame,
                unicast,
                profile,
                &sessions,
                metrics,
            )
        }
    }
}

impl StandaloneServiceSignals {
    pub(super) fn shutdown_all(&mut self) {
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

/// Drains at most `budget` frames from `iter`, routing/processing each. On
/// budget exhaustion or a propagating dispatch error the unconsumed
/// remainder stays inside the iterator - it is the caller's parked wave.
fn drain_wave_frames(
    iter: &mut std::vec::IntoIter<crate::interface::TunPacket>,
    budget: &mut usize,
    send_one: &mut impl FnMut(crate::interface::TunPacket) -> Result<(), DataPlaneFault>,
) -> Result<(), DataPlaneFault> {
    for packet in iter.by_ref() {
        if *budget == 0 {
            break;
        }
        send_one(packet)?;
        *budget -= 1;
    }
    Ok(())
}

/// Server TUN uplink source. Unix registers the `O_NONBLOCK` TUN fd with the
/// Tokio reactor (`TunReadSource`) and the run loop reads frames straight off
/// the descriptor - no reader thread, channel, or `ppoll`. Backends without
/// a pollable fd (Wintun) keep the wave-batched reader thread.
///
/// Fd contract (same as the client): readiness stays latched until an inner
/// read returns `WouldBlock`, so the drain must run on every readiness fire -
/// the server dispatch has no carrier gate, so every frame is processed or
/// dropped through the bounded downlink queues anyway.
pub(super) enum ServerTunIngress {
    Fd(crate::interface::TunReadSource),
    Channel {
        rx: std::sync::mpsc::Receiver<Vec<crate::interface::TunPacket>>,
        /// Parks a partially drained reader wave when the 32-frame drain
        /// budget cuts mid-wave; resumed before new waves are received.
        pending: Option<std::vec::IntoIter<crate::interface::TunPacket>>,
    },
    Closed,
}

impl ServerTunIngress {
    /// Waits for uplink progress: fd readiness on the reactor path, channel
    /// waves on the reader-thread path. On `Closed` (or an fd-less platform
    /// where `Fd` cannot exist) this never resolves.
    pub(super) async fn wait_progress(&self, notify: &tokio::sync::Notify) {
        match self {
            ServerTunIngress::Fd(end) => end.readable().await,
            ServerTunIngress::Channel { .. } => notify.notified().await,
            ServerTunIngress::Closed => std::future::pending().await,
        }
    }

    pub(super) fn is_live(&self) -> bool {
        !matches!(self, ServerTunIngress::Closed)
    }
}

/// `router == None`: packets are processed locally (legacy single-loop).
/// `Some(router)`: the coordinator classifies and routes each packet's
/// targets to owning shards; `live_state` supplies shared domain state only.
///
/// Ingress dispatch: `Fd` reads frames one-by-one off the reactor-registered
/// descriptor (kernel queue buffers; `WouldBlock` clears readiness), while
/// `Channel` consumes reader waves under the same frame-counted drain bound
/// (32) with a parked `IntoIter` remainder.
#[allow(clippy::too_many_arguments)]
pub(super) fn drain_server_tun_packets(
    live_state: &mut LiveServerState,
    tun_ctx: &ServerTunContext,
    router: Option<&ShardRouter>,
    ingress: &mut ServerTunIngress,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<bool, DataPlaneFault> {
    let reader_gone = |tun_ctx: &ServerTunContext| {
        if tun_ctx
            .tun_reader_shutdown
            .as_ref()
            .is_some_and(|shutdown| shutdown.load(Ordering::Acquire))
        {
            return None;
        }
        Some(tun_ctx.tun_fault.lock().clone().unwrap_or(DataPlaneFault::ChannelDisconnected {
            component: "server TUN reader channel".to_string(),
        }))
    };
    let mut send_one = |packet: crate::interface::TunPacket| match router {
        Some(router) => route_server_tun_packet(live_state, tun_ctx, router, packet, metrics),
        None => process_server_tun_packet(live_state, tun_ctx, packet, out, socket, metrics),
    };
    let mut budget = 32usize;

    match ingress {
        ServerTunIngress::Fd(end) => {
            while budget > 0 {
                // `try_io` yields Err(WouldBlock) when readiness was lost or
                // the fd drained empty - either way the level-triggered
                // branch re-fires on the next frame.
                let packet = match end.try_read_packet() {
                    Ok((block, len)) => {
                        if masque_trace_enabled() {
                            let (src, dst, proto) = if len >= 20 && block[0] >> 4 == 4 {
                                (
                                    format!(
                                        "{}.{}.{}.{}",
                                        block[12], block[13], block[14], block[15]
                                    ),
                                    format!(
                                        "{}.{}.{}.{}",
                                        block[16], block[17], block[18], block[19]
                                    ),
                                    block[9],
                                )
                            } else {
                                ("?".to_string(), "?".to_string(), 0)
                            };
                            log::info!(
                                "server TUN ingress read packet bytes={} proto={} src={} dst={}",
                                len,
                                proto,
                                src,
                                dst
                            );
                        }
                        crate::interface::TunPacket::new(block, len).map_err(|error| {
                            DataPlaneFault::ReaderStopped {
                                component: "server TUN fd".to_string(),
                                error: error.to_string(),
                            }
                        })?
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if masque_trace_enabled() {
                            log::info!("server TUN ingress drained (fd WouldBlock)");
                        }
                        break;
                    }
                    Err(error) => {
                        return Err(DataPlaneFault::ReaderStopped {
                            component: "server TUN fd".to_string(),
                            error: error.to_string(),
                        });
                    }
                };
                send_one(packet)?;
                budget -= 1;
            }
            Ok(budget == 0)
        }
        ServerTunIngress::Channel { rx, pending } => {
            if let Some(iter) = pending.as_mut() {
                drain_wave_frames(iter, &mut budget, &mut send_one)?;
                if iter.len() == 0 {
                    *pending = None;
                }
                if budget == 0 {
                    // Preserve the wake-up contract: a remainder is parked, so
                    // the caller must re-arm rather than wait for a new reader
                    // notify.
                    return Ok(true);
                }
            }

            while budget > 0 {
                match rx.try_recv() {
                    Ok(wave) => {
                        let mut iter = wave.into_iter();
                        drain_wave_frames(&mut iter, &mut budget, &mut send_one)?;
                        if iter.len() > 0 {
                            *pending = Some(iter);
                            return Ok(true);
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        *ingress = ServerTunIngress::Closed;
                        if let Some(fault) = reader_gone(tun_ctx) {
                            return Err(fault);
                        }
                        return Ok(false);
                    }
                }
            }

            match rx.try_recv() {
                Ok(wave) => {
                    *pending = Some(wave.into_iter());
                    Ok(true)
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    *ingress = ServerTunIngress::Closed;
                    match reader_gone(tun_ctx) {
                        Some(fault) => Err(fault),
                        None => Ok(false),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => Ok(false),
            }
        }
        ServerTunIngress::Closed => Ok(false),
    }
}

pub const QKEY_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const FINAL_CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_millis(500);
/// Cover-SNI strategy values embedded in issued QKeys. The string values are a
/// stable wire contract (`df_sni_mode` JSON); the Rust names moved off the
/// removed domain-fronting terminology in TODO-1048.
pub const COVER_SNI_MODE_FIXED: &str = "fixed";
pub const COVER_SNI_MODE_AUTO_ROTATING: &str = "auto_rotating";
/// No cover rotation: the issued QKey names the server's own listen host.
pub const COVER_SNI_MODE_OFF: &str = "off";

/// Allowlist of cover names an issued QKey may ask the client to present. Each
/// entry is a host whose certificate the deployment's hop presents or relays.
pub(super) const BUILTIN_COVER_SNI_ALLOWLIST: &[&str] = &[
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

#[cfg(test)]
mod scheduled_tun_telemetry_tests {
    use super::*;

    #[test]
    fn scheduled_admission_does_not_report_transport_backpressure() {
        let metrics = Metrics::new();
        let mut pending = PendingTunDownlinks::with_limits(4, 64, 4);
        let target: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        enqueue_scheduled_tun_downlink(
            &mut pending,
            target,
            SessionId::from_u64(1),
            1,
            PendingTunPacket::from_vec(vec![1, 2, 3]),
            Instant::now(),
            &metrics,
        )
        .unwrap();

        let output = metrics.export();
        assert!(output.contains("quicfuscate_bandwidth_scheduler_enqueued_total 1"));
        assert!(output
            .contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 0"));
    }
}

impl Default for LiveServerState {
    // `ServerConfig::default()` is validated by the fallible constructor; the
    // legacy Default API has no error channel, so preserve its infallible
    // contract with a narrow disposition rather than hiding the failure.
    #[allow(clippy::panic)]
    fn default() -> Self {
        Self::try_new(ServerConfig::default())
            .unwrap_or_else(|error| panic!("default live server state construction failed: {error}"))
    }
}

struct ServerRuntimeLiveParts<'a> {
    live_state: &'a mut LiveServerState,
    accept_loop: &'a AcceptLoop,
    accept_max_clients: usize,
    server_tun: Option<&'a Arc<TunInterface>>,
    server_ips: ServerTunIps,
    assignment_settings: ServerAssignmentSettings,
    tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    tun_notify: Arc<tokio::sync::Notify>,
    shutdown: Arc<AtomicBool>,
    uring_worker: Option<Arc<LiveUringWorker>>,
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
    /// Cooperative cancellation for the standalone TUN reader.
    tun_reader_shutdown: Option<Arc<AtomicBool>>,
    /// Owned reader handle. `stop()` joins it before releasing the TUN device.
    tun_reader_handle: Option<std::thread::JoinHandle<()>>,
    /// Wakes the run loop as soon as the reader queues a TUN frame.
    tun_notify: Arc<tokio::sync::Notify>,
    /// First terminal server TUN data-plane fault for this runtime generation.
    tun_fault: Arc<Mutex<Option<DataPlaneFault>>>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
    admin_web_bootstrap: StandaloneAdminWebBootstrap,
    standalone_runtime_metadata: Option<StandaloneRuntimeMetadata>,
    service_signals: StandaloneServiceSignals,
}

#[derive(Clone)]
struct StandaloneReloadPolicy {
    fec_mode_override: Option<qf_engine_types::FecMode>,
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
    pub runtime_generation: u64,
}

#[derive(Default)]
struct StandaloneServiceSignals {
    admin: Option<Arc<AtomicBool>>,
    admin_web: Option<Arc<AtomicBool>>,
    metrics: Option<Arc<AtomicBool>>,
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

fn source_fingerprint_profile(
    state: &LiveServerState,
    packet: &[u8],
) -> Option<OsFingerprintProfile> {
    let remote_addr = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            state.domain.shared.sessions.read().get_by_client_ip(source).map(Session::remote_addr)
        }
        Some(6) if packet.len() >= 40 => {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            state.domain.shared.sessions.read().get_by_client_ipv6(source).map(Session::remote_addr)
        }
        _ => None,
    }?;
    state.clients.get(&remote_addr).map(QuicFuscateConnection::tunnel_ingress_profile)
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
fn drain_pending_tun_downlinks(
    live: &mut ServerLiveRuntime,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    let mut deferred_sessions = std::collections::HashSet::new();
    let sessions = Arc::clone(&live.live_state.domain.shared.sessions);
    let now = live.live_state.clock.now();
    while let Some(mut entry) = live.live_state.pending_tun_downlinks.pop_next(&deferred_sessions) {
        if entry.is_expired(now) {
            metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);
            log::warn!(
                "dropping expired pending TUN downlink for {} after {} ms",
                entry.target,
                now.saturating_duration_since(entry.queued_at).as_millis()
            );
            continue;
        }
        let Some(stats) = sessions.read().bandwidth_stats(entry.session_id) else {
            metrics.record_tun_downlink_backpressure_drop(
                TunDownlinkBackpressureDrop::TerminalTransportError,
            );
            continue;
        };
        let weight = stats.policy.weight;
        if !live.live_state.pending_tun_downlinks.reserve_capacity(entry.packet.len()) {
            metrics.record_tun_downlink_backpressure_retry();
            live.live_state.pending_tun_downlinks.requeue_front(entry, weight);
            break;
        }
        {
            let mut sessions = sessions.write();
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
                        live.live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                        metrics.record_tun_downlink_backpressure_retry();
                        deferred_sessions.insert(entry.session_id);
                        live.live_state.pending_tun_downlinks.requeue_front(entry, weight);
                        continue;
                    }
                    BandwidthDecision::DailyQuotaExceeded
                    | BandwidthDecision::MonthlyQuotaExceeded
                    | BandwidthDecision::ClockUnavailable => {
                        live.live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                        continue;
                    }
                }
            }
        }
        let target = entry.target;
        let send_result = {
            let Some(connection) = live.live_state.clients.get_mut(&target) else {
                live.live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
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
            Ok(()) => {
                metrics.record_bandwidth_scheduler_delivery(entry.packet.len());
                queued.push(target);
            }
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                live.live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
                log::debug!("pending TUN downlink for {} still backpressured", target);
                metrics.record_tun_downlink_backpressure_retry();
                deferred_sessions.insert(entry.session_id);
                live.live_state.pending_tun_downlinks.requeue_front(entry, weight);
            }
            Err(error) => {
                live.live_state.pending_tun_downlinks.refund_capacity(entry.packet.len());
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
        live.live_state.pending_tun_downlinks.len(),
        live.live_state.pending_tun_downlinks.bytes(),
    );
    metrics.set_bandwidth_scheduler_active_clients(
        live.live_state.pending_tun_downlinks.active_clients(),
    );

    flush_tun_downlink_queue(live, &queued, out, socket, metrics)
}

#[cfg(test)]
fn enqueue_pending_tun_downlink(
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
        PendingTunDownlink { target, session_id, packet, queued_at, bandwidth_accounted: false },
        weight,
        PendingTunDownlinkAdmission::TransportBackpressure,
        metrics,
    )
}

fn enqueue_scheduled_tun_downlink(
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
fn flush_tun_downlink_queue(
    live: &mut ServerLiveRuntime,
    queued: &[SocketAddr],
    out: &mut [u8],
    socket: &UdpSocket,
    _metrics: &Metrics,
) -> Result<(), DataPlaneFault> {
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
    Ok(())
}

fn process_server_tun_packet(
    live: &mut ServerLiveRuntime,
    packet: &[u8],
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
    fingerprint_profile: OsFingerprintProfile,
) -> Result<(), DataPlaneFault> {
    let Some(tun) = live.server_tun.clone() else {
        return Ok(());
    };
    let server_ips = ServerTunIps {
        ipv4: live.server_tun_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ipv6: live.server_tun_ipv6,
    };
    let source_profile =
        source_fingerprint_profile(&live.live_state, packet).unwrap_or(fingerprint_profile);
    if handle_local_tun_packet(packet, &tun, server_ips, source_profile, metrics)? {
        return Ok(());
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
        write_downlink_error(
            packet,
            &tun,
            server_ips,
            source_profile,
            RoutingOutcome::TimeExceeded,
            None,
            metrics,
        )?;
        return Ok(());
    }
    let mut targets = smallvec::SmallVec::<[(SocketAddr, SessionId); 4]>::new();
    {
        let sessions = live.live_state.domain.shared.sessions.read();
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
                    packet,
                    &tun,
                    server_ips,
                    source_profile,
                    RoutingOutcome::Unknown,
                    None,
                    metrics,
                )?;
                return Ok(());
            }
            DownlinkRoute::Malformed => {
                metrics.routing_drop_malformed.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            DownlinkRoute::Local { .. } => return Ok(()),
        }
    }

    log::debug!(
        "process_server_tun_packet: targets={} clients_count={}",
        targets.len(),
        live.live_state.clients.len()
    );
    let mut direct_send_targets = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    for (target, session_id) in targets {
        let Some(connection) = live.live_state.clients.get(&target) else {
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
                    source_profile,
                    RoutingOutcome::PacketTooBig,
                    Some(effective_mtu),
                    metrics,
                )?;
            }
            continue;
        }
        let Some(stats) = live.live_state.domain.shared.sessions.read().bandwidth_stats(session_id)
        else {
            continue;
        };
        let weight = stats.policy.weight;
        let requires_scheduler = live.live_state.pending_tun_downlinks.uses_shared_capacity()
            || live.live_state.pending_tun_downlinks.contains_session(session_id);
        if !requires_scheduler {
            let decision = live.live_state.domain.shared.sessions.write().check_bandwidth(
                session_id,
                BandwidthDirection::Downlink,
                packet.len(),
            );
            metrics.record_bandwidth_decision(BandwidthDirection::Downlink, decision, packet.len());
            match decision {
                BandwidthDecision::Allowed => {
                    let send_result = live
                        .live_state
                        .clients
                        .get_mut(&target)
                        .map(|connection| connection.send_masque_downlink(packet));
                    match send_result {
                        Some(Ok(())) => {
                            metrics.record_bandwidth_scheduler_delivery(packet.len());
                            direct_send_targets.push(target);
                            continue;
                        }
                        Some(Err(crate::error::ConnectionError::DgramQueueFull)) => {
                            if let Err(reject) = enqueue_pending_tun_downlink_with_accounting(
                                &mut live.live_state.pending_tun_downlinks,
                                PendingTunDownlink {
                                    target,
                                    session_id,
                                    packet: packet.to_vec(),
                                    queued_at: live.live_state.clock.now(),
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
                            continue;
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
                        None => continue,
                    }
                }
                BandwidthDecision::RateLimited => {
                    metrics.record_tun_downlink_backpressure_retry();
                }
                BandwidthDecision::DailyQuotaExceeded
                | BandwidthDecision::MonthlyQuotaExceeded
                | BandwidthDecision::ClockUnavailable => {
                    continue
                }
            }
        }
        let enqueue_result = enqueue_scheduled_tun_downlink(
            &mut live.live_state.pending_tun_downlinks,
            target,
            session_id,
            weight,
            packet.to_vec(),
            live.live_state.clock.now(),
            metrics,
        );
        if let Err(reject) = enqueue_result {
            log::warn!(
                "dropping TUN downlink for {} after bounded scheduler rejection: {:?}",
                target,
                reject
            );
        }
    }

    flush_tun_downlink_queue(live, &direct_send_targets, out, socket, metrics)?;
    drain_pending_tun_downlinks(live, out, socket, metrics)
}

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
            vec![1, 2, 3],
            Instant::now(),
            &metrics,
        )
        .unwrap();

        let output = metrics.export();
        assert!(output.contains("quicfuscate_bandwidth_scheduler_enqueued_total 1"));
        assert!(output.contains(
            "quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 0"
        ));
    }
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

/// Drain bounded batches from the standalone TUN reader and report whether a
/// follow-up wake-up is required for more queued packets.
fn drain_server_tun_packets(
    live: &mut ServerLiveRuntime,
    tun_rx: &mut Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
    fingerprint_profile: OsFingerprintProfile,
) -> Result<bool, DataPlaneFault> {
    for _ in 0..32 {
        let result = tun_rx.as_ref().map(std::sync::mpsc::Receiver::try_recv);
        match result {
            Some(Ok(packet)) => process_server_tun_packet(
                live,
                &packet,
                out,
                socket,
                metrics,
                fingerprint_profile,
            )?,
            Some(Err(std::sync::mpsc::TryRecvError::Empty)) => return Ok(false),
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                *tun_rx = None;
                if live
                    .tun_reader_shutdown
                    .as_ref()
                    .is_some_and(|shutdown| shutdown.load(Ordering::Acquire))
                {
                    return Ok(false);
                }
                return Err(live.tun_fault.lock().clone().unwrap_or(
                    DataPlaneFault::ChannelDisconnected {
                        component: "server TUN reader channel".to_string(),
                    },
                ));
            }
            None => return Ok(false),
        }
    }

    match tun_rx.as_ref().map(std::sync::mpsc::Receiver::try_recv) {
        Some(Ok(packet)) => {
            process_server_tun_packet(
                live,
                &packet,
                out,
                socket,
                metrics,
                fingerprint_profile,
            )?;
            Ok(true)
        }
        Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
            *tun_rx = None;
            if live
                .tun_reader_shutdown
                .as_ref()
                .is_some_and(|shutdown| shutdown.load(Ordering::Acquire))
            {
                return Ok(false);
            }
            Err(live.tun_fault.lock().clone().unwrap_or(
                DataPlaneFault::ChannelDisconnected {
                    component: "server TUN reader channel".to_string(),
                },
            ))
        }
        Some(Err(std::sync::mpsc::TryRecvError::Empty)) | None => Ok(false),
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

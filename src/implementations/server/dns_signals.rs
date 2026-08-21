use super::*;

/// Extract the destination IPv4 address from a raw IP packet.
///
/// Returns `None` if the packet is too short, is not IPv4, or has options
/// that make the header length invalid.
#[cfg(test)]
pub(super) fn parse_ipv4_dest(pkt: &[u8]) -> Option<std::net::Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    // Destination IP is at bytes 16-19
    let dest = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some(dest)
}

/// Extract the destination IPv6 address from a raw IP packet.
/// Returns None if the packet is too short or is not IPv6.
#[cfg(test)]
pub(super) fn parse_ipv6_dest(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 40 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 6 {
        return None;
    }
    // IPv6 destination address is at offset 24-39
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Addr::from(addr))
}

/// Extract the destination IP address (IPv4 or IPv6) from a raw IP packet.
#[cfg(test)]
pub(super) fn parse_ip_dest(pkt: &[u8]) -> Option<std::net::IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_ipv4_dest(pkt).map(std::net::IpAddr::V4),
        6 => parse_ipv6_dest(pkt).map(std::net::IpAddr::V6),
        _ => None,
    }
}

pub(super) struct InterceptedIpv4DnsQuery<'a> {
    pub(super) src_ip: Ipv4Addr,
    pub(super) dst_ip: Ipv4Addr,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) ttl: u8,
    pub(super) payload: &'a [u8],
}

pub(super) struct InterceptedIpv6DnsQuery<'a> {
    pub(super) src_ip: Ipv6Addr,
    pub(super) dst_ip: Ipv6Addr,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) hop_limit: u8,
    pub(super) payload: &'a [u8],
}

pub(super) fn parse_ipv4_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv4DnsQuery<'_>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl + 8 || total_len != pkt.len() {
        return None;
    }
    if ones_complement_checksum_raw(&pkt[..ihl]) != 0 {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_fragment & 0x3fff != 0 {
        return None;
    }
    if pkt[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let udp = &pkt[ihl..total_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len != udp.len() {
        return None;
    }
    let udp_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if udp_checksum != 0 && !ipv4_udp_checksum_is_valid(src_ip, dst_ip, udp) {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }

    Some(InterceptedIpv4DnsQuery { src_ip, dst_ip, src_port, dst_port, ttl: pkt[8], payload })
}

pub(super) fn parse_ipv6_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv6DnsQuery<'_>> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if payload_len < 8 || 40usize.checked_add(payload_len)? != pkt.len() {
        return None;
    }
    if pkt[6] != 17 {
        return None;
    }

    let udp = &pkt[40..40 + payload_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len != udp.len() {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    let src_ip = Ipv6Addr::from(src);
    let dst_ip = Ipv6Addr::from(dst);
    if u16::from_be_bytes([udp[6], udp[7]]) == 0 || !ipv6_udp_checksum_is_valid(src_ip, dst_ip, udp)
    {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }
    Some(InterceptedIpv6DnsQuery { src_ip, dst_ip, src_port, dst_port, hop_limit: pkt[7], payload })
}

pub(super) fn ones_complement_checksum_raw(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn ones_complement_checksum(data: &[u8]) -> u16 {
    ones_complement_checksum_raw(data)
}

pub(super) fn ipv4_udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_packet);
    let checksum = ones_complement_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

pub(super) fn ipv4_udp_checksum_is_valid(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> bool {
    let mut pseudo = Vec::with_capacity(12 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_packet);
    ones_complement_checksum_raw(&pseudo) == 0
}

pub(super) fn ipv6_udp_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(17);
    pseudo.extend_from_slice(udp_packet);
    let checksum = ones_complement_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

pub(super) fn ipv6_udp_checksum_is_valid(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> bool {
    let mut pseudo = Vec::with_capacity(40 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(17);
    pseudo.extend_from_slice(udp_packet);
    ones_complement_checksum_raw(&pseudo) == 0
}

pub(super) fn build_ipv4_udp_dns_response_packet(
    query: &InterceptedIpv4DnsQuery<'_>,
    dns_response: &[u8],
    fingerprint_profile: OsFingerprintProfile,
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(dns_response.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if udp_len > u16::MAX as usize || total_len > u16::MAX as usize {
        return None;
    }

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = fingerprint_profile.ttl().max(query.ttl);
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&query.dst_ip.octets());
    pkt[16..20].copy_from_slice(&query.src_ip.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_start = 20;
    pkt[udp_start..udp_start + 2].copy_from_slice(&query.dst_port.to_be_bytes());
    pkt[udp_start + 2..udp_start + 4].copy_from_slice(&query.src_port.to_be_bytes());
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[udp_start + 8..].copy_from_slice(dns_response);
    let udp_checksum = ipv4_udp_checksum(query.dst_ip, query.src_ip, &pkt[udp_start..]);
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(pkt)
}

pub(super) fn build_ipv6_udp_dns_response_packet(
    query: &InterceptedIpv6DnsQuery<'_>,
    dns_response: &[u8],
    fingerprint_profile: OsFingerprintProfile,
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(dns_response.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }
    let total_len = 40usize.checked_add(udp_len)?;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = fingerprint_profile.ttl().max(query.hop_limit);
    pkt[8..24].copy_from_slice(&query.dst_ip.octets());
    pkt[24..40].copy_from_slice(&query.src_ip.octets());

    let udp_start = 40;
    pkt[udp_start..udp_start + 2].copy_from_slice(&query.dst_port.to_be_bytes());
    pkt[udp_start + 2..udp_start + 4].copy_from_slice(&query.src_port.to_be_bytes());
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[udp_start + 8..].copy_from_slice(dns_response);
    let udp_checksum = ipv6_udp_checksum(query.dst_ip, query.src_ip, &pkt[udp_start..]);
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(pkt)
}

pub(super) fn response_from_dns_upstream_result(
    query: &[u8],
    result: Result<Vec<u8>, crate::dns::DnsProxyError>,
) -> Vec<u8> {
    match result {
        Ok(response) => response,
        Err(error) => {
            log::debug!("DNS upstream resolution failed, returning SERVFAIL: {error}");
            crate::dns::parse_dns_query(query)
                .map(|parsed| crate::dns::build_dns_servfail(&parsed))
                .or_else(|| crate::dns::build_dns_servfail_from_packet(query))
                .unwrap_or_default()
        }
    }
}

pub(super) fn resolve_dns_query_via_upstream(
    query: &[u8],
    upstream_resolvers: &[Ipv4Addr],
) -> Vec<u8> {
    response_from_dns_upstream_result(
        query,
        crate::dns::resolve_via_dns_upstreams(query, upstream_resolvers),
    )
}

const DNS_INTERCEPT_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const DNS_INTERCEPT_WORKER_REAP_INTERVAL: Duration = Duration::from_millis(2);
const DNS_INTERCEPT_WORKER_QUEUED_CANCEL_TIMEOUT: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(super) enum DnsInterceptWorkerResult {
    ResponseQueued,
    EmptyResponse,
    ResponseBuildFailed,
    LatePublication,
    QueueRejected(qf_transport_types::MasqueDownlinkQueueReject),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DnsInterceptWorkerSpawnError {
    Closed,
}

pub(super) struct DnsInterceptWorkerTask {
    handle: tokio::task::JoinHandle<DnsInterceptWorkerResult>,
    started: Arc<AtomicBool>,
}

pub(super) struct DnsInterceptWorkerState {
    pub(super) closed: bool,
    pub(super) tasks: Vec<DnsInterceptWorkerTask>,
}

/// Owns accepted DNS blocking operations and closes the publication gate before drain.
pub(super) struct DnsInterceptWorkerOwner {
    pub(super) state: Arc<Mutex<DnsInterceptWorkerState>>,
    metrics: Arc<Metrics>,
}

impl DnsInterceptWorkerOwner {
    pub(super) fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            state: Arc::new(Mutex::new(DnsInterceptWorkerState {
                closed: false,
                tasks: Vec::new(),
            })),
            metrics,
        }
    }

    pub(super) fn close_admission(&self) {
        self.state.lock().closed = true;
    }

    pub(super) fn spawn<F>(&self, operation: F) -> Result<(), DnsInterceptWorkerSpawnError>
    where
        F: FnOnce() -> DnsInterceptWorkerResult + Send + 'static,
    {
        let mut state = self.state.lock();
        if state.closed {
            return Err(DnsInterceptWorkerSpawnError::Closed);
        }

        let started = Arc::new(AtomicBool::new(false));
        let started_for_worker = Arc::clone(&started);
        let metrics = Arc::clone(&self.metrics);
        let handle = tokio::task::spawn_blocking(move || {
            started_for_worker.store(true, Ordering::Release);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
                Ok(result) => {
                    record_dns_intercept_worker_result(&metrics, &result);
                    result
                }
                Err(payload) => {
                    metrics.record_dns_intercept_worker_event(
                        crate::implementations::server::metrics::DnsInterceptWorkerEvent::Panic,
                    );
                    std::panic::resume_unwind(payload);
                }
            }
        });
        state.tasks.push(DnsInterceptWorkerTask { handle, started });
        Ok(())
    }

    fn take_finished(&self) -> Vec<DnsInterceptWorkerTask> {
        let mut state = self.state.lock();
        let mut finished = Vec::new();
        let mut index = 0;
        while index < state.tasks.len() {
            if state.tasks[index].handle.is_finished() {
                finished.push(state.tasks.swap_remove(index));
            } else {
                index += 1;
            }
        }
        finished
    }

    fn take_all(&self) -> Vec<DnsInterceptWorkerTask> {
        std::mem::take(&mut self.state.lock().tasks)
    }

    pub(super) fn has_tasks(&self) -> bool {
        !self.state.lock().tasks.is_empty()
    }

    pub(super) async fn observe_finished(&self) {
        for task in self.take_finished() {
            Self::observe_join_result(&self.metrics, task.started, task.handle.await);
        }
    }

    fn observe_join_result(
        metrics: &Metrics,
        started: Arc<AtomicBool>,
        result: Result<DnsInterceptWorkerResult, tokio::task::JoinError>,
    ) {
        if let Err(error) = result {
            if error.is_cancelled() {
                let event = if started.load(Ordering::Acquire) {
                    crate::implementations::server::metrics::DnsInterceptWorkerEvent::StartedCancellation
                } else {
                    crate::implementations::server::metrics::DnsInterceptWorkerEvent::QueuedCancellation
                };
                metrics.record_dns_intercept_worker_event(event);
            } else if !error.is_panic() {
                metrics.record_dns_intercept_worker_event(
                    crate::implementations::server::metrics::DnsInterceptWorkerEvent::JoinError,
                );
            }
        }
    }

    pub(super) async fn shutdown(&self) {
        self.close_admission();
        // Async worker reaping is governed by Tokio time. The blocking
        // operation itself remains a native worker and may be abandoned after
        // this bounded runtime deadline expires.
        let deadline = tokio::time::Instant::now() + DNS_INTERCEPT_WORKER_SHUTDOWN_TIMEOUT;
        loop {
            self.observe_finished().await;
            if !self.has_tasks() {
                return;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(DNS_INTERCEPT_WORKER_REAP_INTERVAL)).await;
        }
        self.observe_finished().await;

        for task in self.take_all() {
            let DnsInterceptWorkerTask { handle, started } = task;
            if handle.is_finished() {
                Self::observe_join_result(&self.metrics, started, handle.await);
                continue;
            }

            handle.abort();
            if started.load(Ordering::Acquire) {
                self.metrics.record_dns_intercept_worker_event(
                    crate::implementations::server::metrics::DnsInterceptWorkerEvent::ShutdownExpired,
                );
                log::warn!(
                    "DNS intercept worker exceeded the bounded shutdown deadline; operation was deliberately abandoned"
                );
                continue;
            }

            match tokio::time::timeout(DNS_INTERCEPT_WORKER_QUEUED_CANCEL_TIMEOUT, handle).await {
                Ok(result) => Self::observe_join_result(&self.metrics, started, result),
                Err(_) => {
                    let event = if started.load(Ordering::Acquire) {
                        crate::implementations::server::metrics::DnsInterceptWorkerEvent::ShutdownExpired
                    } else {
                        crate::implementations::server::metrics::DnsInterceptWorkerEvent::QueuedCancellation
                    };
                    self.metrics.record_dns_intercept_worker_event(event);
                }
            }
        }
    }

    pub(super) fn abandon(&self) {
        self.close_admission();
        for task in self.take_all() {
            if task.handle.is_finished() {
                drop(task.handle);
                continue;
            }
            task.handle.abort();
            let event = if task.started.load(Ordering::Acquire) {
                crate::implementations::server::metrics::DnsInterceptWorkerEvent::ShutdownExpired
            } else {
                crate::implementations::server::metrics::DnsInterceptWorkerEvent::QueuedCancellation
            };
            self.metrics.record_dns_intercept_worker_event(event);
        }
    }
}

impl Drop for DnsInterceptWorkerOwner {
    fn drop(&mut self) {
        self.state.lock().closed = true;
        for task in std::mem::take(&mut self.state.lock().tasks) {
            task.handle.abort();
        }
    }
}

fn record_dns_intercept_worker_result(metrics: &Metrics, result: &DnsInterceptWorkerResult) {
    let event = match result {
        DnsInterceptWorkerResult::ResponseQueued => {
            crate::implementations::server::metrics::DnsInterceptWorkerEvent::ResponseQueued
        }
        DnsInterceptWorkerResult::EmptyResponse => {
            crate::implementations::server::metrics::DnsInterceptWorkerEvent::EmptyResponse
        }
        DnsInterceptWorkerResult::ResponseBuildFailed => {
            crate::implementations::server::metrics::DnsInterceptWorkerEvent::ResponseBuildFailed
        }
        DnsInterceptWorkerResult::LatePublication => {
            crate::implementations::server::metrics::DnsInterceptWorkerEvent::LatePublication
        }
        DnsInterceptWorkerResult::QueueRejected(reason) => match reason {
            qf_transport_types::MasqueDownlinkQueueReject::PacketCapacity => {
                metrics.record_masque_downlink_response_drop(*reason);
                crate::implementations::server::metrics::DnsInterceptWorkerEvent::QueueRejectedPacketCapacity
            }
            qf_transport_types::MasqueDownlinkQueueReject::ByteCapacity => {
                metrics.record_masque_downlink_response_drop(*reason);
                crate::implementations::server::metrics::DnsInterceptWorkerEvent::QueueRejectedByteCapacity
            }
        },
    };
    metrics.record_dns_intercept_worker_event(event);
}

pub(super) fn publish_dns_intercept_response(
    state: &Arc<Mutex<DnsInterceptWorkerState>>,
    downlink_queue: &Arc<std::sync::Mutex<qf_transport_types::MasqueDownlinkQueue>>,
    packet: Vec<u8>,
) -> DnsInterceptWorkerResult {
    let state_guard = state.lock();
    if state_guard.closed {
        return DnsInterceptWorkerResult::LatePublication;
    }
    let admission = match downlink_queue.lock() {
        Ok(mut guard) => guard.enqueue(packet),
        Err(poisoned) => poisoned.into_inner().enqueue(packet),
    };
    match admission {
        Ok(()) => DnsInterceptWorkerResult::ResponseQueued,
        Err(reason) => DnsInterceptWorkerResult::QueueRejected(reason),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "The live MASQUE callback passes each ownership boundary explicitly"
)]
pub(super) fn spawn_dns_intercept(
    pkt: &[u8],
    upstream_resolvers: Arc<Vec<Ipv4Addr>>,
    downlink_queue: Arc<std::sync::Mutex<qf_transport_types::MasqueDownlinkQueue>>,
    metrics: Arc<Metrics>,
    admission: Arc<crate::dns::DnsAdmission>,
    workers: Arc<DnsInterceptWorkerOwner>,
    session_id: Option<SessionId>,
    fingerprint_profile: OsFingerprintProfile,
) -> bool {
    let parsed = parse_ipv4_udp_dns_query(pkt)
        .map(|query| {
            let src_ip = query.src_ip;
            let dst_ip = query.dst_ip;
            let src_port = query.src_port;
            let dst_port = query.dst_port;
            let ttl = query.ttl;
            let payload = query.payload.to_vec();
            Box::new(move |response: &[u8]| {
                let query = InterceptedIpv4DnsQuery {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ttl,
                    payload: &payload,
                };
                build_ipv4_udp_dns_response_packet(&query, response, fingerprint_profile)
            }) as Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send>
        })
        .or_else(|| {
            parse_ipv6_udp_dns_query(pkt).map(|query| {
                let src_ip = query.src_ip;
                let dst_ip = query.dst_ip;
                let src_port = query.src_port;
                let dst_port = query.dst_port;
                let hop_limit = query.hop_limit;
                let payload = query.payload.to_vec();
                Box::new(move |response: &[u8]| {
                    let query = InterceptedIpv6DnsQuery {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        hop_limit,
                        payload: &payload,
                    };
                    build_ipv6_udp_dns_response_packet(&query, response, fingerprint_profile)
                }) as Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send>
            })
        });
    let Some(build_response_packet) = parsed else {
        return false;
    };
    let payload = if let Some(query) = parse_ipv4_udp_dns_query(pkt) {
        query.payload.to_vec()
    } else if let Some(query) = parse_ipv6_udp_dns_query(pkt) {
        query.payload.to_vec()
    } else {
        return false;
    };
    let Some(source_ip) = parse_ipv4_udp_dns_query(pkt)
        .map(|query| IpAddr::V4(query.src_ip))
        .or_else(|| parse_ipv6_udp_dns_query(pkt).map(|query| IpAddr::V6(query.src_ip)))
    else {
        return false;
    };
    let identity = session_id
        .map(|id| crate::dns::DnsAdmissionIdentity::Session(id.as_u64()))
        .unwrap_or(crate::dns::DnsAdmissionIdentity::Source(source_ip));
    let permit = match admission.try_acquire(identity) {
        Ok(permit) => permit,
        Err(reason) => {
            metrics.record_dns_intercept_admission_reject(reason);
            log::debug!(
                "DNS intercept dropped before upstream resolution for {identity:?}: {reason}"
            );
            return true;
        }
    };
    metrics.record_dns_intercept_admitted();
    let worker_state = Arc::clone(&workers.state);
    let spawn_result = workers.spawn(move || {
        let _permit = permit;
        let response = resolve_dns_query_via_upstream(&payload, upstream_resolvers.as_slice());
        if response.is_empty() {
            return DnsInterceptWorkerResult::EmptyResponse;
        }
        let Some(packet) = build_response_packet(&response) else {
            return DnsInterceptWorkerResult::ResponseBuildFailed;
        };
        publish_dns_intercept_response(&worker_state, &downlink_queue, packet)
    });
    if matches!(spawn_result, Err(DnsInterceptWorkerSpawnError::Closed)) {
        metrics.record_dns_intercept_worker_event(
            crate::implementations::server::metrics::DnsInterceptWorkerEvent::ClosedBeforeSpawn,
        );
    }
    true
}

pub(crate) fn open_server_tun(
    tun_config: TunConfig,
    pool: Arc<MemoryPool>,
) -> Result<TunInterface, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tun_config, pool);
        Err(
            "server TUN mode is supported only on Linux until a native routing owner and proof exist for this platform"
                .to_string(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        crate::interface::validate_tun_runtime_requirements().map_err(|e| format!("{:?}", e))?;
        TunInterface::open(tun_config, pool).map_err(|e| format!("{:?}", e))
    }
}

#[cfg(test)]
mod dns_intercept_admission_tests {
    use super::*;

    #[test]
    fn admission_bounds_concurrent_upstream_work() {
        let admission = crate::dns::DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
            max_in_flight: 1,
            global_pps: 100,
            global_burst: 100,
            per_identity_pps: 100,
            per_identity_burst: 100,
            max_identities: 4,
            idle_timeout: Duration::from_secs(60),
        })
        .expect("admission config");
        let source =
            crate::dns::DnsAdmissionIdentity::Source(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        let permit = admission.try_acquire(source).expect("first exchange must be admitted");

        assert!(matches!(
            admission.try_acquire(source),
            Err(crate::dns::DnsAdmissionReject::InFlight)
        ));

        drop(permit);
        assert!(admission.try_acquire(source).is_ok());
    }

    #[test]
    fn admission_applies_global_and_per_source_caps() {
        let per_source = crate::dns::DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
            max_in_flight: 4,
            global_pps: 100,
            global_burst: 100,
            per_identity_pps: 1,
            per_identity_burst: 1,
            max_identities: 4,
            idle_timeout: Duration::from_secs(60),
        })
        .expect("admission config");
        let first_source =
            crate::dns::DnsAdmissionIdentity::Source(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        let second_source =
            crate::dns::DnsAdmissionIdentity::Source(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 3)));
        let permit =
            per_source.try_acquire(first_source).expect("first source query must be admitted");
        drop(permit);
        assert!(matches!(
            per_source.try_acquire(first_source),
            Err(crate::dns::DnsAdmissionReject::IdentityRate)
        ));
        let other_permit = per_source
            .try_acquire(second_source)
            .expect("a different source must have its own bucket");
        drop(other_permit);

        let global = crate::dns::DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
            max_in_flight: 4,
            global_pps: 1,
            global_burst: 1,
            per_identity_pps: 100,
            per_identity_burst: 100,
            max_identities: 4,
            idle_timeout: Duration::from_secs(60),
        })
        .expect("admission config");
        let permit =
            global.try_acquire(first_source).expect("global burst must admit the first query");
        drop(permit);
        assert!(matches!(
            global.try_acquire(second_source),
            Err(crate::dns::DnsAdmissionReject::GlobalRate)
        ));
    }

    #[test]
    fn admission_scopes_sessions_independently_and_cleans_released_state() {
        let admission = crate::dns::DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
            max_in_flight: 4,
            global_pps: 100,
            global_burst: 100,
            per_identity_pps: 1,
            per_identity_burst: 1,
            max_identities: 1,
            idle_timeout: Duration::from_secs(60),
        })
        .expect("admission config");
        let first = crate::dns::DnsAdmissionIdentity::Session(41);
        let replacement = crate::dns::DnsAdmissionIdentity::Session(42);
        let permit = admission.try_acquire(first).expect("first session query");
        drop(permit);

        assert!(matches!(
            admission.try_acquire(replacement),
            Err(crate::dns::DnsAdmissionReject::IdentityCapacity)
        ));
        assert!(admission.remove_identity(first));
        let permit = admission
            .try_acquire(replacement)
            .expect("replacement session must not inherit released state");
        drop(permit);
        assert_eq!(admission.snapshot().tracked_identities, 1);
    }

    #[test]
    fn admission_uses_session_identity_as_the_fairness_unit() {
        let admission = crate::dns::DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
            max_in_flight: 4,
            global_pps: 100,
            global_burst: 100,
            per_identity_pps: 1,
            per_identity_burst: 1,
            max_identities: 4,
            idle_timeout: Duration::from_secs(60),
        })
        .expect("admission config");
        let first = crate::dns::DnsAdmissionIdentity::Session(41);
        let second = crate::dns::DnsAdmissionIdentity::Session(42);
        let permit = admission.try_acquire(first).expect("first session query");
        drop(permit);
        assert!(matches!(
            admission.try_acquire(first),
            Err(crate::dns::DnsAdmissionReject::IdentityRate)
        ));
        let permit = admission.try_acquire(second).expect("second session query");
        drop(permit);
    }
}

#[cfg(test)]
mod dns_intercept_worker_tests {
    use super::*;

    fn worker_test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("worker lifecycle test runtime must build")
    }

    #[test]
    fn worker_owner_reaps_completion_and_panic() {
        let runtime = worker_test_runtime();
        runtime.block_on(async {
            let metrics = Arc::new(Metrics::new());
            let owner = DnsInterceptWorkerOwner::new(Arc::clone(&metrics));
            owner
                .spawn(|| DnsInterceptWorkerResult::ResponseQueued)
                .expect("completion worker must be accepted");
            owner
                .spawn(|| panic!("intentional worker panic"))
                .expect("panic worker must be accepted");

            for _ in 0..100 {
                owner.observe_finished().await;
                if !owner.has_tasks() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            assert!(!owner.has_tasks());
            assert_eq!(metrics.dns_intercept_worker_response_queued.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.dns_intercept_worker_panic.load(Ordering::Relaxed), 1);

            owner.close_admission();
            assert_eq!(
                owner.spawn(|| DnsInterceptWorkerResult::ResponseQueued),
                Err(DnsInterceptWorkerSpawnError::Closed)
            );
        });
    }

    #[test]
    fn worker_owner_cancels_queued_work_and_bounds_started_shutdown() {
        let runtime = worker_test_runtime();
        runtime.block_on(async {
            let metrics = Arc::new(Metrics::new());
            let owner = DnsInterceptWorkerOwner::new(Arc::clone(&metrics));
            let first_started = Arc::new(AtomicBool::new(false));
            let release_first = Arc::new(AtomicBool::new(false));
            let first_started_for_worker = Arc::clone(&first_started);
            let release_first_for_worker = Arc::clone(&release_first);
            owner
                .spawn(move || {
                    first_started_for_worker.store(true, Ordering::Release);
                    while !release_first_for_worker.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    DnsInterceptWorkerResult::ResponseQueued
                })
                .expect("started blocking worker must be accepted");

            while !first_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }

            let second_started = Arc::new(AtomicBool::new(false));
            let second_started_for_worker = Arc::clone(&second_started);
            owner
                .spawn(move || {
                    second_started_for_worker.store(true, Ordering::Release);
                    DnsInterceptWorkerResult::ResponseQueued
                })
                .expect("queued blocking worker must be accepted");

            let shutdown_started = Instant::now();
            owner.shutdown().await;
            assert!(shutdown_started.elapsed() < Duration::from_secs(1));
            assert!(!second_started.load(Ordering::Acquire));
            assert_eq!(metrics.dns_intercept_worker_queued_cancellation.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.dns_intercept_worker_shutdown_expired.load(Ordering::Relaxed), 1);

            release_first.store(true, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn worker_owner_closes_publication_before_teardown() {
        let runtime = worker_test_runtime();
        runtime.block_on(async {
            let metrics = Arc::new(Metrics::new());
            let owner = DnsInterceptWorkerOwner::new(Arc::clone(&metrics));
            let queue = Arc::new(std::sync::Mutex::new(
                qf_transport_types::MasqueDownlinkQueue::new(1, 1024),
            ));
            let worker_started = Arc::new(AtomicBool::new(false));
            let release_worker = Arc::new(AtomicBool::new(false));
            let worker_state = Arc::clone(&owner.state);
            let worker_queue = Arc::clone(&queue);
            let worker_started_for_worker = Arc::clone(&worker_started);
            let release_worker_for_worker = Arc::clone(&release_worker);
            owner
                .spawn(move || {
                    worker_started_for_worker.store(true, Ordering::Release);
                    while !release_worker_for_worker.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    publish_dns_intercept_response(&worker_state, &worker_queue, vec![1, 2, 3])
                })
                .expect("publication worker must be accepted");

            while !worker_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            owner.close_admission();
            release_worker.store(true, Ordering::Release);
            owner.shutdown().await;

            assert_eq!(metrics.dns_intercept_worker_late_publication.load(Ordering::Relaxed), 1);
            assert_eq!(queue.lock().expect("queue mutex must remain healthy").len(), 0);
        });
    }
}

pub(super) enum ServerSignalEvent {
    Shutdown(&'static [u8]),
    #[cfg(unix)]
    Reload,
}

#[cfg(unix)]
pub(super) struct ServerSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ServerSignals {
    pub(super) fn install() -> std::io::Result<Self> {
        Ok(Self {
            sigint: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            sigterm: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            sighup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    pub(super) async fn recv(&mut self) -> ServerSignalEvent {
        tokio::select! {
            _ = self.sigint.recv() => {
                log::info!("SIGINT received");
                ServerSignalEvent::Shutdown(b"sigint")
            }
            _ = self.sigterm.recv() => {
                log::info!("SIGTERM received");
                ServerSignalEvent::Shutdown(b"sigterm")
            }
            _ = self.sighup.recv() => {
                log::info!("SIGHUP received");
                ServerSignalEvent::Reload
            }
        }
    }
}

#[cfg(not(unix))]
pub(super) struct ServerSignals;

#[cfg(not(unix))]
impl ServerSignals {
    pub(super) fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    pub(super) async fn recv(&mut self) -> ServerSignalEvent {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Shutdown signal received");
        ServerSignalEvent::Shutdown(b"shutdown")
    }
}

#[cfg(unix)]
pub(crate) async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    // Use `async_io` so tokio properly clears the edge-triggered readiness
    // when `recvmsg` returns `WouldBlock`.  Calling `ready()` + raw `recvmsg`
    // in a loop causes a busy-spin because tokio never observes the EAGAIN.
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::READABLE, || {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyRecvBuffer::new_mut(&mut slice).map_err(std::io::Error::from)?;
            let (transfer, addr) = zc.recv_from(fd).map_err(std::io::Error::from)?;
            Ok((transfer.transferred(), addr))
        })
        .await
}

/// Drain the kernel socket buffer until `WouldBlock`, returning up to `max`
/// datagrams per call (TODO-901 step 1: amortize one tokio wakeup across a
/// whole burst instead of paying select! + admission per single recvmsg).
///
/// The first datagram waits for readability via the same `async_io` pattern as
/// [`recv_datagram_from`]; the rest of the burst is drained with non-blocking
/// `try_recv_from` into one reused scratch buffer until EAGAIN or capacity.
#[cfg(unix)]
pub(crate) async fn recv_datagram_batch(
    socket: &tokio::net::UdpSocket,
    max: usize,
) -> std::io::Result<Vec<(Vec<u8>, std::net::SocketAddr)>> {
    const DRAIN_BATCH_CAP: usize = 64;
    let cap = max.min(DRAIN_BATCH_CAP).max(1);
    let mut scratch = vec![0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
    let mut batch = Vec::with_capacity(cap);

    // Blocking wait for the first datagram of the burst.
    let (len, from) = recv_datagram_from(socket, &mut scratch).await?;
    batch.push((scratch[..len].to_vec(), from));

    // Drain the rest of the burst without blocking.
    while batch.len() < cap {
        match socket.try_recv_from(&mut scratch) {
            Ok((len, from)) => batch.push((scratch[..len].to_vec(), from)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(batch)
}

#[cfg(not(unix))]
pub(crate) async fn recv_datagram_batch(
    socket: &tokio::net::UdpSocket,
    max: usize,
) -> std::io::Result<Vec<(Vec<u8>, std::net::SocketAddr)>> {
    const DRAIN_BATCH_CAP: usize = 64;
    let cap = max.min(DRAIN_BATCH_CAP).max(1);
    let mut scratch = vec![0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
    let mut batch = Vec::with_capacity(cap);

    loop {
        match socket.try_recv_from(&mut scratch) {
            Ok((len, from)) => batch.push((scratch[..len].to_vec(), from)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
        if batch.len() >= cap {
            break;
        }
    }
    Ok(batch)
}

#[cfg(not(unix))]
pub(crate) async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match socket.try_recv_from(buf) {
            Ok(result) => return Ok(result),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

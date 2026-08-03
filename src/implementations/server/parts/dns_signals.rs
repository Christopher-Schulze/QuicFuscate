/// Extract the destination IPv4 address from a raw IP packet.
///
/// Returns `None` if the packet is too short, is not IPv4, or has options
/// that make the header length invalid.
#[cfg(test)]
fn parse_ipv4_dest(pkt: &[u8]) -> Option<std::net::Ipv4Addr> {
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
fn parse_ipv6_dest(pkt: &[u8]) -> Option<Ipv6Addr> {
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
fn parse_ip_dest(pkt: &[u8]) -> Option<std::net::IpAddr> {
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

struct InterceptedIpv4DnsQuery<'a> {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: &'a [u8],
}

struct InterceptedIpv6DnsQuery<'a> {
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    hop_limit: u8,
    payload: &'a [u8],
}

fn parse_ipv4_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv4DnsQuery<'_>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl + 8 || total_len > pkt.len() {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_fragment & 0x1fff != 0 {
        return None;
    }
    if pkt[9] != 17 {
        return None;
    }

    let udp = &pkt[ihl..total_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }

    Some(InterceptedIpv4DnsQuery {
        src_ip: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst_ip: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        src_port,
        dst_port,
        ttl: pkt[8],
        payload,
    })
}

fn parse_ipv6_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv6DnsQuery<'_>> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if payload_len < 8 || 40usize.checked_add(payload_len)? > pkt.len() {
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
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    Some(InterceptedIpv6DnsQuery {
        src_ip: Ipv6Addr::from(src),
        dst_ip: Ipv6Addr::from(dst),
        src_port,
        dst_port,
        hop_limit: pkt[7],
        payload,
    })
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
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

fn ipv4_udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
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

fn ipv6_udp_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
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

fn build_ipv4_udp_dns_response_packet(
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

fn build_ipv6_udp_dns_response_packet(
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

fn response_from_dns_upstream_result(
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

fn resolve_dns_query_via_upstream(query: &[u8], upstream_resolvers: &[Ipv4Addr]) -> Vec<u8> {
    response_from_dns_upstream_result(
        query,
        crate::dns::resolve_via_dns_upstreams(query, upstream_resolvers),
    )
}

fn spawn_dns_intercept(
    pkt: &[u8],
    upstream_resolvers: Arc<Vec<Ipv4Addr>>,
    downlink_queue: Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
    metrics: Arc<Metrics>,
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
    tokio::task::spawn_blocking(move || {
        let response = resolve_dns_query_via_upstream(&payload, upstream_resolvers.as_slice());
        if response.is_empty() {
            return;
        }
        if let Some(packet) = build_response_packet(&response) {
            let admission = match downlink_queue.lock() {
                Ok(mut guard) => guard.enqueue(packet),
                Err(poisoned) => poisoned.into_inner().enqueue(packet),
            };
            if let Err(reason) = admission {
                metrics.record_masque_downlink_response_drop(reason);
            }
        }
    });
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

enum ServerSignalEvent {
    Shutdown(&'static [u8]),
    Reload,
}

#[cfg(unix)]
struct ServerSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ServerSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self {
            sigint: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            sigterm: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            sighup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    async fn recv(&mut self) -> ServerSignalEvent {
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
struct ServerSignals;

#[cfg(not(unix))]
impl ServerSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> ServerSignalEvent {
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
    use std::io::ErrorKind;

    // Use `async_io` so tokio properly clears the edge-triggered readiness
    // when `recvmsg` returns `WouldBlock`.  Calling `ready()` + raw `recvmsg`
    // in a loop causes a busy-spin because tokio never observes the EAGAIN.
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::READABLE, || {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            match zc.recv_from(fd) {
                Ok((rc, addr)) if rc >= 0 => Ok((rc as usize, addr)),
                Ok(_) => {
                    Err(std::io::Error::new(ErrorKind::UnexpectedEof, "negative recv_from result"))
                }
                Err(e) => Err(e),
            }
        })
        .await
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

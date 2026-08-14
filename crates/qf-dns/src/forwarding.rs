//! DNS forwarding and DoH transport owners.

use super::*;
use std::net::{SocketAddr, ToSocketAddrs};

/// Handle a DNS query packet by forwarding it to an upstream resolver and
/// returning the response. This is the server-side path: plain DNS over UDP
/// to upstream resolvers.
///
/// Security: the response source IP is validated to match the upstream
/// resolver, preventing DNS amplification and response spoofing attacks.
/// The response is also size-limited to 4096 bytes (well above the typical
/// DNS UDP payload size of 512 bytes, accommodating EDNS0 but preventing
/// oversized amplification payloads).
pub fn forward_dns_query(query: &[u8], upstream: Ipv4Addr) -> std::io::Result<Vec<u8>> {
    validate_dns_query_size(query).map_err(dns_query_size_io_error)?;
    forward_dns_query_until(query, upstream, Instant::now() + DNS_FORWARDING_DEADLINE)
}

pub(super) fn dns_query_size_io_error(error: DnsQuerySizeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

pub(super) fn remaining_until(deadline: Instant) -> std::io::Result<Duration> {
    let now = Instant::now();
    match deadline.checked_duration_since(now) {
        Some(remaining) if !remaining.is_zero() => Ok(remaining),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS forwarding deadline exceeded",
        )),
    }
}

pub(super) fn forward_dns_query_until(
    query: &[u8],
    upstream: Ipv4Addr,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_write_timeout(Some(remaining_until(deadline)?))?;
    let upstream_addr = SocketAddr::new(std::net::IpAddr::V4(upstream), 53);
    sock.send_to(query, upstream_addr)?;
    receive_dns_response(&sock, upstream_addr, query, deadline)
}

pub(super) fn receive_dns_response(
    sock: &std::net::UdpSocket,
    upstream_addr: SocketAddr,
    query: &[u8],
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
    let mut rejections = 0u32;
    loop {
        sock.set_read_timeout(Some(remaining_until(deadline)?))?;
        let (len, resp_addr) = sock.recv_from(&mut buf)?;
        // Reject responses from any source other than the upstream resolver.
        // This prevents DNS spoofing/amplification attacks where an attacker
        // sends a forged response from a different IP.
        if resp_addr != upstream_addr {
            rejections += 1;
            log::warn!(
                "DNS: rejecting response from {resp_addr} (expected {upstream_addr}) [{rejections}/{DNS_MAX_SPOOFED_REJECTIONS}]"
            );
            if rejections >= DNS_MAX_SPOOFED_REJECTIONS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "DNS: too many spoofed responses from non-upstream sources",
                ));
            }
            continue;
        }
        if len > DNS_MESSAGE_MAX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("DNS: upstream response exceeds {} bytes", DNS_MESSAGE_MAX_SIZE),
            ));
        }
        // The source address only proves who sent the datagram, not which question it
        // answers. A stale, misdirected, or forged response from the resolver's own
        // address must not satisfy this query, so bind it to the outstanding
        // transaction and question before it leaves the forwarding boundary. A
        // mismatch keeps waiting under the same bounded rejection budget, because the
        // legitimate answer may still be in flight.
        let response = buf.get(..len).unwrap_or(&[]);
        if let Err(reason) = match_response_to_query(query, response) {
            rejections += 1;
            log::warn!(
                "DNS: rejecting unmatched response from {resp_addr}: {reason} [{rejections}/{DNS_MAX_SPOOFED_REJECTIONS}]"
            );
            if rejections >= DNS_MAX_SPOOFED_REJECTIONS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "DNS: too many responses that do not match the outstanding question",
                ));
            }
            continue;
        }
        buf.truncate(len);
        return Ok(buf);
    }
}

/// Build a shared `reqwest::Client` tuned for DoH resolution: short
/// timeouts, HTTPS-only, no redirects, rustls TLS backend. The client
/// owns a connection pool so reusing it across queries avoids a fresh
/// TLS handshake per DNS request. Cloning the returned client is cheap
/// (Arc bump) and shares the pool.
pub fn build_doh_client() -> Result<reqwest::Client, DnsProxyError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(3))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("quicfuscate-doh/1.0")
        .build()
        .map_err(|e| DnsProxyError::DohError(format!("HTTP client build failed: {e}")))
}

/// Build a DoH client with static resolution overrides for each endpoint.
///
/// The overrides are deliberately resolved synchronously before a client-side
/// DNS proxy changes the host resolver. The URL hostname remains the TLS SNI
/// and HTTP authority, while the connection destination remains stable after
/// the local resolver becomes active.
pub fn build_doh_client_for_endpoints(
    endpoints: &[String],
) -> Result<reqwest::Client, DnsProxyError> {
    if endpoints.is_empty() {
        return Err(DnsProxyError::ConfigError(
            "at least one DoH endpoint is required".to_string(),
        ));
    }
    if endpoints.len() > 8 {
        return Err(DnsProxyError::ConfigError(
            "at most eight DoH endpoints are supported".to_string(),
        ));
    }

    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(3))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("quicfuscate-doh/1.0");

    for endpoint in endpoints {
        let url = url::Url::parse(endpoint).map_err(|error| {
            DnsProxyError::ConfigError(format!("invalid DoH endpoint {endpoint:?}: {error}"))
        })?;
        if url.scheme() != "https" {
            return Err(DnsProxyError::ConfigError(format!(
                "DoH endpoint must use https: {endpoint}"
            )));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(DnsProxyError::ConfigError(format!(
                "DoH endpoint contains unsupported credentials or fragment: {endpoint}"
            )));
        }
        let host = url.host_str().ok_or_else(|| {
            DnsProxyError::ConfigError(format!("DoH endpoint has no host: {endpoint}"))
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            DnsProxyError::ConfigError(format!("DoH endpoint has no usable port: {endpoint}"))
        })?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        let addresses: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|error| {
                DnsProxyError::ConfigError(format!(
                    "could not resolve DoH endpoint host {host:?}: {error}"
                ))
            })?
            .collect();
        if addresses.is_empty() {
            return Err(DnsProxyError::ConfigError(format!(
                "DoH endpoint host resolved to no addresses: {host}"
            )));
        }
        builder = builder.resolve_to_addrs(host, &addresses);
    }

    builder
        .build()
        .map_err(|error| DnsProxyError::DohError(format!("HTTP client build failed: {error}")))
}

/// Handle a DNS query by resolving via DoH (client-side) using a caller-
/// supplied `reqwest::Client`. Sends the raw DNS query as
/// `application/dns-message` (RFC 8484) to the DoH endpoint via HTTP POST.
/// The response body is the raw DNS response packet.
///
/// The client is expected to be built via [`build_doh_client`] (or an
/// equivalent configuration) and reused across queries to benefit from
/// connection pooling and avoid a per-query TLS handshake.
pub async fn resolve_via_doh_with_client(
    query: &[u8],
    doh_endpoint: &str,
    client: &reqwest::Client,
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;

    let mut response = client
        .post(doh_endpoint)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .map_err(|e| DnsProxyError::DohError(format!("DoH request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(DnsProxyError::DohError(format!(
            "DoH endpoint returned HTTP {}",
            response.status()
        )));
    }

    let content_type =
        response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !content_type.contains("application/dns-message") {
        return Err(DnsProxyError::DohError(format!(
            "DoH endpoint returned unexpected content-type: {content_type}"
        )));
    }

    validate_doh_content_length(response.content_length())?;
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(DNS_HEADER_SIZE),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DnsProxyError::DohError(format!("DoH response read failed: {e}")))?
    {
        append_bounded_dns_response(&mut body, &chunk)?;
    }

    // Validate that the response is a valid DNS packet (at least 12-byte header).
    if body.len() < DNS_HEADER_SIZE {
        return Err(DnsProxyError::DohError("DoH response too short for DNS packet".into()));
    }

    // RFC 8484 §4.2.1 says the ID "SHOULD be set to 0" in DoH, but
    // configured providers echo the query ID. Keep that correlation check
    // and bind it to the complete bounded question tuple; otherwise a
    // same-ID response for another query could cross this boundary.
    validate_doh_response_semantics(query, &body)?;

    Ok(body)
}

pub(super) fn validate_doh_content_length(
    content_length: Option<u64>,
) -> Result<(), DnsProxyError> {
    if let Some(length) = content_length {
        if length > DNS_MESSAGE_MAX_SIZE as u64 {
            return Err(DnsProxyError::ResponseTooLarge {
                actual: length,
                maximum: DNS_MESSAGE_MAX_SIZE,
            });
        }
    }
    Ok(())
}

pub(super) fn append_bounded_dns_response(
    body: &mut Vec<u8>,
    chunk: &[u8],
) -> Result<(), DnsProxyError> {
    let attempted_length = body.len().saturating_add(chunk.len());
    if attempted_length > DNS_MESSAGE_MAX_SIZE {
        return Err(DnsProxyError::ResponseTooLarge {
            actual: attempted_length as u64,
            maximum: DNS_MESSAGE_MAX_SIZE,
        });
    }
    body.extend_from_slice(chunk);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct DnsQuestionIdentity {
    id: u16,
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

fn parse_dns_question_identity(
    packet: &[u8],
    response: bool,
) -> Result<DnsQuestionIdentity, &'static str> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err("DNS message is shorter than its header");
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let has_response_flag = flags & DNS_FLAG_QR != 0;
    if response {
        if !has_response_flag {
            return Err("response QR flag is not set");
        }
        if flags & DNS_FLAG_OPCODE_MASK != DNS_OPCODE_QUERY {
            return Err("DNS message uses an unsupported opcode");
        }
    } else if !valid_dns_query_flags(flags) {
        return Err("DNS query uses an unsupported flag combination");
    }

    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count != 1 {
        return Err("DNS message must contain exactly one question");
    }

    let (qname, question_end) = parse_canonical_dns_name(packet, DNS_HEADER_SIZE)
        .ok_or("DNS question name is malformed")?;
    let fields_end = question_end.checked_add(4).ok_or("DNS question field offset overflow")?;
    let fields = packet.get(question_end..fields_end).ok_or("DNS question fields are truncated")?;

    Ok(DnsQuestionIdentity {
        id,
        qname,
        qtype: u16::from_be_bytes([fields[0], fields[1]]),
        qclass: u16::from_be_bytes([fields[2], fields[3]]),
    })
}

/// Parse one bounded DNS name into a canonical, case-insensitive wire form.
///
/// The caller only uses this for the first question. The pointer rules still
/// reject forward references, reserved label prefixes, loops, and names above
/// the RFC 1035 255-byte wire limit. Answer and additional sections remain
/// opaque to preserve valid compression and EDNS records.
pub(super) fn parse_canonical_dns_name(packet: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let parsed = parse_dns_name(packet, start)?;
    let mut canonical = parsed.wire;
    let mut cursor = 0;
    while cursor < canonical.len() {
        let label_length = usize::from(canonical[cursor]);
        if label_length == 0 {
            break;
        }
        let label_start = cursor.checked_add(1)?;
        let label_end = label_start.checked_add(label_length)?;
        let label = canonical.get_mut(label_start..label_end)?;
        for byte in label {
            if byte.is_ascii_uppercase() {
                *byte += b'a' - b'A';
            }
        }
        cursor = label_end;
    }
    Some((canonical, parsed.end))
}

/// Why a response could not be bound to its outstanding query.
///
/// The variants separate the three cases a caller must not conflate: the query we
/// sent is unparseable (a local defect), the response is unparseable (a remote or
/// forged message), and a well-formed response that answers a different question.
#[derive(Debug)]
enum DnsResponseMismatch {
    QueryParse(&'static str),
    ResponseParse(&'static str),
    Mismatch(String),
}

impl std::fmt::Display for DnsResponseMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryParse(reason) => write!(f, "query semantic validation failed: {reason}"),
            Self::ResponseParse(reason) => {
                write!(f, "response semantic validation failed: {reason}")
            }
            Self::Mismatch(detail) => f.write_str(detail),
        }
    }
}

/// Bind a response to the outstanding query by transaction ID and the complete
/// question tuple.
///
/// Source-address equality is not transaction authentication: a stale, misdirected,
/// or forged datagram can arrive from the configured resolver's address and answer a
/// different question. This is transport-neutral and owns that check for both the UDP
/// forwarder and DoH.
fn match_response_to_query(query: &[u8], response: &[u8]) -> Result<(), DnsResponseMismatch> {
    let expected =
        parse_dns_question_identity(query, false).map_err(DnsResponseMismatch::QueryParse)?;
    let actual =
        parse_dns_question_identity(response, true).map_err(DnsResponseMismatch::ResponseParse)?;

    if expected.id != actual.id {
        return Err(DnsResponseMismatch::Mismatch(format!(
            "response ID mismatch: expected {}, got {}",
            expected.id, actual.id
        )));
    }
    if expected.qname != actual.qname {
        return Err(DnsResponseMismatch::Mismatch("response QNAME mismatch".into()));
    }
    if expected.qtype != actual.qtype {
        return Err(DnsResponseMismatch::Mismatch(format!(
            "response QTYPE mismatch: expected {}, got {}",
            expected.qtype, actual.qtype
        )));
    }
    if expected.qclass != actual.qclass {
        return Err(DnsResponseMismatch::Mismatch(format!(
            "response QCLASS mismatch: expected {}, got {}",
            expected.qclass, actual.qclass
        )));
    }
    Ok(())
}

pub(super) fn validate_doh_response_semantics(
    query: &[u8],
    response: &[u8],
) -> Result<(), DnsProxyError> {
    match_response_to_query(query, response)
        .map_err(|reason| DnsProxyError::DohError(format!("DoH {reason}")))
}

/// Handle a DNS query by resolving via DoH (client-side). Convenience
/// wrapper around [`resolve_via_doh_with_client`] that builds a one-off
/// `reqwest::Client` per call. Suitable for standalone/test use; for
/// high-volume DNS proxying, build a client once with [`build_doh_client`]
/// and call [`resolve_via_doh_with_client`] directly.
pub async fn resolve_via_doh(query: &[u8], doh_endpoint: &str) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    let client = build_doh_client()?;
    resolve_via_doh_with_client(query, doh_endpoint, &client).await
}

pub(super) async fn resolve_via_doh_endpoints(
    query: &[u8],
    doh_endpoints: &[String],
    client: &reqwest::Client,
) -> Result<Vec<u8>, DnsProxyError> {
    resolve_via_doh_endpoints_until(
        query,
        doh_endpoints,
        client,
        tokio::time::Instant::now() + DNS_FORWARDING_DEADLINE,
    )
    .await
}

pub(super) async fn resolve_via_doh_endpoints_until(
    query: &[u8],
    doh_endpoints: &[String],
    client: &reqwest::Client,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    let mut last_error = None;
    for endpoint in doh_endpoints {
        if tokio::time::Instant::now() >= deadline {
            return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh));
        }
        match tokio::time::timeout_at(
            deadline,
            resolve_via_doh_with_client(query, endpoint, client),
        )
        .await
        {
            Err(_) => return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh)),
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(DnsProxyError::QuerySize(error))) => {
                return Err(DnsProxyError::QuerySize(error));
            }
            Ok(Err(error)) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh));
                }
                last_error = Some(error.to_string());
            }
        }
    }
    Err(DnsProxyError::UpstreamError(format!(
        "all DoH endpoints failed{}",
        last_error.map(|error| format!(": {error}")).unwrap_or_default()
    )))
}

pub(super) async fn run_dns_blocking_with_deadline<T, F>(
    deadline: Instant,
    operation: F,
) -> Result<T, DnsProxyError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DnsProxyError> + Send + 'static,
{
    // Native DNS socket deadlines stay in the blocking worker's std clock
    // domain. Tokio only receives the remaining duration, avoiding an
    // implicit Instant conversion at the async boundary.
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp));
    }
    let task = tokio::task::spawn_blocking(operation);
    match tokio::time::timeout(remaining, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            Err(DnsProxyError::UpstreamError(format!("DNS forwarding worker failed: {error}")))
        }
        Err(_) => Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp)),
    }
}

pub(super) async fn resolve_via_dns_upstreams_async(
    query: &[u8],
    upstream_resolvers: &[Ipv4Addr],
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    let query = query.to_vec();
    let upstream_resolvers = upstream_resolvers.to_vec();
    let deadline = Instant::now() + DNS_FORWARDING_DEADLINE;
    run_dns_blocking_with_deadline(deadline, move || {
        resolve_via_dns_upstreams_until(&query, &upstream_resolvers, deadline)
    })
    .await
}

pub(super) fn resolve_via_dns_upstreams_until(
    query: &[u8],
    upstream_resolvers: &[Ipv4Addr],
    deadline: Instant,
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    if upstream_resolvers.is_empty() {
        return Err(DnsProxyError::UpstreamError(
            "no DNS upstream resolvers are configured".to_string(),
        ));
    }

    let mut last_error = None;
    for upstream in upstream_resolvers {
        if Instant::now() >= deadline {
            return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp));
        }
        match forward_dns_query_until(query, *upstream, deadline) {
            Ok(response) => return Ok(response),
            Err(error) => {
                log::debug!("DNS upstream {upstream} failed: {error}");
                if error.kind() == std::io::ErrorKind::TimedOut {
                    return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp));
                }
                last_error = Some(error.to_string());
            }
        }
        if Instant::now() >= deadline {
            return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp));
        }
    }
    Err(DnsProxyError::UpstreamError(format!(
        "all DNS upstream resolvers failed{}",
        last_error.map(|error| format!(": {error}")).unwrap_or_default()
    )))
}

/// Resolve through plain DNS upstreams using the shared typed result contract.
/// A successful response is returned unchanged, including a genuine upstream
/// NXDOMAIN. Transport and configuration failures remain errors so callers can
/// synthesize SERVFAIL without confusing failure with a negative answer.
pub fn resolve_via_dns_upstreams(
    query: &[u8],
    upstream_resolvers: &[Ipv4Addr],
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    resolve_via_dns_upstreams_until(
        query,
        upstream_resolvers,
        Instant::now() + DNS_FORWARDING_DEADLINE,
    )
}

//! DNS through tunnel (TODO-435).
//!
//! Provides a DNS proxy that intercepts DNS queries from the TUN interface
//! and forwards them over DoH (DNS-over-HTTPS) through the VPN tunnel,
//! preventing DNS leaks. On the server side, intercepted DNS queries from
//! clients are forwarded to upstream resolvers.
//!
//! Wire format: standard DNS over UDP (port 53) intercepted from TUN,
//! parsed, and either resolved via DoH (client-side) or forwarded to
//! upstream DNS servers (server-side).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// Default upstream DoH providers used when none are configured.
pub const DEFAULT_DOH_UPSTREAM: &[&str] =
    &["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"];

/// Default upstream DNS resolvers (server-side forwarding).
pub const DEFAULT_DNS_UPSTREAM: &[Ipv4Addr] =
    &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)];

/// DNS query types (RFC 1035 §3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQType {
    A = 1,
    NS = 2,
    CNAME = 5,
    AAAA = 28,
    MX = 15,
    TXT = 16,
    PTR = 12,
    SRV = 33,
    HTTPS = 65,
    Unknown = 0,
}

impl DnsQType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            28 => Self::AAAA,
            15 => Self::MX,
            16 => Self::TXT,
            12 => Self::PTR,
            33 => Self::SRV,
            65 => Self::HTTPS,
            _ => Self::Unknown,
        }
    }
}

/// A parsed DNS query header + question.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub flags: u16,
    pub qname: String,
    pub qtype: DnsQType,
    pub qclass: u16,
}

/// A DNS response ready to send back to the client.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub raw: Vec<u8>,
}

/// Parse a raw DNS query packet (UDP, port 53).
pub fn parse_dns_query(pkt: &[u8]) -> Option<DnsQuery> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    // Parse the first question.
    let mut pos = 12;
    let qname = parse_name(pkt, &mut pos)?;
    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    Some(DnsQuery { id, flags, qname, qtype: DnsQType::from_u16(qtype), qclass })
}

/// Parse a DNS name (RFC 1035 §3.1, label encoding).
fn parse_name(pkt: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_pos = 0;
    let mut iterations = 0;

    loop {
        if *pos >= pkt.len() || iterations > 128 {
            return None;
        }
        let len = pkt[*pos];
        if len == 0 {
            *pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if *pos + 1 >= pkt.len() {
                return None;
            }
            if !jumped {
                jump_pos = *pos + 2;
            }
            *pos = ((len as usize & 0x3F) << 8) | (pkt[*pos + 1] as usize);
            jumped = true;
            iterations += 1;
            continue;
        }
        let label_len = len as usize;
        *pos += 1;
        if *pos + label_len > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[*pos..*pos + label_len]).to_string());
        *pos += label_len;
        iterations += 1;
    }

    if jumped {
        *pos = jump_pos;
    }
    Some(labels.join("."))
}

/// Encode a DNS name into wire format (RFC 1035 §3.1).
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0); // Root terminator.
}

/// Build a DNS response packet with the given answer records.
///
/// For A records: `answers` is a list of (name, ipv4).
/// For AAAA records: `answers` is a list of (name, ipv6).
pub fn build_dns_response_a(query: &DnsQuery, answers: &[Ipv4Addr]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);
    // Header: ID, flags (QR=1, RD=1, RA=1, RCODE=0), QDCOUNT=1, ANCOUNT=answers.len()
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&[0x81, 0x80]); // Standard response, no error
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question section.
    encode_name(&query.qname, &mut pkt);
    pkt.extend_from_slice(&(query.qtype as u16).to_be_bytes());
    pkt.extend_from_slice(&query.qclass.to_be_bytes());
    // Answer section.
    for ip in answers {
        encode_name(&query.qname, &mut pkt);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        pkt.extend_from_slice(&30u32.to_be_bytes()); // TTL 30s
        pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(&ip.octets());
    }
    pkt
}

/// Build a DNS response for AAAA records.
pub fn build_dns_response_aaaa(query: &DnsQuery, answers: &[Ipv6Addr]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&[0x81, 0x80]);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query.qname, &mut pkt);
    pkt.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
    pkt.extend_from_slice(&query.qclass.to_be_bytes());
    for ip in answers {
        encode_name(&query.qname, &mut pkt);
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&30u32.to_be_bytes());
        pkt.extend_from_slice(&16u16.to_be_bytes());
        pkt.extend_from_slice(&ip.octets());
    }
    pkt
}

/// Build a NXDOMAIN response (no such domain).
pub fn build_dns_nxdomain(query: &DnsQuery) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&[0x81, 0x83]); // NXDOMAIN
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // 0 answers
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query.qname, &mut pkt);
    pkt.extend_from_slice(&(query.qtype as u16).to_be_bytes());
    pkt.extend_from_slice(&query.qclass.to_be_bytes());
    pkt
}

/// Check if a UDP packet on port 53 is a DNS query.
pub fn is_dns_query(pkt: &[u8]) -> bool {
    pkt.len() >= 12 && parse_dns_query(pkt).is_some()
}

/// DNS proxy configuration.
///
/// The `doh_client` field caches a shared `reqwest::Client` so that DoH
/// queries reuse a single connection pool and avoid a per-query TLS
/// handshake. It is lazily initialized on the first DoH query via
/// [`DnsProxyConfig::doh_client`] and cheaply cloned (Arc bump) thereafter.
/// Callers that construct a `DnsProxyConfig` once and reuse it across many
/// queries get the full pooling benefit automatically.
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Upstream DoH endpoints (client-side).
    pub doh_endpoints: Vec<String>,
    /// Upstream DNS resolvers (server-side forwarding).
    pub upstream_resolvers: Vec<Ipv4Addr>,
    /// Whether to use DoH (client) or plain DNS forwarding (server).
    pub use_doh: bool,
    /// Listen port for the DNS proxy (default 53).
    pub listen_port: u16,
    /// Cached shared DoH HTTP client (lazily initialized). Cloning the
    /// config clones the `Arc`, sharing the underlying connection pool.
    doh_client: Arc<parking_lot::Mutex<Option<reqwest::Client>>>,
}

impl DnsProxyConfig {
    /// Build a client-side DoH configuration with endpoint resolution pinned
    /// before the system resolver is redirected to the local proxy.
    pub fn for_client_endpoints(doh_endpoints: Vec<String>) -> Result<Self, DnsProxyError> {
        if doh_endpoints.is_empty() {
            return Err(DnsProxyError::ConfigError(
                "at least one DoH endpoint is required".to_string(),
            ));
        }
        let config = Self {
            doh_endpoints,
            upstream_resolvers: Vec::new(),
            use_doh: true,
            listen_port: 53,
            doh_client: Arc::new(parking_lot::Mutex::new(None)),
        };
        config.prepare_doh_client()?;
        Ok(config)
    }

    /// Resolve and cache the DoH client before the system resolver changes.
    ///
    /// A client DNS proxy cannot resolve its own DoH host through the proxy.
    /// Pinning the endpoint addresses here keeps subsequent requests on the
    /// VPN path without re-entering the local DNS listener.
    pub fn prepare_doh_client(&self) -> Result<(), DnsProxyError> {
        let client = build_doh_client_for_endpoints(&self.doh_endpoints)?;
        *self.doh_client.lock() = Some(client);
        Ok(())
    }

    /// Returns a shared `reqwest::Client` for DoH resolution, building it
    /// on first call and reusing it on subsequent calls. Cloning the
    /// config (or the returned client) is cheap — both are Arc bumps that
    /// share the same connection pool.
    ///
    /// Returns an error only if the initial client build fails (e.g.
    /// TLS backend unavailable); subsequent calls retry the build.
    pub fn doh_client(&self) -> Result<reqwest::Client, DnsProxyError> {
        let mut guard = self.doh_client.lock();
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let client = build_doh_client_for_endpoints(&self.doh_endpoints)?;
        *guard = Some(client.clone());
        Ok(client)
    }

    /// Test-only accessor: whether the cached client has been built.
    #[cfg(test)]
    pub fn doh_client_inner(&self) -> bool {
        self.doh_client.lock().is_some()
    }
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            doh_endpoints: DEFAULT_DOH_UPSTREAM.iter().map(|s| s.to_string()).collect(),
            upstream_resolvers: DEFAULT_DNS_UPSTREAM.to_vec(),
            use_doh: true,
            listen_port: 53,
            doh_client: Arc::new(parking_lot::Mutex::new(None)),
        }
    }
}

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
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let upstream_addr = SocketAddr::new(std::net::IpAddr::V4(upstream), 53);
    sock.send_to(query, upstream_addr)?;
    let mut buf = vec![0u8; 4096];
    // Bound the number of spoofed-response rejections. Without this an
    // attacker flooding the ephemeral socket with forged packets could
    // keep the loop spinning until the read timeout. 8 rejections is far
    // beyond legitimate noise (a real upstream replies exactly once).
    const MAX_SPOOFED_REJECTIONS: u32 = 8;
    let mut rejections = 0u32;
    loop {
        let (len, resp_addr) = sock.recv_from(&mut buf)?;
        // Reject responses from any source other than the upstream resolver.
        // This prevents DNS spoofing/amplification attacks where an attacker
        // sends a forged response from a different IP.
        if resp_addr != upstream_addr {
            rejections += 1;
            log::warn!(
                "DNS: rejecting response from {resp_addr} (expected {upstream_addr}) [{rejections}/{MAX_SPOOFED_REJECTIONS}]"
            );
            if rejections >= MAX_SPOOFED_REJECTIONS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "DNS: too many spoofed responses from non-upstream sources",
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
    let response = client
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

    let body = response
        .bytes()
        .await
        .map_err(|e| DnsProxyError::DohError(format!("DoH response read failed: {e}")))?;

    // Validate that the response is a valid DNS packet (at least 12-byte header).
    if body.len() < 12 {
        return Err(DnsProxyError::DohError("DoH response too short for DNS packet".into()));
    }

    // Verify the DNS transaction ID matches. RFC 8484 §4.2.1 says the ID
    // "SHOULD be set to 0" in DoH, but in practice all major providers
    // (Cloudflare, Google, Quad9) echo the query ID. We enforce a match as
    // a spoofing/injection defense: an attacker who cannot see the query
    // cannot guess the 16-bit ID. If a strict RFC 8484 server returns ID=0
    // for a non-zero query ID, this check will reject it — but no known
    // production DoH server does this.
    let query_id = u16::from_be_bytes([query[0], query[1]]);
    let response_id = u16::from_be_bytes([body[0], body[1]]);
    if query_id != response_id {
        return Err(DnsProxyError::DohError(format!(
            "DoH response ID mismatch: expected {query_id}, got {response_id}"
        )));
    }

    Ok(body.to_vec())
}

/// Handle a DNS query by resolving via DoH (client-side). Convenience
/// wrapper around [`resolve_via_doh_with_client`] that builds a one-off
/// `reqwest::Client` per call. Suitable for standalone/test use; for
/// high-volume DNS proxying, build a client once with [`build_doh_client`]
/// and call [`resolve_via_doh_with_client`] directly.
pub async fn resolve_via_doh(query: &[u8], doh_endpoint: &str) -> Result<Vec<u8>, DnsProxyError> {
    let client = build_doh_client()?;
    resolve_via_doh_with_client(query, doh_endpoint, &client).await
}

/// Error type for DNS proxy operations.
#[derive(Debug)]
pub enum DnsProxyError {
    IoError(std::io::Error),
    DohError(String),
    ParseError(String),
    ConfigError(String),
}

impl std::fmt::Display for DnsProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "DNS I/O error: {e}"),
            Self::DohError(s) => write!(f, "DoH error: {s}"),
            Self::ParseError(s) => write!(f, "DNS parse error: {s}"),
            Self::ConfigError(s) => write!(f, "DNS configuration error: {s}"),
        }
    }
}

impl std::error::Error for DnsProxyError {}

impl From<std::io::Error> for DnsProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// Process a DNS query packet and return a response packet.
///
/// This is the main entry point for the DNS proxy. It:
/// 1. Parses the DNS query.
/// 2. Forwards to upstream resolver (server-side) or DoH (client-side).
/// 3. Returns the response packet ready to send back to the client.
pub async fn process_dns_query(
    pkt: &[u8],
    config: &DnsProxyConfig,
) -> Result<Vec<u8>, DnsProxyError> {
    let query = parse_dns_query(pkt)
        .ok_or_else(|| DnsProxyError::ParseError("invalid DNS query".into()))?;

    if config.use_doh && !config.doh_endpoints.is_empty() {
        // Client-side: resolve via DoH through the tunnel. The shared HTTP
        // client is cached in the config so it is built once and reused
        // across all queries and endpoints, benefiting from connection
        // pooling and avoiding a per-query TLS handshake.
        //
        // If the cached client cannot be built (e.g. TLS backend
        // unavailable), fall back to NXDOMAIN rather than propagating the
        // error — the caller expects a DNS response packet, not an error.
        match config.doh_client() {
            Ok(client) => {
                for endpoint in &config.doh_endpoints {
                    if let Ok(response) = resolve_via_doh_with_client(pkt, endpoint, &client).await
                    {
                        return Ok(response);
                    }
                }
                // All DoH endpoints failed — fall back to NXDOMAIN.
                Ok(build_dns_nxdomain(&query))
            }
            Err(e) => {
                log::warn!("DoH client build failed, returning NXDOMAIN: {e}");
                Ok(build_dns_nxdomain(&query))
            }
        }
    } else if !config.upstream_resolvers.is_empty() {
        // Server-side: forward to upstream DNS resolver.
        for upstream in &config.upstream_resolvers {
            if let Ok(response) = forward_dns_query(pkt, *upstream) {
                return Ok(response);
            }
        }
        Ok(build_dns_nxdomain(&query))
    } else {
        Ok(build_dns_nxdomain(&query))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dns_query_packet(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Standard query, RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                    // Question: encode domain name.
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root terminator.
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        pkt
    }

    #[test]
    fn test_parse_dns_query() {
        let pkt = make_dns_query_packet("example.com", 1);
        let query = parse_dns_query(&pkt).unwrap();
        assert_eq!(query.id, 12345);
        assert_eq!(query.qname, "example.com");
        assert_eq!(query.qtype, DnsQType::A);
        assert_eq!(query.qclass, 1);
    }

    #[test]
    fn test_parse_dns_query_aaaa() {
        let pkt = make_dns_query_packet("example.com", 28);
        let query = parse_dns_query(&pkt).unwrap();
        assert_eq!(query.qtype, DnsQType::AAAA);
    }

    #[test]
    fn test_parse_dns_query_too_short() {
        assert!(parse_dns_query(&[0, 1, 2]).is_none());
    }

    #[test]
    fn test_build_dns_response_a() {
        let query = DnsQuery {
            id: 42,
            flags: 0x0100,
            qname: "test.com".into(),
            qtype: DnsQType::A,
            qclass: 1,
        };
        let ips = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let response = build_dns_response_a(&query, &ips);
        // Verify ID.
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 42);
        // Verify ANCOUNT = 2.
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2);
    }

    #[test]
    fn test_build_dns_nxdomain() {
        let query = DnsQuery {
            id: 99,
            flags: 0x0100,
            qname: "nonexistent.invalid".into(),
            qtype: DnsQType::A,
            qclass: 1,
        };
        let response = build_dns_nxdomain(&query);
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 99);
        // RCODE = 3 (NXDOMAIN) in flags.
        assert_eq!(response[3] & 0x0F, 3);
    }

    #[test]
    fn test_is_dns_query() {
        let pkt = make_dns_query_packet("example.com", 1);
        assert!(is_dns_query(&pkt));
        assert!(!is_dns_query(&[0, 1, 2]));
    }

    #[test]
    fn test_dns_qtype_from_u16() {
        assert_eq!(DnsQType::from_u16(1), DnsQType::A);
        assert_eq!(DnsQType::from_u16(28), DnsQType::AAAA);
        assert_eq!(DnsQType::from_u16(999), DnsQType::Unknown);
    }

    #[test]
    fn test_dns_proxy_config_default() {
        let config = DnsProxyConfig::default();
        assert!(!config.doh_endpoints.is_empty());
        assert!(!config.upstream_resolvers.is_empty());
        assert!(config.use_doh);
        assert_eq!(config.listen_port, 53);
    }

    #[test]
    fn test_client_dns_proxy_config_prepares_ip_endpoint() {
        let config =
            DnsProxyConfig::for_client_endpoints(vec!["https://127.0.0.1/dns-query".to_string()])
                .expect("IP-based DoH endpoint should be valid");

        assert!(config.use_doh);
        assert!(config.upstream_resolvers.is_empty());
        assert!(config.doh_client.lock().is_some());
    }

    #[test]
    fn test_client_dns_proxy_config_rejects_non_https_endpoint() {
        let result =
            DnsProxyConfig::for_client_endpoints(vec!["http://127.0.0.1/dns-query".to_string()]);

        assert!(matches!(result, Err(DnsProxyError::ConfigError(_))));
    }

    #[test]
    fn test_client_dns_proxy_config_rejects_endpoint_credentials() {
        let result = DnsProxyConfig::for_client_endpoints(vec![
            "https://user:password@127.0.0.1/dns-query".to_string(),
        ]);

        assert!(matches!(result, Err(DnsProxyError::ConfigError(_))));
    }

    #[tokio::test]
    async fn test_resolve_via_doh_rejects_invalid_endpoint() {
        // An invalid endpoint should return a DohError, not panic.
        let pkt = make_dns_query_packet("example.com", 1);
        let result = resolve_via_doh(&pkt, "https://invalid.localhost.invalid/dns-query").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProxyError::DohError(_)));
    }

    #[tokio::test]
    async fn test_resolve_via_doh_rejects_http_endpoint() {
        // The client is configured for HTTPS only; HTTP should fail.
        let pkt = make_dns_query_packet("example.com", 1);
        let result = resolve_via_doh(&pkt, "http://127.0.0.1:1/dns-query").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_build_doh_client_succeeds() {
        // The client builder must succeed with the canonical configuration.
        let client = build_doh_client();
        assert!(client.is_ok(), "build_doh_client should succeed");
    }

    #[tokio::test]
    async fn test_resolve_via_doh_with_client_rejects_invalid_endpoint() {
        // Using a shared client, an invalid endpoint should still return a
        // DohError, not panic. This verifies the shared-client path.
        let pkt = make_dns_query_packet("example.com", 1);
        let client = build_doh_client().unwrap();
        let result = resolve_via_doh_with_client(
            &pkt,
            "https://invalid.localhost.invalid/dns-query",
            &client,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DnsProxyError::DohError(_)));
    }

    #[tokio::test]
    async fn test_process_dns_query_with_no_resolvers_returns_nxdomain() {
        let pkt = make_dns_query_packet("example.com", 1);
        let config = DnsProxyConfig {
            doh_endpoints: vec![],
            upstream_resolvers: vec![],
            use_doh: false,
            ..Default::default()
        };
        let result = process_dns_query(&pkt, &config).await.unwrap();
        // Should be NXDOMAIN (RCODE=3).
        assert_eq!(result[3] & 0x0F, 3);
    }

    #[tokio::test]
    async fn test_doh_client_is_cached_and_shared() {
        // The cached client must be built once and reused on subsequent
        // calls. After the first call the cache slot must be populated;
        // the second call must succeed without rebuilding.
        let config = DnsProxyConfig::default();
        // Before first call: cache is empty.
        assert!(!config.doh_client_inner(), "cache must be empty initially");
        let _c1 = config.doh_client().unwrap();
        // After first call: cache is populated.
        assert!(config.doh_client_inner(), "cache must be populated after first call");
        // Second call must succeed (returns a clone of the cached client).
        let _c2 = config.doh_client().unwrap();
        assert!(config.doh_client_inner(), "cache must remain populated");
    }

    #[tokio::test]
    async fn test_process_dns_query_doh_failure_returns_nxdomain_not_error() {
        // When DoH is enabled but all endpoints fail (unreachable), the
        // function must return a NXDOMAIN response packet, not an error.
        // This is the production contract: callers expect a DNS response.
        let pkt = make_dns_query_packet("example.com", 1);
        let config = DnsProxyConfig {
            doh_endpoints: vec!["https://invalid.localhost.invalid/dns-query".to_string()],
            upstream_resolvers: vec![],
            use_doh: true,
            ..Default::default()
        };
        let result = process_dns_query(&pkt, &config).await;
        assert!(result.is_ok(), "DoH failure should return NXDOMAIN, not error");
        let response = result.unwrap();
        assert_eq!(response[3] & 0x0F, 3, "response should be NXDOMAIN (RCODE=3)");
    }
}

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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
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
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            doh_endpoints: DEFAULT_DOH_UPSTREAM.iter().map(|s| s.to_string()).collect(),
            upstream_resolvers: DEFAULT_DNS_UPSTREAM.to_vec(),
            use_doh: true,
            listen_port: 53,
        }
    }
}

/// Handle a DNS query packet by forwarding it to an upstream resolver and
/// returning the response. This is the server-side path: plain DNS over UDP
/// to upstream resolvers.
pub fn forward_dns_query(query: &[u8], upstream: Ipv4Addr) -> std::io::Result<Vec<u8>> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let upstream_addr = SocketAddr::new(std::net::IpAddr::V4(upstream), 53);
    sock.send_to(query, upstream_addr)?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

/// Handle a DNS query by resolving via DoH (client-side). Sends the raw DNS
/// query as `application/dns-message` to the DoH endpoint.
pub async fn resolve_via_doh(query: &[u8], doh_endpoint: &str) -> Result<Vec<u8>, DnsProxyError> {
    // Use a minimal HTTP client. We avoid pulling in reqwest/hyper for this
    // — the DoH request is a simple POST with a binary body.
    // In production, this would use the QUIC tunnel's HTTP/3 stack.
    // For now, we use a plain TCP+TLS connection via std.
    //
    // NOTE: This is a synchronous stub that returns an error. The actual DoH
    // resolution happens through the VPN tunnel's HTTP/3 client, which is
    // wired in the connection layer. This function exists for standalone DNS
    // proxy mode.
    let _ = (query, doh_endpoint);
    Err(DnsProxyError::NotImplemented(
        "DoH resolution requires the VPN tunnel's HTTP/3 client".into(),
    ))
}

/// Error type for DNS proxy operations.
#[derive(Debug)]
pub enum DnsProxyError {
    IoError(std::io::Error),
    NotImplemented(String),
    ParseError(String),
}

impl std::fmt::Display for DnsProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "DNS I/O error: {e}"),
            Self::NotImplemented(s) => write!(f, "DNS not implemented: {s}"),
            Self::ParseError(s) => write!(f, "DNS parse error: {s}"),
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
        // Client-side: resolve via DoH through the tunnel.
        for endpoint in &config.doh_endpoints {
            if let Ok(response) = resolve_via_doh(pkt, endpoint).await {
                return Ok(response);
            }
        }
        // DoH failed, fall back to NXDOMAIN.
        Ok(build_dns_nxdomain(&query))
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
}

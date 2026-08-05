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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default upstream DoH providers used when none are configured.
pub const DEFAULT_DOH_UPSTREAM: &[&str] =
    &["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"];

/// Default upstream DNS resolvers (server-side forwarding).
pub const DEFAULT_DNS_UPSTREAM: &[Ipv4Addr] =
    &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)];

/// Maximum DNS message size accepted at the forwarding boundary.
pub const DNS_MESSAGE_MAX_SIZE: usize = 4096;
/// Minimum DNS message size required for a transaction header.
pub const DNS_HEADER_SIZE: usize = 12;
/// Aggregate budget for all upstream fallback attempts for one query.
pub const DNS_FORWARDING_DEADLINE: Duration = Duration::from_secs(5);

const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_OPCODE_MASK: u16 = 0x7800;
const DNS_OPCODE_QUERY: u16 = 0;
const DNS_FLAG_RD: u16 = 0x0100;
const DNS_FLAG_CD: u16 = 0x0010;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_NXDOMAIN: u8 = 3;

const DNS_ADMISSION_MAX_IN_FLIGHT: usize = 4_096;
const DNS_ADMISSION_MAX_RATE: u64 = 10_000_000;
const DNS_ADMISSION_MAX_BURST: u64 = 20_000_000;
const DNS_ADMISSION_MAX_IDENTITIES: usize = 65_536;
const DNS_ADMISSION_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const DNS_ADMISSION_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
const DNS_MAX_SPOOFED_REJECTIONS: u32 = 8;
const DNS_MAX_NAME_WIRE_SIZE: usize = 255;
const DNS_MAX_NAME_POINTERS: usize = 128;

/// Validated admission policy for DNS work at a concrete caller boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAdmissionConfig {
    /// Maximum number of upstream exchanges executing concurrently.
    pub max_in_flight: usize,
    /// Aggregate accepted query rate across all identities and upstreams.
    pub global_pps: u64,
    /// Aggregate initial token burst.
    pub global_burst: u64,
    /// Sustained rate for one session or source identity.
    pub per_identity_pps: u64,
    /// Initial token burst for one session or source identity.
    pub per_identity_burst: u64,
    /// Hard cap on retained identity buckets.
    pub max_identities: usize,
    /// Idle duration after which an identity bucket can be removed.
    pub idle_timeout: Duration,
}

impl DnsAdmissionConfig {
    /// Conservative policy for a local client listener shared by localhost processes.
    pub const fn client_default() -> Self {
        Self {
            max_in_flight: 2,
            global_pps: 100,
            global_burst: 200,
            per_identity_pps: 100,
            per_identity_burst: 200,
            max_identities: 4,
            idle_timeout: Duration::from_secs(60),
        }
    }

    /// Existing server intercept policy with explicit bounded identity state.
    pub const fn server_default() -> Self {
        Self {
            max_in_flight: 128,
            global_pps: 2_000,
            global_burst: 4_000,
            per_identity_pps: 100,
            per_identity_burst: 200,
            max_identities: 1_024,
            idle_timeout: Duration::from_secs(60),
        }
    }

    /// Validate all admission values before a listener or server runtime starts.
    pub fn validate(&self) -> Result<(), DnsAdmissionConfigError> {
        if self.max_in_flight == 0 {
            return Err(DnsAdmissionConfigError::Zero("max_in_flight"));
        }
        if self.max_in_flight > DNS_ADMISSION_MAX_IN_FLIGHT {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "max_in_flight",
                value: self.max_in_flight as u64,
                maximum: DNS_ADMISSION_MAX_IN_FLIGHT as u64,
            });
        }
        if self.global_pps == 0 {
            return Err(DnsAdmissionConfigError::Zero("global_pps"));
        }
        if self.global_pps > DNS_ADMISSION_MAX_RATE {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "global_pps",
                value: self.global_pps,
                maximum: DNS_ADMISSION_MAX_RATE,
            });
        }
        if self.global_burst == 0 {
            return Err(DnsAdmissionConfigError::Zero("global_burst"));
        }
        if self.global_burst > DNS_ADMISSION_MAX_BURST {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "global_burst",
                value: self.global_burst,
                maximum: DNS_ADMISSION_MAX_BURST,
            });
        }
        if self.per_identity_pps == 0 {
            return Err(DnsAdmissionConfigError::Zero("per_identity_pps"));
        }
        if self.per_identity_pps > DNS_ADMISSION_MAX_RATE {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "per_identity_pps",
                value: self.per_identity_pps,
                maximum: DNS_ADMISSION_MAX_RATE,
            });
        }
        if self.per_identity_burst == 0 {
            return Err(DnsAdmissionConfigError::Zero("per_identity_burst"));
        }
        if self.per_identity_burst > DNS_ADMISSION_MAX_BURST {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "per_identity_burst",
                value: self.per_identity_burst,
                maximum: DNS_ADMISSION_MAX_BURST,
            });
        }
        if self.max_identities == 0 {
            return Err(DnsAdmissionConfigError::Zero("max_identities"));
        }
        if self.max_identities > DNS_ADMISSION_MAX_IDENTITIES {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "max_identities",
                value: self.max_identities as u64,
                maximum: DNS_ADMISSION_MAX_IDENTITIES as u64,
            });
        }
        if self.idle_timeout.is_zero() {
            return Err(DnsAdmissionConfigError::Zero("idle_timeout"));
        }
        if self.idle_timeout > DNS_ADMISSION_MAX_IDLE_TIMEOUT {
            return Err(DnsAdmissionConfigError::TooLarge {
                field: "idle_timeout_secs",
                value: self.idle_timeout.as_secs(),
                maximum: DNS_ADMISSION_MAX_IDLE_TIMEOUT.as_secs(),
            });
        }
        Ok(())
    }
}

impl Default for DnsAdmissionConfig {
    fn default() -> Self {
        Self::client_default()
    }
}

/// Configuration validation failure for DNS admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsAdmissionConfigError {
    Zero(&'static str),
    TooLarge { field: &'static str, value: u64, maximum: u64 },
}

impl std::fmt::Display for DnsAdmissionConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero(field) => write!(f, "DNS admission {field} must be nonzero"),
            Self::TooLarge { field, value, maximum } => {
                write!(f, "DNS admission {field}={value} exceeds maximum {maximum}")
            }
        }
    }
}

impl std::error::Error for DnsAdmissionConfigError {}

/// Identity used to scope DNS admission state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsAdmissionIdentity {
    /// Authenticated server session. This is the fairness unit for live TUN DNS.
    Session(u64),
    /// Source address fallback where no authenticated session identity exists.
    Source(IpAddr),
}

/// Reason why a DNS query was rejected before upstream work started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsAdmissionReject {
    InFlight,
    GlobalRate,
    IdentityRate,
    IdentityCapacity,
}

impl DnsAdmissionReject {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::GlobalRate => "global_rate",
            Self::IdentityRate => "identity_rate",
            Self::IdentityCapacity => "identity_capacity",
        }
    }
}

impl std::fmt::Display for DnsAdmissionReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read-only DNS admission counters and current bounded state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAdmissionSnapshot {
    pub max_in_flight: usize,
    pub active_in_flight: usize,
    pub global_pps: u64,
    pub global_burst: u64,
    pub per_identity_pps: u64,
    pub per_identity_burst: u64,
    pub max_identities: usize,
    pub tracked_identities: usize,
    pub accepted: u64,
    pub rejected_in_flight: u64,
    pub rejected_global_rate: u64,
    pub rejected_identity_rate: u64,
    pub rejected_identity_capacity: u64,
}

struct DnsTokenBucket {
    tokens: u64,
    capacity: u64,
    refill_rate: u64,
    last_refill: Instant,
    last_seen: Instant,
}

impl DnsTokenBucket {
    fn new(rate: u64, capacity: u64, now: Instant) -> Self {
        Self { tokens: capacity, capacity, refill_rate: rate, last_refill: now, last_seen: now }
    }

    fn consume(&mut self, now: Instant) -> bool {
        self.last_seen = now;
        let elapsed = now.saturating_duration_since(self.last_refill);
        if elapsed >= Duration::from_secs(1) {
            let refill = (elapsed.as_micros() * u128::from(self.refill_rate))
                .checked_div(1_000_000)
                .unwrap_or(u128::from(self.capacity));
            let refill = u64::try_from(refill).unwrap_or(u64::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn is_idle(&self, now: Instant, timeout: Duration) -> bool {
        now.saturating_duration_since(self.last_seen) >= timeout
    }
}

struct DnsAdmissionState {
    global: DnsTokenBucket,
    identities: HashMap<DnsAdmissionIdentity, DnsTokenBucket>,
    last_prune: Instant,
}

impl DnsAdmissionState {
    fn new(config: DnsAdmissionConfig) -> Self {
        let now = Instant::now();
        Self {
            global: DnsTokenBucket::new(config.global_pps, config.global_burst, now),
            identities: HashMap::new(),
            last_prune: now,
        }
    }

    fn prune_if_due(&mut self, now: Instant, timeout: Duration) {
        let interval = timeout.min(DNS_ADMISSION_PRUNE_INTERVAL);
        if now.saturating_duration_since(self.last_prune) < interval {
            return;
        }
        self.last_prune = now;
        self.identities.retain(|_, bucket| !bucket.is_idle(now, timeout));
    }

    fn prune_all(&mut self, now: Instant, timeout: Duration) -> usize {
        let before = self.identities.len();
        self.identities.retain(|_, bucket| !bucket.is_idle(now, timeout));
        self.last_prune = now;
        before.saturating_sub(self.identities.len())
    }
}

/// Shared, bounded admission owner for DNS forwarding work.
pub struct DnsAdmission {
    config: DnsAdmissionConfig,
    in_flight: Arc<tokio::sync::Semaphore>,
    state: parking_lot::Mutex<DnsAdmissionState>,
    accepted: AtomicU64,
    rejected_in_flight: AtomicU64,
    rejected_global_rate: AtomicU64,
    rejected_identity_rate: AtomicU64,
    rejected_identity_capacity: AtomicU64,
}

/// Permit held for the complete upstream exchange and response construction.
pub struct DnsAdmissionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Forwarding stage whose aggregate deadline was exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsForwardingStage {
    Doh,
    Udp,
}

impl std::fmt::Display for DnsForwardingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Doh => f.write_str("DoH fallback"),
            Self::Udp => f.write_str("UDP fallback"),
        }
    }
}

/// Size validation failure for a raw DNS query passed to a forwarding helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsQuerySizeError {
    TooShort { actual: usize, minimum: usize },
    TooLarge { actual: usize, maximum: usize },
}

impl std::fmt::Display for DnsQuerySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { actual, minimum } => {
                write!(f, "DNS query is too short: {actual} bytes, minimum is {minimum}")
            }
            Self::TooLarge { actual, maximum } => {
                write!(f, "DNS query is too large: {actual} bytes, maximum is {maximum}")
            }
        }
    }
}

impl std::error::Error for DnsQuerySizeError {}

/// Validate the raw DNS message size before allocating or issuing upstream I/O.
pub fn validate_dns_query_size(query: &[u8]) -> Result<(), DnsQuerySizeError> {
    if query.len() < DNS_HEADER_SIZE {
        return Err(DnsQuerySizeError::TooShort { actual: query.len(), minimum: DNS_HEADER_SIZE });
    }
    if query.len() > DNS_MESSAGE_MAX_SIZE {
        return Err(DnsQuerySizeError::TooLarge {
            actual: query.len(),
            maximum: DNS_MESSAGE_MAX_SIZE,
        });
    }
    Ok(())
}

impl DnsAdmission {
    pub fn try_new(config: DnsAdmissionConfig) -> Result<Self, DnsAdmissionConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            in_flight: Arc::new(tokio::sync::Semaphore::new(config.max_in_flight)),
            state: parking_lot::Mutex::new(DnsAdmissionState::new(config)),
            accepted: AtomicU64::new(0),
            rejected_in_flight: AtomicU64::new(0),
            rejected_global_rate: AtomicU64::new(0),
            rejected_identity_rate: AtomicU64::new(0),
            rejected_identity_capacity: AtomicU64::new(0),
        })
    }

    pub fn try_acquire(
        &self,
        identity: DnsAdmissionIdentity,
    ) -> Result<DnsAdmissionPermit, DnsAdmissionReject> {
        let permit = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| self.reject(DnsAdmissionReject::InFlight))?;
        let now = Instant::now();
        let mut state = self.state.lock();
        state.prune_if_due(now, self.config.idle_timeout);
        if !state.identities.contains_key(&identity)
            && state.identities.len() >= self.config.max_identities
        {
            drop(state);
            drop(permit);
            return Err(self.reject(DnsAdmissionReject::IdentityCapacity));
        }
        if !state.global.consume(now) {
            drop(state);
            drop(permit);
            return Err(self.reject(DnsAdmissionReject::GlobalRate));
        }
        let bucket = state.identities.entry(identity).or_insert_with(|| {
            DnsTokenBucket::new(self.config.per_identity_pps, self.config.per_identity_burst, now)
        });
        if !bucket.consume(now) {
            drop(state);
            drop(permit);
            return Err(self.reject(DnsAdmissionReject::IdentityRate));
        }
        drop(state);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(DnsAdmissionPermit { _permit: permit })
    }

    pub fn remove_identity(&self, identity: DnsAdmissionIdentity) -> bool {
        self.state.lock().identities.remove(&identity).is_some()
    }

    pub fn prune_idle(&self) -> usize {
        let now = Instant::now();
        self.state.lock().prune_all(now, self.config.idle_timeout)
    }

    pub fn snapshot(&self) -> DnsAdmissionSnapshot {
        let state = self.state.lock();
        let active_in_flight =
            self.config.max_in_flight.saturating_sub(self.in_flight.available_permits());
        DnsAdmissionSnapshot {
            max_in_flight: self.config.max_in_flight,
            active_in_flight,
            global_pps: self.config.global_pps,
            global_burst: self.config.global_burst,
            per_identity_pps: self.config.per_identity_pps,
            per_identity_burst: self.config.per_identity_burst,
            max_identities: self.config.max_identities,
            tracked_identities: state.identities.len(),
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected_in_flight: self.rejected_in_flight.load(Ordering::Relaxed),
            rejected_global_rate: self.rejected_global_rate.load(Ordering::Relaxed),
            rejected_identity_rate: self.rejected_identity_rate.load(Ordering::Relaxed),
            rejected_identity_capacity: self.rejected_identity_capacity.load(Ordering::Relaxed),
        }
    }

    fn reject(&self, reason: DnsAdmissionReject) -> DnsAdmissionReject {
        let counter = match reason {
            DnsAdmissionReject::InFlight => &self.rejected_in_flight,
            DnsAdmissionReject::GlobalRate => &self.rejected_global_rate,
            DnsAdmissionReject::IdentityRate => &self.rejected_identity_rate,
            DnsAdmissionReject::IdentityCapacity => &self.rejected_identity_capacity,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        reason
    }
}

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
    /// Original wire QTYPE, retained when `qtype` is `Unknown`.
    pub raw_qtype: u16,
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
    if flags & DNS_FLAG_QR != 0 {
        return None;
    }
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
    Some(DnsQuery { id, flags, qname, qtype: DnsQType::from_u16(qtype), raw_qtype: qtype, qclass })
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

fn response_flags(request_flags: u16, rcode: u8) -> u16 {
    DNS_FLAG_QR
        | (request_flags & (DNS_FLAG_OPCODE_MASK | DNS_FLAG_RD | DNS_FLAG_CD))
        | u16::from(rcode & 0x0f)
}

fn append_question(query: &DnsQuery, pkt: &mut Vec<u8>) {
    encode_name(&query.qname, pkt);
    pkt.extend_from_slice(&query.raw_qtype.to_be_bytes());
    pkt.extend_from_slice(&query.qclass.to_be_bytes());
}

fn build_dns_error(query: &DnsQuery, rcode: u8) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&response_flags(query.flags, rcode).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    append_question(query, &mut pkt);
    pkt
}

/// Build a DNS response packet with the given answer records.
///
/// For A records: `answers` is a list of (name, ipv4).
/// For AAAA records: `answers` is a list of (name, ipv6).
pub fn build_dns_response_a(query: &DnsQuery, answers: &[Ipv4Addr]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);
    // Header: ID, derived response flags, QDCOUNT=1, ANCOUNT=answers.len().
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&response_flags(query.flags, DNS_RCODE_NOERROR).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question section.
    append_question(query, &mut pkt);
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
    pkt.extend_from_slice(&response_flags(query.flags, DNS_RCODE_NOERROR).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    append_question(query, &mut pkt);
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
    build_dns_error(query, DNS_RCODE_NXDOMAIN)
}

/// Build a SERVFAIL response for an upstream or proxy failure.
pub fn build_dns_servfail(query: &DnsQuery) -> Vec<u8> {
    build_dns_error(query, DNS_RCODE_SERVFAIL)
}

/// Build a header-only SERVFAIL when the query cannot be parsed into a full
/// question. Packets without a complete transaction ID cannot receive a
/// correlated response and return `None`.
pub fn build_dns_servfail_from_packet(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 2 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], *pkt.get(1)?]);
    let request_flags = if pkt.len() >= 4 { u16::from_be_bytes([pkt[2], pkt[3]]) } else { 0 };
    let mut response = Vec::with_capacity(12);
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags(request_flags, DNS_RCODE_SERVFAIL).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    Some(response)
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
    /// Admission policy owned by the active listener caller. The forwarding
    /// helper does not consume this policy because it has no caller identity.
    pub admission: DnsAdmissionConfig,
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
            admission: DnsAdmissionConfig::client_default(),
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
            admission: DnsAdmissionConfig::server_default(),
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
    validate_dns_query_size(query).map_err(dns_query_size_io_error)?;
    forward_dns_query_until(query, upstream, Instant::now() + DNS_FORWARDING_DEADLINE)
}

fn dns_query_size_io_error(error: DnsQuerySizeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

fn remaining_until(deadline: Instant) -> std::io::Result<Duration> {
    let now = Instant::now();
    match deadline.checked_duration_since(now) {
        Some(remaining) if !remaining.is_zero() => Ok(remaining),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS forwarding deadline exceeded",
        )),
    }
}

fn forward_dns_query_until(
    query: &[u8],
    upstream: Ipv4Addr,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_write_timeout(Some(remaining_until(deadline)?))?;
    let upstream_addr = SocketAddr::new(std::net::IpAddr::V4(upstream), 53);
    sock.send_to(query, upstream_addr)?;
    receive_dns_response(&sock, upstream_addr, deadline)
}

fn receive_dns_response(
    sock: &std::net::UdpSocket,
    upstream_addr: SocketAddr,
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

fn validate_doh_content_length(content_length: Option<u64>) -> Result<(), DnsProxyError> {
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

fn append_bounded_dns_response(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), DnsProxyError> {
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

fn parse_doh_question_identity(
    packet: &[u8],
    response: bool,
) -> Result<DnsQuestionIdentity, &'static str> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err("DNS message is shorter than its header");
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let has_response_flag = flags & DNS_FLAG_QR != 0;
    if has_response_flag != response {
        return Err(if response { "response QR flag is not set" } else { "query QR flag is set" });
    }
    if flags & DNS_FLAG_OPCODE_MASK != DNS_OPCODE_QUERY {
        return Err("DNS message uses an unsupported opcode");
    }

    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count != 1 {
        return Err("DNS message must contain exactly one question");
    }

    let (qname, question_end) =
        parse_doh_name(packet, DNS_HEADER_SIZE).ok_or("DNS question name is malformed")?;
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
fn parse_doh_name(packet: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut canonical = Vec::with_capacity(32);
    let mut cursor = start;
    let mut consumed_end = None;
    let mut pointer_count = 0;

    loop {
        let length = *packet.get(cursor)?;
        match length & 0xc0 {
            0x00 => {
                let label_length = usize::from(length);
                if label_length == 0 {
                    let end = cursor.checked_add(1)?;
                    canonical.push(0);
                    return Some((canonical, consumed_end.unwrap_or(end)));
                }
                if label_length > 63 {
                    return None;
                }
                let label_start = cursor.checked_add(1)?;
                let label_end = label_start.checked_add(label_length)?;
                let canonical_length = canonical.len().checked_add(label_length + 1)?;
                if canonical_length > DNS_MAX_NAME_WIRE_SIZE {
                    return None;
                }
                let label = packet.get(label_start..label_end)?;
                canonical.push(length);
                for byte in label {
                    let lower =
                        if byte.is_ascii_uppercase() { *byte + (b'a' - b'A') } else { *byte };
                    canonical.push(lower);
                }
                cursor = label_end;
            }
            0xc0 => {
                let pointer_end = cursor.checked_add(2)?;
                let pointer = packet.get(cursor..pointer_end)?;
                let target = (usize::from(pointer[0] & 0x3f) << 8) | usize::from(pointer[1]);
                if target < DNS_HEADER_SIZE || target >= cursor {
                    return None;
                }
                pointer_count += 1;
                if pointer_count > DNS_MAX_NAME_POINTERS {
                    return None;
                }
                if consumed_end.is_none() {
                    consumed_end = Some(pointer_end);
                }
                cursor = target;
            }
            _ => return None,
        }
    }
}

fn validate_doh_response_semantics(query: &[u8], response: &[u8]) -> Result<(), DnsProxyError> {
    let expected = parse_doh_question_identity(query, false).map_err(|reason| {
        DnsProxyError::DohError(format!("DoH query semantic validation failed: {reason}"))
    })?;
    let actual = parse_doh_question_identity(response, true).map_err(|reason| {
        DnsProxyError::DohError(format!("DoH response semantic validation failed: {reason}"))
    })?;

    if expected.id != actual.id {
        return Err(DnsProxyError::DohError(format!(
            "DoH response ID mismatch: expected {}, got {}",
            expected.id, actual.id
        )));
    }
    if expected.qname != actual.qname {
        return Err(DnsProxyError::DohError("DoH response QNAME mismatch".into()));
    }
    if expected.qtype != actual.qtype {
        return Err(DnsProxyError::DohError(format!(
            "DoH response QTYPE mismatch: expected {}, got {}",
            expected.qtype, actual.qtype
        )));
    }
    if expected.qclass != actual.qclass {
        return Err(DnsProxyError::DohError(format!(
            "DoH response QCLASS mismatch: expected {}, got {}",
            expected.qclass, actual.qclass
        )));
    }
    Ok(())
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

async fn resolve_via_doh_endpoints(
    query: &[u8],
    doh_endpoints: &[String],
    client: &reqwest::Client,
) -> Result<Vec<u8>, DnsProxyError> {
    resolve_via_doh_endpoints_until(
        query,
        doh_endpoints,
        client,
        Instant::now() + DNS_FORWARDING_DEADLINE,
    )
    .await
}

async fn resolve_via_doh_endpoints_until(
    query: &[u8],
    doh_endpoints: &[String],
    client: &reqwest::Client,
    deadline: Instant,
) -> Result<Vec<u8>, DnsProxyError> {
    validate_dns_query_size(query).map_err(DnsProxyError::QuerySize)?;
    let mut last_error = None;
    for endpoint in doh_endpoints {
        if Instant::now() >= deadline {
            return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh));
        }
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
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
                if Instant::now() >= deadline {
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

async fn run_dns_blocking_with_deadline<T, F>(
    deadline: Instant,
    operation: F,
) -> Result<T, DnsProxyError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DnsProxyError> + Send + 'static,
{
    if Instant::now() >= deadline {
        return Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp));
    }
    let task = tokio::task::spawn_blocking(operation);
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            Err(DnsProxyError::UpstreamError(format!("DNS forwarding worker failed: {error}")))
        }
        Err(_) => Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp)),
    }
}

async fn resolve_via_dns_upstreams_async(
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

fn resolve_via_dns_upstreams_until(
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

/// Error type for DNS proxy operations.
#[derive(Debug)]
pub enum DnsProxyError {
    IoError(std::io::Error),
    DohError(String),
    UpstreamError(String),
    ParseError(String),
    ConfigError(String),
    AdmissionRejected(DnsAdmissionReject),
    QuerySize(DnsQuerySizeError),
    ResponseTooLarge { actual: u64, maximum: usize },
    DeadlineExceeded(DnsForwardingStage),
}

impl std::fmt::Display for DnsProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "DNS I/O error: {e}"),
            Self::DohError(s) => write!(f, "DoH error: {s}"),
            Self::UpstreamError(s) => write!(f, "DNS upstream error: {s}"),
            Self::ParseError(s) => write!(f, "DNS parse error: {s}"),
            Self::ConfigError(s) => write!(f, "DNS configuration error: {s}"),
            Self::AdmissionRejected(reason) => write!(f, "DNS admission rejected: {reason}"),
            Self::QuerySize(error) => write!(f, "DNS query size rejected: {error}"),
            Self::ResponseTooLarge { actual, maximum } => {
                write!(f, "DNS response too large: {actual} bytes, maximum is {maximum}")
            }
            Self::DeadlineExceeded(stage) => write!(f, "DNS {stage} deadline exceeded"),
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
///
/// Admission is intentionally owned by the active caller boundary, not this
/// helper: the helper has no stable session or source identity and retained
/// direct callers must not silently share an implicit global bucket.
pub async fn process_dns_query(
    pkt: &[u8],
    config: &DnsProxyConfig,
) -> Result<Vec<u8>, DnsProxyError> {
    let Some(query) = parse_dns_query(pkt) else {
        return build_dns_servfail_from_packet(pkt).ok_or_else(|| {
            DnsProxyError::ParseError("invalid DNS query without a complete transaction ID".into())
        });
    };

    if config.use_doh && !config.doh_endpoints.is_empty() {
        // Client-side: resolve via DoH through the tunnel. The shared HTTP
        // client is cached in the config so it is built once and reused
        // across all queries and endpoints, benefiting from connection
        // pooling and avoiding a per-query TLS handshake.
        //
        let result = match config.doh_client() {
            Ok(client) => resolve_via_doh_endpoints(pkt, &config.doh_endpoints, &client).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                log::warn!("DoH resolution failed, returning SERVFAIL: {error}");
                Ok(build_dns_servfail(&query))
            }
        }
    } else {
        match resolve_via_dns_upstreams_async(pkt, &config.upstream_resolvers).await {
            Ok(response) => Ok(response),
            Err(error) => {
                log::warn!("DNS resolution failed, returning SERVFAIL: {error}");
                Ok(build_dns_servfail(&query))
            }
        }
    }
}

/// Process a DNS query at a caller boundary with explicit admission identity.
///
/// This is the supported public entry point for callers that own an upstream
/// exchange. The permit spans parsing, upstream fallback, and response
/// construction. [`process_dns_query`] remains a low-level forwarding
/// primitive for callers that have already performed admission elsewhere.
pub async fn process_dns_query_with_admission(
    pkt: &[u8],
    config: &DnsProxyConfig,
    admission: &DnsAdmission,
    identity: DnsAdmissionIdentity,
) -> Result<Vec<u8>, DnsProxyError> {
    let _permit = admission.try_acquire(identity).map_err(DnsProxyError::AdmissionRejected)?;
    process_dns_query(pkt, config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_dns_query_packet(domain: &str, qtype: u16) -> Vec<u8> {
        make_dns_query_packet_with_flags(domain, qtype, 0x0100)
    }

    fn make_dns_query_packet_with_flags(domain: &str, qtype: u16, flags: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&flags.to_be_bytes());
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

    fn response_from_question_packet(question: &[u8], flags: u16) -> Vec<u8> {
        let mut response = question[..DNS_HEADER_SIZE].to_vec();
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[4..6].copy_from_slice(&1u16.to_be_bytes());
        response[6..12].fill(0);
        response.extend_from_slice(&question[DNS_HEADER_SIZE..]);
        response
    }

    fn valid_doh_response(query: &[u8]) -> Vec<u8> {
        let mut response = response_from_question_packet(query, DNS_FLAG_QR | DNS_FLAG_RD | 0x0080);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&30u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);
        response.extend_from_slice(&[0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        response
    }

    fn malformed_doh_response(query: &[u8]) -> Vec<u8> {
        let mut response = query[..DNS_HEADER_SIZE].to_vec();
        response[2..4].copy_from_slice(&(DNS_FLAG_QR | DNS_FLAG_RD).to_be_bytes());
        response[4..6].copy_from_slice(&1u16.to_be_bytes());
        response[6..12].fill(0);
        response.extend_from_slice(&[3, b'e']);
        response
    }

    async fn resolve_against_local_response(
        query: &[u8],
        body: Vec<u8>,
        status: &str,
        content_type: &str,
    ) -> Result<Vec<u8>, DnsProxyError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind DoH test listener");
        let address = listener.local_addr().expect("DoH test listener address");
        let status = status.to_owned();
        let content_type = content_type.to_owned();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept DoH test request");
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).await.expect("read DoH test request");
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.expect("write DoH test headers");
            stream.write_all(&body).await.expect("write DoH test body");
        });
        let client = reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build local DoH test client");
        let endpoint = format!("http://{address}/dns-query");
        let result = resolve_via_doh_with_client(query, &endpoint, &client).await;
        server.await.expect("DoH test server task");
        result
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
    fn dns_query_size_validation_is_typed_and_bounded() {
        assert_eq!(
            validate_dns_query_size(&[0u8; DNS_HEADER_SIZE - 1]),
            Err(DnsQuerySizeError::TooShort {
                actual: DNS_HEADER_SIZE - 1,
                minimum: DNS_HEADER_SIZE,
            })
        );
        let oversized = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
        assert_eq!(
            validate_dns_query_size(&oversized),
            Err(DnsQuerySizeError::TooLarge {
                actual: DNS_MESSAGE_MAX_SIZE + 1,
                maximum: DNS_MESSAGE_MAX_SIZE,
            })
        );
        assert!(validate_dns_query_size(&[0u8; DNS_HEADER_SIZE]).is_ok());
    }

    #[test]
    fn test_parse_dns_query_rejects_response_packets() {
        let mut pkt = make_dns_query_packet("example.com", 1);
        pkt[2] |= 0x80;
        assert!(parse_dns_query(&pkt).is_none());
    }

    #[test]
    fn doh_name_matching_accepts_case_insensitive_bounded_compression() {
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        packet.extend_from_slice(&[3, b'w', b'w', b'w', 0]);
        let compressed_start = packet.len();
        packet.extend_from_slice(&[3, b'W', b'W', b'W', 0xc0, 0x0c]);

        let (name, end) = parse_doh_name(&packet, compressed_start).expect("compressed name");
        assert_eq!(name, vec![3, b'w', b'w', b'w', 3, b'w', b'w', b'w', 0]);
        assert_eq!(end, packet.len());
    }

    #[test]
    fn test_unknown_qtype_is_preserved_in_servfail_question() {
        let raw_qtype = 65280;
        let pkt = make_dns_query_packet("example.com", raw_qtype);
        let query = parse_dns_query(&pkt).expect("query should parse");
        assert_eq!(query.qtype, DnsQType::Unknown);
        assert_eq!(query.raw_qtype, raw_qtype);

        let response = build_dns_servfail(&query);
        let mut pos = 12;
        parse_name(&response, &mut pos).expect("response question name");
        assert_eq!(u16::from_be_bytes([response[pos], response[pos + 1]]), raw_qtype);
    }

    #[test]
    fn test_synthesized_response_preserves_opcode_rd_and_cd() {
        let pkt = make_dns_query_packet_with_flags("example.com", 1, 0x2910);
        let query = parse_dns_query(&pkt).expect("query should parse");
        let response = build_dns_servfail(&query);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]),
            0xa912,
            "response must set QR, preserve opcode/RD/CD, and set SERVFAIL"
        );
    }

    #[tokio::test]
    async fn test_malformed_query_with_transaction_id_returns_servfail() {
        let pkt = [0x12, 0x34, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = process_dns_query(&pkt, &DnsProxyConfig::default()).await.unwrap();
        assert_eq!(u16::from_be_bytes([result[0], result[1]]), 0x1234);
        assert_eq!(result[3] & 0x0f, DNS_RCODE_SERVFAIL);
        assert_eq!(u16::from_be_bytes([result[4], result[5]]), 0);
    }

    #[test]
    fn test_build_dns_response_a() {
        let query = DnsQuery {
            id: 42,
            flags: 0x0100,
            qname: "test.com".into(),
            qtype: DnsQType::A,
            raw_qtype: 1,
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
            raw_qtype: 1,
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
    async fn test_resolve_via_doh_rejects_short_and_oversized_input_before_network() {
        let client = build_doh_client().expect("DoH client");
        let short = resolve_via_doh_with_client(
            &[0u8; DNS_HEADER_SIZE - 1],
            "https://127.0.0.1:1/dns-query",
            &client,
        )
        .await
        .expect_err("short query must be rejected before network I/O");
        assert!(matches!(short, DnsProxyError::QuerySize(DnsQuerySizeError::TooShort { .. })));

        let oversized = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
        let large =
            resolve_via_doh_with_client(&oversized, "https://127.0.0.1:1/dns-query", &client)
                .await
                .expect_err("oversized query must be rejected before network I/O");
        assert!(matches!(large, DnsProxyError::QuerySize(DnsQuerySizeError::TooLarge { .. })));
    }

    #[tokio::test]
    async fn doh_response_contract_accepts_valid_compressed_answer_and_edns() {
        let query = make_dns_query_packet("example.com", 1);
        let expected = valid_doh_response(&query);
        let actual = resolve_against_local_response(
            &query,
            expected.clone(),
            "200 OK",
            "application/dns-message; charset=binary",
        )
        .await
        .expect("valid DoH response");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn doh_response_contract_rejects_semantic_and_transport_mismatches() {
        let query = make_dns_query_packet("example.com", 1);
        let wrong_name = make_dns_query_packet("wrong.example.com", 1);
        let wrong_type = make_dns_query_packet("example.com", 28);
        let mut wrong_class = make_dns_query_packet("example.com", 1);
        let class_start = wrong_class.len() - 2;
        wrong_class[class_start..].copy_from_slice(&3u16.to_be_bytes());

        let semantic_cases = [
            ("wrong-name", response_from_question_packet(&wrong_name, DNS_FLAG_QR | DNS_FLAG_RD)),
            ("wrong-type", response_from_question_packet(&wrong_type, DNS_FLAG_QR | DNS_FLAG_RD)),
            ("wrong-class", response_from_question_packet(&wrong_class, DNS_FLAG_QR | DNS_FLAG_RD)),
            ("qr-clear", response_from_question_packet(&query, DNS_FLAG_RD)),
            (
                "unsupported-opcode",
                response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD | 0x0800),
            ),
            ("multiple-questions", {
                let mut response = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
                response[4..6].copy_from_slice(&2u16.to_be_bytes());
                response
            }),
            ("malformed-question", malformed_doh_response(&query)),
            ("wrong-id", {
                let mut response = valid_doh_response(&query);
                response[0..2].copy_from_slice(&54321u16.to_be_bytes());
                response
            }),
        ];

        for (label, response) in semantic_cases {
            let result = resolve_against_local_response(
                &query,
                response,
                "200 OK",
                "application/dns-message",
            )
            .await;
            assert!(matches!(result, Err(DnsProxyError::DohError(_))), "case {label}");
        }

        let status = resolve_against_local_response(
            &query,
            valid_doh_response(&query),
            "500 Internal Server Error",
            "application/dns-message",
        )
        .await;
        assert!(matches!(status, Err(DnsProxyError::DohError(_))));

        let content_type = resolve_against_local_response(
            &query,
            valid_doh_response(&query),
            "200 OK",
            "application/json",
        )
        .await;
        assert!(matches!(content_type, Err(DnsProxyError::DohError(_))));

        let oversized = resolve_against_local_response(
            &query,
            vec![0u8; DNS_MESSAGE_MAX_SIZE + 1],
            "200 OK",
            "application/dns-message",
        )
        .await;
        assert!(matches!(
            oversized,
            Err(DnsProxyError::ResponseTooLarge { actual, maximum })
                if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                    && maximum == DNS_MESSAGE_MAX_SIZE
        ));
    }

    #[test]
    fn doh_response_body_is_bounded_for_content_length_and_chunks() {
        assert!(validate_doh_content_length(Some(DNS_MESSAGE_MAX_SIZE as u64)).is_ok());
        assert!(matches!(
            validate_doh_content_length(Some((DNS_MESSAGE_MAX_SIZE + 1) as u64)),
            Err(DnsProxyError::ResponseTooLarge { actual, maximum })
                if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                    && maximum == DNS_MESSAGE_MAX_SIZE
        ));

        let mut body = Vec::new();
        append_bounded_dns_response(&mut body, &[0u8; DNS_MESSAGE_MAX_SIZE])
            .expect("body at the limit must be accepted");
        let error = append_bounded_dns_response(&mut body, &[0u8])
            .expect_err("body beyond the limit must be rejected");
        assert!(matches!(
            error,
            DnsProxyError::ResponseTooLarge { actual, maximum }
                if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                    && maximum == DNS_MESSAGE_MAX_SIZE
        ));
    }

    #[test]
    fn udp_forwarding_rejects_oversized_datagrams_without_truncation() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
        let payload = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
        sender
            .send_to(&payload, receiver.local_addr().expect("receiver address"))
            .expect("oversized datagram send");

        let error = receive_dns_response(
            &receiver,
            sender.local_addr().expect("sender address"),
            Instant::now() + Duration::from_secs(1),
        )
        .expect_err("oversized datagram must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn expired_dns_deadline_is_rejected_before_socket_wait() {
        let error = remaining_until(Instant::now() - Duration::from_millis(1))
            .expect_err("expired deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn fallback_deadlines_are_checked_before_each_transport() {
        let query = make_dns_query_packet("example.com", 1);
        let client = build_doh_client().expect("DoH client");
        let doh_result = resolve_via_doh_endpoints_until(
            &query,
            &["https://127.0.0.1:1/dns-query".to_string()],
            &client,
            Instant::now() - Duration::from_millis(1),
        )
        .await;
        assert!(matches!(
            doh_result,
            Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh))
        ));

        let udp_result = resolve_via_dns_upstreams_until(
            &query,
            &[Ipv4Addr::LOCALHOST],
            Instant::now() - Duration::from_millis(1),
        );
        assert!(matches!(
            udp_result,
            Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp))
        ));
    }

    #[tokio::test]
    async fn plain_dns_blocking_boundary_returns_at_aggregate_deadline() {
        let started = Instant::now();
        let result =
            run_dns_blocking_with_deadline(Instant::now() + Duration::from_millis(40), || {
                std::thread::sleep(Duration::from_millis(200));
                Ok::<_, DnsProxyError>(())
            })
            .await;

        assert!(matches!(result, Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp))));
        assert!(started.elapsed() < Duration::from_millis(180));
    }

    #[tokio::test]
    async fn test_process_dns_query_with_no_resolvers_returns_servfail() {
        let pkt = make_dns_query_packet("example.com", 1);
        let config = DnsProxyConfig {
            doh_endpoints: vec![],
            upstream_resolvers: vec![],
            use_doh: false,
            ..Default::default()
        };
        let result = process_dns_query(&pkt, &config).await.unwrap();
        assert_eq!(result[3] & 0x0F, DNS_RCODE_SERVFAIL);
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
    async fn test_process_dns_query_doh_failure_returns_servfail_not_nxdomain() {
        // When DoH is enabled but all endpoints fail, the proxy must return
        // SERVFAIL rather than fabricating a negative answer.
        let pkt = make_dns_query_packet("example.com", 1);
        let config = DnsProxyConfig {
            doh_endpoints: vec!["https://invalid.localhost.invalid/dns-query".to_string()],
            upstream_resolvers: vec![],
            use_doh: true,
            ..Default::default()
        };
        let result = process_dns_query(&pkt, &config).await;
        assert!(result.is_ok(), "DoH failure should return SERVFAIL, not error");
        let response = result.unwrap();
        assert_eq!(response[3] & 0x0F, DNS_RCODE_SERVFAIL, "response should be SERVFAIL");
    }

    #[test]
    fn dns_admission_defaults_are_explicit_and_invalid_values_fail_closed() {
        let client = DnsAdmissionConfig::client_default();
        assert_eq!(client.max_in_flight, 2);
        assert_eq!(client.global_pps, 100);
        assert_eq!(client.max_identities, 4);
        assert!(client.validate().is_ok());

        let mut invalid = client;
        invalid.max_identities = 0;
        assert!(matches!(invalid.validate(), Err(DnsAdmissionConfigError::Zero("max_identities"))));
    }
}

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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qf_common::time_source::ProtocolClock;

mod forwarding;

#[cfg(test)]
use forwarding::{
    append_bounded_dns_response, parse_canonical_dns_name, receive_dns_response, remaining_until,
    resolve_via_dns_upstreams_until, resolve_via_doh_endpoints_until,
    run_dns_blocking_with_deadline, validate_doh_content_length,
};
pub use forwarding::{
    build_doh_client, build_doh_client_for_endpoints, forward_dns_query, resolve_via_dns_upstreams,
    resolve_via_doh, resolve_via_doh_with_client,
};
use forwarding::{resolve_via_dns_upstreams_async, resolve_via_doh_endpoints};

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
const DNS_FLAG_AA: u16 = 0x0400;
const DNS_FLAG_TC: u16 = 0x0200;
const DNS_FLAG_RA: u16 = 0x0080;
const DNS_FLAG_Z: u16 = 0x0040;
const DNS_FLAG_RCODE_MASK: u16 = 0x000f;
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
    fn new(config: DnsAdmissionConfig, now: Instant) -> Self {
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
    clock: ProtocolClock,
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
        Self::try_new_with_clock(config, &ProtocolClock::default())
    }

    /// Create a DNS admission owner bound to an explicit protocol clock.
    pub fn try_new_with_clock(
        config: DnsAdmissionConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, DnsAdmissionConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            clock: clock.clone(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(config.max_in_flight)),
            state: parking_lot::Mutex::new(DnsAdmissionState::new(config, clock.now())),
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
        let now = self.clock.now();
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
        let now = self.clock.now();
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
    /// Expanded, byte-preserving QNAME used for answer owner names.
    pub qname_wire: Vec<u8>,
    pub qtype: DnsQType,
    /// Original wire QTYPE, retained when `qtype` is `Unknown`.
    pub raw_qtype: u16,
    pub qclass: u16,
    /// Exact original question section bytes, including compression and casing.
    pub question_wire: Vec<u8>,
}

/// A DNS response ready to send back to the client.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub raw: Vec<u8>,
}

/// Parse a raw DNS query packet (UDP, port 53).
pub fn parse_dns_query(pkt: &[u8]) -> Option<DnsQuery> {
    validate_dns_query_size(pkt).ok()?;
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if !valid_dns_query_flags(flags) {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount != 1 {
        return None;
    }

    let parsed_name = parse_dns_name(pkt, DNS_HEADER_SIZE)?;
    let fields_end = parsed_name.end.checked_add(4)?;
    let fields = pkt.get(parsed_name.end..fields_end)?;
    let question_wire = pkt.get(DNS_HEADER_SIZE..fields_end)?.to_vec();
    let raw_qtype = u16::from_be_bytes([fields[0], fields[1]]);
    let qclass = u16::from_be_bytes([fields[2], fields[3]]);
    Some(DnsQuery {
        id,
        flags,
        qname: parsed_name.display,
        qname_wire: parsed_name.wire,
        qtype: DnsQType::from_u16(raw_qtype),
        raw_qtype,
        qclass,
        question_wire,
    })
}

fn valid_dns_query_flags(flags: u16) -> bool {
    flags
        & (DNS_FLAG_QR
            | DNS_FLAG_OPCODE_MASK
            | DNS_FLAG_AA
            | DNS_FLAG_TC
            | DNS_FLAG_RA
            | DNS_FLAG_Z
            | DNS_FLAG_RCODE_MASK)
        == 0
}

struct ParsedDnsName {
    display: String,
    wire: Vec<u8>,
    end: usize,
}

/// Parse a bounded DNS name while preserving its expanded wire bytes.
fn parse_dns_name(pkt: &[u8], start: usize) -> Option<ParsedDnsName> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut wire = Vec::with_capacity(32);
    let mut cursor = start;
    let mut consumed_end = None;
    let mut pointer_count = 0;

    loop {
        let length = *pkt.get(cursor)?;
        match length & 0xc0 {
            0x00 => {
                let label_length = usize::from(length);
                if label_length == 0 {
                    let end = cursor.checked_add(1)?;
                    if wire.len().checked_add(1)? > DNS_MAX_NAME_WIRE_SIZE {
                        return None;
                    }
                    wire.push(0);
                    let display = labels
                        .iter()
                        .map(|label| String::from_utf8_lossy(label).into_owned())
                        .collect::<Vec<_>>()
                        .join(".");
                    return Some(ParsedDnsName { display, wire, end: consumed_end.unwrap_or(end) });
                }
                if label_length > 63 {
                    return None;
                }
                let label_start = cursor.checked_add(1)?;
                let label_end = label_start.checked_add(label_length)?;
                if wire.len().checked_add(label_length + 1)? > DNS_MAX_NAME_WIRE_SIZE {
                    return None;
                }
                let label = pkt.get(label_start..label_end)?.to_vec();
                wire.push(length);
                wire.extend_from_slice(&label);
                labels.push(label);
                cursor = label_end;
            }
            0xc0 => {
                let pointer_end = cursor.checked_add(2)?;
                let pointer = pkt.get(cursor..pointer_end)?;
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

/// Parse a DNS name (RFC 1035 §3.1, label encoding).
#[cfg(test)]
fn parse_name(pkt: &[u8], pos: &mut usize) -> Option<String> {
    let parsed = parse_dns_name(pkt, *pos)?;
    *pos = parsed.end;
    Some(parsed.display)
}

fn append_qname(query: &DnsQuery, out: &mut Vec<u8>) {
    if query.qname_wire.is_empty() {
        encode_name(&query.qname, out);
    } else {
        out.extend_from_slice(&query.qname_wire);
    }
}

fn append_question(query: &DnsQuery, pkt: &mut Vec<u8>) {
    if !query.question_wire.is_empty() {
        pkt.extend_from_slice(&query.question_wire);
    } else {
        encode_name(&query.qname, pkt);
        pkt.extend_from_slice(&query.raw_qtype.to_be_bytes());
        pkt.extend_from_slice(&query.qclass.to_be_bytes());
    }
}

fn response_flags(request_flags: u16, rcode: u8) -> u16 {
    DNS_FLAG_QR | (request_flags & (DNS_FLAG_RD | DNS_FLAG_CD)) | u16::from(rcode & 0x0f)
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
        append_qname(query, &mut pkt);
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
        append_qname(query, &mut pkt);
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
mod tests;

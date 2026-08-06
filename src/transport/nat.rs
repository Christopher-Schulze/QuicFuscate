//! NAT traversal: STUN (RFC 5389), TURN (RFC 5766), and ICE (RFC 8445).
//!
//! This module provides the building blocks for establishing peer-to-peer
//! QUIC connections across NATs:
//!
//! - [`StunClient`] performs STUN Binding Requests to discover the public
//!   server-reflexive (SRFLX) address mapped by the NAT.
//! - [`TurnClient`] performs minimal TURN Allocate / CreatePermission /
//!   SendIndication exchanges to relay traffic through a TURN server when
//!   direct connectivity is impossible.
//! - [`IceAgent`] gathers host + SRFLX candidates and selects the
//!   highest-priority working candidate pair.
//!
//! All wire encoding/decoding follows RFC 5389 for STUN and RFC 5766 for TURN.
//! The XOR-MAPPED-ADDRESS, XOR-RELAYED-ADDRESS, and XOR-PEER-ADDRESS
//! attributes are decoded by XORing the transported IP and port with the STUN
//! magic cookie (and transaction ID for IPv6).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::RngCore;

use super::config::{NatDiscoveryReason, NatTraversalConfig};

// ============================================================================
// Constants (RFC 5389 / RFC 5766 / RFC 8445)
// ============================================================================

/// STUN magic cookie (RFC 5389 Section 6).
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message types (RFC 5389 Section 6 / RFC 5766 Section 2).
const MSG_BINDING_REQUEST: u16 = 0x0001;
const MSG_BINDING_RESPONSE: u16 = 0x0101;
const MSG_BINDING_ERROR_RESPONSE: u16 = 0x0111;
const MSG_ALLOCATE_REQUEST: u16 = 0x0003;
const MSG_ALLOCATE_SUCCESS_RESPONSE: u16 = 0x0103;
const MSG_CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const MSG_CREATE_PERMISSION_SUCCESS_RESPONSE: u16 = 0x0108;
const MSG_SEND_INDICATION: u16 = 0x0019;

/// STUN attribute types.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0029;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_ERROR_CODE: u16 = 0x0009;
/// SOFTWARE attribute (RFC 5389 Section 15.10). Optional; used in tests.
#[allow(dead_code)]
const ATTR_SOFTWARE: u16 = 0x8022;

/// Address family codes inside MAPPED-ADDRESS style attributes.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// UDP protocol number used in TURN REQUESTED-TRANSPORT (RFC 5766 Section 3).
const IPPROTO_UDP: u8 = 17;

/// STUN header size in bytes.
const STUN_HEADER_LEN: usize = 20;

/// Transaction ID length in bytes (RFC 5389: 96 bits = 12 bytes).
const TRANSACTION_ID_LEN: usize = 12;

/// Default per-request timeout for STUN/TURN exchanges.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Error type
// ============================================================================

/// Errors produced by the NAT traversal subsystem.
#[derive(Debug, Clone, PartialEq)]
pub enum NatError {
    /// The peer returned a STUN/TURN error response with the given code and
    /// human-readable reason phrase.
    ServerError(u16, String),
    /// The response did not match the transaction ID of the request.
    TransactionIdMismatch,
    /// The response message type was unexpected.
    UnexpectedMessageType(u16),
    /// A required attribute was missing from the response.
    MissingAttribute(&'static str),
    /// A buffer was too short to hold/parse the message.
    BufferTooShort,
    /// An I/O error occurred on the UDP socket.
    Io(String),
    /// The address family in an attribute is unsupported.
    UnsupportedFamily(u8),
    /// No tokio runtime was available to drive the async exchange.
    NoRuntime,
    /// The remote endpoint did not respond within the timeout.
    Timeout,
}

impl std::fmt::Display for NatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatError::ServerError(code, reason) => {
                write!(f, "STUN/TURN server error {}: {}", code, reason)
            }
            NatError::TransactionIdMismatch => write!(f, "STUN transaction ID mismatch"),
            NatError::UnexpectedMessageType(t) => {
                write!(f, "unexpected STUN message type 0x{:04X}", t)
            }
            NatError::MissingAttribute(name) => write!(f, "missing STUN attribute: {}", name),
            NatError::BufferTooShort => write!(f, "STUN buffer too short"),
            NatError::Io(msg) => write!(f, "NAT I/O error: {}", msg),
            NatError::UnsupportedFamily(fam) => write!(f, "unsupported address family: {}", fam),
            NatError::NoRuntime => write!(f, "no tokio runtime available for NAT exchange"),
            NatError::Timeout => write!(f, "NAT exchange timed out"),
        }
    }
}

impl std::error::Error for NatError {}

impl From<std::io::Error> for NatError {
    fn from(e: std::io::Error) -> Self {
        NatError::Io(e.to_string())
    }
}

// ============================================================================
// Low-level STUN message codec
// ============================================================================

/// A parsed STUN/TURN message header + attribute slice.
#[derive(Debug, Clone)]
struct StunMessage {
    msg_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    /// Raw attribute bytes (the body after the 20-byte header).
    attrs: Vec<u8>,
}

impl StunMessage {
    /// Encode a request message into bytes.
    fn encode_request(
        msg_type: u16,
        transaction_id: &[u8; TRANSACTION_ID_LEN],
        attrs: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(STUN_HEADER_LEN + attrs.len());
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(transaction_id);
        buf.extend_from_slice(attrs);
        buf
    }

    /// Parse a received STUN/TURN message from raw bytes.
    fn parse(buf: &[u8]) -> Result<Self, NatError> {
        if buf.len() < STUN_HEADER_LEN {
            return Err(NatError::BufferTooShort);
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            // RFC 5389 requires the magic cookie for compliant messages.
            return Err(NatError::UnexpectedMessageType(msg_type));
        }
        let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&buf[8..8 + TRANSACTION_ID_LEN]);
        let body_end = STUN_HEADER_LEN + msg_len;
        if buf.len() < body_end {
            return Err(NatError::BufferTooShort);
        }
        Ok(Self { msg_type, transaction_id, attrs: buf[STUN_HEADER_LEN..body_end].to_vec() })
    }

    /// Iterate over attributes as (type, value) pairs, skipping padding.
    fn attributes(&self) -> impl Iterator<Item = (u16, &[u8])> {
        StunAttrIter { buf: &self.attrs, pos: 0 }
    }

    /// Find the first attribute of the given type.
    fn find_attr(&self, attr_type: u16) -> Option<&[u8]> {
        self.attributes().find(|(t, _)| *t == attr_type).map(|(_, v)| v)
    }
}

/// Iterator over STUN attribute TLVs (RFC 5389 Section 5).
struct StunAttrIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for StunAttrIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let attr_type = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        let attr_len =
            u16::from_be_bytes([self.buf[self.pos + 2], self.buf[self.pos + 3]]) as usize;
        let val_start = self.pos + 4;
        let val_end = val_start + attr_len;
        if val_end > self.buf.len() {
            return None;
        }
        let value = &self.buf[val_start..val_end];
        // Attributes are padded to 4-byte boundaries (padding not counted in len).
        let padded_len = (attr_len + 3) & !3;
        self.pos = val_start + padded_len;
        Some((attr_type, value))
    }
}

/// Encode a single STUN attribute (type + length + value + padding).
fn encode_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + value.len() + 3);
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    // Pad to 4-byte boundary.
    let pad = (4 - (value.len() & 3)) & 3;
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf
}

/// Encode a REQUESTED-TRANSPORT attribute (RFC 5766 Section 5.5).
/// Value: 1 byte protocol + 3 bytes RFFU (reserved, zero).
fn encode_requested_transport(protocol: u8) -> Vec<u8> {
    encode_attr(ATTR_REQUESTED_TRANSPORT, &[protocol, 0, 0, 0])
}

/// Generate a fresh random 12-byte transaction ID.
fn new_transaction_id() -> [u8; TRANSACTION_ID_LEN] {
    let mut tid = [0u8; TRANSACTION_ID_LEN];
    rand::rng().fill_bytes(&mut tid);
    tid
}

// ============================================================================
// XOR-ADDRESS attribute codec (shared by XOR-MAPPED / XOR-RELAYED / XOR-PEER)
// ============================================================================

/// Decode an XOR-encoded address attribute (RFC 5389 Section 15.2).
///
/// The port is XORed with the top 16 bits of the magic cookie. For IPv4 the
/// address is XORed with the full 32-bit magic cookie; for IPv6 it is XORed
/// with the magic cookie concatenated with the 96-bit transaction ID.
fn decode_xor_address(
    value: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, NatError> {
    if value.len() < 4 {
        return Err(NatError::BufferTooShort);
    }
    let family = value[1];
    let xor_port = u16::from_be_bytes([value[2], value[3]]);
    // Top 16 bits of the magic cookie.
    let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(NatError::BufferTooShort);
            }
            let xor_addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xor_addr ^ STUN_MAGIC_COOKIE;
            let ip = Ipv4Addr::from(addr);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(NatError::BufferTooShort);
            }
            // XOR key = magic cookie (4 bytes) || transaction ID (12 bytes).
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(transaction_id);
            let mut addr_bytes = [0u8; 16];
            for i in 0..16 {
                addr_bytes[i] = value[4 + i] ^ key[i];
            }
            let ip = Ipv6Addr::from(addr_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        other => Err(NatError::UnsupportedFamily(other)),
    }
}

/// Encode an XOR-encoded address attribute (used for test symmetry and TURN
/// request construction).
fn encode_xor_address(
    attr_type: u16,
    addr: SocketAddr,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Vec<u8> {
    let port = addr.port();
    let xor_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            let mut value = vec![0u8; 8];
            value[1] = FAMILY_IPV4;
            value[2..4].copy_from_slice(&xor_port.to_be_bytes());
            let xor_addr = u32::from(ipv4) ^ STUN_MAGIC_COOKIE;
            value[4..8].copy_from_slice(&xor_addr.to_be_bytes());
            encode_attr(attr_type, &value)
        }
        IpAddr::V6(ipv6) => {
            let mut value = vec![0u8; 20];
            value[1] = FAMILY_IPV6;
            value[2..4].copy_from_slice(&xor_port.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(transaction_id);
            let addr_bytes = ipv6.octets();
            for i in 0..16 {
                value[4 + i] = addr_bytes[i] ^ key[i];
            }
            encode_attr(attr_type, &value)
        }
    }
}

/// Decode an ERROR-CODE attribute (RFC 5389 Section 15.6).
///
/// Returns (error_class * 100 + error_number, reason phrase).
fn decode_error_code(value: &[u8]) -> Option<(u16, String)> {
    if value.len() < 4 {
        return None;
    }
    let class = value[2] as u16;
    let number = value[3] as u16;
    let code = class * 100 + number;
    let reason = if value.len() > 4 {
        String::from_utf8_lossy(&value[4..]).to_string()
    } else {
        String::new()
    };
    Some((code, reason))
}

// ============================================================================
// STUN client
// ============================================================================

/// Result of a successful STUN Binding Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunBindingResult {
    /// The server-reflexive (public) address observed by the STUN server.
    pub mapped_address: SocketAddr,
    /// The source address from which the STUN server sent its response.
    pub response_origin: SocketAddr,
}

/// STUN client: discovers the public server-reflexive address via Binding
/// Requests (RFC 5389).
#[derive(Debug, Clone)]
pub struct StunClient {
    /// Per-request timeout. Defaults to 5 seconds.
    timeout: Duration,
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StunClient {
    /// Create a new STUN client with the default 5-second request timeout.
    pub fn new() -> Self {
        Self { timeout: DEFAULT_REQUEST_TIMEOUT }
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform a STUN Binding Request against `stun_server` and return the
    /// discovered server-reflexive address plus the response origin.
    ///
    /// Sends a single Binding Request with a random transaction ID, awaits the
    /// Binding Response, validates the transaction ID, and decodes the
    /// XOR-MAPPED-ADDRESS attribute (RFC 5389 Section 15.2).
    pub async fn binding_request(
        &self,
        stun_server: SocketAddr,
    ) -> Result<StunBindingResult, NatError> {
        let tid = new_transaction_id();
        // A binding request carries no mandatory attributes; an optional
        // SOFTWARE attribute (RFC 5389 Section 15.10) is omitted to keep the
        // request minimal and avoid leaking implementation details.
        let request = StunMessage::encode_request(MSG_BINDING_REQUEST, &tid, &[]);

        let socket = tokio::net::UdpSocket::bind(match stun_server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;

        socket.send_to(&request, stun_server).await?;

        let mut buf = vec![0u8; 2048];
        let (len, response_origin) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| NatError::Timeout)?
            .map_err(NatError::from)?;

        let msg = StunMessage::parse(&buf[..len])?;

        if msg.transaction_id != tid {
            return Err(NatError::TransactionIdMismatch);
        }

        match msg.msg_type {
            MSG_BINDING_RESPONSE => {}
            MSG_BINDING_ERROR_RESPONSE => {
                if let Some(err_val) = msg.find_attr(ATTR_ERROR_CODE) {
                    if let Some((code, reason)) = decode_error_code(err_val) {
                        return Err(NatError::ServerError(code, reason));
                    }
                }
                return Err(NatError::ServerError(0, "unknown binding error".to_string()));
            }
            other => return Err(NatError::UnexpectedMessageType(other)),
        }

        let xor_val = msg
            .find_attr(ATTR_XOR_MAPPED_ADDRESS)
            .ok_or(NatError::MissingAttribute("XOR-MAPPED-ADDRESS"))?;

        let mapped_address = decode_xor_address(xor_val, &msg.transaction_id)?;

        Ok(StunBindingResult { mapped_address, response_origin })
    }
}

// ============================================================================
// ICE candidate model (RFC 8445)
// ============================================================================

/// ICE candidate type (RFC 8445 Section 5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// A candidate obtained by binding to a local interface.
    Host,
    /// A server-reflexive candidate discovered via STUN.
    ServerReflexive,
    /// A peer-reflexive candidate discovered during connectivity checks.
    PeerReflexive,
    /// A relayed candidate obtained from a TURN server.
    Relay,
}

impl CandidateType {
    /// Type preference used in the ICE priority formula (RFC 8445 Section 5.1.2).
    /// Host is preferred, then peer-reflexive, then server-reflexive, then relay.
    fn type_preference(self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }
}

/// A single ICE candidate (RFC 8445 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IceCandidate {
    /// Candidate type (host / srflx / prflx / relay).
    pub candidate_type: CandidateType,
    /// The transport address of the candidate.
    pub address: SocketAddr,
    /// The base address: the local address from which packets are sent for
    /// this candidate. For host candidates this equals `address`.
    pub base: SocketAddr,
    /// ICE priority (RFC 8445 Section 5.1.2).
    pub priority: u32,
    /// Component ID (1 for RTP/data, 2 for RTCP). QUIC uses component 1.
    pub component_id: u16,
}

impl IceCandidate {
    /// Compute the ICE priority per RFC 8445 Section 5.1.2:
    ///
    /// ```text
    /// priority = 2^24 * type_preference
    ///          + 2^8  * local_preference
    ///          + (256 - component_id)
    /// ```
    pub fn compute_priority(
        candidate_type: CandidateType,
        local_preference: u32,
        component_id: u16,
    ) -> u32 {
        let type_pref = candidate_type.type_preference();
        let comp = (256u32).saturating_sub(component_id as u32);
        (type_pref << 24) | ((local_preference & 0xFFFF) << 8) | comp
    }

    /// Create a host candidate for the given local address.
    pub fn host(address: SocketAddr, local_preference: u32, component_id: u16) -> Self {
        Self {
            candidate_type: CandidateType::Host,
            address,
            base: address,
            priority: Self::compute_priority(CandidateType::Host, local_preference, component_id),
            component_id,
        }
    }

    /// Create a server-reflexive candidate.
    pub fn server_reflexive(
        mapped: SocketAddr,
        base: SocketAddr,
        local_preference: u32,
        component_id: u16,
    ) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            address: mapped,
            base,
            priority: Self::compute_priority(
                CandidateType::ServerReflexive,
                local_preference,
                component_id,
            ),
            component_id,
        }
    }
}

// ============================================================================
// ICE agent
// ============================================================================

/// ICE agent: gathers candidates and selects the best candidate pair
/// (RFC 8445).
#[derive(Debug, Clone)]
pub struct IceAgent {
    stun: StunClient,
    /// Local preference used when computing candidate priorities.
    local_preference: u32,
}

impl Default for IceAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl IceAgent {
    /// Create a new ICE agent with default STUN client and local preference 65535.
    pub fn new() -> Self {
        Self { stun: StunClient::new(), local_preference: 65535 }
    }

    /// Override the local preference used for priority computation.
    pub fn with_local_preference(mut self, pref: u32) -> Self {
        self.local_preference = pref & 0xFFFF;
        self
    }

    /// Gather host and server-reflexive candidates.
    ///
    /// For each local address a host candidate is created. For each STUN
    /// server a Binding Request is issued; the resulting SRFLX candidate's
    /// base is the first local address whose family matches the STUN server.
    ///
    /// Because STUN exchanges require async I/O, this method blocks on an
    /// async runtime when one is available. When called from outside a Tokio
    /// runtime a temporary single-threaded runtime is created. When called
    /// from within a multi-threaded Tokio runtime `block_in_place` is used.
    pub fn gather_candidates(
        &mut self,
        local_addrs: &[SocketAddr],
        stun_servers: &[SocketAddr],
    ) -> Vec<IceCandidate> {
        let mut candidates = Vec::new();

        // Host candidates: one per local address.
        for &addr in local_addrs {
            candidates.push(IceCandidate::host(addr, self.local_preference, 1));
        }

        // Server-reflexive candidates: one per STUN server (best-effort).
        if !stun_servers.is_empty() {
            match block_on_async(self.gather_srflx(local_addrs, stun_servers)) {
                Ok(Ok(cands)) => candidates.extend(cands),
                Ok(Err(e)) => log::warn!("[nat] SRFLX candidate gathering failed: {}", e),
                Err(e) => log::warn!("[nat] SRFLX candidate gathering blocked failed: {}", e),
            }
        }

        // Sort by descending priority so callers see the best candidate first.
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        candidates
    }

    /// Async variant of [`Self::gather_candidates`] for runtime call sites that
    /// already execute inside Tokio. This avoids `block_in_place` and is the
    /// preferred path for live client/server operation.
    pub async fn gather_candidates_async(
        &self,
        local_addrs: &[SocketAddr],
        stun_servers: &[SocketAddr],
    ) -> Vec<IceCandidate> {
        let mut candidates = Vec::new();

        for &addr in local_addrs {
            candidates.push(IceCandidate::host(addr, self.local_preference, 1));
        }

        if !stun_servers.is_empty() {
            match self.gather_srflx(local_addrs, stun_servers).await {
                Ok(cands) => candidates.extend(cands),
                Err(e) => log::warn!("[nat] async SRFLX candidate gathering failed: {}", e),
            }
        }

        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        candidates
    }

    /// Async helper that issues STUN Binding Requests for each server.
    async fn gather_srflx(
        &self,
        local_addrs: &[SocketAddr],
        stun_servers: &[SocketAddr],
    ) -> Result<Vec<IceCandidate>, NatError> {
        let mut out = Vec::new();
        for &server in stun_servers {
            match self.stun.binding_request(server).await {
                Ok(result) => {
                    // Pick a base address matching the STUN server's family.
                    let base = local_addrs
                        .iter()
                        .copied()
                        .find(|a| a.is_ipv4() == server.is_ipv4())
                        .unwrap_or(result.mapped_address);
                    out.push(IceCandidate::server_reflexive(
                        result.mapped_address,
                        base,
                        self.local_preference,
                        1,
                    ));
                }
                Err(e) => {
                    log::debug!("[nat] STUN binding to {} failed: {}", server, e);
                }
            }
        }
        Ok(out)
    }

    /// Select the highest-priority candidate pair from the local and remote
    /// candidate lists (RFC 8445 Section 5.1.2 / 6.1.2).
    ///
    /// Candidate pairs are ordered by the priority formula
    /// `min(local, remote)` shifted left by 32 plus the remote priority, and
    /// the pair with the greatest value is returned. Only candidates with
    /// matching component IDs are considered.
    pub fn select_best_pair(
        &self,
        local: &[IceCandidate],
        remote: &[IceCandidate],
    ) -> Option<(IceCandidate, IceCandidate)> {
        let mut best: Option<(u64, IceCandidate, IceCandidate)> = None;
        for &l in local {
            for &r in remote {
                if l.component_id != r.component_id {
                    continue;
                }
                // RFC 8445 Section 6.1.2: pair priority.
                let g = l.priority as u64;
                let d = r.priority as u64;
                let pair_priority = if g <= d { (g << 32) + 2 * d + 1 } else { (d << 32) + 2 * g };
                match best {
                    Some((bp, _, _)) if pair_priority <= bp => {}
                    _ => best = Some((pair_priority, l, r)),
                }
            }
        }
        best.map(|(_, l, r)| (l, r))
    }
}

/// Optional NAT path-discovery controller.
///
/// This controller turns the low-level STUN/ICE building blocks into a bounded
/// runtime policy: discovery only happens when the configured
/// [`NatTraversalConfig`] allows the requested [`NatDiscoveryReason`] and the
/// probe cooldown has elapsed. It deliberately does not run by default.
#[derive(Debug, Clone)]
pub struct NatPathDiscovery {
    config: NatTraversalConfig,
    ice: IceAgent,
    clock: crate::time_source::ProtocolClock,
    last_probe: Option<std::time::Instant>,
}

impl NatPathDiscovery {
    /// Create a controller from a normalized NAT traversal config.
    pub fn new(config: NatTraversalConfig) -> Self {
        Self::new_with_clock(config, crate::time_source::ProtocolClock::default())
    }

    /// Create a controller with an explicit protocol clock.
    pub fn new_with_clock(
        config: NatTraversalConfig,
        clock: crate::time_source::ProtocolClock,
    ) -> Self {
        Self { config: config.normalized(), ice: IceAgent::new(), clock, last_probe: None }
    }

    /// Borrow the normalized NAT traversal config.
    pub fn config(&self) -> &NatTraversalConfig {
        &self.config
    }

    /// Returns true if discovery may start now for `reason`.
    pub fn should_probe(&self, reason: NatDiscoveryReason, now: std::time::Instant) -> bool {
        if !self.config.allows_discovery(reason) {
            return false;
        }
        let interval = Duration::from_millis(self.config.probe_interval_ms);
        match self.last_probe {
            Some(last) => now.saturating_duration_since(last) >= interval,
            None => true,
        }
    }

    /// Gather local host and server-reflexive candidates when policy permits.
    ///
    /// Returns an empty list when disabled, when the reason is not permitted,
    /// or when the cooldown has not elapsed. Candidate count is capped by
    /// `config.max_candidates`.
    pub async fn gather_candidates(
        &mut self,
        local_addrs: &[SocketAddr],
        reason: NatDiscoveryReason,
    ) -> Vec<IceCandidate> {
        let now = self.clock.now();
        if !self.should_probe(reason, now) {
            return Vec::new();
        }
        self.last_probe = Some(now);

        let mut candidates = if self.config.ice_enabled {
            self.ice.gather_candidates_async(local_addrs, &self.config.stun_servers).await
        } else {
            local_addrs.iter().copied().map(|addr| IceCandidate::host(addr, 65_535, 1)).collect()
        };
        candidates.truncate(self.config.max_candidates);
        candidates
    }
}

/// Block on an async future, supporting both runtime-present and runtime-absent
/// call sites.
///
/// - If called from within a Tokio runtime, uses `block_in_place` +
///   `Handle::block_on`. This requires a multi-threaded runtime; on a
///   current-thread runtime it will panic (documented limitation).
/// - If no runtime is active, builds a temporary current-thread runtime.
fn block_on_async<F: Future>(fut: F) -> Result<F::Output, NatError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // SAFETY: block_in_place is only valid on a multi-thread runtime.
            Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
        }
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| NatError::NoRuntime)?;
            Ok(rt.block_on(fut))
        }
    }
}

// ============================================================================
// TURN client (RFC 5766)
// ============================================================================

/// Minimal TURN client: allocates a relayed address, installs permissions, and
/// sends data via Send Indications (RFC 5766).
#[derive(Debug, Clone)]
pub struct TurnClient {
    timeout: Duration,
}

impl Default for TurnClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TurnClient {
    /// Create a new TURN client with the default 5-second request timeout.
    pub fn new() -> Self {
        Self { timeout: DEFAULT_REQUEST_TIMEOUT }
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a TURN Allocate Request and return the relayed address
    /// (XOR-RELAYED-ADDRESS) granted by the server (RFC 5766 Section 3).
    pub async fn allocate(&self, turn_server: SocketAddr) -> Result<SocketAddr, NatError> {
        let tid = new_transaction_id();
        let attrs = encode_requested_transport(IPPROTO_UDP);
        let request = StunMessage::encode_request(MSG_ALLOCATE_REQUEST, &tid, &attrs);

        let socket = tokio::net::UdpSocket::bind(match turn_server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;

        socket.send_to(&request, turn_server).await?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| NatError::Timeout)?
            .map_err(NatError::from)?;

        let msg = StunMessage::parse(&buf[..len])?;
        if msg.transaction_id != tid {
            return Err(NatError::TransactionIdMismatch);
        }

        match msg.msg_type {
            MSG_ALLOCATE_SUCCESS_RESPONSE => {}
            other => {
                if let Some(err_val) = msg.find_attr(ATTR_ERROR_CODE) {
                    if let Some((code, reason)) = decode_error_code(err_val) {
                        return Err(NatError::ServerError(code, reason));
                    }
                }
                return Err(NatError::UnexpectedMessageType(other));
            }
        }

        let xor_val = msg
            .find_attr(ATTR_XOR_RELAYED_ADDRESS)
            .ok_or(NatError::MissingAttribute("XOR-RELAYED-ADDRESS"))?;

        decode_xor_address(xor_val, &msg.transaction_id)
    }

    /// Install a permission for `peer` on the TURN server (RFC 5766 Section 4).
    ///
    /// Sends a CreatePermission Request containing an XOR-PEER-ADDRESS
    /// attribute and awaits the success response.
    pub async fn create_permission(
        &self,
        turn_server: SocketAddr,
        peer: SocketAddr,
    ) -> Result<(), NatError> {
        let tid = new_transaction_id();
        let peer_attr = encode_xor_address(ATTR_XOR_PEER_ADDRESS, peer, &tid);
        let request = StunMessage::encode_request(MSG_CREATE_PERMISSION_REQUEST, &tid, &peer_attr);

        let socket = tokio::net::UdpSocket::bind(match turn_server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;

        socket.send_to(&request, turn_server).await?;

        let mut buf = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| NatError::Timeout)?
            .map_err(NatError::from)?;

        let msg = StunMessage::parse(&buf[..len])?;
        if msg.transaction_id != tid {
            return Err(NatError::TransactionIdMismatch);
        }

        match msg.msg_type {
            MSG_CREATE_PERMISSION_SUCCESS_RESPONSE => Ok(()),
            other => {
                if let Some(err_val) = msg.find_attr(ATTR_ERROR_CODE) {
                    if let Some((code, reason)) = decode_error_code(err_val) {
                        return Err(NatError::ServerError(code, reason));
                    }
                }
                Err(NatError::UnexpectedMessageType(other))
            }
        }
    }

    /// Send application data to `peer` via a TURN Send Indication
    /// (RFC 5766 Section 5). Send Indications are not acknowledged by the
    /// server, so this returns `Ok(())` once the indication is transmitted.
    pub async fn send_indication(
        &self,
        turn_server: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
    ) -> Result<(), NatError> {
        let tid = new_transaction_id();
        let peer_attr = encode_xor_address(ATTR_XOR_PEER_ADDRESS, peer, &tid);
        let data_attr = encode_attr(ATTR_DATA, data);
        let mut attrs = peer_attr;
        attrs.extend_from_slice(&data_attr);
        let request = StunMessage::encode_request(MSG_SEND_INDICATION, &tid, &attrs);

        let socket = tokio::net::UdpSocket::bind(match turn_server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;

        socket.send_to(&request, turn_server).await?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::config::NatTraversalMode;
    use super::*;

    // --- STUN message header encode/decode ---

    #[test]
    fn stun_binding_request_header_is_well_formed() {
        let tid = [0xAA; TRANSACTION_ID_LEN];
        let pkt = StunMessage::encode_request(MSG_BINDING_REQUEST, &tid, &[]);
        assert_eq!(pkt.len(), STUN_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), MSG_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0); // no attributes
        assert_eq!(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), STUN_MAGIC_COOKIE);
        assert_eq!(&pkt[8..20], &tid);
    }

    #[test]
    fn stun_message_round_trips_through_parse() {
        let tid = new_transaction_id();
        let attrs = encode_attr(ATTR_SOFTWARE, b"QuicFuscate/0.4");
        let pkt = StunMessage::encode_request(MSG_BINDING_REQUEST, &tid, &attrs);
        let msg = StunMessage::parse(&pkt).expect("parse");
        assert_eq!(msg.msg_type, MSG_BINDING_REQUEST);
        assert_eq!(msg.transaction_id, tid);
        let sw = msg.find_attr(ATTR_SOFTWARE).expect("SOFTWARE attr");
        assert_eq!(sw, b"QuicFuscate/0.4");
    }

    #[test]
    fn stun_parse_rejects_short_buffer() {
        let buf = [0u8; 10];
        assert_eq!(StunMessage::parse(&buf).unwrap_err(), NatError::BufferTooShort);
    }

    #[test]
    fn stun_parse_rejects_bad_magic_cookie() {
        let mut pkt =
            StunMessage::encode_request(MSG_BINDING_REQUEST, &[0; TRANSACTION_ID_LEN], &[]);
        // Corrupt the magic cookie.
        pkt[4] = 0x00;
        pkt[5] = 0x00;
        pkt[6] = 0x00;
        pkt[7] = 0x00;
        assert!(matches!(
            StunMessage::parse(&pkt).unwrap_err(),
            NatError::UnexpectedMessageType(_)
        ));
    }

    #[test]
    fn stun_attribute_iterator_skips_padding() {
        // Two attributes: 3-byte value (padded to 4) and 1-byte value (padded to 4).
        let attrs =
            [encode_attr(0x0001, &[0x01, 0x02, 0x03]), encode_attr(0x0002, &[0xFF])].concat();
        let tid = [0; TRANSACTION_ID_LEN];
        let pkt = StunMessage::encode_request(MSG_BINDING_REQUEST, &tid, &attrs);
        let msg = StunMessage::parse(&pkt).unwrap();
        let collected: Vec<(u16, Vec<u8>)> =
            msg.attributes().map(|(t, v)| (t, v.to_vec())).collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].0, 0x0001);
        assert_eq!(collected[0].1, vec![0x01, 0x02, 0x03]);
        assert_eq!(collected[1].0, 0x0002);
        assert_eq!(collected[1].1, vec![0xFF]);
    }

    // --- XOR-MAPPED-ADDRESS encode/decode ---

    #[test]
    fn xor_mapped_address_ipv4_round_trip() {
        let tid = new_transaction_id();
        let addr: SocketAddr = "203.0.113.42:12345".parse().unwrap();
        let encoded = encode_xor_address(ATTR_XOR_MAPPED_ADDRESS, addr, &tid);
        // The attribute is wrapped in a TLV; strip the 4-byte header for decoding.
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), ATTR_XOR_MAPPED_ADDRESS);
        let val_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        let value = &encoded[4..4 + val_len];
        let decoded = decode_xor_address(value, &tid).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_mapped_address_ipv6_round_trip() {
        let tid = new_transaction_id();
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let encoded = encode_xor_address(ATTR_XOR_MAPPED_ADDRESS, addr, &tid);
        let val_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        let value = &encoded[4..4 + val_len];
        let decoded = decode_xor_address(value, &tid).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_mapped_address_decodes_known_vector() {
        // Construct a response by hand: mapped 192.0.2.1:32853.
        // port_xor = 32853 ^ (0x2112A442 >> 16) = 32853 ^ 0x2112
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let tid = [0u8; TRANSACTION_ID_LEN];
        let encoded = encode_xor_address(ATTR_XOR_MAPPED_ADDRESS, addr, &tid);
        let val_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        let value = &encoded[4..4 + val_len];
        let decoded = decode_xor_address(value, &tid).unwrap();
        assert_eq!(decoded, addr);
        // Verify the family byte.
        assert_eq!(value[1], FAMILY_IPV4);
    }

    #[test]
    fn xor_mapped_address_rejects_unknown_family() {
        let mut value = vec![0u8; 8];
        value[1] = 0x09; // bogus family
        let tid = [0u8; TRANSACTION_ID_LEN];
        assert_eq!(
            decode_xor_address(&value, &tid).unwrap_err(),
            NatError::UnsupportedFamily(0x09)
        );
    }

    #[test]
    fn xor_mapped_address_rejects_short_value() {
        let tid = [0u8; TRANSACTION_ID_LEN];
        assert_eq!(decode_xor_address(&[0u8; 2], &tid).unwrap_err(), NatError::BufferTooShort);
        // IPv4 needs 8 bytes.
        let mut v = vec![0u8; 5];
        v[1] = FAMILY_IPV4;
        assert_eq!(decode_xor_address(&v, &tid).unwrap_err(), NatError::BufferTooShort);
        // IPv6 needs 20 bytes.
        let mut v6 = vec![0u8; 10];
        v6[1] = FAMILY_IPV6;
        assert_eq!(decode_xor_address(&v6, &tid).unwrap_err(), NatError::BufferTooShort);
    }

    // --- ERROR-CODE decode ---

    #[test]
    fn error_code_decodes_class_and_number() {
        // class=4, number=87 -> 487, reason "Allocation Quota Reached"
        let value = [0x00, 0x00, 0x04, 0x57, b'A', b'Q', b'R'];
        let (code, reason) = decode_error_code(&value).unwrap();
        assert_eq!(code, 487);
        assert_eq!(reason, "AQR");
    }

    #[test]
    fn error_code_rejects_short_value() {
        assert!(decode_error_code(&[0x00, 0x01]).is_none());
    }

    // --- ICE candidate priority ---

    #[test]
    fn host_priority_beats_srflx_priority() {
        let host = IceCandidate::compute_priority(CandidateType::Host, 65535, 1);
        let srflx = IceCandidate::compute_priority(CandidateType::ServerReflexive, 65535, 1);
        assert!(host > srflx);
    }

    #[test]
    fn candidate_priority_matches_rfc_formula() {
        // priority = 2^24 * type_pref + 2^8 * local_pref + (256 - component_id)
        let host = IceCandidate::compute_priority(CandidateType::Host, 65535, 1);
        let expected = (126u32 << 24) | (65535 << 8) | (256 - 1);
        assert_eq!(host, expected);
    }

    #[test]
    fn component_id_affects_priority() {
        let c1 = IceCandidate::compute_priority(CandidateType::Host, 100, 1);
        let c2 = IceCandidate::compute_priority(CandidateType::Host, 100, 2);
        assert!(c1 > c2);
    }

    #[test]
    fn relay_priority_is_lowest() {
        let relay = IceCandidate::compute_priority(CandidateType::Relay, 65535, 1);
        let srflx = IceCandidate::compute_priority(CandidateType::ServerReflexive, 1, 1);
        assert!(relay < srflx);
    }

    #[test]
    fn type_preference_values_match_rfc() {
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::PeerReflexive.type_preference(), 110);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::Relay.type_preference(), 0);
    }

    // --- ICE candidate pair selection ---

    #[test]
    fn select_best_pair_picks_highest_priority() {
        let local = vec![
            IceCandidate::host("10.0.0.1:5000".parse().unwrap(), 65535, 1),
            IceCandidate::server_reflexive(
                "203.0.113.5:5000".parse().unwrap(),
                "10.0.0.1:5000".parse().unwrap(),
                65535,
                1,
            ),
        ];
        let remote = vec![
            IceCandidate::host("10.0.0.2:5000".parse().unwrap(), 65535, 1),
            IceCandidate::server_reflexive(
                "198.51.100.7:5000".parse().unwrap(),
                "10.0.0.2:5000".parse().unwrap(),
                65535,
                1,
            ),
        ];
        let agent = IceAgent::new();
        let (l, r) = agent.select_best_pair(&local, &remote).expect("a pair");
        // Host/host should win (both highest type preference).
        assert_eq!(l.candidate_type, CandidateType::Host);
        assert_eq!(r.candidate_type, CandidateType::Host);
    }

    #[test]
    fn select_best_pair_respects_component_id() {
        let local = vec![IceCandidate::host("10.0.0.1:5000".parse().unwrap(), 65535, 1)];
        let remote = vec![IceCandidate::host("10.0.0.2:5000".parse().unwrap(), 65535, 2)];
        let agent = IceAgent::new();
        assert!(agent.select_best_pair(&local, &remote).is_none());
    }

    #[test]
    fn select_best_pair_returns_none_when_empty() {
        let agent = IceAgent::new();
        assert!(agent.select_best_pair(&[], &[]).is_none());
    }

    #[test]
    fn select_best_pair_pair_priority_formula() {
        // Verify the RFC 8445 pair priority ordering: a host/host pair must
        // outrank a host/srflx pair.
        let host_local = IceCandidate::host("10.0.0.1:5000".parse().unwrap(), 65535, 1);
        let host_remote = IceCandidate::host("10.0.0.2:5000".parse().unwrap(), 65535, 1);
        let srflx_remote = IceCandidate::server_reflexive(
            "198.51.100.7:5000".parse().unwrap(),
            "10.0.0.2:5000".parse().unwrap(),
            65535,
            1,
        );
        let local = vec![host_local];
        let remote = vec![host_remote, srflx_remote];
        let agent = IceAgent::new();
        let (l, r) = agent.select_best_pair(&local, &remote).unwrap();
        assert_eq!(l, host_local);
        assert_eq!(r, host_remote);
    }

    // --- gather_candidates (host only, no STUN servers) ---

    #[test]
    fn gather_candidates_host_only_without_stun_servers() {
        let mut agent = IceAgent::new();
        let local = vec!["10.0.0.1:5000".parse().unwrap(), "10.0.0.2:5001".parse().unwrap()];
        let cands = agent.gather_candidates(&local, &[]);
        assert_eq!(cands.len(), 2);
        assert!(cands.iter().all(|c| c.candidate_type == CandidateType::Host));
        // Sorted by descending priority.
        assert!(cands[0].priority >= cands[1].priority);
    }

    #[tokio::test]
    async fn nat_path_discovery_disabled_returns_no_candidates() {
        let mut discovery = NatPathDiscovery::new(NatTraversalConfig::default());
        let local = vec!["10.0.0.1:5000".parse().unwrap()];
        let cands =
            discovery.gather_candidates(&local, NatDiscoveryReason::ConnectivityFailure).await;
        assert!(cands.is_empty());
    }

    #[tokio::test]
    async fn nat_path_discovery_respects_reason_policy() {
        let config = NatTraversalConfig {
            enabled: true,
            mode: NatTraversalMode::ConnectivityFallback,
            ice_enabled: false,
            ..NatTraversalConfig::default()
        };
        let mut discovery = NatPathDiscovery::new(config);
        let local = vec!["10.0.0.1:5000".parse().unwrap()];

        let roaming = discovery.gather_candidates(&local, NatDiscoveryReason::Roaming).await;
        assert!(roaming.is_empty());

        let fallback =
            discovery.gather_candidates(&local, NatDiscoveryReason::ConnectivityFailure).await;
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].candidate_type, CandidateType::Host);
    }

    #[tokio::test]
    async fn nat_path_discovery_cooldown_and_cap_candidates() {
        let config = NatTraversalConfig {
            enabled: true,
            mode: NatTraversalMode::Always,
            ice_enabled: false,
            probe_interval_ms: 60_000,
            max_candidates: 1,
            ..NatTraversalConfig::default()
        };
        let mut discovery = NatPathDiscovery::new(config);
        let local = vec!["10.0.0.1:5000".parse().unwrap(), "10.0.0.2:5001".parse().unwrap()];

        let first = discovery.gather_candidates(&local, NatDiscoveryReason::Manual).await;
        assert_eq!(first.len(), 1);

        let second = discovery.gather_candidates(&local, NatDiscoveryReason::Manual).await;
        assert!(second.is_empty(), "cooldown must suppress immediate repeat probes");
    }

    // --- TURN message format ---

    #[test]
    fn turn_allocate_request_includes_requested_transport_udp() {
        let tid = new_transaction_id();
        let attrs = encode_requested_transport(IPPROTO_UDP);
        let pkt = StunMessage::encode_request(MSG_ALLOCATE_REQUEST, &tid, &attrs);
        let msg = StunMessage::parse(&pkt).unwrap();
        assert_eq!(msg.msg_type, MSG_ALLOCATE_REQUEST);
        let rt = msg.find_attr(ATTR_REQUESTED_TRANSPORT).expect("REQUESTED-TRANSPORT");
        assert_eq!(rt.len(), 4);
        assert_eq!(rt[0], IPPROTO_UDP);
        assert_eq!(&rt[1..4], &[0, 0, 0]);
    }

    #[test]
    fn turn_send_indication_encodes_peer_and_data() {
        let tid = new_transaction_id();
        let peer: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let payload = b"hello turn";
        let peer_attr = encode_xor_address(ATTR_XOR_PEER_ADDRESS, peer, &tid);
        let data_attr = encode_attr(ATTR_DATA, payload);
        let mut attrs = peer_attr.clone();
        attrs.extend_from_slice(&data_attr);
        let pkt = StunMessage::encode_request(MSG_SEND_INDICATION, &tid, &attrs);
        let msg = StunMessage::parse(&pkt).unwrap();
        assert_eq!(msg.msg_type, MSG_SEND_INDICATION);

        let peer_val = msg.find_attr(ATTR_XOR_PEER_ADDRESS).expect("XOR-PEER-ADDRESS");
        let decoded_peer = decode_xor_address(peer_val, &tid).unwrap();
        assert_eq!(decoded_peer, peer);

        let data_val = msg.find_attr(ATTR_DATA).expect("DATA");
        assert_eq!(data_val, payload);
    }

    #[test]
    fn turn_create_permission_request_encodes_xor_peer_address() {
        let tid = new_transaction_id();
        let peer: SocketAddr = "198.51.100.20:7000".parse().unwrap();
        let peer_attr = encode_xor_address(ATTR_XOR_PEER_ADDRESS, peer, &tid);
        let pkt = StunMessage::encode_request(MSG_CREATE_PERMISSION_REQUEST, &tid, &peer_attr);
        let msg = StunMessage::parse(&pkt).unwrap();
        assert_eq!(msg.msg_type, MSG_CREATE_PERMISSION_REQUEST);
        let val = msg.find_attr(ATTR_XOR_PEER_ADDRESS).expect("XOR-PEER-ADDRESS");
        let decoded = decode_xor_address(val, &tid).unwrap();
        assert_eq!(decoded, peer);
    }

    // --- End-to-end STUN binding against a local echo server ---

    /// A minimal in-process STUN server that echoes a Binding Response with a
    /// fixed XOR-MAPPED-ADDRESS, used to exercise the full async path.
    async fn run_local_stun_server(
        mapped: SocketAddr,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            if let Ok((len, from)) = sock.recv_from(&mut buf).await {
                let msg = StunMessage::parse(&buf[..len]).unwrap();
                assert_eq!(msg.msg_type, MSG_BINDING_REQUEST);
                let xor_attr =
                    encode_xor_address(ATTR_XOR_MAPPED_ADDRESS, mapped, &msg.transaction_id);
                let response = StunMessage::encode_request(
                    MSG_BINDING_RESPONSE,
                    &msg.transaction_id,
                    &xor_attr,
                );
                let _ = sock.send_to(&response, from).await;
            }
        });
        (server_addr, handle)
    }

    #[tokio::test]
    async fn stun_binding_request_round_trip_ipv4() {
        let mapped: SocketAddr = "203.0.113.77:9999".parse().unwrap();
        let (server, handle) = run_local_stun_server(mapped).await;

        let client = StunClient::new().with_timeout(Duration::from_secs(2));
        let result = client.binding_request(server).await.expect("binding ok");

        assert_eq!(result.mapped_address, mapped);
        assert_eq!(result.response_origin, server);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn stun_binding_request_times_out() {
        // Bind a socket but never respond.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = silent.local_addr().unwrap();
        let client = StunClient::new().with_timeout(Duration::from_millis(100));
        let err = client.binding_request(server_addr).await.unwrap_err();
        assert_eq!(err, NatError::Timeout);
    }

    #[tokio::test]
    async fn stun_binding_request_rejects_error_response() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = sock.local_addr().unwrap();
        let mapped: SocketAddr = "203.0.113.78:8888".parse().unwrap();
        let (_mapped_server, _handle) = run_local_stun_server(mapped).await;

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            if let Ok((len, from)) = sock.recv_from(&mut buf).await {
                let msg = StunMessage::parse(&buf[..len]).unwrap();
                // Reply with a Binding Error Response carrying ERROR-CODE 300.
                let mut err_val = vec![0u8; 4];
                err_val[2] = 3; // class
                err_val[3] = 0; // number
                err_val.extend_from_slice(b"Try Alternate");
                let err_attr = encode_attr(ATTR_ERROR_CODE, &err_val);
                let response = StunMessage::encode_request(
                    MSG_BINDING_ERROR_RESPONSE,
                    &msg.transaction_id,
                    &err_attr,
                );
                let _ = sock.send_to(&response, from).await;
            }
        });

        let client = StunClient::new().with_timeout(Duration::from_secs(2));
        let err = client.binding_request(server_addr).await.unwrap_err();
        match err {
            NatError::ServerError(300, reason) => assert_eq!(reason, "Try Alternate"),
            other => panic!("expected ServerError(300), got {:?}", other),
        }
        handle.await.unwrap();
    }

    // --- End-to-end TURN allocate against a local echo server ---

    async fn run_local_turn_allocate_server(
        relayed: SocketAddr,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((len, from)) = sock.recv_from(&mut buf).await {
                let msg = StunMessage::parse(&buf[..len]).unwrap();
                assert_eq!(msg.msg_type, MSG_ALLOCATE_REQUEST);
                let rt = msg.find_attr(ATTR_REQUESTED_TRANSPORT).unwrap();
                assert_eq!(rt[0], IPPROTO_UDP);
                let relay_attr =
                    encode_xor_address(ATTR_XOR_RELAYED_ADDRESS, relayed, &msg.transaction_id);
                let response = StunMessage::encode_request(
                    MSG_ALLOCATE_SUCCESS_RESPONSE,
                    &msg.transaction_id,
                    &relay_attr,
                );
                let _ = sock.send_to(&response, from).await;
            }
        });
        (server_addr, handle)
    }

    #[tokio::test]
    async fn turn_allocate_round_trip() {
        let relayed: SocketAddr = "203.0.113.200:33333".parse().unwrap();
        let (server, handle) = run_local_turn_allocate_server(relayed).await;

        let client = TurnClient::new().with_timeout(Duration::from_secs(2));
        let addr = client.allocate(server).await.expect("allocate ok");
        assert_eq!(addr, relayed);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn turn_create_permission_round_trip() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = sock.local_addr().unwrap();
        let peer: SocketAddr = "198.51.100.50:6000".parse().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            if let Ok((len, from)) = sock.recv_from(&mut buf).await {
                let msg = StunMessage::parse(&buf[..len]).unwrap();
                assert_eq!(msg.msg_type, MSG_CREATE_PERMISSION_REQUEST);
                let val = msg.find_attr(ATTR_XOR_PEER_ADDRESS).unwrap();
                let decoded = decode_xor_address(val, &msg.transaction_id).unwrap();
                assert_eq!(decoded, peer);
                let response = StunMessage::encode_request(
                    MSG_CREATE_PERMISSION_SUCCESS_RESPONSE,
                    &msg.transaction_id,
                    &[],
                );
                let _ = sock.send_to(&response, from).await;
            }
        });

        let client = TurnClient::new().with_timeout(Duration::from_secs(2));
        client.create_permission(server_addr, peer).await.expect("permission ok");
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn turn_send_indication_transmits_without_response() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = sock.local_addr().unwrap();
        let peer: SocketAddr = "198.51.100.51:6001".parse().unwrap();
        let payload = b"relay me";

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (len, _) = sock.recv_from(&mut buf).await.unwrap();
            let msg = StunMessage::parse(&buf[..len]).unwrap();
            assert_eq!(msg.msg_type, MSG_SEND_INDICATION);
            let data = msg.find_attr(ATTR_DATA).unwrap();
            assert_eq!(data, payload);
        });

        let client = TurnClient::new().with_timeout(Duration::from_secs(2));
        client.send_indication(server_addr, peer, payload).await.expect("send ok");
        handle.await.unwrap();
    }

    // --- NatError Display ---

    #[test]
    fn nat_error_display_is_informative() {
        assert_eq!(
            NatError::ServerError(401, "Unauthorized".to_string()).to_string(),
            "STUN/TURN server error 401: Unauthorized"
        );
        assert_eq!(NatError::Timeout.to_string(), "NAT exchange timed out");
        assert_eq!(
            NatError::MissingAttribute("XOR-MAPPED-ADDRESS").to_string(),
            "missing STUN attribute: XOR-MAPPED-ADDRESS"
        );
    }
}

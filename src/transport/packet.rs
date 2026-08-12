use crate::crypto::aead::{self as tls_aead, AeadOpen, AeadSeal};
use crate::crypto::{select_packet_data_aead, AesGcm128};
use crate::error::ConnectionError;
use std::collections::VecDeque;
use std::sync::Arc;

pub use qf_crypto::{TlsCoverCipherKind, TlsCoverInstallOutcome, TlsCoverKeyMaterial};
pub use qf_transport_crypto_stream::CryptoStream;
// no direct varint helpers used here

/// Derive 16-byte header protection key from TLS secret (RFC 9001 compliant)
pub fn derive_hp_key(secret: &[u8]) -> Result<[u8; 16], ConnectionError> {
    derive_hp_key_for_version(secret, crate::transport::PROTOCOL_VERSION)
}

/// Derives a version-specific 16-byte header protection key.
pub fn derive_hp_key_for_version(secret: &[u8], version: u32) -> Result<[u8; 16], ConnectionError> {
    let hp_vec = crate::crypto::kdf::derive_hdr_key_for_version(secret, 16, version)?;
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_vec);
    Ok(hp)
}

/// Long header form bit (0x80) - set for long headers, clear for short headers.
pub const FORM_BIT: u8 = 0x80;
/// Fixed bit (0x40) - set on regular QUIC packets; ignored for Version Negotiation.
pub const FIXED_BIT: u8 = qf_transport_types::QUIC_FIXED_BIT;
/// Key phase bit (0x04) in short header first byte.
pub const KEY_PHASE_BIT: u8 = 0x04;
/// Packet type mask (0x30) for long header type field extraction.
pub const TYPE_MASK: u8 = 0x30;
/// Packet number length mask (0x03) - low 2 bits encode PN length minus 1.
pub const PKT_NUM_MASK: u8 = 0x03;

/// Maximum Connection ID length per RFC 9000 (20 bytes).
pub const MAX_CID_LEN: usize = 20;
/// Maximum packet number encoding length (4 bytes).
pub const MAX_PKT_NUM_LEN: usize = 4;
/// Bytes of sample used for HP
pub const SAMPLE_LEN: usize = 16;
const AEAD_TAG_LEN: usize = 16;
const MAX_QUIC_VARINT: u64 = 0x3fff_ffff_ffff_ffff;

#[inline]
fn checked_usize_add(left: usize, right: usize) -> Result<usize, ConnectionError> {
    left.checked_add(right).ok_or(ConnectionError::InvalidPacket)
}

#[inline]
fn checked_buffer_end(
    buffer_len: usize,
    start: usize,
    length: usize,
) -> Result<usize, ConnectionError> {
    let end = checked_usize_add(start, length)?;
    if end > buffer_len {
        return Err(ConnectionError::BufferTooShort);
    }
    Ok(end)
}

#[inline]
fn checked_cid_wire_len(length: usize) -> Result<u8, ConnectionError> {
    if length > MAX_CID_LEN || length > u8::MAX as usize {
        return Err(ConnectionError::InvalidPacket);
    }
    Ok(length as u8)
}

#[inline]
fn checked_varint_value(length: usize) -> Result<u64, ConnectionError> {
    let value = u64::try_from(length).map_err(|_| ConnectionError::InvalidPacket)?;
    if value > MAX_QUIC_VARINT {
        return Err(ConnectionError::InvalidPacket);
    }
    Ok(value)
}

/// Compatibility export of the crypto-owned header-protection contract.
pub use qf_crypto::aead::PacketHeaderProtector as HeaderProtector;

fn hp_sample_bounds(buf_len: usize, pn_offset: usize) -> Result<(usize, usize), ConnectionError> {
    if pn_offset == 0 {
        return Err(ConnectionError::InvalidPacket);
    }
    let sample_offset =
        pn_offset.checked_add(MAX_PKT_NUM_LEN).ok_or(ConnectionError::InvalidPacket)?;
    let sample_end = sample_offset.checked_add(SAMPLE_LEN).ok_or(ConnectionError::InvalidPacket)?;
    if sample_end > buf_len {
        return Err(ConnectionError::InvalidPacket);
    }
    Ok((sample_offset, sample_end))
}

fn hp_packet_number_bounds(
    buf_len: usize,
    pn_offset: usize,
    pn_len: usize,
) -> Result<(), ConnectionError> {
    if !(1..=MAX_PKT_NUM_LEN).contains(&pn_len) || pn_offset == 0 {
        return Err(ConnectionError::InvalidPacket);
    }
    let pn_end = pn_offset.checked_add(pn_len).ok_or(ConnectionError::InvalidPacket)?;
    if pn_end > buf_len {
        return Err(ConnectionError::BufferTooShort);
    }
    Ok(())
}

fn trace_handshake_hp(label: &str, sample: &[u8], mask: [u8; 5]) {
    log::trace!(
        "[pkt] {} sample={:02x}{:02x}{:02x}{:02x} mask={:02x}{:02x}{:02x}{:02x}{:02x}",
        label,
        sample[0],
        sample[1],
        sample[2],
        sample[3],
        mask[0],
        mask[1],
        mask[2],
        mask[3],
        mask[4]
    );
}

fn trace_open_failure(hdr: &Header, aad_len: usize, payload_len: usize) {
    log::trace!(
        "[pkt] open fail ty={:?} pn={} pn_len={} aad_len={} payload_len={}",
        hdr.ty,
        hdr.pkt_num,
        hdr.pkt_num_len,
        aad_len,
        payload_len
    );
}

// PacketType is defined once in transport.rs; re-export for local convenience.
pub use super::PacketType;

// Connection establishment functions (moved from transport.rs to externalize packet module API)

/// Creates a new client-side QUIC connection with the given parameters.
pub fn connect(
    _sni: Option<&str>,
    scid: &[u8],
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    connect_with_clock(
        _sni,
        scid,
        local,
        peer,
        config,
        crate::time_source::ProtocolClock::default(),
    )
}

/// Creates a client connection using an explicit protocol clock owner.
pub fn connect_with_clock(
    _sni: Option<&str>,
    scid: &[u8],
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
    clock: crate::time_source::ProtocolClock,
) -> Result<crate::transport::Connection, ConnectionError> {
    let mut conn = crate::transport::Connection::new_with_role_and_clock(
        scid,
        local,
        peer,
        config.clone(),
        false,
        clock,
    )?;

    // Client selects an unpredictable initial DCID (RFC 9000). This DCID is also the ODCID
    // used for Initial key derivation (RFC 9001).
    let mut dcid = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut dcid);
    conn.set_initial_dcid(crate::transport::ConnectionId::from_ref(&dcid));

    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = std::sync::Arc::new(qf_fec::FecObserver::new());
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut()
        .set_stealth_mode(false, browser_profile)
        .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;

    Ok(conn)
}

/// Creates a new server-side QUIC connection accepting a client handshake.
pub fn accept(
    scid: &[u8],
    initial_key_dcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    accept_with_clock(
        scid,
        initial_key_dcid,
        local,
        peer,
        config,
        crate::time_source::ProtocolClock::default(),
    )
}

/// Creates a server connection using an explicit protocol clock owner.
pub fn accept_with_clock(
    scid: &[u8],
    initial_key_dcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
    clock: crate::time_source::ProtocolClock,
) -> Result<crate::transport::Connection, ConnectionError> {
    // Create connection with server role
    // Record the Destination Connection ID from this Initial for RFC 9001
    // key derivation. After Retry this is the server's Retry SCID, not the
    // client's original destination connection ID.
    let mut conn = crate::transport::Connection::new_with_role_and_clock(
        scid,
        local,
        peer,
        config.clone(),
        true,
        clock,
    )?;
    if let Some(initial_key_dcid) = initial_key_dcid {
        conn.set_initial_dcid(crate::transport::ConnectionId::from_ref(initial_key_dcid));
    }
    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = std::sync::Arc::new(qf_fec::FecObserver::new());
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut()
        .set_stealth_mode(false, browser_profile)
        .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;

    Ok(conn)
}

/// Parsed QUIC packet header (Vec-based variant used during packet processing).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// Packet type.
    pub ty: PacketType,
    /// QUIC version (0 for short header or Version Negotiation).
    pub version: u32,
    /// Destination Connection ID bytes.
    pub dcid: Vec<u8>,
    /// Source Connection ID bytes (empty for short headers).
    pub scid: Vec<u8>,
    /// Decoded packet number.
    pub pkt_num: u64,
    /// On-wire packet number encoding length in bytes (1-4).
    pub pkt_num_len: usize,
    /// Token from Initial or Retry packets.
    pub token: Option<Vec<u8>>,
    /// Supported versions from Version Negotiation packets.
    pub versions: Option<Vec<u32>>,
    /// Key phase bit for 1-RTT key rotation.
    pub key_phase: bool,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::arch::x86_64::*;

/// SIMD-optimized packet number encoding
pub fn encode_pkt_num(pn: u64, pn_len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if !(1..=MAX_PKT_NUM_LEN).contains(&pn_len) {
        return Err(ConnectionError::InvalidPacket);
    }
    if out.len() < pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe {
        // AVX2 optimized path for 4-byte packet numbers
        if pn_len == 4
            && crate::optimize::FeatureDetector::instance()
                .features_full()
                .simd_dispatch_matrix()
                .avx2
        {
            // Keep the wire representation big-endian. Converting the bytes
            // to a native integer before the unaligned store preserves their
            // order on x86_64 and avoids the previous reversed-byte shuffle.
            let pn_bytes = (pn as u32).to_be_bytes();
            let pn_vec = _mm_cvtsi32_si128(i32::from_ne_bytes(pn_bytes));
            _mm_storeu_si32(out.as_mut_ptr(), pn_vec);
            return Ok(4);
        }
    }

    // Fallback scalar path
    match pn_len {
        1 => {
            out[0] = pn as u8;
            Ok(1)
        }
        2 => {
            let bytes = (pn as u16).to_be_bytes();
            out[..2].copy_from_slice(&bytes);
            Ok(2)
        }
        3 => {
            out[0] = (pn >> 16) as u8;
            out[1] = (pn >> 8) as u8;
            out[2] = pn as u8;
            Ok(3)
        }
        4 => {
            let bytes = (pn as u32).to_be_bytes();
            out[..4].copy_from_slice(&bytes);
            Ok(4)
        }
        _ => Err(ConnectionError::InvalidPacket),
    }
}

/// Minimal header parsing to get PN offset and header fields
pub fn parse_header(buf: &[u8], short_dcid_len: usize) -> Result<(Header, usize), ConnectionError> {
    use crate::transport::udpfast::{likely, unlikely};
    if unlikely(buf.is_empty()) {
        return Err(ConnectionError::BufferTooShort);
    }
    let first = buf[0];
    if likely((first & crate::transport::packet::FORM_BIT) == 0) {
        // Short header (most common in established connections)
        if unlikely((first & crate::transport::packet::FIXED_BIT) == 0) {
            return Err(ConnectionError::InvalidPacket);
        }
        if short_dcid_len > MAX_CID_LEN {
            return Err(ConnectionError::InvalidPacket);
        }
        let pn_off = checked_usize_add(1, short_dcid_len)?;
        if unlikely(buf.len() < pn_off) {
            return Err(ConnectionError::BufferTooShort);
        }
        let dcid = buf[1..pn_off].to_vec();
        let hdr = Header {
            ty: PacketType::Short,
            version: 0,
            dcid,
            scid: Vec::new(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: (first & crate::transport::packet::KEY_PHASE_BIT) != 0,
        };
        return Ok((hdr, pn_off));
    }
    // Long header parsing
    if buf.len() < 7 {
        return Err(ConnectionError::BufferTooShort);
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != 0 && unlikely((first & crate::transport::packet::FIXED_BIT) == 0) {
        return Err(ConnectionError::InvalidPacket);
    }
    let mut off = 5usize;
    let dcid_len = *buf.get(off).ok_or(ConnectionError::BufferTooShort)? as usize;
    off = checked_usize_add(off, 1)?;
    if dcid_len > MAX_CID_LEN {
        return Err(ConnectionError::InvalidPacket);
    }
    let dcid_start = off;
    let dcid_end = checked_buffer_end(buf.len(), dcid_start, dcid_len)?;
    let scid_len = *buf.get(dcid_end).ok_or(ConnectionError::BufferTooShort)? as usize;
    off = checked_usize_add(dcid_end, 1)?;
    if scid_len > MAX_CID_LEN {
        return Err(ConnectionError::InvalidPacket);
    }
    let scid_end = checked_buffer_end(buf.len(), off, scid_len)?;
    let dcid = buf[dcid_start..dcid_end].to_vec();
    let scid = buf[off..scid_end].to_vec();
    off = scid_end;
    let ty_bits = first & crate::transport::packet::TYPE_MASK;
    let ty = crate::transport::version::packet_type_from_long_header(version, ty_bits)?;
    let mut token = None;
    let mut versions = None;
    if ty == PacketType::VersionNegotiation {
        let remaining = buf.len().saturating_sub(off);
        if remaining == 0 || !remaining.is_multiple_of(4) {
            return Err(ConnectionError::InvalidPacket);
        }
        versions = Some(
            buf[off..]
                .chunks_exact(4)
                .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .collect(),
        );
        off = buf.len();
    } else if ty == PacketType::Initial {
        let (tok_len, used) = crate::transport::varint::read_varint(&buf[off..])?;
        let tok_len = usize::try_from(tok_len).map_err(|_| ConnectionError::InvalidPacket)?;
        off = checked_usize_add(off, used)?;
        let token_end = checked_buffer_end(buf.len(), off, tok_len)?;
        if tok_len > 0 {
            token = Some(buf[off..token_end].to_vec());
        }
        off = token_end;
    } else if ty == PacketType::Retry {
        let tag_start =
            buf.len().checked_sub(AEAD_TAG_LEN).ok_or(ConnectionError::BufferTooShort)?;
        if tag_start < off {
            return Err(ConnectionError::BufferTooShort);
        }
        let tok_len = tag_start - off;
        if tok_len > 0 {
            token = Some(buf[off..tag_start].to_vec());
        }
        off = tag_start;
    }
    let hdr = Header {
        ty,
        version,
        dcid,
        scid,
        pkt_num: 0,
        pkt_num_len: 0,
        token,
        versions,
        key_phase: false,
    };
    Ok((hdr, off))
}

/// Format a Short header directly from a DCID slice, bypassing `Header`
/// construction. This eliminates two `Vec` allocations (`dcid.to_vec()` +
/// `scid.to_vec()`) on the 1-RTT send hot path — `ConnectionId` is already
/// a stack-allocated `Copy` type and `scid` is always empty for Short headers.
#[inline]
pub fn format_short_header(
    dcid: &[u8],
    key_phase: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    checked_cid_wire_len(dcid.len())?;
    let end = checked_buffer_end(out.len(), 1, dcid.len())?;
    let mut first = crate::transport::packet::FIXED_BIT; // 0x40
    if key_phase {
        first |= crate::transport::packet::KEY_PHASE_BIT;
    }
    out[0] = first;
    out[1..end].copy_from_slice(dcid);
    Ok(end)
}

/// Minimal header formatting to get PN offset and header fields
pub fn format_header(h: &Header, out: &mut [u8]) -> Result<usize, ConnectionError> {
    match h.ty {
        PacketType::Short => {
            checked_cid_wire_len(h.dcid.len())?;
            if !h.scid.is_empty() || h.token.is_some() || h.versions.is_some() {
                return Err(ConnectionError::InvalidPacket);
            }
            let end = checked_buffer_end(out.len(), 1, h.dcid.len())?;
            let mut first = crate::transport::packet::FIXED_BIT; // 0x40
            if h.key_phase {
                first |= crate::transport::packet::KEY_PHASE_BIT;
            }
            out[0] = first;
            out[1..end].copy_from_slice(&h.dcid);
            Ok(end)
        }
        PacketType::Initial | PacketType::Handshake | PacketType::ZeroRTT | PacketType::Retry => {
            // Long header: [first][version:4][dcid_len:1][dcid][scid_len:1][scid]
            let dcid_len = checked_cid_wire_len(h.dcid.len())?;
            let scid_len = checked_cid_wire_len(h.scid.len())?;
            let token = h.token.as_deref().unwrap_or(&[]);
            let token_value = checked_varint_value(token.len())?;
            let type_bits = crate::transport::version::long_header_type_bits(h.version, h.ty)?;
            let mut required = 5usize;
            required = checked_usize_add(required, 1)?;
            required = checked_usize_add(required, h.dcid.len())?;
            required = checked_usize_add(required, 1)?;
            required = checked_usize_add(required, h.scid.len())?;
            if h.ty == PacketType::Initial {
                required = checked_usize_add(
                    required,
                    crate::transport::pn::varint::varint_len(token_value),
                )?;
            }
            if h.ty == PacketType::Initial || h.ty == PacketType::Retry {
                required = checked_usize_add(required, token.len())?;
            } else if h.token.is_some() {
                return Err(ConnectionError::InvalidPacket);
            }
            if out.len() < required {
                return Err(ConnectionError::BufferTooShort);
            }
            let mut first = FORM_BIT | FIXED_BIT; // long header with fixed bit
            first |= type_bits;
            out[0] = first;
            out[1..5].copy_from_slice(&h.version.to_be_bytes());
            let mut off = 5usize;
            off = checked_usize_add(off, 1)?;
            let dcid_end = checked_buffer_end(out.len(), off, h.dcid.len())?;
            let scid_len_offset = dcid_end;
            let scid_bytes_start = checked_usize_add(scid_len_offset, 1)?;
            let scid_end = checked_buffer_end(out.len(), scid_bytes_start, h.scid.len())?;
            out[5] = dcid_len;
            out[6..dcid_end].copy_from_slice(&h.dcid);
            out[scid_len_offset] = scid_len;
            out[scid_bytes_start..scid_end].copy_from_slice(&h.scid);
            off = scid_end;
            if h.ty == PacketType::Initial {
                let written = crate::transport::varint::write_varint(token_value, &mut out[off..])?;
                off = checked_usize_add(off, written)?;
                let token_end = checked_buffer_end(out.len(), off, token.len())?;
                out[off..token_end].copy_from_slice(token);
                off = token_end;
            } else if h.ty == PacketType::Retry {
                let token_end = checked_buffer_end(out.len(), off, token.len())?;
                out[off..token_end].copy_from_slice(token);
                off = token_end;
            }
            Ok(off)
        }
        _ => Err(ConnectionError::InvalidPacket),
    }
}

fn unprotect_and_decrypt_with_key(
    hp: &dyn HeaderProtector,
    aead: &dyn crate::crypto::aead::AeadOpen,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
    pre_parsed: Option<(Header, usize)>,
) -> Result<(Header, usize, usize), ConnectionError> {
    let (mut hdr, pn_off) = match pre_parsed {
        Some(parsed) => parsed,
        None => parse_header(buf, short_dcid_len)?,
    };

    let (sample_off, sample_end) = hp_sample_bounds(buf.len(), pn_off)?;
    let mask = hp.new_mask(&buf[sample_off..sample_end])?;
    if hdr.ty == PacketType::Handshake {
        trace_handshake_hp("hp open hs", &buf[sample_off..sample_end], mask);
    }

    let first_mask = if hdr.ty == PacketType::Short { mask[0] & 0x1f } else { mask[0] & 0x0f };
    let first_unprotected = buf[0] ^ first_mask;
    let pn_len = (first_unprotected & 0x03) as usize + 1;
    hp_packet_number_bounds(buf.len(), pn_off, pn_len)?;

    buf[0] = first_unprotected;
    if hdr.ty == PacketType::Short {
        hdr.key_phase = (first_unprotected & crate::transport::packet::KEY_PHASE_BIT) != 0;
    }
    hdr.pkt_num_len = pn_len;
    let aad_len = checked_usize_add(pn_off, pn_len)?;
    let payload_len = buf.len() - aad_len;
    if payload_len < AEAD_TAG_LEN {
        return Err(ConnectionError::BufferTooShort);
    }
    for i in 0..pn_len {
        buf[pn_off + i] ^= mask[1 + i];
    }

    let mut encoded_pn = 0u32;
    for i in 0..pn_len {
        encoded_pn = (encoded_pn << 8) | buf[pn_off + i] as u32;
    }
    hdr.pkt_num =
        crate::optimize::transport::decode_packet_number(encoded_pn, largest_pn_hint, pn_len as u8);

    let (aad_buf, payload_buf) = buf.split_at_mut(aad_len);
    let aad = &aad_buf[..aad_len];
    let plaintext_len = match aead.open_with_u64_counter(hdr.pkt_num, aad, payload_buf) {
        Ok(n) => n,
        Err(e) => {
            trace_open_failure(&hdr, aad_len, payload_len);
            return Err(e);
        }
    };

    Ok((hdr, aad_len, plaintext_len))
}

/// Full RFC 9001 compliant HP/Decrypt implementation
pub fn unprotect_and_decrypt(
    crypto: &CryptoContext,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
) -> Result<(Header, usize, usize), ConnectionError> {
    unprotect_and_decrypt_parsed(crypto, buf, short_dcid_len, largest_pn_hint, None)
}

/// Lock-free 1-RTT fast path for `unprotect_and_decrypt_parsed`.
///
/// Attempts to unprotect+decrypt a Short-header packet using the ArcSwap-loaded
/// 1-RTT keys. Returns `Done` if the packet is not Short-header or no 1-RTT keys
/// are available, signaling the caller to fall back to the full RwLock path.
pub(crate) fn unprotect_and_decrypt_1rtt(
    keys: &OneRttCrypto,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
    pre_parsed: Option<(Header, usize)>,
) -> Result<(Header, usize, usize), ConnectionError> {
    let (hdr, pn_off) = match pre_parsed {
        Some(parsed) => parsed,
        None => parse_header(buf, short_dcid_len)?,
    };
    if hdr.ty != PacketType::Short {
        return Err(ConnectionError::Done);
    }
    unprotect_and_decrypt_with_key(
        &*keys.hp_open,
        &*keys.open,
        buf,
        short_dcid_len,
        largest_pn_hint,
        Some((hdr, pn_off)),
    )
}

/// Like [`unprotect_and_decrypt`], but accepts an optional pre-parsed header to avoid
/// redundant header parsing on the recv hot path.
pub fn unprotect_and_decrypt_parsed(
    crypto: &CryptoContext,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
    pre_parsed: Option<(Header, usize)>,
) -> Result<(Header, usize, usize), ConnectionError> {
    // Parse once (or reuse caller parse) to identify packet class and route to the right key set.
    let (hdr, pn_off) = match pre_parsed {
        Some(parsed) => parsed,
        None => parse_header(buf, short_dcid_len)?,
    };
    // Move hdr into the match arms — only one arm executes, so no clone needed
    // for Initial/Handshake/ZeroRTT. For Short, use take() to pass the header
    // to the first candidate only (subsequent candidates get None and re-parse
    // internally), eliminating the pre-clone that was here previously.
    match hdr.ty {
        PacketType::Initial => {
            let (hp, aead) = match (
                crypto.hp_initial_open.as_ref().or(crypto.hp_initial.as_ref()),
                crypto.open_initial.as_ref(),
            ) {
                (Some(hp), Some(aead)) => (hp.as_ref(), aead.as_ref()),
                _ => return Err(ConnectionError::Done),
            };
            unprotect_and_decrypt_with_key(
                hp,
                aead,
                buf,
                short_dcid_len,
                largest_pn_hint,
                Some((hdr, pn_off)),
            )
        }
        PacketType::Handshake => {
            let (hp, aead) = match (
                crypto.hp_handshake_open.as_ref().or(crypto.hp_handshake.as_ref()),
                crypto.open_handshake.as_ref(),
            ) {
                (Some(hp), Some(aead)) => (hp.as_ref(), aead.as_ref()),
                _ => return Err(ConnectionError::Done),
            };
            unprotect_and_decrypt_with_key(
                hp,
                aead,
                buf,
                short_dcid_len,
                largest_pn_hint,
                Some((hdr, pn_off)),
            )
        }
        PacketType::ZeroRTT => {
            let (hp, aead) = match (
                crypto.hp_0rtt_open.as_ref().or(crypto.hp_0rtt.as_ref()),
                crypto.open_0rtt.as_ref(),
            ) {
                (Some(hp), Some(aead)) => (hp.as_ref(), aead as &dyn tls_aead::AeadOpen),
                _ => return Err(ConnectionError::Done),
            };
            unprotect_and_decrypt_with_key(
                hp,
                aead,
                buf,
                short_dcid_len,
                largest_pn_hint,
                Some((hdr, pn_off)),
            )
        }
        PacketType::Short => {
            let mut candidates: Vec<(&dyn HeaderProtector, &dyn crate::crypto::aead::AeadOpen)> =
                Vec::new();
            let hp_1rtt = crypto.hp_1rtt_open.as_deref().or(crypto.hp_1rtt.as_deref());
            if let (Some(hp), Some(aead)) = (hp_1rtt, crypto.open_1rtt.as_deref()) {
                candidates.push((hp, aead as &dyn tls_aead::AeadOpen));
            }
            if let Some(hp) = hp_1rtt {
                for prev in &crypto.previous_read_1rtt {
                    candidates.push((hp, &*prev.open as &dyn tls_aead::AeadOpen));
                }
            }
            if candidates.is_empty() {
                return Err(ConnectionError::Done);
            }
            let original = if candidates.len() > 1 { Some(buf.to_vec()) } else { None };
            let mut last_err = ConnectionError::CryptoError("crypto failure".into());
            // take() moves the header to the first candidate; subsequent
            // candidates get None and parse internally. No clone needed.
            let mut hdr_opt = Some((hdr, pn_off));
            for (hp, aead) in candidates.into_iter() {
                // Restore buf from the original snapshot for candidates after
                // the first (previous attempt's HP removal modified buf).
                if hdr_opt.is_none() {
                    if let Some(orig) = original.as_ref() {
                        buf.copy_from_slice(orig);
                    }
                }
                let pre = hdr_opt.take();
                match unprotect_and_decrypt_with_key(
                    hp,
                    aead,
                    buf,
                    short_dcid_len,
                    largest_pn_hint,
                    pre,
                ) {
                    Ok(v) => return Ok(v),
                    Err(e) => last_err = e,
                }
            }
            Err(last_err)
        }
        _ => Ok((hdr, pn_off, buf.len().saturating_sub(pn_off))),
    }
}

#[cfg(test)]
mod tests;

/// Applies header protection to an outgoing packet (masks first byte and PN).
pub fn protect_header(
    crypto: &CryptoContext,
    buf: &mut [u8],
    pn_off: usize,
    pn_len: usize,
    pkt_type: PacketType,
) -> Result<(), ConnectionError> {
    hp_packet_number_bounds(buf.len(), pn_off, pn_len)?;

    // Select HP based on packet type
    let hp = match pkt_type {
        PacketType::Initial => crypto.hp_initial.as_deref(),
        PacketType::Handshake => crypto.hp_handshake.as_deref(),
        PacketType::ZeroRTT => crypto.hp_0rtt.as_deref(),
        PacketType::Short => crypto.hp_1rtt.as_deref(),
        _ => return Ok(()),
    };

    let hp = match hp {
        Some(h) => h,
        None => return Ok(()), // No HP available yet
    };

    let (sample_off, sample_end) = hp_sample_bounds(buf.len(), pn_off)?;

    let mask = hp.new_mask(&buf[sample_off..sample_end])?;
    if pkt_type == PacketType::Handshake {
        trace_handshake_hp("hp protect hs", &buf[sample_off..sample_end], mask);
    }

    // Mask the first byte
    if pkt_type == PacketType::Short {
        buf[0] ^= mask[0] & 0x1f; // Short header: 5 bits
    } else {
        buf[0] ^= mask[0] & 0x0f; // Long header: 4 bits
    }

    // Mask the packet number
    for i in 0..pn_len {
        buf[pn_off + i] ^= mask[1 + i];
    }

    Ok(())
}

/// Full encryption for outgoing packets
pub fn encrypt_and_protect(
    crypto: &CryptoContext,
    buf: &mut [u8],
    hdr_len: usize,
    pn: u64,
    pn_len: usize,
    pkt_type: PacketType,
) -> Result<usize, ConnectionError> {
    if hdr_len > buf.len() {
        return Err(ConnectionError::BufferTooShort);
    }
    if !matches!(
        pkt_type,
        PacketType::Initial | PacketType::Handshake | PacketType::ZeroRTT | PacketType::Short
    ) {
        return Ok(hdr_len);
    }
    if !(1..=MAX_PKT_NUM_LEN).contains(&pn_len) || hdr_len < pn_len {
        return Err(ConnectionError::InvalidPacket);
    }
    let pn_off = hdr_len - pn_len;
    hp_packet_number_bounds(buf.len(), pn_off, pn_len)?;
    hp_sample_bounds(buf.len(), pn_off)?;
    let payload_len = buf.len() - hdr_len;
    if payload_len < AEAD_TAG_LEN {
        return Err(ConnectionError::BufferTooShort);
    }

    // Select AEAD based on packet type
    let aead: Option<&dyn tls_aead::AeadSeal> = match pkt_type {
        PacketType::Initial => crypto.seal_initial.as_deref().map(|a| a as &dyn tls_aead::AeadSeal),
        PacketType::Handshake => {
            crypto.seal_handshake.as_deref().map(|a| a as &dyn tls_aead::AeadSeal)
        }
        PacketType::ZeroRTT => crypto.seal_0rtt.as_ref().map(|a| a as &dyn tls_aead::AeadSeal),
        PacketType::Short => crypto.seal_1rtt.as_deref().map(|a| a as &dyn tls_aead::AeadSeal),
        _ => return Ok(hdr_len),
    };

    let aead = match aead {
        Some(a) => a,
        None => return Ok(hdr_len), // No AEAD available yet
    };

    // Encode packet number length (pn_len - 1) into the low 2 bits of the first header byte.
    // This is required for correct header protection removal on the peer.
    buf[0] = (buf[0] & !PKT_NUM_MASK) | (((pn_len as u8) - 1) & PKT_NUM_MASK);

    // Encrypt payload in-place. Reserve 16 bytes for AEAD tag at the tail of the payload buffer.
    let (aad, payload) = buf.split_at_mut(hdr_len);
    let plaintext_len = payload.len() - AEAD_TAG_LEN;
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, payload, plaintext_len, None)?;

    // Apply header protection
    protect_header(crypto, buf, pn_off, pn_len, pkt_type)?;

    checked_usize_add(hdr_len, ciphertext_len)
}

/// Seal multiple 1-RTT/0-RTT payloads through the installed data-plane AEAD sealer.
///
/// Buffers must not alias. AEGIS backends reuse cipher state across the batch.
pub fn seal_data_aead_batch(
    crypto: &CryptoContext,
    items: &mut [tls_aead::AeadSealItem<'_>],
) -> Result<(), ConnectionError> {
    let seal =
        crypto.seal_1rtt.as_deref().or(crypto.seal_0rtt.as_ref()).ok_or_else(|| {
            ConnectionError::TlsError("missing AEAD sealer for batch seal".into())
        })?;
    seal.seal_batch(items)
}

/// Open multiple 1-RTT/0-RTT payloads through the installed data-plane AEAD opener.
pub fn open_data_aead_batch(
    crypto: &CryptoContext,
    items: &mut [tls_aead::AeadOpenItem<'_>],
) -> Result<(), ConnectionError> {
    let open =
        crypto.open_1rtt.as_deref().or(crypto.open_0rtt.as_ref()).ok_or_else(|| {
            ConnectionError::TlsError("missing AEAD opener for batch open".into())
        })?;
    open.open_batch(items)
}

/// Selects the server's most-preferred QUIC version that the client also supports.
///
/// Iterates `server_versions` in preference order and returns the first entry
/// that also appears in `client_versions`. Returns `None` when no common
/// version exists. In that case, the caller should emit a Version Negotiation
/// packet via [`generate_version_negotiation_packet`].
pub fn negotiate_version(client_versions: &[u32], server_versions: &[u32]) -> Option<u32> {
    server_versions.iter().find(|&&sv| client_versions.contains(&sv)).copied()
}

/// Builds a Version Negotiation (VN) response packet listing `server_versions`.
///
/// Per RFC 9000 Section 17.2.1, the VN packet's DCID echoes the client's SCID
/// and its SCID echoes the client's DCID; the caller is responsible for passing
/// the already-swapped connection IDs in `dcid` / `scid`. The form bit is set,
/// while all other first-byte bits are non-invariant. The `client_versions`
/// argument is accepted for API symmetry but is not encoded; only the server's
/// supported versions appear in the packet body.
pub fn generate_version_negotiation_packet(
    _client_versions: &[u32],
    server_versions: &[u32],
    dcid: &[u8],
    scid: &[u8],
) -> Result<Vec<u8>, ConnectionError> {
    checked_cid_wire_len(dcid.len())?;
    checked_cid_wire_len(scid.len())?;
    if server_versions.is_empty() {
        return Err(ConnectionError::InvalidPacket);
    }
    let versions_len =
        server_versions.len().checked_mul(4).ok_or(ConnectionError::InvalidPacket)?;
    let base_len = checked_usize_add(1 + 4, 1)?;
    let base_len = checked_usize_add(base_len, dcid.len())?;
    let base_len = checked_usize_add(base_len, 1)?;
    let base_len = checked_usize_add(base_len, scid.len())?;
    let capacity = checked_usize_add(base_len, versions_len)?;
    let mut pkt = Vec::with_capacity(capacity);
    // Only the form bit is invariant. RFC 9000 recommends setting the fixed-bit
    // position so VN packets resemble other QUIC packets on multiplexed ports.
    let first = crate::transport::rand::rand_u8() | FORM_BIT | FIXED_BIT;
    pkt.push(first);
    // Version field is 0x00000000 for VN packets.
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // DCID (echoes the client's SCID).
    pkt.push(checked_cid_wire_len(dcid.len())?);
    pkt.extend_from_slice(dcid);
    // SCID (echoes the client's DCID).
    pkt.push(checked_cid_wire_len(scid.len())?);
    pkt.extend_from_slice(scid);
    // Supported versions, big-endian.
    for v in server_versions {
        pkt.extend_from_slice(&v.to_be_bytes());
    }
    Ok(pkt)
}

/// Extracts the version list from a Version Negotiation packet.
///
/// Returns `Some(versions)` when `pkt` is a well-formed VN packet (form bit set,
/// version field zero, and a whole number of 4-byte version
/// entries). Returns `None` otherwise.
pub fn parse_version_negotiation(pkt: &[u8]) -> Option<Vec<u32>> {
    if pkt.is_empty() {
        return None;
    }
    let first = pkt[0];
    // Only the form bit is defined for VN; the remaining seven bits are ignored.
    if (first & FORM_BIT) == 0 {
        return None;
    }
    if pkt.len() < 5 {
        return None;
    }
    let version = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    if version != 0 {
        return None;
    }
    let mut off = 5usize;
    // DCID length + bytes.
    let dcid_len = usize::from(*pkt.get(off)?);
    if dcid_len > MAX_CID_LEN {
        return None;
    }
    off = off.checked_add(1)?;
    let dcid_end = off.checked_add(dcid_len)?;
    if dcid_end > pkt.len() {
        return None;
    }
    off = dcid_end;
    // SCID length + bytes.
    let scid_len = usize::from(*pkt.get(off)?);
    if scid_len > MAX_CID_LEN {
        return None;
    }
    off = off.checked_add(1)?;
    let scid_end = off.checked_add(scid_len)?;
    if scid_end > pkt.len() {
        return None;
    }
    off = scid_end;
    // Remaining bytes must be a whole number of 4-byte version entries.
    let remaining = pkt.len().saturating_sub(off);
    if remaining == 0 || !remaining.is_multiple_of(4) {
        return None;
    }
    Some(
        pkt[off..]
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect(),
    )
}

/// Builds a stateless server VN response for an unsupported long-header packet.
///
/// The response is emitted before allocating connection state. Supported
/// versions retain endpoint preference order; one reserved grease value is
/// appended but is never considered selectable.
pub fn server_version_negotiation_response(
    packet: &[u8],
    supported_versions: &[u32],
) -> Result<Option<Vec<u8>>, ConnectionError> {
    if packet.len() < crate::transport::MIN_CLIENT_INITIAL_LEN
        || packet.first().is_none_or(|first| first & FORM_BIT == 0)
        || packet.len() < 7
    {
        return Ok(None);
    }
    let version =
        u32::from_be_bytes(packet[1..5].try_into().map_err(|_| ConnectionError::InvalidPacket)?);
    if version == 0 || supported_versions.contains(&version) {
        return Ok(None);
    }

    let mut offset = 5usize;
    let dcid_len = usize::from(packet[offset]);
    if dcid_len > MAX_CID_LEN {
        return Err(ConnectionError::InvalidPacket);
    }
    offset += 1;
    let dcid_end = offset.checked_add(dcid_len).ok_or(ConnectionError::InvalidPacket)?;
    if dcid_end >= packet.len() {
        return Err(ConnectionError::InvalidPacket);
    }
    let dcid = &packet[offset..dcid_end];
    offset = dcid_end;
    let scid_len = usize::from(packet[offset]);
    if scid_len > MAX_CID_LEN {
        return Err(ConnectionError::InvalidPacket);
    }
    offset += 1;
    let scid_end = offset.checked_add(scid_len).ok_or(ConnectionError::InvalidPacket)?;
    if scid_end > packet.len() {
        return Err(ConnectionError::InvalidPacket);
    }
    let scid = &packet[offset..scid_end];

    let mut offered = supported_versions
        .iter()
        .copied()
        .filter(|version| crate::transport::is_supported_version(*version))
        .collect::<Vec<_>>();
    if offered.is_empty() {
        return Err(ConnectionError::InvalidState);
    }
    offered.push(crate::transport::version::generate_reserved_version());
    Ok(Some(generate_version_negotiation_packet(&[], &offered, scid, dcid)?))
}

fn retry_integrity_material(
    version: u32,
) -> Result<(&'static [u8; 16], &'static [u8; 12]), ConnectionError> {
    const KEY_V1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE_V1: [u8; 12] =
        [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];
    const KEY_V2: [u8; 16] = [
        0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc,
        0x92,
    ];
    const NONCE_V2: [u8; 12] =
        [0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a];
    match version {
        crate::transport::PROTOCOL_VERSION => Ok((&KEY_V1, &NONCE_V1)),
        crate::transport::PROTOCOL_VERSION_V2 => Ok((&KEY_V2, &NONCE_V2)),
        _ => Err(ConnectionError::VersionMismatch),
    }
}

/// Appends a Retry Integrity Tag using the version-specific RFC key and nonce.
pub fn append_retry_tag(
    buf: &mut Vec<u8>,
    odcid: &[u8],
    version: u32,
) -> Result<(), ConnectionError> {
    checked_cid_wire_len(odcid.len())?;
    let hdr_len = buf.len();
    let capacity = checked_usize_add(1, odcid.len())?;
    let capacity = checked_usize_add(capacity, hdr_len)?;
    let mut pseudo = Vec::with_capacity(capacity);
    pseudo.push(checked_cid_wire_len(odcid.len())?);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&buf[..hdr_len]);
    let (key, nonce) = retry_integrity_material(version)?;
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(key, nonce, &pseudo);
    buf.extend_from_slice(&tag);
    Ok(())
}

/// Verifies the Retry Integrity Tag of a received Retry packet.
pub fn verify_retry_tag(packet: &[u8], odcid: &[u8], version: u32) -> Result<(), ConnectionError> {
    if packet.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    checked_cid_wire_len(odcid.len())?;
    let hdr_len = packet.len() - 16;
    let tag_in = &packet[hdr_len..];
    let capacity = checked_usize_add(1, odcid.len())?;
    let capacity = checked_usize_add(capacity, hdr_len)?;
    let mut pseudo = Vec::with_capacity(capacity);
    pseudo.push(checked_cid_wire_len(odcid.len())?);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&packet[..hdr_len]);
    let (key, nonce) = retry_integrity_material(version)?;
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(key, nonce, &pseudo);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ tag_in[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(ConnectionError::CryptoError("crypto failure".into()))
    }
}

/// HKDF-based key/iv derivation for AEAD from TLS secrets (RFC 9001 compliant)
pub fn derive_key_iv(secret: &[u8]) -> Result<([u8; 32], [u8; 12]), ConnectionError> {
    derive_key_iv_for_version(secret, crate::transport::PROTOCOL_VERSION)
}

/// Derives version-specific packet key and IV material.
pub fn derive_key_iv_for_version(
    secret: &[u8],
    version: u32,
) -> Result<([u8; 32], [u8; 12]), ConnectionError> {
    let key_vec = crate::crypto::kdf::derive_pkt_key_for_version(secret, 32, version)?;
    let iv_vec = crate::crypto::kdf::derive_pkt_iv_for_version(secret, 12, version)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    Ok((key, iv))
}

/// Derive Initial secrets from destination connection ID (RFC 9001 compliant)
pub fn derive_initial_secrets(
    dcid: &[u8],
    version: u32,
) -> Result<(Vec<u8>, Vec<u8>), ConnectionError> {
    let initial_secret = crate::crypto::kdf::derive_initial_secret(dcid, version);
    let client_secret = crate::crypto::kdf::derive_client_initial_secret(&initial_secret)?;
    let server_secret = crate::crypto::kdf::derive_server_initial_secret(&initial_secret)?;
    Ok((client_secret, server_secret))
}

/// Apply header protection mask (for encryption)
pub fn apply_hp(
    first: u8,
    pn: &mut [u8],
    sample: &[u8],
    is_long: bool,
    hp: &dyn HeaderProtector,
) -> Result<(u8, usize), ConnectionError> {
    let mask = hp.new_mask(sample)?;
    let first_new = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };
    // PN length is encoded in the low 2 bits of the (possibly masked) first byte, plus 1
    let pn_len = ((first_new & PKT_NUM_MASK) as usize) + 1;
    if pn.len() < pn_len {
        return Err(ConnectionError::BufferTooShort);
    }
    for i in 0..pn_len {
        pn[i] ^= mask[i + 1];
    }
    Ok((first_new, pn_len))
}

/// Remove header protection mask (for decryption)
pub fn remove_hp(
    buf: &mut [u8],
    hp: &dyn HeaderProtector,
    pn_offset: usize,
) -> Result<(u8, usize), ConnectionError> {
    let (sample_offset, sample_end) = hp_sample_bounds(buf.len(), pn_offset)?;

    // Generate mask
    let mask = hp.new_mask(&buf[sample_offset..sample_end])?;

    // Check if it's a long header packet
    let first = buf[0];
    let is_long = (first & FORM_BIT) != 0;

    // Unmask the first byte to get packet number length
    let first_unmasked = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };

    // Get packet number length (encoded in low 2 bits + 1)
    let pn_len = ((first_unmasked & PKT_NUM_MASK) as usize) + 1;
    hp_packet_number_bounds(buf.len(), pn_offset, pn_len)?;

    // Unmask the packet number
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[i + 1];
    }

    // Update the first byte
    buf[0] = first_unmasked;

    Ok((first_unmasked, pn_len))
}

/// Decrypt a QUIC packet payload (alternative implementation)
pub fn decrypt_payload(
    buf: &mut [u8],
    pn: u64,
    pn_len: usize,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadOpen,
) -> Result<usize, ConnectionError> {
    if !(1..=MAX_PKT_NUM_LEN).contains(&pn_len) || hdr_len < pn_len {
        return Err(ConnectionError::InvalidPacket);
    }
    if hdr_len > buf.len() {
        return Err(ConnectionError::BufferTooShort);
    }
    if buf.len() - hdr_len < AEAD_TAG_LEN {
        // Need at least header + AEAD tag
        return Err(ConnectionError::BufferTooShort);
    }

    // Split buffer to avoid borrowing conflicts
    let (aad_buf, payload_buf) = buf.split_at_mut(hdr_len);
    let aad = &aad_buf[..hdr_len];

    // Decrypt in-place
    let _payload_len = payload_buf.len();
    let plaintext_len = aead.open_with_u64_counter(pn, aad, payload_buf)?;

    checked_usize_add(hdr_len, plaintext_len)
}

/// Encrypt a QUIC packet payload
pub fn encrypt_packet(
    buf: &mut [u8],
    payload_len: usize,
    pn: u64,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadSeal,
) -> Result<usize, ConnectionError> {
    if hdr_len > buf.len() {
        return Err(ConnectionError::BufferTooShort);
    }
    let payload_end = checked_buffer_end(buf.len(), hdr_len, payload_len)?;
    checked_buffer_end(buf.len(), payload_end, AEAD_TAG_LEN)?;

    // Zero-copy AAD: copy header to stack buffer (eliminates heap allocation)
    const MAX_AAD_STACK: usize = 64;
    let mut aad_stack = [0u8; MAX_AAD_STACK];
    let aad: &[u8] = if hdr_len <= MAX_AAD_STACK {
        aad_stack[..hdr_len].copy_from_slice(&buf[..hdr_len]);
        &aad_stack[..hdr_len]
    } else {
        return Err(ConnectionError::InvalidPacket);
    };

    // Encrypt in-place
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, buf, payload_end, None)?;

    Ok(ciphertext_len)
}

const ONE_RTT_READ_KEY_WINDOW: usize = 4;

struct PreviousRead1RttKey {
    open: Arc<crate::crypto::PacketAeadOpen>,
}

/// Lock-free 1-RTT crypto keys for the data-plane hot path.
///
/// Stored in `ArcSwapOption<OneRttCrypto>` on `Connection`. The hot path
/// (seal/open) loads this lock-free instead of acquiring the CryptoContext
/// RwLock. Key updates store a new `Arc<OneRttCrypto>` atomically.
pub(crate) struct OneRttCrypto {
    /// 1-RTT seal (encrypt) key.
    pub(crate) seal: Arc<crate::crypto::PacketAeadSeal>,
    /// 1-RTT open (decrypt) key.
    pub(crate) open: Arc<crate::crypto::PacketAeadOpen>,
    /// Header protector for outgoing 1-RTT packets.
    pub(crate) hp_seal: Arc<dyn HeaderProtector + Send + Sync>,
    /// Header protector for incoming 1-RTT packets.
    pub(crate) hp_open: Arc<dyn HeaderProtector + Send + Sync>,
}

/// Per-connection cryptographic state (AEAD keys, HP keys, TLS Cover cipher, CryptoStreams).
#[derive(Default)]
pub struct CryptoContext {
    /// AEAD open (decrypt) key for Initial packets (AES-GCM).
    pub open_initial: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    /// AEAD open (decrypt) key for Handshake packets (AES-GCM).
    pub open_handshake: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    /// AEAD open (decrypt) key for 0-RTT packets (forked data-plane AEAD contract under the explicit full-fork assumption).
    pub(crate) open_0rtt: Option<crate::crypto::PacketAeadOpen>,
    /// AEAD open (decrypt) key for 1-RTT packets (forked data-plane AEAD contract under the explicit full-fork assumption).
    pub(crate) open_1rtt: Option<Arc<crate::crypto::PacketAeadOpen>>,
    /// AEAD seal (encrypt) key for Initial packets.
    pub seal_initial: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    /// AEAD seal (encrypt) key for Handshake packets.
    pub seal_handshake: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    /// AEAD seal (encrypt) key for 0-RTT packets.
    pub(crate) seal_0rtt: Option<crate::crypto::PacketAeadSeal>,
    /// AEAD seal (encrypt) key for 1-RTT packets.
    pub(crate) seal_1rtt: Option<Arc<crate::crypto::PacketAeadSeal>>,
    /// Header protection key for outgoing Initial packets.
    pub hp_initial: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for outgoing Handshake packets.
    pub hp_handshake: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for outgoing 0-RTT packets.
    pub hp_0rtt: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for outgoing 1-RTT packets.
    pub hp_1rtt: Option<Arc<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for incoming Initial packets (direction-specific).
    pub hp_initial_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for incoming Handshake packets (direction-specific).
    pub hp_handshake_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for incoming 0-RTT packets (direction-specific).
    pub hp_0rtt_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    /// Header protection key for incoming 1-RTT packets (direction-specific).
    pub hp_1rtt_open: Option<Arc<dyn HeaderProtector + Send + Sync>>,
    /// Current 1-RTT read secret for key update derivation.
    pub(crate) read_secret_1rtt: Option<crate::secret::SecretBytes>,
    /// Current 1-RTT write secret for key update derivation.
    pub(crate) write_secret_1rtt: Option<crate::secret::SecretBytes>,
    /// Current 1-RTT read key generation counter.
    pub read_generation_1rtt: u64,
    /// Current 1-RTT write key generation counter.
    pub write_generation_1rtt: u64,
    /// Whether 0-RTT early data is enabled for this context.
    pub zero_rtt_enabled: bool,
    previous_read_1rtt: VecDeque<PreviousRead1RttKey>,
    tls_cover_cipher: qf_crypto::TlsCoverCipherState,
    /// TLS Cover write sequence number.
    pub tls_cover_write_seq: u64,
    /// TLS Cover read sequence number.
    pub tls_cover_read_seq: u64,
    /// CRYPTO frame stream for Initial encryption level.
    pub crypto_initial: CryptoStream,
    /// CRYPTO frame stream for 0-RTT encryption level.
    pub crypto_0rtt: CryptoStream,
    /// CRYPTO frame stream for Handshake encryption level.
    pub crypto_handshake: CryptoStream,
    /// CRYPTO frame stream for Application encryption level.
    pub crypto_application: CryptoStream,
}

impl CryptoContext {
    /// Returns true while an Initial or Handshake flight still needs transmission.
    pub fn has_pending_handshake_send(&self) -> bool {
        self.crypto_initial.has_pending_send() || self.crypto_handshake.has_pending_send()
    }

    /// Installs 0-RTT read and write keys from the given TLS secrets.
    pub fn install_0rtt_keys(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (read_key, read_iv) = derive_key_iv(read_secret)?;
        let (write_key, write_iv) = derive_key_iv(write_secret)?;
        let write_hp = derive_hp_key(write_secret)?;
        let read_hp = derive_hp_key(read_secret)?;
        let (_, open) = select_packet_data_aead(&read_key, &read_iv);
        let (seal, _) = select_packet_data_aead(&write_key, &write_iv);
        self.zero_rtt_enabled = true;
        self.open_0rtt = Some(open);
        self.seal_0rtt = Some(seal);
        self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::from_key(&write_hp)));
        self.hp_0rtt_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&read_hp)));
        Ok(())
    }
}

impl CryptoContext {
    /// Enables or disables 0-RTT key installation for this crypto context.
    pub fn set_zero_rtt_enabled(&mut self, enabled: bool) {
        self.zero_rtt_enabled = enabled;
    }

    /// Install or rotate the TLS Cover cipher without permitting counter reuse.
    pub fn install_tls_cover_cipher(
        &mut self,
        material: TlsCoverKeyMaterial<'_>,
    ) -> Result<TlsCoverInstallOutcome, ConnectionError> {
        self.tls_cover_cipher.install(
            material,
            &mut self.tls_cover_write_seq,
            &mut self.tls_cover_read_seq,
        )
    }

    #[inline]
    /// Returns the TLS Cover cipher algorithm in use, if configured.
    pub fn tls_cover_cipher_kind(&self) -> Option<TlsCoverCipherKind> {
        self.tls_cover_cipher.cipher_kind()
    }

    /// Encrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn encrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        self.tls_cover_cipher.encrypt_record(&mut self.tls_cover_write_seq, aad, plaintext)
    }

    /// Decrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn decrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        self.tls_cover_cipher.decrypt_record(&mut self.tls_cover_read_seq, aad, ciphertext)
    }

    /// Install AES-GCM for Initial packets (compatibility path).
    /// QUIC initial keys are direction-specific, so we accept read/write secrets separately.
    pub fn install_aes_gcm_initial(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
        version: u32,
    ) -> Result<(), ConnectionError> {
        let rkey = crate::crypto::kdf::derive_pkt_key_for_version(read_secret, 16, version)?;
        let wkey = crate::crypto::kdf::derive_pkt_key_for_version(write_secret, 16, version)?;
        let riv = crate::crypto::kdf::derive_pkt_iv_for_version(read_secret, 12, version)?;
        let wiv = crate::crypto::kdf::derive_pkt_iv_for_version(write_secret, 12, version)?;
        let mut k16 = [0u8; 16];
        let mut iv12 = [0u8; 12];
        k16.copy_from_slice(&wkey);
        iv12.copy_from_slice(&wiv);
        self.seal_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv12)));
        k16.copy_from_slice(&rkey);
        iv12.copy_from_slice(&riv);
        self.open_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv12)));
        // HP can be installed later when header protection keys are derived
        Ok(())
    }

    /// Install AES-GCM for Handshake packets (compatibility path)
    pub fn install_aes_gcm_handshake(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&key[..16]);
        let seal = AesGcm128::from_arrays(&k16, &iv);
        let open = AesGcm128::from_arrays(&k16, &iv);
        self.seal_handshake = Some(Box::new(seal));
        self.open_handshake = Some(Box::new(open));
        // HP can be installed later when header protection keys are derived
        Ok(())
    }

    /// Install AES-based Header Protection for Initial packets.
    /// QUIC header protection is direction-specific, so we accept read/write secrets separately.
    pub fn install_hp_initial(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
        version: u32,
    ) -> Result<(), ConnectionError> {
        let hp_key_w = derive_hp_key_for_version(write_secret, version)?;
        let hp_key_r = derive_hp_key_for_version(read_secret, version)?;
        self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key_w)));
        self.hp_initial_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key_r)));
        Ok(())
    }

    /// Install AES-based Header Protection for Handshake packets
    pub fn install_hp_handshake(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let hp_key = derive_hp_key(secret)?;
        self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        self.hp_handshake_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        Ok(())
    }

    fn install_read_1rtt_secret(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let (_, open) = select_packet_data_aead(&key, &iv);
        let hp_key = derive_hp_key(secret)?;
        self.open_1rtt = Some(Arc::new(open));
        self.hp_1rtt_open = Some(Arc::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        Ok(())
    }

    fn install_write_1rtt_secret(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let (seal, _) = select_packet_data_aead(&key, &iv);
        let hp_key = derive_hp_key(secret)?;
        self.seal_1rtt = Some(Arc::new(seal));
        self.hp_1rtt = Some(Arc::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        Ok(())
    }

    fn push_previous_read_key(&mut self, open: Arc<crate::crypto::PacketAeadOpen>) {
        self.previous_read_1rtt.push_back(PreviousRead1RttKey { open });
        while self.previous_read_1rtt.len() > ONE_RTT_READ_KEY_WINDOW {
            let _ = self.previous_read_1rtt.pop_front();
        }
    }

    /// Rotates the 1-RTT read key, pushing the old key into the read window.
    pub fn rotate_1rtt_read_keypair(
        &mut self,
        open: Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>,
    ) {
        if let Some(prev_open) = self.open_1rtt.take() {
            self.push_previous_read_key(prev_open);
        }
        self.open_1rtt = Some(Arc::new(crate::crypto::PacketAeadOpen::dynamic(open)));
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        self.read_secret_1rtt = None;
    }

    /// Rotates the 1-RTT write key, replacing the current sealer.
    pub fn rotate_1rtt_write_keypair(
        &mut self,
        seal: Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>,
    ) {
        self.seal_1rtt = Some(Arc::new(crate::crypto::PacketAeadSeal::dynamic(seal)));
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        self.write_secret_1rtt = None;
    }

    /// Derives the next 1-RTT read secret and rotates the opener.
    pub fn key_update_1rtt_read(&mut self) -> Result<bool, ConnectionError> {
        let Some(cur) = self.read_secret_1rtt.as_deref() else {
            return Ok(false);
        };
        let next = crate::crypto::kdf::derive_next_secret(cur)?;
        let (key, iv) = derive_key_iv(&next)?;
        let (_, open) = select_packet_data_aead(&key, &iv);
        if let Some(prev_open) = self.open_1rtt.take() {
            self.push_previous_read_key(prev_open);
        }
        self.open_1rtt = Some(Arc::new(open));
        self.read_secret_1rtt = Some(crate::secret::SecretBytes::new(next, "tls_1rtt_read_secret"));
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        Ok(true)
    }

    /// Derives the next 1-RTT write secret and rotates the sealer.
    pub fn key_update_1rtt_write(&mut self) -> Result<bool, ConnectionError> {
        let Some(cur) = self.write_secret_1rtt.as_deref() else {
            return Ok(false);
        };
        let next = crate::crypto::kdf::derive_next_secret(cur)?;
        let (key, iv) = derive_key_iv(&next)?;
        let (seal, _) = select_packet_data_aead(&key, &iv);
        self.seal_1rtt = Some(Arc::new(seal));
        self.write_secret_1rtt =
            Some(crate::secret::SecretBytes::new(next, "tls_1rtt_write_secret"));
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        Ok(true)
    }

    /// Backwards-compatible helper for call sites that still update both directions together.
    pub fn key_update_1rtt(&mut self) -> Result<bool, ConnectionError> {
        let write = self.key_update_1rtt_write()?;
        let read = self.key_update_1rtt_read()?;
        Ok(write || read)
    }
}

impl crate::qftls::QuicTlsKeyInstaller for parking_lot::RwLock<CryptoContext> {
    fn clear_handshake_and_one_rtt_keys(&self) {
        let mut crypto = self.write();
        crypto.seal_handshake = None;
        crypto.open_handshake = None;
        crypto.hp_handshake = None;
        crypto.hp_handshake_open = None;
        crypto.seal_1rtt = None;
        crypto.open_1rtt = None;
        crypto.hp_1rtt = None;
        crypto.hp_1rtt_open = None;
        crypto.read_secret_1rtt = None;
        crypto.write_secret_1rtt = None;
        crypto.read_generation_1rtt = 0;
        crypto.write_generation_1rtt = 0;
        crypto.previous_read_1rtt.clear();
    }

    fn install_handshake_keys(&self, keys: crate::qftls::QuicTlsHandshakeKeys) {
        let mut crypto = self.write();
        crypto.seal_handshake = Some(keys.seal);
        crypto.open_handshake = Some(keys.open);
        crypto.hp_handshake = Some(keys.hp_seal);
        crypto.hp_handshake_open = Some(keys.hp_open);
    }

    fn install_one_rtt_keys(&self, keys: crate::qftls::QuicTlsOneRttKeys) {
        let mut crypto = self.write();
        crypto.seal_1rtt = Some(keys.seal);
        crypto.open_1rtt = Some(keys.open);
        crypto.hp_1rtt = Some(keys.hp_seal);
        crypto.hp_1rtt_open = Some(keys.hp_open);
        crypto.read_secret_1rtt = None;
        crypto.write_secret_1rtt = None;
        crypto.read_generation_1rtt = 0;
        crypto.write_generation_1rtt = 0;
        crypto.previous_read_1rtt.clear();
    }

    fn has_one_rtt_keys(&self) -> bool {
        let crypto = self.read();
        crypto.seal_1rtt.is_some()
            && crypto.open_1rtt.is_some()
            && crypto.hp_1rtt.is_some()
            && crypto.hp_1rtt_open.is_some()
    }

    fn key_update_1rtt_read(&self) -> Result<bool, ConnectionError> {
        self.write().key_update_1rtt_read()
    }

    fn key_update_1rtt_write(&self) -> Result<bool, ConnectionError> {
        self.write().key_update_1rtt_write()
    }

    fn rotate_1rtt_read_keypair(&self, open: Box<dyn qf_crypto::aead::AeadOpen + Send + Sync>) {
        self.write().rotate_1rtt_read_keypair(open);
    }

    fn rotate_1rtt_write_keypair(&self, seal: Box<dyn qf_crypto::aead::AeadSeal + Send + Sync>) {
        self.write().rotate_1rtt_write_keypair(seal);
    }
}

// Install AEAD/HP from TLS key schedule.
impl crate::crypto::aead::KeyScheduleHooks for CryptoContext {
    fn set_read_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_initial_open =
                    Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_handshake = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_handshake_open =
                    Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (_, open) = select_packet_data_aead(&key, &iv);
                    self.open_0rtt = Some(open);
                    let hp_key = derive_hp_key(secret)?;
                    self.hp_0rtt_open =
                        Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.install_read_1rtt_secret(secret)?;
                self.read_secret_1rtt =
                    Some(crate::secret::SecretBytes::new(secret.to_vec(), "tls_1rtt_read_secret"));
                self.read_generation_1rtt = 0;
                self.previous_read_1rtt.clear();
            }
        }
        Ok(())
    }
    fn set_write_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_handshake = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (seal, _) = select_packet_data_aead(&key, &iv);
                    self.seal_0rtt = Some(seal);
                    let hp_key = derive_hp_key(secret)?;
                    self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.install_write_1rtt_secret(secret)?;
                self.write_secret_1rtt =
                    Some(crate::secret::SecretBytes::new(secret.to_vec(), "tls_1rtt_write_secret"));
                self.write_generation_1rtt = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod secret_erasure_tests;

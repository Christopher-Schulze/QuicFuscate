use crate::crypto::aead::{self as tls_aead, AeadOpen, AeadSeal};
use crate::crypto::{select_packet_data_aead, AesGcm128, ChaCha20Poly1305};
use crate::error::ConnectionError;
use crate::optimize::telemetry;
use std::collections::VecDeque;
use std::sync::Arc;
// no direct varint helpers used here

/// Derive 16-byte header protection key from TLS secret (RFC 9001 compliant)
pub fn derive_hp_key(secret: &[u8]) -> [u8; 16] {
    let hp_vec = crate::crypto::kdf::derive_hdr_key(secret, 16);
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_vec[..16]);
    hp
}

/// Long header form bit (0x80) - set for long headers, clear for short headers.
pub const FORM_BIT: u8 = 0x80;
/// Fixed bit (0x40) - must be set in all QUIC packets except Version Negotiation.
pub const FIXED_BIT: u8 = 0x40;
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

/// Header protection trait for masking packet numbers
pub trait HeaderProtector {
    /// Derives a 5-byte HP mask from a 16-byte sample.
    fn new_mask(&self, sample: &[u8]) -> [u8; 5];
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
    let mut conn = crate::transport::Connection::new_client(scid, local, peer, config.clone());

    // Client selects an unpredictable initial DCID (RFC 9000). This DCID is also the ODCID
    // used for Initial key derivation (RFC 9001).
    let mut dcid = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut dcid);
    conn.set_initial_dcid(crate::transport::ConnectionId::from_vec(dcid.to_vec()));

    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = crate::fec::FecTransportObserver::new();
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut().set_stealth_mode(false, browser_profile);

    Ok(conn)
}

/// Creates a new server-side QUIC connection accepting a client handshake.
pub fn accept(
    scid: &[u8],
    odcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    // Create connection with server role
    // Record ODCID for Initial key derivation (RFC 9001).
    let mut conn = crate::transport::Connection::new_server(scid, local, peer, config.clone());
    if let Some(odcid) = odcid {
        conn.set_initial_dcid(crate::transport::ConnectionId::from_vec(odcid.to_vec()));
    }
    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = crate::fec::FecTransportObserver::new();
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut().set_stealth_mode(false, browser_profile);

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
    if out.len() < pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe {
        // AVX2 optimized path for 4-byte packet numbers
        if pn_len == 4
            && crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AVX2)
        {
            let pn_bytes = pn.to_be_bytes();
            let pn_vec = _mm_set_epi32(0, 0, 0, pn as i32);
            let shuffled = _mm_shuffle_epi8(
                pn_vec,
                _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3),
            );
            _mm_storeu_si32(out.as_mut_ptr() as *mut i32, shuffled);
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
        if unlikely(buf.len() < 1 + short_dcid_len) {
            return Err(ConnectionError::BufferTooShort);
        }
        let dcid = buf[1..1 + short_dcid_len].to_vec();
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
        let pn_off = 1 + short_dcid_len;
        return Ok((hdr, pn_off));
    }
    // Long header parsing
    if buf.len() < 7 {
        return Err(ConnectionError::BufferTooShort);
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version == 0 {
        // Version Negotiation must clear the fixed bit.
        if unlikely((first & crate::transport::packet::FIXED_BIT) != 0) {
            return Err(ConnectionError::InvalidPacket);
        }
    } else if unlikely((first & crate::transport::packet::FIXED_BIT) == 0) {
        return Err(ConnectionError::InvalidPacket);
    }
    let mut off = 5;
    if buf.len() < off + 1 {
        return Err(ConnectionError::BufferTooShort);
    }
    let dcid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + dcid_len + 1 {
        return Err(ConnectionError::BufferTooShort);
    }
    let dcid = buf[off..off + dcid_len].to_vec();
    off += dcid_len;
    let scid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + scid_len {
        return Err(ConnectionError::BufferTooShort);
    }
    let scid = buf[off..off + scid_len].to_vec();
    off += scid_len;
    let ty_bits = first & crate::transport::packet::TYPE_MASK;
    let ty = match (version, ty_bits) {
        (0, _) => PacketType::VersionNegotiation,
        (_, 0x00) => PacketType::Initial,
        (_, 0x10) => PacketType::ZeroRTT,
        (_, 0x20) => PacketType::Handshake,
        (_, 0x30) => PacketType::Retry,
        _ => PacketType::Initial,
    };
    let mut token = None;
    if ty == PacketType::Initial {
        let (tok_len, used) = crate::transport::varint::read_varint(&buf[off..])?;
        let tok_len = tok_len as usize;
        off += used;
        if buf.len() < off + tok_len {
            return Err(ConnectionError::BufferTooShort);
        }
        if tok_len > 0 {
            token = Some(buf[off..off + tok_len].to_vec());
        }
        off += tok_len;
    } else if ty == PacketType::Retry {
        if buf.len() < off + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let tok_len = buf.len() - off - 16;
        if tok_len > 0 {
            token = Some(buf[off..off + tok_len].to_vec());
        }
        off += tok_len;
    }
    let hdr = Header {
        ty,
        version,
        dcid,
        scid,
        pkt_num: 0,
        pkt_num_len: 0,
        token,
        versions: None,
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
    if out.is_empty() {
        return Err(ConnectionError::BufferTooShort);
    }
    let mut first = crate::transport::packet::FIXED_BIT; // 0x40
    if key_phase {
        first |= crate::transport::packet::KEY_PHASE_BIT;
    }
    out[0] = first;
    if out.len() < 1 + dcid.len() {
        return Err(ConnectionError::BufferTooShort);
    }
    out[1..1 + dcid.len()].copy_from_slice(dcid);
    Ok(1 + dcid.len())
}

/// Minimal header formatting to get PN offset and header fields
pub fn format_header(h: &Header, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if out.is_empty() {
        return Err(ConnectionError::BufferTooShort);
    }
    match h.ty {
        PacketType::Short => {
            let mut first = crate::transport::packet::FIXED_BIT; // 0x40
            if h.key_phase {
                first |= crate::transport::packet::KEY_PHASE_BIT;
            }
            out[0] = first;
            if out.len() < 1 + h.dcid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[1..1 + h.dcid.len()].copy_from_slice(&h.dcid);
            Ok(1 + h.dcid.len())
        }
        PacketType::Initial | PacketType::Handshake => {
            // Long header: [first][version:4][dcid_len:1][dcid][scid_len:1][scid]
            let mut first = FORM_BIT | FIXED_BIT; // long header with fixed bit
            first |= match h.ty {
                PacketType::Initial => 0x00,
                PacketType::Handshake => 0x20,
                _ => 0x00,
            };
            out[0] = first;
            if out.len() < 1 + 4 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[1..5].copy_from_slice(&h.version.to_be_bytes());
            let mut off = 5;
            if out.len() < off + 1 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off] = h.dcid.len() as u8;
            off += 1;
            if out.len() < off + h.dcid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + h.dcid.len()].copy_from_slice(&h.dcid);
            off += h.dcid.len();
            if out.len() < off + 1 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off] = h.scid.len() as u8;
            off += 1;
            if out.len() < off + h.scid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + h.scid.len()].copy_from_slice(&h.scid);
            off += h.scid.len();
            if h.ty == PacketType::Initial {
                let token = h.token.as_deref().unwrap_or(&[]);
                off += crate::transport::varint::write_varint(token.len() as u64, &mut out[off..])?;
                if out.len() < off + token.len() {
                    return Err(ConnectionError::BufferTooShort);
                }
                out[off..off + token.len()].copy_from_slice(token);
                off += token.len();
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

    // Remove header protection when sample is available; otherwise accept unprotected headers.
    // Sample is taken 4 bytes after the PN offset.
    let sample_off = pn_off + 4;
    let pn_len;
    if buf.len() >= sample_off + 16 {
        let mask = hp.new_mask(&buf[sample_off..sample_off + 16]);
        if hdr.ty == PacketType::Handshake {
            trace_handshake_hp("hp open hs", &buf[sample_off..sample_off + 16], mask);
        }
        if hdr.ty == PacketType::Short {
            buf[0] ^= mask[0] & 0x1f;
            hdr.key_phase = (buf[0] & crate::transport::packet::KEY_PHASE_BIT) != 0;
        } else {
            buf[0] ^= mask[0] & 0x0f;
        }
        pn_len = (buf[0] & 0x03) as usize + 1;
        hdr.pkt_num_len = pn_len;
        for i in 0..pn_len {
            buf[pn_off + i] ^= mask[1 + i];
        }
    } else {
        pn_len = (buf[0] & 0x03) as usize + 1;
        hdr.pkt_num_len = pn_len;
    }

    if buf.len() < pn_off + pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    let mut encoded_pn = 0u32;
    for i in 0..pn_len {
        encoded_pn = (encoded_pn << 8) | buf[pn_off + i] as u32;
    }
    hdr.pkt_num =
        crate::optimize::transport::decode_packet_number(encoded_pn, largest_pn_hint, pn_len as u8);

    let aad_len = pn_off + pn_len;
    let payload_off = aad_len;
    let payload_len = buf.len() - payload_off;

    if payload_len < 16 {
        return Err(ConnectionError::BufferTooShort);
    }

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
mod tests {
    use super::*;

    #[test]
    fn initial_header_token_roundtrip() {
        let header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![0x11, 0x22, 0x33],
            scid: vec![0x44, 0x55],
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(vec![0x01, 0x02, 0x03, 0x04]),
            versions: None,
            key_phase: false,
        };
        let mut buf = vec![0u8; 64];
        let off = format_header(&header, &mut buf).expect("format header");
        let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
        assert_eq!(parsed.ty, PacketType::Initial);
        assert_eq!(parsed.token, header.token);
        assert_eq!(off, parsed_off);
    }

    #[test]
    fn initial_header_empty_token_roundtrip() {
        let header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![0x01],
            scid: vec![0x02],
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };
        let mut buf = vec![0u8; 32];
        let off = format_header(&header, &mut buf).expect("format header");
        let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
        assert_eq!(parsed.ty, PacketType::Initial);
        assert!(parsed.token.is_none());
        assert_eq!(off, parsed_off);
    }

    #[test]
    fn version_negotiation_clears_fixed_bit_and_parses() {
        let pkt = generate_version_negotiation_packet(
            &[crate::transport::PROTOCOL_VERSION],
            &[crate::transport::PROTOCOL_VERSION],
            &[0x22], // dcid (echoes client SCID)
            &[0x11], // scid (echoes client DCID)
        );
        assert_eq!(pkt[0] & FORM_BIT, FORM_BIT);
        assert_eq!(pkt[0] & FIXED_BIT, 0);
        let (parsed, _) = parse_header(&pkt, 0).expect("parse vn");
        assert_eq!(parsed.ty, PacketType::VersionNegotiation);
    }

    #[test]
    fn version_negotiation_with_fixed_bit_set_is_rejected() {
        let mut pkt = vec![
            FORM_BIT | FIXED_BIT,
            0x00,
            0x00,
            0x00,
            0x00, // version = 0 (VN)
            0x01,
            0x11, // dcid
            0x01,
            0x22, // scid
        ];
        pkt.extend_from_slice(&crate::transport::PROTOCOL_VERSION.to_be_bytes());
        assert!(matches!(parse_header(&pkt, 0), Err(ConnectionError::InvalidPacket)));
    }

    // --- QUIC version negotiation (TODO-453) ---

    #[test]
    fn vn_packet_generation_and_parsing_roundtrip() {
        let server_versions =
            vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
        let pkt = generate_version_negotiation_packet(
            &[crate::transport::PROTOCOL_VERSION],
            &server_versions,
            &[0xaa, 0xbb], // dcid
            &[0xcc],       // scid
        );
        let parsed = parse_version_negotiation(&pkt).expect("VN must parse");
        assert_eq!(parsed, server_versions);
    }

    #[test]
    fn vn_packet_parse_rejects_non_vn_packets() {
        // Fixed bit set => not a VN packet.
        let bad = vec![FORM_BIT | FIXED_BIT, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_version_negotiation(&bad).is_none());
        // Non-zero version field => not a VN packet.
        let bad2 = vec![FORM_BIT, 0, 0, 0, 1, 0, 0];
        assert!(parse_version_negotiation(&bad2).is_none());
        // Truncated version list (not a multiple of 4).
        let bad3 = vec![FORM_BIT, 0, 0, 0, 0, 0x01, 0xaa, 0x01, 0xbb, 0x01, 0x02, 0x03];
        assert!(parse_version_negotiation(&bad3).is_none());
        // Empty packet.
        assert!(parse_version_negotiation(&[]).is_none());
    }

    #[test]
    fn negotiate_version_selects_highest_common() {
        let client = vec![crate::transport::PROTOCOL_VERSION];
        let server =
            vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
        // Server prefers v2 but client only offers v1 => v1 selected.
        assert_eq!(negotiate_version(&client, &server), Some(crate::transport::PROTOCOL_VERSION));
        // Both offer v2 => server's top preference (v2) selected.
        let client2 =
            vec![crate::transport::PROTOCOL_VERSION, crate::transport::PROTOCOL_VERSION_V2];
        assert_eq!(
            negotiate_version(&client2, &server),
            Some(crate::transport::PROTOCOL_VERSION_V2)
        );
    }

    #[test]
    fn negotiate_version_no_common_returns_none() {
        let client = vec![0xdeadbeef];
        let server = vec![crate::transport::PROTOCOL_VERSION];
        assert!(negotiate_version(&client, &server).is_none());
    }

    #[test]
    fn v1_and_v2_coexistence_roundtrip() {
        // Server advertises both v1 and v2; client offers v2 first.
        let server_versions =
            vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
        let client_versions = vec![crate::transport::PROTOCOL_VERSION_V2];
        // Version selection picks v2.
        assert_eq!(
            negotiate_version(&client_versions, &server_versions),
            Some(crate::transport::PROTOCOL_VERSION_V2)
        );
        // VN packet contains both server versions and parses back identically.
        let pkt = generate_version_negotiation_packet(
            &client_versions,
            &server_versions,
            &[0x01],
            &[0x02],
        );
        assert_eq!(parse_version_negotiation(&pkt).unwrap(), server_versions);
    }

    #[test]
    fn unsupported_version_triggers_vn_response() {
        // Client offers only an unsupported version; server has no common match.
        let client_versions = vec![0xdeadbeef];
        let server_versions =
            vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
        assert!(negotiate_version(&client_versions, &server_versions).is_none());
        // Server responds with a VN packet advertising its supported versions.
        let pkt = generate_version_negotiation_packet(
            &client_versions,
            &server_versions,
            &[0x11],
            &[0x22],
        );
        let parsed = parse_version_negotiation(&pkt).expect("VN response must parse");
        assert_eq!(parsed, server_versions);
        assert!(!parsed.contains(&0xdeadbeef));
    }

    #[test]
    fn retry_header_parses_token_payload() {
        let mut pkt = vec![
            FORM_BIT | FIXED_BIT | 0x30, // Retry
            0x00,
            0x00,
            0x00,
            0x01, // version = v1
            0x01,
            0xaa, // dcid
            0x01,
            0xbb, // scid
            0x01,
            0x02, // token
        ];
        pkt.extend_from_slice(&[0u8; 16]); // integrity tag
        let (parsed, _) = parse_header(&pkt, 0).expect("parse retry");
        assert_eq!(parsed.ty, PacketType::Retry);
        assert_eq!(parsed.scid, vec![0xbb]);
        assert_eq!(parsed.token, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn unprotect_requires_keys_for_encrypted_packets() {
        let header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![0x11, 0x22, 0x33],
            scid: vec![0x44, 0x55],
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };
        let mut buf = vec![0u8; 64];
        let off = format_header(&header, &mut buf).expect("format");
        let crypto = CryptoContext::default();
        let err = unprotect_and_decrypt(&crypto, &mut buf[..off], 0, 0).expect_err("must fail");
        assert!(matches!(err, ConnectionError::Done));
    }

    #[test]
    fn read_key_window_retains_recent_generations() {
        let mut crypto = CryptoContext::default();
        let secret = [0x11u8; 32];
        crate::crypto::aead::KeyScheduleHooks::set_read_secret(
            &mut crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &secret,
        );
        for _ in 0..(ONE_RTT_READ_KEY_WINDOW + 3) {
            assert!(crypto.key_update_1rtt_read());
        }
        assert_eq!(crypto.previous_read_1rtt.len(), ONE_RTT_READ_KEY_WINDOW);
    }

    #[test]
    fn short_header_decrypt_falls_back_to_previous_read_key() {
        let mut crypto = CryptoContext::default();
        let secret = [0x42u8; 32];
        crate::crypto::aead::KeyScheduleHooks::set_read_secret(
            &mut crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &secret,
        );
        crate::crypto::aead::KeyScheduleHooks::set_write_secret(
            &mut crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &secret,
        );

        let header = Header {
            ty: PacketType::Short,
            version: 0,
            dcid: vec![],
            scid: vec![],
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };

        let mut packet = vec![0u8; 64];
        let hdr_no_pn = format_header(&header, &mut packet).expect("format");
        let pn = 7u64;
        let pn_len = 1usize;
        packet[hdr_no_pn] = pn as u8;
        let hdr_len = hdr_no_pn + pn_len;
        let plaintext = b"hello";
        packet[hdr_len..hdr_len + plaintext.len()].copy_from_slice(plaintext);
        let total = hdr_len + plaintext.len() + 16;
        let used = encrypt_and_protect(
            &crypto,
            &mut packet[..total],
            hdr_len,
            pn,
            pn_len,
            PacketType::Short,
        )
        .expect("seal");

        assert!(crypto.key_update_1rtt_read());

        let mut incoming = packet[..used].to_vec();
        let (_hdr, aad_len, pt_len) =
            unprotect_and_decrypt(&crypto, &mut incoming, 0, 0).expect("decrypt with read window");
        assert_eq!(&incoming[aad_len..aad_len + pt_len], plaintext);
    }

    #[test]
    fn data_aead_batch_seal_open_via_crypto_context() {
        use crate::crypto::aead::{AeadOpenItem, AeadSealItem};

        let key = [0x7Eu8; 32];
        let iv = [0x6Du8; 16];
        let (seal, open) = select_packet_data_aead(&key, &iv);
        let crypto = CryptoContext {
            seal_1rtt: Some(Arc::new(seal)),
            open_1rtt: Some(Arc::new(open)),
            ..CryptoContext::default()
        };

        let ad = b"pkt-batch-ad";
        let pt = b"packet-batch-payload";
        let mut bufs: Vec<Vec<u8>> = (0..4)
            .map(|_| {
                let mut b = vec![0u8; pt.len() + 16];
                b[..pt.len()].copy_from_slice(pt);
                b
            })
            .collect();
        let mut seal_items: Vec<AeadSealItem<'_>> = bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadSealItem {
                counter: i as u64 + 10,
                ad,
                buf: buf.as_mut_slice(),
                plaintext_len: pt.len(),
            })
            .collect();
        seal_data_aead_batch(&crypto, seal_items.as_mut_slice()).expect("batch seal");

        let mut open_items: Vec<AeadOpenItem<'_>> = bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadOpenItem { counter: i as u64 + 10, ad, buf: buf.as_mut_slice() })
            .collect();
        open_data_aead_batch(&crypto, open_items.as_mut_slice()).expect("batch open");
        for buf in &bufs {
            assert_eq!(&buf[..pt.len()], pt);
        }
    }

    #[test]
    fn tls_cover_same_material_reinstall_preserves_counters() {
        let mut crypto = CryptoContext::default();
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let material = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv };
        assert_eq!(
            crypto.install_tls_cover_cipher(material),
            Ok(TlsCoverInstallOutcome::Installed)
        );

        let plaintext = b"partial-session";
        let aad = b"tls-cover-aad";
        let mut ciphertext = crypto.encrypt_tls_cover_record(aad, plaintext).expect("seal");
        crypto.decrypt_tls_cover_record(aad, &mut ciphertext).expect("open");
        assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (1, 1));

        assert_eq!(
            crypto.install_tls_cover_cipher(material),
            Ok(TlsCoverInstallOutcome::Unchanged)
        );
        assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (1, 1));
    }

    #[test]
    fn tls_cover_fresh_material_rotation_resets_state_and_retires_old_material() {
        let mut crypto = CryptoContext::default();
        let chacha_key = [0x31u8; 32];
        let aes_key = [0x42u8; 16];
        let first_iv = [0x53u8; 12];
        let second_iv = [0x64u8; 12];
        let first = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &chacha_key, iv: &first_iv };
        let second = TlsCoverKeyMaterial::Aes128Gcm { key: &aes_key, iv: &second_iv };
        crypto.install_tls_cover_cipher(first).expect("initial install");
        crypto.encrypt_tls_cover_record(b"aad", b"record").expect("partial use");

        assert_eq!(crypto.install_tls_cover_cipher(second), Ok(TlsCoverInstallOutcome::Installed));
        assert_eq!(crypto.tls_cover_cipher_kind(), Some(TlsCoverCipherKind::Aes128Gcm));
        assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (0, 0));
        assert_eq!(crypto.retired_tls_cover_identities.len(), 1);
        assert_eq!(crypto.install_tls_cover_cipher(first), Err(ConnectionError::KeyUpdateError));
    }

    #[test]
    fn tls_cover_repeated_rotation_never_reactivates_retired_material() {
        let mut crypto = CryptoContext::default();
        let key_a = [0x71u8; 32];
        let key_b = [0x72u8; 16];
        let key_c = [0x73u8; 32];
        let iv_a = [0x81u8; 12];
        let iv_b = [0x82u8; 12];
        let iv_c = [0x83u8; 12];
        let material_a = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key_a, iv: &iv_a };
        let material_b = TlsCoverKeyMaterial::Aes128Gcm { key: &key_b, iv: &iv_b };
        let material_c = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key_c, iv: &iv_c };

        crypto.install_tls_cover_cipher(material_a).expect("install A");
        crypto.install_tls_cover_cipher(material_b).expect("rotate to B");
        crypto.install_tls_cover_cipher(material_c).expect("rotate to C");
        assert_eq!(crypto.retired_tls_cover_identities.len(), 2);
        assert_eq!(
            crypto.install_tls_cover_cipher(material_a),
            Err(ConnectionError::KeyUpdateError)
        );
        assert_eq!(
            crypto.install_tls_cover_cipher(material_b),
            Err(ConnectionError::KeyUpdateError)
        );
        assert_eq!(
            crypto.install_tls_cover_cipher(material_c),
            Ok(TlsCoverInstallOutcome::Unchanged)
        );

        let mut reconnect = CryptoContext::default();
        assert_eq!(
            reconnect.install_tls_cover_cipher(material_a),
            Ok(TlsCoverInstallOutcome::Installed),
            "a fresh connection owns an independent sequence space"
        );
    }

    #[test]
    fn tls_cover_sequence_exhaustion_fails_closed() {
        let mut crypto = CryptoContext::default();
        let key = [0x91u8; 32];
        let iv = [0x92u8; 12];
        crypto
            .install_tls_cover_cipher(TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv })
            .expect("install");

        crypto.tls_cover_write_seq = u64::MAX;
        assert_eq!(
            crypto.encrypt_tls_cover_record(b"aad", b"record"),
            Err(ConnectionError::AeadLimitReached)
        );
        crypto.tls_cover_read_seq = u64::MAX;
        let mut ciphertext = [0u8; 16];
        assert_eq!(
            crypto.decrypt_tls_cover_record(b"aad", &mut ciphertext),
            Err(ConnectionError::AeadLimitReached)
        );
    }

    #[test]
    fn pending_handshake_send_tracks_only_unsent_handshake_flights() {
        let mut crypto = CryptoContext::default();
        assert!(!crypto.has_pending_handshake_send());

        crypto.crypto_handshake.send(b"client-finished");
        assert!(crypto.has_pending_handshake_send());

        let (_, bytes) =
            crypto.crypto_handshake.next_crypto_frame(usize::MAX).expect("queued handshake flight");
        assert_eq!(bytes, b"client-finished");
        assert!(!crypto.has_pending_handshake_send());
    }
}

/// Applies header protection to an outgoing packet (masks first byte and PN).
pub fn protect_header(
    crypto: &CryptoContext,
    buf: &mut [u8],
    pn_off: usize,
    pn_len: usize,
    pkt_type: PacketType,
) -> Result<(), ConnectionError> {
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

    // Sample is taken 4 bytes after the PN offset
    let sample_off = pn_off + 4;
    if buf.len() < sample_off + 16 {
        return Err(ConnectionError::BufferTooShort);
    }

    let mask = hp.new_mask(&buf[sample_off..sample_off + 16]);
    if pkt_type == PacketType::Handshake {
        trace_handshake_hp("hp protect hs", &buf[sample_off..sample_off + 16], mask);
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

    if hdr_len < pn_len {
        return Err(ConnectionError::InvalidPacket);
    }
    if buf.len() < hdr_len + 16 {
        return Err(ConnectionError::BufferTooShort);
    }

    // Encode packet number length (pn_len - 1) into the low 2 bits of the first header byte.
    // This is required for correct header protection removal on the peer.
    if pn_len == 0 || pn_len > 4 {
        return Err(ConnectionError::InvalidPacket);
    }
    buf[0] = (buf[0] & !PKT_NUM_MASK) | (((pn_len as u8) - 1) & PKT_NUM_MASK);

    // The packet number offset
    let pn_off = hdr_len - pn_len;

    // Encrypt payload in-place. Reserve 16 bytes for AEAD tag at the tail of the payload buffer.
    let (aad, payload) = buf.split_at_mut(hdr_len);
    let plaintext_len = payload.len().saturating_sub(16);
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, payload, plaintext_len, None)?;

    // Apply header protection
    protect_header(crypto, buf, pn_off, pn_len, pkt_type)?;

    Ok(hdr_len + ciphertext_len)
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
/// version exists — in that case the caller should emit a Version Negotiation
/// packet via [`generate_version_negotiation_packet`]. See TODO-453.
pub fn negotiate_version(client_versions: &[u32], server_versions: &[u32]) -> Option<u32> {
    server_versions.iter().find(|&&sv| client_versions.contains(&sv)).copied()
}

/// Builds a Version Negotiation (VN) response packet listing `server_versions`.
///
/// Per RFC 9000 Section 17.2.1, the VN packet's DCID echoes the client's SCID
/// and its SCID echoes the client's DCID; the caller is responsible for passing
/// the already-swapped connection IDs in `dcid` / `scid`. The form bit is set
/// and the fixed bit is cleared, as required for VN packets. The `client_versions`
/// argument is accepted for API symmetry but is not encoded — only the server's
/// supported versions appear in the packet body. See TODO-453.
pub fn generate_version_negotiation_packet(
    _client_versions: &[u32],
    server_versions: &[u32],
    dcid: &[u8],
    scid: &[u8],
) -> Vec<u8> {
    let mut pkt =
        Vec::with_capacity(1 + 4 + 1 + dcid.len() + 1 + scid.len() + server_versions.len() * 4);
    // First byte: form bit set, fixed bit cleared, remaining bits random.
    let first = (crate::transport::rand::rand_u8() | FORM_BIT) & !FIXED_BIT;
    pkt.push(first);
    // Version field is 0x00000000 for VN packets.
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // DCID (echoes the client's SCID).
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    // SCID (echoes the client's DCID).
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(scid);
    // Supported versions, big-endian.
    for v in server_versions {
        pkt.extend_from_slice(&v.to_be_bytes());
    }
    pkt
}

/// Extracts the version list from a Version Negotiation packet.
///
/// Returns `Some(versions)` when `pkt` is a well-formed VN packet (form bit set,
/// fixed bit clear, version field zero, and a whole number of 4-byte version
/// entries). Returns `None` otherwise. See TODO-453.
pub fn parse_version_negotiation(pkt: &[u8]) -> Option<Vec<u32>> {
    if pkt.is_empty() {
        return None;
    }
    let first = pkt[0];
    // VN packets set the form bit and clear the fixed bit.
    if (first & FORM_BIT) == 0 || (first & FIXED_BIT) != 0 {
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
    if off >= pkt.len() {
        return None;
    }
    let dcid_len = pkt[off] as usize;
    off += 1;
    if off + dcid_len > pkt.len() {
        return None;
    }
    off += dcid_len;
    // SCID length + bytes.
    if off >= pkt.len() {
        return None;
    }
    let scid_len = pkt[off] as usize;
    off += 1;
    if off + scid_len > pkt.len() {
        return None;
    }
    off += scid_len;
    // Remaining bytes must be a whole number of 4-byte version entries.
    let remaining = pkt.len().saturating_sub(off);
    if remaining == 0 || !remaining.is_multiple_of(4) {
        return None;
    }
    let count = remaining / 4;
    let mut versions = Vec::with_capacity(count);
    for _ in 0..count {
        versions.push(u32::from_be_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]));
        off += 4;
    }
    Some(versions)
}

/// Appends a Retry Integrity Tag to a Retry packet buffer (RFC 9001 Section 5.8).
pub fn append_retry_tag(buf: &mut Vec<u8>, _odcid: &[u8], _version: u32) {
    let hdr_len = buf.len();
    let mut pseudo = Vec::with_capacity(1 + _odcid.len() + hdr_len);
    pseudo.push(_odcid.len() as u8);
    pseudo.extend_from_slice(_odcid);
    pseudo.extend_from_slice(&buf[..hdr_len]);
    const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const RETRY_INTEGRITY_NONCE_V1: [u8; 12] =
        [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(
        &RETRY_INTEGRITY_KEY_V1,
        &RETRY_INTEGRITY_NONCE_V1,
        &pseudo,
    );
    buf.extend_from_slice(&tag);
}

/// Verifies the Retry Integrity Tag of a received Retry packet.
pub fn verify_retry_tag(packet: &[u8], odcid: &[u8], _version: u32) -> Result<(), ConnectionError> {
    if packet.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let hdr_len = packet.len() - 16;
    let tag_in = &packet[hdr_len..];
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + hdr_len);
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&packet[..hdr_len]);
    const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const RETRY_INTEGRITY_NONCE_V1: [u8; 12] =
        [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(
        &RETRY_INTEGRITY_KEY_V1,
        &RETRY_INTEGRITY_NONCE_V1,
        &pseudo,
    );
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
pub fn derive_key_iv(secret: &[u8]) -> ([u8; 32], [u8; 12]) {
    let key_vec = crate::crypto::kdf::derive_pkt_key(secret, 32);
    let iv_vec = crate::crypto::kdf::derive_pkt_iv(secret, 12);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec[..32]);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec[..12]);
    (key, iv)
}

/// Derive Initial secrets from destination connection ID (RFC 9001 compliant)
pub fn derive_initial_secrets(dcid: &[u8], version: u32) -> (Vec<u8>, Vec<u8>) {
    let initial_secret = crate::crypto::kdf::derive_initial_secret(dcid, version);
    let client_secret = crate::crypto::kdf::derive_client_initial_secret(&initial_secret);
    let server_secret = crate::crypto::kdf::derive_server_initial_secret(&initial_secret);
    (client_secret, server_secret)
}

/// Apply header protection mask (for encryption)
pub fn apply_hp(
    first: u8,
    pn: &mut [u8],
    sample: &[u8],
    is_long: bool,
    hp: &dyn HeaderProtector,
) -> (u8, usize) {
    let mask = hp.new_mask(sample);
    let first_new = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };
    // PN length is encoded in the low 2 bits of the (possibly masked) first byte, plus 1
    let pn_len = ((first_new & PKT_NUM_MASK) as usize) + 1;
    for i in 0..pn_len.min(4) {
        pn[i] ^= mask[i + 1];
    }
    (first_new, pn_len)
}

/// Remove header protection mask (for decryption)
pub fn remove_hp(
    buf: &mut [u8],
    hp: &dyn HeaderProtector,
    pn_offset: usize,
) -> Result<(u8, usize), ConnectionError> {
    if buf.len() < pn_offset + 4 + 16 {
        return Err(ConnectionError::InvalidPacket);
    }

    // Sample starts 4 bytes after the packet number offset
    let sample_offset = pn_offset + 4;
    let sample = &buf[sample_offset..sample_offset + 16];

    // Generate mask
    let mask = hp.new_mask(sample);

    // Check if it's a long header packet
    let first = buf[0];
    let is_long = (first & FORM_BIT) != 0;

    // Unmask the first byte to get packet number length
    let first_unmasked = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };

    // Get packet number length (encoded in low 2 bits + 1)
    let pn_len = ((first_unmasked & PKT_NUM_MASK) as usize) + 1;

    // Unmask the packet number
    for i in 0..pn_len.min(4) {
        if pn_offset + i < buf.len() {
            buf[pn_offset + i] ^= mask[i + 1];
        }
    }

    // Update the first byte
    buf[0] = first_unmasked;

    Ok((first_unmasked, pn_len))
}

/// Decrypt a QUIC packet payload (alternative implementation)
pub fn decrypt_payload(
    buf: &mut [u8],
    pn: u64,
    _pn_len: usize,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadOpen,
) -> Result<usize, ConnectionError> {
    if buf.len() < hdr_len + 16 {
        // Need at least header + AEAD tag
        return Err(ConnectionError::InvalidPacket);
    }

    // Split buffer to avoid borrowing conflicts
    let (aad_buf, payload_buf) = buf.split_at_mut(hdr_len);
    let aad = &aad_buf[..hdr_len];

    // Decrypt in-place
    let _payload_len = payload_buf.len();
    let plaintext_len = aead.open_with_u64_counter(pn, aad, payload_buf)?;

    Ok(hdr_len + plaintext_len)
}

/// Encrypt a QUIC packet payload
pub fn encrypt_packet(
    buf: &mut [u8],
    payload_len: usize,
    pn: u64,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadSeal,
) -> Result<usize, ConnectionError> {
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
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, buf, hdr_len + payload_len, None)?;

    Ok(ciphertext_len)
}

/// CryptoStream manages CRYPTO frame data for each encryption level
#[derive(Default)]
pub struct CryptoStream {
    /// Send buffer for outgoing CRYPTO frames
    send_buf: Vec<u8>,
    /// Current send offset
    send_off: u64,
    /// Receive buffer for incoming CRYPTO frames (may arrive out of order)
    recv_buf: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Next expected receive offset
    recv_off: u64,
    /// Maximum receive offset seen
    recv_max: u64,
}

impl CryptoStream {
    /// Creates a new empty CryptoStream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue data to be sent in CRYPTO frames
    pub fn send(&mut self, data: &[u8]) {
        self.send_buf.extend_from_slice(data);
    }

    /// Get next CRYPTO frame to send (up to max_len bytes)
    pub fn next_crypto_frame(&mut self, max_len: usize) -> Option<(u64, Vec<u8>)> {
        if self.send_buf.is_empty() {
            return None;
        }

        let len = max_len.min(self.send_buf.len());
        let offset = self.send_off;
        let data = self.send_buf.drain(..len).collect();
        self.send_off += len as u64;

        Some((offset, data))
    }

    /// Returns true while unsent CRYPTO bytes remain at this encryption level.
    pub fn has_pending_send(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// Receive a CRYPTO frame (may be out of order)
    pub fn recv(&mut self, offset: u64, data: Vec<u8>) -> Result<(), ConnectionError> {
        if offset + data.len() as u64 > self.recv_max + 65536 {
            // Reject data too far ahead
            return Err(ConnectionError::FlowControl);
        }

        self.recv_max = self.recv_max.max(offset + data.len() as u64);
        self.recv_buf.insert(offset, data);
        Ok(())
    }

    /// Read available contiguous data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut written = 0;

        while written < buf.len() {
            if let Some(data) = self.recv_buf.remove(&self.recv_off) {
                let to_copy = (buf.len() - written).min(data.len());
                buf[written..written + to_copy].copy_from_slice(&data[..to_copy]);
                written += to_copy;
                self.recv_off += to_copy as u64;

                // If we didn't consume all data, put remainder back
                if to_copy < data.len() {
                    self.recv_buf.insert(self.recv_off, data[to_copy..].to_vec());
                    break;
                }
            } else {
                break;
            }
        }

        written
    }

    /// Check if there's data ready to read
    pub fn has_data(&self) -> bool {
        self.recv_buf.contains_key(&self.recv_off)
    }

    /// Resets all buffers and offsets to initial state.
    pub fn reset(&mut self) {
        self.send_buf.clear();
        self.send_off = 0;
        self.recv_buf.clear();
        self.recv_off = 0;
        self.recv_max = 0;
    }
}

/// Identifies the AEAD algorithm used for TLS Cover traffic encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherKind {
    /// ChaCha20-Poly1305 AEAD.
    ChaCha20Poly1305,
    /// AES-128-GCM AEAD.
    Aes128Gcm,
}

/// Borrowed TLS Cover key material accepted by the single installation contract.
///
/// Reinstalling the active material is an idempotent no-op that preserves record
/// sequence numbers. Installing fresh material retires the previous identity and
/// resets both directions. A retired identity cannot be installed again in the
/// same context, which prevents nonce reuse after profile or cipher rotation.
#[derive(Clone, Copy)]
pub enum TlsCoverKeyMaterial<'a> {
    /// ChaCha20-Poly1305 with a 256-bit key and 96-bit base IV.
    ChaCha20Poly1305 { key: &'a [u8; 32], iv: &'a [u8; 12] },
    /// AES-128-GCM with a 128-bit key and 96-bit base IV.
    Aes128Gcm { key: &'a [u8; 16], iv: &'a [u8; 12] },
}

impl TlsCoverKeyMaterial<'_> {
    fn identity(self) -> [u8; 32] {
        let mut encoded = [0u8; 45];
        let encoded_len = match self {
            Self::ChaCha20Poly1305 { key, iv } => {
                encoded[0] = 1;
                encoded[1..33].copy_from_slice(key);
                encoded[33..45].copy_from_slice(iv);
                45
            }
            Self::Aes128Gcm { key, iv } => {
                encoded[0] = 2;
                encoded[1..17].copy_from_slice(key);
                encoded[17..29].copy_from_slice(iv);
                29
            }
        };
        crate::crypto::hkdf::sha256(&encoded[..encoded_len])
    }

    fn cipher_pair(self) -> (TlsCoverCipher, TlsCoverCipher) {
        match self {
            Self::ChaCha20Poly1305 { key, iv } => (
                TlsCoverCipher::ChaCha(ChaCha20Poly1305::new(key, iv)),
                TlsCoverCipher::ChaCha(ChaCha20Poly1305::new(key, iv)),
            ),
            Self::Aes128Gcm { key, iv } => (
                TlsCoverCipher::AesGcm(AesGcm128::new(key, iv)),
                TlsCoverCipher::AesGcm(AesGcm128::new(key, iv)),
            ),
        }
    }
}

/// Result of a TLS Cover key installation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverInstallOutcome {
    /// Fresh key material replaced the active cipher pair.
    Installed,
    /// The exact active key material was already installed; counters were preserved.
    Unchanged,
}

pub(crate) enum TlsCoverCipher {
    ChaCha(ChaCha20Poly1305),
    AesGcm(AesGcm128),
}

impl TlsCoverCipher {
    #[inline(always)]
    fn seal(
        &self,
        counter: u64,
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, ConnectionError> {
        match self {
            TlsCoverCipher::ChaCha(cipher) => crate::crypto::aead::AeadSeal::seal_with_u64_counter(
                cipher,
                counter,
                aad,
                buffer,
                plaintext_len,
                None,
            ),
            TlsCoverCipher::AesGcm(cipher) => tls_aead::AeadSeal::seal_with_u64_counter(
                cipher,
                counter,
                aad,
                buffer,
                plaintext_len,
                None,
            ),
        }
    }

    #[inline(always)]
    fn open(&self, counter: u64, aad: &[u8], buffer: &mut [u8]) -> Result<usize, ConnectionError> {
        match self {
            TlsCoverCipher::ChaCha(cipher) => {
                crate::crypto::aead::AeadOpen::open_with_u64_counter(cipher, counter, aad, buffer)
            }
            TlsCoverCipher::AesGcm(cipher) => {
                tls_aead::AeadOpen::open_with_u64_counter(cipher, counter, aad, buffer)
            }
        }
    }

    #[inline(always)]
    pub(crate) fn kind(&self) -> TlsCoverCipherKind {
        match self {
            TlsCoverCipher::ChaCha(_) => TlsCoverCipherKind::ChaCha20Poly1305,
            TlsCoverCipher::AesGcm(_) => TlsCoverCipherKind::Aes128Gcm,
        }
    }
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
    pub read_secret_1rtt: Option<Vec<u8>>,
    /// Current 1-RTT write secret for key update derivation.
    pub write_secret_1rtt: Option<Vec<u8>>,
    /// Current 1-RTT read key generation counter.
    pub read_generation_1rtt: u64,
    /// Current 1-RTT write key generation counter.
    pub write_generation_1rtt: u64,
    /// Whether 0-RTT early data is enabled for this context.
    pub zero_rtt_enabled: bool,
    previous_read_1rtt: VecDeque<PreviousRead1RttKey>,
    seal_tls_cover: Option<TlsCoverCipher>,
    open_tls_cover: Option<TlsCoverCipher>,
    active_tls_cover_identity: Option<[u8; 32]>,
    retired_tls_cover_identities: Vec<[u8; 32]>,
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
    pub fn install_0rtt_keys(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        self.zero_rtt_enabled = true;
        let (read_key, read_iv) = derive_key_iv(read_secret);
        let (write_key, write_iv) = derive_key_iv(write_secret);
        let (_, open) = select_packet_data_aead(&read_key, &read_iv);
        let (seal, _) = select_packet_data_aead(&write_key, &write_iv);
        self.open_0rtt = Some(open);
        self.seal_0rtt = Some(seal);
        self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::new(write_secret)));
        self.hp_0rtt_open = Some(Box::new(crate::crypto::aead::AesHp::new(read_secret)));
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
        let identity = material.identity();
        if self.active_tls_cover_identity == Some(identity) {
            return Ok(TlsCoverInstallOutcome::Unchanged);
        }
        if self.retired_tls_cover_identities.contains(&identity) {
            return Err(ConnectionError::KeyUpdateError);
        }

        let (seal, open) = material.cipher_pair();
        if let Some(active_identity) = self.active_tls_cover_identity.replace(identity) {
            self.retired_tls_cover_identities.push(active_identity);
        }
        self.seal_tls_cover = Some(seal);
        self.open_tls_cover = Some(open);
        self.tls_cover_write_seq = 0;
        self.tls_cover_read_seq = 0;
        Ok(TlsCoverInstallOutcome::Installed)
    }

    #[inline]
    /// Returns the TLS Cover cipher algorithm in use, if configured.
    pub fn tls_cover_cipher_kind(&self) -> Option<TlsCoverCipherKind> {
        self.seal_tls_cover.as_ref().map(|cipher| cipher.kind())
    }

    /// Encrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn encrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        let cipher = self
            .seal_tls_cover
            .as_ref()
            .ok_or(ConnectionError::CryptoError("crypto failure".into()))?;

        let seq = self.tls_cover_write_seq;
        self.tls_cover_write_seq = seq.checked_add(1).ok_or(ConnectionError::AeadLimitReached)?;

        let mut buffer = Vec::with_capacity(plaintext.len() + 16);
        buffer.extend_from_slice(plaintext);
        let pt_len = plaintext.len();
        buffer.resize(pt_len + 16, 0);

        let result = cipher.seal(seq, aad, buffer.as_mut_slice(), pt_len);
        match result {
            Ok(_) => match cipher {
                TlsCoverCipher::ChaCha(_) => telemetry::FAKETLS_CHACHA_OPS.inc(),
                TlsCoverCipher::AesGcm(_) => telemetry::FAKETLS_AES_GCM_OPS.inc(),
            },
            Err(_) => telemetry::FAKETLS_CIPHER_FAILURES.inc(),
        }
        result?;

        Ok(buffer)
    }

    /// Decrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn decrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        let cipher = self
            .open_tls_cover
            .as_ref()
            .ok_or(ConnectionError::CryptoError("crypto failure".into()))?;

        let seq = self.tls_cover_read_seq;
        self.tls_cover_read_seq = seq.checked_add(1).ok_or(ConnectionError::AeadLimitReached)?;

        cipher.open(seq, aad, ciphertext).inspect_err(|_| telemetry::FAKETLS_CIPHER_FAILURES.inc())
    }

    /// Install AES-GCM for Initial packets (compatibility path).
    /// QUIC initial keys are direction-specific, so we accept read/write secrets separately.
    pub fn install_aes_gcm_initial(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        let (rkey, riv) = derive_key_iv(read_secret);
        let (wkey, wiv) = derive_key_iv(write_secret);
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&wkey[..16]);
        self.seal_initial = Some(Box::new(AesGcm128::new(&k16, &wiv)));
        k16.copy_from_slice(&rkey[..16]);
        self.open_initial = Some(Box::new(AesGcm128::new(&k16, &riv)));
        // HP can be installed later when header protection keys are derived
    }

    /// Install AES-GCM for Handshake packets (compatibility path)
    pub fn install_aes_gcm_handshake(&mut self, secret: &[u8]) {
        let (key, iv) = derive_key_iv(secret);
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&key[..16]);
        let seal = AesGcm128::new(&k16, &iv);
        let open = AesGcm128::new(&k16, &iv);
        self.seal_handshake = Some(Box::new(seal));
        self.open_handshake = Some(Box::new(open));
        // HP can be installed later when header protection keys are derived
    }

    /// Install AES-based Header Protection for Initial packets.
    /// QUIC header protection is direction-specific, so we accept read/write secrets separately.
    pub fn install_hp_initial(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        let hp_key_w = derive_hp_key(write_secret);
        let hp_key_r = derive_hp_key(read_secret);
        self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key_w)));
        self.hp_initial_open = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key_r)));
    }

    /// Install AES-based Header Protection for Handshake packets
    pub fn install_hp_handshake(&mut self, secret: &[u8]) {
        let hp_key = derive_hp_key(secret);
        self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key)));
        self.hp_handshake_open = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key)));
    }

    fn install_read_1rtt_secret(&mut self, secret: &[u8]) {
        let (key, iv) = derive_key_iv(secret);
        let (_, open) = select_packet_data_aead(&key, &iv);
        self.open_1rtt = Some(Arc::new(open));
        self.hp_1rtt_open = Some(Arc::new(crate::crypto::aead::AesHp::new(secret)));
    }

    fn install_write_1rtt_secret(&mut self, secret: &[u8]) {
        let (key, iv) = derive_key_iv(secret);
        let (seal, _) = select_packet_data_aead(&key, &iv);
        self.seal_1rtt = Some(Arc::new(seal));
        self.hp_1rtt = Some(Arc::new(crate::crypto::aead::AesHp::new(secret)));
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
        self.open_1rtt = Some(Arc::new(crate::crypto::PacketAeadOpen::Dynamic(open)));
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        self.read_secret_1rtt = None;
    }

    /// Rotates the 1-RTT write key, replacing the current sealer.
    pub fn rotate_1rtt_write_keypair(
        &mut self,
        seal: Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>,
    ) {
        self.seal_1rtt = Some(Arc::new(crate::crypto::PacketAeadSeal::Dynamic(seal)));
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        self.write_secret_1rtt = None;
    }

    /// Derives the next 1-RTT read secret and rotates the opener.
    pub fn key_update_1rtt_read(&mut self) -> bool {
        let Some(cur) = self.read_secret_1rtt.as_deref() else {
            return false;
        };
        let next = crate::crypto::kdf::derive_next_secret(cur);
        if let Some(prev_open) = self.open_1rtt.take() {
            self.push_previous_read_key(prev_open);
        }
        let (key, iv) = derive_key_iv(&next);
        let (_, open) = select_packet_data_aead(&key, &iv);
        self.open_1rtt = Some(Arc::new(open));
        self.read_secret_1rtt = Some(next);
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        true
    }

    /// Derives the next 1-RTT write secret and rotates the sealer.
    pub fn key_update_1rtt_write(&mut self) -> bool {
        let Some(cur) = self.write_secret_1rtt.as_deref() else {
            return false;
        };
        let next = crate::crypto::kdf::derive_next_secret(cur);
        let (key, iv) = derive_key_iv(&next);
        let (seal, _) = select_packet_data_aead(&key, &iv);
        self.seal_1rtt = Some(Arc::new(seal));
        self.write_secret_1rtt = Some(next);
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        true
    }

    /// Backwards-compatible helper for call sites that still update both directions together.
    pub fn key_update_1rtt(&mut self) -> bool {
        let write = self.key_update_1rtt_write();
        let read = self.key_update_1rtt_read();
        write || read
    }
}

// Install AEAD/HP from TLS key schedule.
impl crate::crypto::aead::KeyScheduleHooks for CryptoContext {
    fn set_read_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) {
        let (key, iv) = derive_key_iv(secret);
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_initial = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_initial_open = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_handshake = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_handshake_open = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (_, open) = select_packet_data_aead(&key, &iv);
                    self.open_0rtt = Some(open);
                    self.hp_0rtt_open = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.read_secret_1rtt = Some(secret.to_vec());
                self.read_generation_1rtt = 0;
                self.previous_read_1rtt.clear();
                self.install_read_1rtt_secret(secret);
            }
        }
    }
    fn set_write_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) {
        let (key, iv) = derive_key_iv(secret);
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_initial = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_handshake = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (seal, _) = select_packet_data_aead(&key, &iv);
                    self.seal_0rtt = Some(seal);
                    self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.write_secret_1rtt = Some(secret.to_vec());
                self.write_generation_1rtt = 0;
                self.install_write_1rtt_secret(secret);
            }
        }
    }
}

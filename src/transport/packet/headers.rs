use super::PacketType;
use super::{
    checked_buffer_end, checked_cid_wire_len, checked_usize_add, checked_varint_value,
    AEAD_TAG_LEN, FIXED_BIT, FORM_BIT, KEY_PHASE_BIT, MAX_CID_LEN, MAX_PKT_NUM_LEN, TYPE_MASK,
};
use crate::error::ConnectionError;

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

/// SIMD-optimized packet number encoding.
pub fn encode_pkt_num(pn: u64, pn_len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if !(1..=MAX_PKT_NUM_LEN).contains(&pn_len) {
        return Err(ConnectionError::InvalidPacket);
    }
    if out.len() < pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe {
        // AVX2 optimized path for 4-byte packet numbers.
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

    // Fallback scalar path.
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

/// Minimal header parsing to get PN offset and header fields.
pub fn parse_header(buf: &[u8], short_dcid_len: usize) -> Result<(Header, usize), ConnectionError> {
    use crate::transport::udpfast::{likely, unlikely};
    if unlikely(buf.is_empty()) {
        return Err(ConnectionError::BufferTooShort);
    }
    let first = buf[0];
    if likely((first & FORM_BIT) == 0) {
        // Short header (most common in established connections).
        if unlikely((first & FIXED_BIT) == 0) {
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
            key_phase: (first & KEY_PHASE_BIT) != 0,
        };
        return Ok((hdr, pn_off));
    }
    // Long header parsing.
    if buf.len() < 7 {
        return Err(ConnectionError::BufferTooShort);
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != 0 && unlikely((first & FIXED_BIT) == 0) {
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
    let ty_bits = first & TYPE_MASK;
    let ty = crate::transport::version::packet_type_from_long_header(version, ty_bits)?;
    let mut token = None;
    let mut versions = None;
    if ty == PacketType::VersionNegotiation {
        let remaining = buf.len().saturating_sub(off);
        if remaining == 0 || !remaining.is_multiple_of(4) {
            return Err(ConnectionError::InvalidPacket);
        }
        versions = Some(
            buf[off..].as_chunks::<4>().0.iter().map(|bytes| u32::from_be_bytes(*bytes)).collect(),
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
/// `scid.to_vec()`) on the 1-RTT send hot path - `ConnectionId` is already
/// a stack-allocated `Copy` type and `scid` is always empty for Short headers.
#[inline]
pub fn format_short_header(
    dcid: &[u8],
    key_phase: bool,
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    checked_cid_wire_len(dcid.len())?;
    let end = checked_buffer_end(out.len(), 1, dcid.len())?;
    let mut first = FIXED_BIT;
    if key_phase {
        first |= KEY_PHASE_BIT;
    }
    out[0] = first;
    out[1..end].copy_from_slice(dcid);
    Ok(end)
}

/// Minimal header formatting to get PN offset and header fields.
pub fn format_header(h: &Header, out: &mut [u8]) -> Result<usize, ConnectionError> {
    match h.ty {
        PacketType::Short => {
            checked_cid_wire_len(h.dcid.len())?;
            if !h.scid.is_empty() || h.token.is_some() || h.versions.is_some() {
                return Err(ConnectionError::InvalidPacket);
            }
            let end = checked_buffer_end(out.len(), 1, h.dcid.len())?;
            let mut first = FIXED_BIT;
            if h.key_phase {
                first |= KEY_PHASE_BIT;
            }
            out[0] = first;
            out[1..end].copy_from_slice(&h.dcid);
            Ok(end)
        }
        PacketType::Initial | PacketType::Handshake | PacketType::ZeroRTT | PacketType::Retry => {
            // Long header: [first][version:4][dcid_len:1][dcid][scid_len:1][scid].
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
            let mut first = FORM_BIT | FIXED_BIT;
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

use crate::crypto::aead::{self as tls_aead, AeadOpen, AeadSeal};
use crate::crypto::{select_packet_data_aead, AesGcm128};
use crate::error::ConnectionError;
use std::collections::VecDeque;
use std::sync::Arc;

mod private_selection;
pub(crate) use private_selection::{select_private_open_for_phase, select_private_seal};
#[cfg(test)]
pub(crate) use private_selection::{
    select_private_packet_protection, PrivatePacketProtectionSelection,
};

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
const PRIVATE_READ_EPOCH_WINDOW: usize = 4;

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

mod headers;
pub use headers::{encode_pkt_num, format_header, format_short_header, parse_header, Header};
mod connection_setup;
pub use connection_setup::{
    accept, accept_with_clock, accept_with_clock_and_original, connect, connect_with_clock,
};
mod retry;
pub use retry::{append_retry_tag, verify_retry_tag};
mod secrets;
pub use secrets::{derive_initial_secrets, derive_key_iv, derive_key_iv_for_version};
mod version_negotiation;
pub use version_negotiation::{
    generate_version_negotiation_packet, negotiate_version, parse_version_negotiation,
    server_version_negotiation_response,
};

fn unprotect_header_with_key(
    hp: &dyn HeaderProtector,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
    pre_parsed: Option<(Header, usize)>,
) -> Result<(Header, usize), ConnectionError> {
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
    if buf.len() - aad_len < AEAD_TAG_LEN {
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

    Ok((hdr, aad_len))
}

fn unprotect_and_decrypt_with_key(
    hp: &dyn HeaderProtector,
    aead: &dyn crate::crypto::aead::AeadOpen,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
    pre_parsed: Option<(Header, usize)>,
) -> Result<(Header, usize, usize), ConnectionError> {
    let (hdr, aad_len) =
        unprotect_header_with_key(hp, buf, short_dcid_len, largest_pn_hint, pre_parsed)?;
    let payload_len = buf.len() - aad_len;
    let plaintext_len =
        match decrypt_payload_plaintext_len(buf, hdr.pkt_num, hdr.pkt_num_len, aad_len, aead) {
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
    let (hdr, aad_len) = unprotect_header_with_key(
        &*keys.hp_open,
        buf,
        short_dcid_len,
        largest_pn_hint,
        Some((hdr, pn_off)),
    )?;
    let aead = select_private_open_for_phase(
        Some(&keys.open),
        keys.private_open.as_ref(),
        keys.private_next_open.as_ref(),
        &keys.private_previous_read,
        hdr.pkt_num,
        keys.private_read_boundary,
        hdr.key_phase,
        keys.private_read_key_phase,
        !keys.private_read_key_phase,
        keys.private_read_start,
        keys.private_read_update_pending,
    )?;
    let plaintext_len =
        decrypt_payload_plaintext_len(buf, hdr.pkt_num, hdr.pkt_num_len, aad_len, aead)?;
    Ok((hdr, aad_len, plaintext_len))
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
            let hp_1rtt = crypto.hp_1rtt_open.as_deref().or(crypto.hp_1rtt.as_deref());
            let hp = hp_1rtt.ok_or(ConnectionError::Done)?;
            if crypto.private_open_1rtt.is_none() {
                let mut candidates: Vec<&dyn tls_aead::AeadOpen> = Vec::new();
                if let Some(aead) = crypto.open_1rtt.as_deref() {
                    candidates.push(aead as &dyn tls_aead::AeadOpen);
                }
                for previous in &crypto.previous_read_1rtt {
                    candidates.push(&*previous.open as &dyn tls_aead::AeadOpen);
                }
                if candidates.is_empty() {
                    return Err(ConnectionError::Done);
                }
                let original = if candidates.len() > 1 { Some(buf.to_vec()) } else { None };
                let mut last_error = ConnectionError::CryptoError("crypto failure".into());
                for (index, aead) in candidates.into_iter().enumerate() {
                    if index > 0 {
                        if let Some(original) = original.as_ref() {
                            buf.copy_from_slice(original);
                        }
                    }
                    let pre = if index == 0 { Some((hdr.clone(), pn_off)) } else { None };
                    match unprotect_and_decrypt_with_key(
                        hp,
                        aead,
                        buf,
                        short_dcid_len,
                        largest_pn_hint,
                        pre,
                    ) {
                        Ok(value) => return Ok(value),
                        Err(error) => last_error = error,
                    }
                }
                return Err(last_error);
            }
            let (hdr, aad_len) = unprotect_header_with_key(
                hp,
                buf,
                short_dcid_len,
                largest_pn_hint,
                Some((hdr, pn_off)),
            )?;
            let previous_private =
                crypto.private_previous_read_1rtt.iter().cloned().collect::<Vec<_>>();
            let aead = select_private_open_for_phase(
                crypto.open_1rtt.as_ref(),
                crypto.private_open_1rtt.as_ref(),
                crypto.private_next_open_1rtt.as_ref(),
                &previous_private,
                hdr.pkt_num,
                crypto.private_read_boundary_1rtt,
                hdr.key_phase,
                crypto.private_read_key_phase_1rtt,
                !crypto.private_read_key_phase_1rtt,
                crypto.private_read_start_1rtt,
                crypto.private_read_update_pending_1rtt,
            )?;
            let payload_len = buf.len().saturating_sub(aad_len);
            let plaintext_len = match decrypt_payload_plaintext_len(
                buf,
                hdr.pkt_num,
                hdr.pkt_num_len,
                aad_len,
                aead,
            ) {
                Ok(n) => n,
                Err(error) => {
                    trace_open_failure(&hdr, aad_len, payload_len);
                    return Err(error);
                }
            };
            Ok((hdr, aad_len, plaintext_len))
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

    // Select AEAD based on packet type. Short-header packets use the committed packet-number
    // boundary, while header protection remains the standard QUIC owner.
    let aead: &dyn tls_aead::AeadSeal = match pkt_type {
        PacketType::Initial => match crypto.seal_initial.as_deref() {
            Some(aead) => aead as &dyn tls_aead::AeadSeal,
            None => return Ok(hdr_len),
        },
        PacketType::Handshake => match crypto.seal_handshake.as_deref() {
            Some(aead) => aead as &dyn tls_aead::AeadSeal,
            None => return Ok(hdr_len),
        },
        PacketType::ZeroRTT => match crypto.seal_0rtt.as_ref() {
            Some(aead) => aead as &dyn tls_aead::AeadSeal,
            None => return Ok(hdr_len),
        },
        PacketType::Short => match select_private_seal(
            crypto.seal_1rtt.as_ref(),
            crypto.private_seal_1rtt.as_ref(),
            pn,
            crypto.private_write_boundary_1rtt,
        ) {
            Ok(aead) => aead,
            Err(ConnectionError::Done) => return Ok(hdr_len),
            Err(error) => return Err(error),
        },
        _ => return Ok(hdr_len),
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
    if crypto.private_seal_1rtt.is_some() {
        return Err(ConnectionError::InvalidState);
    }
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
    if crypto.private_open_1rtt.is_some() {
        return Err(ConnectionError::InvalidState);
    }
    let open =
        crypto.open_1rtt.as_deref().or(crypto.open_0rtt.as_ref()).ok_or_else(|| {
            ConnectionError::TlsError("missing AEAD opener for batch open".into())
        })?;
    open.open_batch(items)
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
    let plaintext_len = decrypt_payload_plaintext_len(buf, pn, pn_len, hdr_len, aead)?;
    checked_usize_add(hdr_len, plaintext_len)
}

fn decrypt_payload_plaintext_len(
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
    aead.open_with_u64_counter(pn, aad, payload_buf)
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

#[derive(Clone)]
pub(crate) struct PreviousPrivateReadEpoch {
    pub(crate) open: Arc<crate::crypto::PacketAeadOpen>,
    pub(crate) start_packet_number: u64,
    pub(crate) key_phase: bool,
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
    /// Optional private payload owner selected only after the decoded PN boundary.
    pub(crate) private_seal: Option<Arc<crate::crypto::PacketAeadSeal>>,
    pub(crate) private_open: Option<Arc<crate::crypto::PacketAeadOpen>>,
    pub(crate) private_next_open: Option<Arc<crate::crypto::PacketAeadOpen>>,
    pub(crate) private_previous_read: Vec<PreviousPrivateReadEpoch>,
    pub(crate) private_write_boundary: Option<u64>,
    pub(crate) private_read_boundary: Option<u64>,
    pub(crate) private_read_start: Option<u64>,
    pub(crate) private_read_key_phase: bool,
    pub(crate) private_read_update_pending: bool,
}

/// Per-connection cryptographic state (AEAD keys, HP keys, TLS Cover cipher, CryptoStreams).
#[derive(Default)]
pub struct CryptoContext {
    /// Secret-free effective packet-protection state for diagnostics and policy truth.
    packet_protection: crate::qftls::PacketProtectionSnapshot,
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
    /// Optional negotiated private 1-RTT payload sealer. Header protection remains standard.
    pub(crate) private_seal_1rtt: Option<Arc<crate::crypto::PacketAeadSeal>>,
    /// Optional negotiated private 1-RTT payload opener. Header protection remains standard.
    pub(crate) private_open_1rtt: Option<Arc<crate::crypto::PacketAeadOpen>>,
    /// Next authenticated private read epoch, derived but not committed until a valid packet
    /// authenticates under its new key phase.
    pub(crate) private_next_open_1rtt: Option<Arc<crate::crypto::PacketAeadOpen>>,
    /// Locally committed standard-to-private write boundary.
    pub(crate) private_write_boundary_1rtt: Option<u64>,
    /// Peer committed standard-to-private read boundary.
    pub(crate) private_read_boundary_1rtt: Option<u64>,
    /// Current private read epoch start packet number and key phase.
    pub(crate) private_read_start_1rtt: Option<u64>,
    pub(crate) private_read_key_phase_1rtt: bool,
    pub(crate) private_read_update_pending_1rtt: bool,
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
    /// Connection-bound private epoch derivation schedule.
    private_epoch_schedule: Option<crate::qftls::PrivateEpochSchedule>,
    private_write_direction: Option<crate::qftls::PrivateDirection>,
    private_read_direction: Option<crate::qftls::PrivateDirection>,
    private_write_epoch: u32,
    private_read_epoch: u32,
    /// Whether 0-RTT early data is enabled for this context.
    pub zero_rtt_enabled: bool,
    previous_read_1rtt: VecDeque<PreviousRead1RttKey>,
    pub(crate) private_previous_read_1rtt: VecDeque<PreviousPrivateReadEpoch>,
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

mod context;

#[cfg(test)]
mod secret_erasure_tests;

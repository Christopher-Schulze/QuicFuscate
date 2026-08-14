use super::*;

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

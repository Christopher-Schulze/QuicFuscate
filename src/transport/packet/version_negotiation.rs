use super::*;

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

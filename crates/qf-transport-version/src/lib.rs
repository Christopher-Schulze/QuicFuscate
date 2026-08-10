//! QUIC version negotiation and long-header version mapping.
//!
//! This leaf owns the protocol-version state machine, transport-parameter codec, and
//! version-specific long-header mapping. It deliberately does not depend on the root transport
//! connection or packet types. The root crate keeps its established `PacketType` API through a
//! narrow compatibility adapter.

use qf_common::rng::fill_secure_or_abort;
use qf_error::ConnectionError;

/// QUIC protocol version 1 (RFC 9000 / RFC 9001).
pub const PROTOCOL_VERSION: u32 = 0x00000001;

/// QUIC protocol version 2 (RFC 9369).
pub const PROTOCOL_VERSION_V2: u32 = 0x6b3343cf;

/// Returns `true` when `version` is supported by this implementation.
#[inline]
pub const fn is_supported_version(version: u32) -> bool {
    version == PROTOCOL_VERSION || version == PROTOCOL_VERSION_V2
}

pub const VERSION_INFORMATION_PARAMETER_ID: u64 = 0x11;
pub const VERSION_NEGOTIATION_ERROR_CODE: u64 = 0x11;
pub const TRANSPORT_PARAMETER_ERROR_CODE: u64 = 0x08;

/// Standards-based QUIC wire version accepted by the engine configuration.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuicVersion {
    /// QUIC version 2 (RFC 9369).
    V2,
    /// QUIC version 1 (RFC 9000).
    V1,
}

impl QuicVersion {
    /// Return the wire version number represented by this configuration value.
    pub const fn wire_version(self) -> u32 {
        match self {
            Self::V2 => PROTOCOL_VERSION_V2,
            Self::V1 => PROTOCOL_VERSION,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInformation {
    pub chosen: u32,
    pub available: Vec<u32>,
}

impl VersionInformation {
    pub fn encode_parameter(&self) -> Result<Vec<u8>, ConnectionError> {
        if self.chosen == 0 || self.available.contains(&0) {
            return Err(ConnectionError::InvalidState);
        }

        let value_len = 4usize
            .checked_add(self.available.len().saturating_mul(4))
            .ok_or(ConnectionError::InvalidState)?;
        let mut encoded = vec![0u8; 16 + value_len];
        let mut offset = 0usize;
        offset += varint::write_varint(VERSION_INFORMATION_PARAMETER_ID, &mut encoded[offset..])?;
        offset += varint::write_varint(value_len as u64, &mut encoded[offset..])?;
        encoded[offset..offset + 4].copy_from_slice(&self.chosen.to_be_bytes());
        offset += 4;
        for version in &self.available {
            encoded[offset..offset + 4].copy_from_slice(&version.to_be_bytes());
            offset += 4;
        }
        encoded.truncate(offset);
        Ok(encoded)
    }

    fn decode_value(value: &[u8]) -> Result<Self, ConnectionError> {
        if value.len() < 4 || !value.len().is_multiple_of(4) {
            return Err(ConnectionError::InvalidPacket);
        }
        let chosen =
            u32::from_be_bytes(value[..4].try_into().map_err(|_| ConnectionError::InvalidPacket)?);
        let available = value[4..]
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect::<Vec<_>>();
        if chosen == 0 || available.contains(&0) {
            return Err(ConnectionError::InvalidPacket);
        }
        Ok(Self { chosen, available })
    }
}

pub fn find_version_information(
    parameters: &[u8],
) -> Result<Option<VersionInformation>, ConnectionError> {
    let mut offset = 0usize;
    let mut found = None;
    while offset < parameters.len() {
        let (parameter_id, id_len) = varint::read_varint(&parameters[offset..])?;
        offset += id_len;
        let (value_len, length_len) = varint::read_varint(&parameters[offset..])?;
        offset += length_len;
        let value_len = usize::try_from(value_len).map_err(|_| ConnectionError::InvalidPacket)?;
        let end = offset.checked_add(value_len).ok_or(ConnectionError::InvalidPacket)?;
        if end > parameters.len() {
            return Err(ConnectionError::InvalidPacket);
        }
        if parameter_id == VERSION_INFORMATION_PARAMETER_ID {
            if found.is_some() {
                return Err(ConnectionError::InvalidPacket);
            }
            found = Some(VersionInformation::decode_value(&parameters[offset..end])?);
        }
        offset = end;
    }
    Ok(found)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionNegotiationState {
    pub original: u32,
    pub chosen: u32,
    pub negotiated: u32,
    pub reacted_to_vn: bool,
    pub peer_information_validated: bool,
    pub grease: u32,
}

impl VersionNegotiationState {
    pub fn new(initial: u32) -> Self {
        Self {
            original: initial,
            chosen: initial,
            negotiated: initial,
            reacted_to_vn: false,
            peer_information_validated: false,
            grease: generate_reserved_version(),
        }
    }

    pub fn select_from_vn(
        &mut self,
        local_preference: &[u32],
        peer_versions: &[u32],
    ) -> Result<u32, ConnectionError> {
        if self.reacted_to_vn || peer_versions.contains(&self.original) {
            return Err(ConnectionError::Done);
        }
        let selected = local_preference
            .iter()
            .copied()
            .find(|version| is_supported_version(*version) && peer_versions.contains(version))
            .ok_or(ConnectionError::VersionMismatch)?;
        self.chosen = selected;
        self.negotiated = selected;
        self.reacted_to_vn = true;
        Ok(selected)
    }
}

#[inline]
pub fn is_reserved_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

pub fn generate_reserved_version() -> u32 {
    let mut bytes = [0u8; 4];
    fill_secure_or_abort(&mut bytes, "qf-transport-version::generate_reserved_version");
    for byte in &mut bytes {
        *byte = (*byte & 0xf0) | 0x0a;
    }
    u32::from_be_bytes(bytes)
}

/// Long-header packet kinds needed by QUIC version mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongHeaderPacketType {
    /// Initial packet.
    Initial,
    /// Retry packet.
    Retry,
    /// Handshake packet.
    Handshake,
    /// 0-RTT packet.
    ZeroRtt,
    /// Version Negotiation packet.
    VersionNegotiation,
}

pub fn packet_type_from_long_header(
    version: u32,
    type_bits: u8,
) -> Result<LongHeaderPacketType, ConnectionError> {
    match version {
        0 => Ok(LongHeaderPacketType::VersionNegotiation),
        PROTOCOL_VERSION => match type_bits {
            0x00 => Ok(LongHeaderPacketType::Initial),
            0x10 => Ok(LongHeaderPacketType::ZeroRtt),
            0x20 => Ok(LongHeaderPacketType::Handshake),
            0x30 => Ok(LongHeaderPacketType::Retry),
            _ => Err(ConnectionError::InvalidPacket),
        },
        PROTOCOL_VERSION_V2 => match type_bits {
            0x00 => Ok(LongHeaderPacketType::Retry),
            0x10 => Ok(LongHeaderPacketType::Initial),
            0x20 => Ok(LongHeaderPacketType::ZeroRtt),
            0x30 => Ok(LongHeaderPacketType::Handshake),
            _ => Err(ConnectionError::InvalidPacket),
        },
        _ => Err(ConnectionError::VersionMismatch),
    }
}

pub fn long_header_type_bits(
    version: u32,
    packet_type: LongHeaderPacketType,
) -> Result<u8, ConnectionError> {
    match (version, packet_type) {
        (PROTOCOL_VERSION, LongHeaderPacketType::Initial) => Ok(0x00),
        (PROTOCOL_VERSION, LongHeaderPacketType::ZeroRtt) => Ok(0x10),
        (PROTOCOL_VERSION, LongHeaderPacketType::Handshake) => Ok(0x20),
        (PROTOCOL_VERSION, LongHeaderPacketType::Retry) => Ok(0x30),
        (PROTOCOL_VERSION_V2, LongHeaderPacketType::Retry) => Ok(0x00),
        (PROTOCOL_VERSION_V2, LongHeaderPacketType::Initial) => Ok(0x10),
        (PROTOCOL_VERSION_V2, LongHeaderPacketType::ZeroRtt) => Ok(0x20),
        (PROTOCOL_VERSION_V2, LongHeaderPacketType::Handshake) => Ok(0x30),
        _ => Err(ConnectionError::InvalidPacket),
    }
}

mod varint {
    use qf_error::ConnectionError;

    #[inline(always)]
    const fn varint_len(value: u64) -> usize {
        if value <= 0x3f {
            1
        } else if value <= 0x3fff {
            2
        } else if value <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    #[inline(always)]
    pub(super) fn write_varint(value: u64, output: &mut [u8]) -> Result<usize, ConnectionError> {
        let length = varint_len(value);
        if output.len() < length {
            return Err(ConnectionError::BufferTooShort);
        }
        if value > 0x3fff_ffff_ffff_ffff {
            return Err(ConnectionError::InvalidPacket);
        }
        let mut bytes = value.to_be_bytes();
        let start = 8 - length;
        bytes[start] |= (length_prefix(length) << 6) as u8;
        output[..length].copy_from_slice(&bytes[start..]);
        Ok(length)
    }

    #[inline(always)]
    pub(super) fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
        let Some(&first) = input.first() else {
            return Err(ConnectionError::BufferTooShort);
        };
        let length = 1usize << usize::from(first >> 6);
        if input.len() < length {
            return Err(ConnectionError::BufferTooShort);
        }
        let mut value = u64::from(first & 0x3f);
        for byte in input.iter().take(length).skip(1) {
            value = (value << 8) | u64::from(*byte);
        }
        Ok((value, length))
    }

    #[inline(always)]
    const fn length_prefix(length: usize) -> usize {
        match length {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::{QuicVersion, PROTOCOL_VERSION, PROTOCOL_VERSION_V2};

    #[test]
    fn configuration_versions_map_to_wire_constants() {
        assert_eq!(QuicVersion::V1.wire_version(), PROTOCOL_VERSION);
        assert_eq!(QuicVersion::V2.wire_version(), PROTOCOL_VERSION_V2);
    }

    #[test]
    fn configuration_versions_serde_roundtrip() {
        for version in [QuicVersion::V1, QuicVersion::V2] {
            let encoded = serde_json::to_string(&version).expect("version serialization");
            let decoded: QuicVersion = serde_json::from_str(&encoded).expect("version parsing");
            assert_eq!(decoded, version);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_header_type_mapping_matches_v1_and_v2() {
        let types = [
            LongHeaderPacketType::Initial,
            LongHeaderPacketType::ZeroRtt,
            LongHeaderPacketType::Handshake,
            LongHeaderPacketType::Retry,
        ];
        for packet_type in types {
            for version in [PROTOCOL_VERSION, PROTOCOL_VERSION_V2] {
                let bits = long_header_type_bits(version, packet_type).unwrap();
                assert_eq!(packet_type_from_long_header(version, bits).unwrap(), packet_type);
            }
        }
    }

    #[test]
    fn version_information_parameter_roundtrips_with_grease() {
        let information = VersionInformation {
            chosen: PROTOCOL_VERSION_V2,
            available: vec![PROTOCOL_VERSION_V2, PROTOCOL_VERSION, generate_reserved_version()],
        };
        let encoded = information.encode_parameter().unwrap();
        assert_eq!(find_version_information(&encoded).unwrap(), Some(information));
    }

    #[test]
    fn reserved_versions_have_required_pattern() {
        for _ in 0..64 {
            let version = generate_reserved_version();
            assert!(is_reserved_version(version));
            assert!(!is_supported_version(version));
        }
    }

    #[test]
    fn malformed_or_duplicate_version_information_is_rejected() {
        let zero_chosen = VersionInformation { chosen: 0, available: vec![PROTOCOL_VERSION] };
        assert!(zero_chosen.encode_parameter().is_err());

        let information =
            VersionInformation { chosen: PROTOCOL_VERSION, available: vec![PROTOCOL_VERSION] }
                .encode_parameter()
                .unwrap();
        let mut duplicate = information.clone();
        duplicate.extend_from_slice(&information);
        assert!(find_version_information(&duplicate).is_err());

        let mut truncated = information;
        truncated.pop();
        assert!(find_version_information(&truncated).is_err());
    }

    #[test]
    fn vn_selection_is_ordered_bounded_and_downgrade_safe() {
        let mut state = VersionNegotiationState::new(PROTOCOL_VERSION_V2);
        assert_eq!(
            state
                .select_from_vn(&[PROTOCOL_VERSION_V2, PROTOCOL_VERSION], &[PROTOCOL_VERSION],)
                .unwrap(),
            PROTOCOL_VERSION
        );
        assert_eq!(
            state.select_from_vn(&[PROTOCOL_VERSION], &[PROTOCOL_VERSION]),
            Err(ConnectionError::Done)
        );

        let mut injected = VersionNegotiationState::new(PROTOCOL_VERSION_V2);
        assert_eq!(
            injected.select_from_vn(
                &[PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
                &[PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
            ),
            Err(ConnectionError::Done)
        );
    }
}

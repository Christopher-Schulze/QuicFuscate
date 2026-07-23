use crate::error::ConnectionError;

use super::{is_supported_version, PacketType, PROTOCOL_VERSION, PROTOCOL_VERSION_V2};

pub const VERSION_INFORMATION_PARAMETER_ID: u64 = 0x11;
pub const VERSION_NEGOTIATION_ERROR_CODE: u64 = 0x11;
pub const TRANSPORT_PARAMETER_ERROR_CODE: u64 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInformation {
    pub chosen: u32,
    pub available: Vec<u32>,
}

impl VersionInformation {
    pub fn encode_parameter(&self) -> Result<Vec<u8>, ConnectionError> {
        if self.chosen == 0 || self.available.iter().any(|version| *version == 0) {
            return Err(ConnectionError::InvalidState);
        }

        let value_len = 4usize
            .checked_add(self.available.len().saturating_mul(4))
            .ok_or(ConnectionError::InvalidState)?;
        let mut encoded = vec![0u8; 16 + value_len];
        let mut offset = 0usize;
        offset += super::pn::varint::write_varint(
            VERSION_INFORMATION_PARAMETER_ID,
            &mut encoded[offset..],
        )?;
        offset += super::pn::varint::write_varint(value_len as u64, &mut encoded[offset..])?;
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
        if chosen == 0 || available.iter().any(|version| *version == 0) {
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
        let (parameter_id, id_len) = super::pn::varint::read_varint(&parameters[offset..])?;
        offset += id_len;
        let (value_len, length_len) = super::pn::varint::read_varint(&parameters[offset..])?;
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
    super::pn::rand::rand_bytes(&mut bytes);
    for byte in &mut bytes {
        *byte = (*byte & 0xf0) | 0x0a;
    }
    u32::from_be_bytes(bytes)
}

pub fn packet_type_from_long_header(
    version: u32,
    type_bits: u8,
) -> Result<PacketType, ConnectionError> {
    match version {
        0 => Ok(PacketType::VersionNegotiation),
        PROTOCOL_VERSION => match type_bits {
            0x00 => Ok(PacketType::Initial),
            0x10 => Ok(PacketType::ZeroRTT),
            0x20 => Ok(PacketType::Handshake),
            0x30 => Ok(PacketType::Retry),
            _ => Err(ConnectionError::InvalidPacket),
        },
        PROTOCOL_VERSION_V2 => match type_bits {
            0x00 => Ok(PacketType::Retry),
            0x10 => Ok(PacketType::Initial),
            0x20 => Ok(PacketType::ZeroRTT),
            0x30 => Ok(PacketType::Handshake),
            _ => Err(ConnectionError::InvalidPacket),
        },
        _ => Err(ConnectionError::VersionMismatch),
    }
}

pub fn long_header_type_bits(version: u32, packet_type: PacketType) -> Result<u8, ConnectionError> {
    match (version, packet_type) {
        (PROTOCOL_VERSION, PacketType::Initial) => Ok(0x00),
        (PROTOCOL_VERSION, PacketType::ZeroRTT) => Ok(0x10),
        (PROTOCOL_VERSION, PacketType::Handshake) => Ok(0x20),
        (PROTOCOL_VERSION, PacketType::Retry) => Ok(0x30),
        (PROTOCOL_VERSION_V2, PacketType::Retry) => Ok(0x00),
        (PROTOCOL_VERSION_V2, PacketType::Initial) => Ok(0x10),
        (PROTOCOL_VERSION_V2, PacketType::ZeroRTT) => Ok(0x20),
        (PROTOCOL_VERSION_V2, PacketType::Handshake) => Ok(0x30),
        _ => Err(ConnectionError::InvalidPacket),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_header_type_mapping_matches_v1_and_v2() {
        let types =
            [PacketType::Initial, PacketType::ZeroRTT, PacketType::Handshake, PacketType::Retry];
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

//! Compatibility adapter for the extracted QUIC version-negotiation owner.

use crate::error::ConnectionError;

pub use qf_transport_version::{
    find_version_information, generate_reserved_version, is_reserved_version, VersionInformation,
    VersionNegotiationState, TRANSPORT_PARAMETER_ERROR_CODE, VERSION_INFORMATION_PARAMETER_ID,
    VERSION_NEGOTIATION_ERROR_CODE,
};

use super::PacketType;

/// Map the extracted long-header classification to the root transport packet type.
pub fn packet_type_from_long_header(
    version: u32,
    type_bits: u8,
) -> Result<PacketType, ConnectionError> {
    qf_transport_version::packet_type_from_long_header(version, type_bits).map(|packet_type| {
        match packet_type {
            qf_transport_version::LongHeaderPacketType::Initial => PacketType::Initial,
            qf_transport_version::LongHeaderPacketType::Retry => PacketType::Retry,
            qf_transport_version::LongHeaderPacketType::Handshake => PacketType::Handshake,
            qf_transport_version::LongHeaderPacketType::ZeroRtt => PacketType::ZeroRTT,
            qf_transport_version::LongHeaderPacketType::VersionNegotiation => {
                PacketType::VersionNegotiation
            }
        }
    })
}

/// Map the root transport packet type into the extracted long-header codec.
pub fn long_header_type_bits(version: u32, packet_type: PacketType) -> Result<u8, ConnectionError> {
    let packet_type = match packet_type {
        PacketType::Initial => qf_transport_version::LongHeaderPacketType::Initial,
        PacketType::Retry => qf_transport_version::LongHeaderPacketType::Retry,
        PacketType::Handshake => qf_transport_version::LongHeaderPacketType::Handshake,
        PacketType::ZeroRTT => qf_transport_version::LongHeaderPacketType::ZeroRtt,
        PacketType::Short | PacketType::VersionNegotiation => {
            return Err(ConnectionError::InvalidPacket)
        }
    };
    qf_transport_version::long_header_type_bits(version, packet_type)
}

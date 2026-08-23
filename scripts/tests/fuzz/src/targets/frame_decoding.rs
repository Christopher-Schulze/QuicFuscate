//! Drives the QUIC frame parser with arbitrary bytes across every packet type.
//!
//! The frame parser must accept or reject each input without a panic or an out-of-bounds access
//! on any leading packet-type byte.

use quicfuscate::transport::frames;
use quicfuscate::transport::PacketType;

pub fn exercise(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let pkt_ty = match data[0] % 6 {
        0 => PacketType::Initial,
        1 => PacketType::Handshake,
        2 => PacketType::ZeroRTT,
        3 => PacketType::Retry,
        4 => PacketType::VersionNegotiation,
        _ => PacketType::Short,
    };
    let _ = frames::from_bytes(&data[1..], pkt_ty);
}

//! Compatibility projection for the FEC wire framing and receiver.

#[cfg(test)]
pub(crate) use qf_fec::receiver::codec_for_mode;
pub use qf_fec::receiver::WireFecReceiver;
pub use qf_fec::wire::{
    is_framed, parse_packet, source_symbol_payload, write_packet, write_source_symbol,
    ParsedWirePacket, WireCodec, WireError, WirePacketMeta, WireProfile, WireReceiveReport,
    HEADER_LEN, MAGIC, MAX_DATAGRAM_OVERHEAD, MAX_GF8_BLOCK_SOURCE_COUNT, MAX_SOURCE_COUNT,
    MAX_TOTAL_COUNT, SOURCE_LENGTH_LEN, SYSTEMATIC_REPAIR_INDEX, VERSION,
};

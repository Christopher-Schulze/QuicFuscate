//! Compatibility projection for the FEC wire framing and receiver.

#[cfg(test)]
pub(crate) use qf_fec::receiver::codec_for_mode;
pub use qf_fec::receiver::{WireDelivery, WireFecReceiver};
pub use qf_fec::wire::{
    is_framed, is_repair_ack, parse_packet, parse_repair_ack, parse_symbol, source_symbol_payload,
    write_packet, write_repair_ack, write_source_symbol, write_symbol, ParsedRepairAck,
    ParsedWirePacket, RepairAckEntry, WireCodec, WireError, WirePacketMeta, WireProfile,
    WireReceiveReport, HEADER_LEN, MAGIC, MAX_DATAGRAM_OVERHEAD, MAX_GF8_BLOCK_SOURCE_COUNT,
    MAX_REPAIR_ACK_ENTRIES, MAX_SOURCE_COUNT, MAX_TOTAL_COUNT, QUIC_REPAIR_DISCRIMINATOR,
    REPAIR_ACK_ENTRY_LEN, SOURCE_LENGTH_LEN, SYMBOL_HEADER_LEN, SYSTEMATIC_REPAIR_INDEX, VERSION,
};

//! Root-independent FEC wire metadata and symbol framing.
//!
//! The root package keeps the pool-backed receiver, while this module owns the
//! authenticated wire contract shared by encoders, decoders, and adapters.

use std::fmt;

pub const MAGIC: [u8; 2] = [0xF1, 0xEC];
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const SOURCE_LENGTH_LEN: usize = 2;
pub const MAX_DATAGRAM_OVERHEAD: usize = HEADER_LEN + (2 * SOURCE_LENGTH_LEN);
pub const SYSTEMATIC_REPAIR_INDEX: u16 = u16::MAX;
pub const MAX_SOURCE_COUNT: u16 = 2048;
pub const MAX_TOTAL_COUNT: u16 = super::MAX_FOUNTAIN_SOURCE_SYMBOLS as u16;
pub const MAX_GF8_BLOCK_SOURCE_COUNT: usize = u8::MAX as usize;

const FLAG_SYSTEMATIC: u8 = 1 << 0;
const KNOWN_FLAGS: u8 = FLAG_SYSTEMATIC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum WireMode {
    Zero,
    Light,
    Normal,
    Medium,
    Strong,
    Extreme,
    Ultra,
    Fountain,
    Streaming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireCodec {
    Gf4 = 1,
    Gf8 = 2,
    Gf16 = 3,
    Fountain = 4,
    StreamingGf8 = 5,
}

impl WireCodec {
    pub fn for_mode(mode: WireMode, block_source_count: usize) -> Result<Self, WireError> {
        if mode == WireMode::Zero {
            return Err(WireError::ZeroModeMustRemainRaw);
        }
        if block_source_count == 0 || block_source_count > MAX_SOURCE_COUNT as usize {
            return Err(WireError::InvalidSourceCount);
        }
        match mode {
            WireMode::Light if block_source_count <= 15 => Ok(Self::Gf4),
            WireMode::Light
            | WireMode::Normal
            | WireMode::Medium
            | WireMode::Strong
            | WireMode::Extreme
            | WireMode::Ultra
                if block_source_count <= MAX_GF8_BLOCK_SOURCE_COUNT =>
            {
                Ok(Self::Gf8)
            }
            WireMode::Light
            | WireMode::Normal
            | WireMode::Medium
            | WireMode::Strong
            | WireMode::Extreme
            | WireMode::Ultra => Ok(Self::Gf16),
            WireMode::Fountain => Ok(Self::Fountain),
            WireMode::Streaming => Ok(Self::StreamingGf8),
            WireMode::Zero => Err(WireError::ZeroModeMustRemainRaw),
        }
    }

    fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Gf4),
            2 => Ok(Self::Gf8),
            3 => Ok(Self::Gf16),
            4 => Ok(Self::Fountain),
            5 => Ok(Self::StreamingGf8),
            _ => Err(WireError::UnsupportedCodec(value)),
        }
    }

    pub fn coefficient_len(self, block_source_count: u16) -> Result<usize, WireError> {
        if block_source_count == 0 || block_source_count > MAX_SOURCE_COUNT {
            return Err(WireError::InvalidSourceCount);
        }
        match self {
            Self::Gf4 if block_source_count <= 15 => Ok(block_source_count as usize),
            Self::Gf8 | Self::StreamingGf8
                if block_source_count <= MAX_GF8_BLOCK_SOURCE_COUNT as u16 =>
            {
                Ok(block_source_count as usize)
            }
            Self::Gf16 => Ok(block_source_count as usize * 2),
            Self::Fountain => Err(WireError::CoefficientsNotApplicable),
            _ => Err(WireError::CodecSourceLimit),
        }
    }

    pub fn write_repair_coefficients(
        self,
        block_source_count: u16,
        repair_index: u16,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        if repair_index == SYSTEMATIC_REPAIR_INDEX {
            return Err(WireError::InvalidRepairMetadata);
        }
        if matches!(self, Self::Gf8 | Self::StreamingGf8) {
            crate::gf_tables::init_tables();
        }
        let coefficient_len = self.coefficient_len(block_source_count)?;
        if output.len() < coefficient_len {
            return Err(WireError::BufferTooShort);
        }
        match self {
            Self::Gf4 => {
                for (source_index, coefficient) in output[..coefficient_len].iter_mut().enumerate()
                {
                    let product = u32::from(repair_index)
                        .checked_add(1)
                        .and_then(|value| value.checked_mul(source_index as u32 + 1))
                        .ok_or(WireError::InvalidRepairMetadata)?;
                    *coefficient = (product % 15) as u8 + 1;
                }
            }
            Self::Gf8 | Self::StreamingGf8 => {
                let source_count = block_source_count as usize;
                for (source_index, coefficient) in output[..coefficient_len].iter_mut().enumerate()
                {
                    *coefficient = source_count
                        .checked_add(repair_index as usize)
                        .filter(|&y| y < 256)
                        .map_or_else(
                            || {
                                let product =
                                    (u32::from(repair_index) + 1) * (source_index as u32 + 1);
                                1 + (product % 255) as u8
                            },
                            |y| crate::gf_tables::gf_inv8((source_index as u8) ^ (y as u8)),
                        );
                }
            }
            Self::Gf16 => {
                let y = block_source_count
                    .checked_add(repair_index)
                    .ok_or(WireError::InvalidRepairMetadata)?;
                for source_index in 0..block_source_count as usize {
                    let coefficient = crate::gf_tables::gf16_inv((source_index as u16) ^ y);
                    let offset = source_index * 2;
                    output[offset..offset + 2].copy_from_slice(&coefficient.to_be_bytes());
                }
            }
            Self::Fountain => return Err(WireError::CoefficientsNotApplicable),
        }
        Ok(coefficient_len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireProfile {
    pub epoch: u32,
    pub codec: WireCodec,
    pub source_count: u16,
    pub total_count: u16,
    pub interleave_depth: u8,
}

impl WireProfile {
    pub fn validate(self) -> Result<Self, WireError> {
        if self.source_count == 0 || self.source_count > MAX_SOURCE_COUNT {
            return Err(WireError::InvalidSourceCount);
        }
        if self.total_count <= self.source_count || self.total_count > MAX_TOTAL_COUNT {
            return Err(WireError::InvalidTotalCount);
        }
        if !(1..=8).contains(&self.interleave_depth) {
            return Err(WireError::InvalidInterleaveDepth);
        }
        if !self.source_count.is_multiple_of(self.interleave_depth as u16) {
            return Err(WireError::UnevenInterleave);
        }
        let block_source_count = self.try_block_source_count()?;
        match self.codec {
            WireCodec::Gf4 if block_source_count > 15 => Err(WireError::CodecSourceLimit),
            WireCodec::Gf8 | WireCodec::StreamingGf8
                if block_source_count > MAX_GF8_BLOCK_SOURCE_COUNT as u16 =>
            {
                Err(WireError::CodecSourceLimit)
            }
            WireCodec::Fountain if self.interleave_depth != 1 => {
                Err(WireError::InvalidInterleaveDepth)
            }
            _ => Ok(self),
        }
    }

    #[inline]
    pub fn block_source_count(self) -> u16 {
        self.try_block_source_count().unwrap_or(0)
    }

    pub fn try_block_source_count(self) -> Result<u16, WireError> {
        if self.source_count == 0 || self.source_count > MAX_SOURCE_COUNT {
            return Err(WireError::InvalidSourceCount);
        }
        if !(1..=8).contains(&self.interleave_depth) {
            return Err(WireError::InvalidInterleaveDepth);
        }
        let depth = u16::from(self.interleave_depth);
        if !self.source_count.is_multiple_of(depth) {
            return Err(WireError::UnevenInterleave);
        }
        let block_source_count = self.source_count / depth;
        if block_source_count == 0 {
            return Err(WireError::InvalidSourceCount);
        }
        Ok(block_source_count)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WirePacketMeta {
    pub profile: WireProfile,
    pub window: u32,
    pub sequence: u64,
    pub repair_index: u16,
    pub block_index: u8,
    pub systematic: bool,
}

impl WirePacketMeta {
    pub fn validate(self) -> Result<Self, WireError> {
        self.profile.validate()?;
        if self.block_index >= self.profile.interleave_depth {
            return Err(WireError::InvalidBlockIndex);
        }
        if self.systematic {
            if self.repair_index != SYSTEMATIC_REPAIR_INDEX
                || self.block_index != (self.sequence % self.profile.interleave_depth as u64) as u8
            {
                return Err(WireError::InvalidSystematicMetadata);
            }
            if self.sequence / self.profile.source_count as u64 != self.window as u64 {
                return Err(WireError::SourceOutsideWindow);
            }
        } else {
            let repair_ordinal = (self.repair_index as u32)
                .saturating_mul(self.profile.interleave_depth as u32)
                .saturating_add(self.block_index as u32);
            let repair_capacity = (self.profile.total_count - self.profile.source_count) as u32;
            if self.repair_index == SYSTEMATIC_REPAIR_INDEX || repair_ordinal >= repair_capacity {
                return Err(WireError::InvalidRepairMetadata);
            }
            if self.profile.codec != WireCodec::Fountain {
                if self.sequence / self.profile.source_count as u64 != self.window as u64 {
                    return Err(WireError::RepairOutsideWindow);
                }
                let window_start = self.window as u64 * self.profile.source_count as u64;
                if self.profile.codec == WireCodec::StreamingGf8
                    && self.sequence % self.profile.interleave_depth as u64
                        != self.block_index as u64
                {
                    return Err(WireError::InvalidRepairMetadata);
                }
                if self.profile.codec != WireCodec::StreamingGf8 {
                    let expected_anchor =
                        window_start.saturating_add(self.block_index as u64).saturating_add(
                            (self.profile.block_source_count() as u64)
                                .saturating_sub(1)
                                .saturating_mul(self.profile.interleave_depth as u64),
                        );
                    if self.sequence != expected_anchor {
                        return Err(WireError::RepairOutsideWindow);
                    }
                }
            }
        }
        Ok(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedWirePacket<'a> {
    pub meta: WirePacketMeta,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireReceiveReport {
    pub systematic: bool,
    pub source_payload_bytes: usize,
    pub wire_bytes: usize,
    pub decoded_packets: usize,
    pub recovered_packets: usize,
    pub recovered_payload_bytes: usize,
}

impl WireReceiveReport {
    pub fn raw_source(payload_bytes: usize) -> Self {
        Self {
            systematic: true,
            source_payload_bytes: payload_bytes,
            wire_bytes: payload_bytes,
            decoded_packets: 1,
            recovered_packets: 0,
            recovered_payload_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    BufferTooShort,
    BadMagic,
    UnsupportedVersion(u8),
    UnsupportedFlags(u8),
    UnsupportedCodec(u8),
    ZeroModeMustRemainRaw,
    PayloadTooLarge,
    LengthMismatch,
    InvalidSourceCount,
    InvalidTotalCount,
    InvalidInterleaveDepth,
    UnevenInterleave,
    CodecSourceLimit,
    CoefficientsNotApplicable,
    InvalidBlockIndex,
    InvalidSystematicMetadata,
    InvalidRepairMetadata,
    InvalidSourceSymbolLength,
    InvalidSourceDatagramLength,
    SourceOutsideWindow,
    RepairOutsideWindow,
    EpochProfileMismatch,
    ResourceExhausted,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid FEC wire packet: {self:?}")
    }
}

impl std::error::Error for WireError {}

#[inline]
pub fn is_framed(datagram: &[u8]) -> bool {
    datagram.starts_with(&MAGIC)
}

pub fn write_packet(
    meta: WirePacketMeta,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    meta.validate()?;
    let payload_len = u16::try_from(payload.len()).map_err(|_| WireError::PayloadTooLarge)?;
    let wire_len = HEADER_LEN.checked_add(payload.len()).ok_or(WireError::PayloadTooLarge)?;
    if output.len() < wire_len {
        return Err(WireError::BufferTooShort);
    }

    output[..HEADER_LEN].fill(0);
    output[0..2].copy_from_slice(&MAGIC);
    output[2] = VERSION;
    output[3] = if meta.systematic { FLAG_SYSTEMATIC } else { 0 };
    output[4] = meta.profile.codec as u8;
    output[5] = meta.profile.interleave_depth;
    output[6] = meta.block_index;
    output[8..12].copy_from_slice(&meta.profile.epoch.to_be_bytes());
    output[12..16].copy_from_slice(&meta.window.to_be_bytes());
    output[16..24].copy_from_slice(&meta.sequence.to_be_bytes());
    output[24..26].copy_from_slice(&meta.profile.source_count.to_be_bytes());
    output[26..28].copy_from_slice(&meta.profile.total_count.to_be_bytes());
    output[28..30].copy_from_slice(&meta.repair_index.to_be_bytes());
    output[30..32].copy_from_slice(&payload_len.to_be_bytes());
    output[HEADER_LEN..wire_len].copy_from_slice(payload);
    Ok(wire_len)
}

pub fn parse_packet(datagram: &[u8]) -> Result<ParsedWirePacket<'_>, WireError> {
    if datagram.len() < HEADER_LEN {
        return Err(WireError::BufferTooShort);
    }
    if datagram[0..2] != MAGIC {
        return Err(WireError::BadMagic);
    }
    if datagram[2] != VERSION {
        return Err(WireError::UnsupportedVersion(datagram[2]));
    }
    if datagram[3] & !KNOWN_FLAGS != 0 {
        return Err(WireError::UnsupportedFlags(datagram[3]));
    }
    if datagram[7] != 0 {
        return Err(WireError::UnsupportedFlags(datagram[7]));
    }

    let systematic = datagram[3] & FLAG_SYSTEMATIC != 0;
    let payload_len = u16::from_be_bytes([datagram[30], datagram[31]]) as usize;
    if datagram.len() != HEADER_LEN + payload_len {
        return Err(WireError::LengthMismatch);
    }
    let profile = WireProfile {
        epoch: u32::from_be_bytes(
            datagram[8..12].try_into().map_err(|_| WireError::BufferTooShort)?,
        ),
        codec: WireCodec::from_byte(datagram[4])?,
        source_count: u16::from_be_bytes([datagram[24], datagram[25]]),
        total_count: u16::from_be_bytes([datagram[26], datagram[27]]),
        interleave_depth: datagram[5],
    };
    let meta = WirePacketMeta {
        profile,
        window: u32::from_be_bytes(
            datagram[12..16].try_into().map_err(|_| WireError::BufferTooShort)?,
        ),
        sequence: u64::from_be_bytes(
            datagram[16..24].try_into().map_err(|_| WireError::BufferTooShort)?,
        ),
        repair_index: u16::from_be_bytes([datagram[28], datagram[29]]),
        block_index: datagram[6],
        systematic,
    }
    .validate()?;

    Ok(ParsedWirePacket { meta, payload: &datagram[HEADER_LEN..] })
}

pub fn write_source_symbol(payload: &[u8], output: &mut [u8]) -> Result<usize, WireError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| WireError::PayloadTooLarge)?;
    let symbol_len =
        SOURCE_LENGTH_LEN.checked_add(payload.len()).ok_or(WireError::PayloadTooLarge)?;
    if output.len() < symbol_len {
        return Err(WireError::BufferTooShort);
    }
    output[..SOURCE_LENGTH_LEN].copy_from_slice(&payload_len.to_be_bytes());
    output[SOURCE_LENGTH_LEN..symbol_len].copy_from_slice(payload);
    Ok(symbol_len)
}

pub fn source_symbol_payload(symbol: &[u8]) -> Result<&[u8], WireError> {
    if symbol.len() < SOURCE_LENGTH_LEN {
        return Err(WireError::InvalidSourceSymbolLength);
    }
    let payload_len = u16::from_be_bytes([symbol[0], symbol[1]]) as usize;
    let end =
        SOURCE_LENGTH_LEN.checked_add(payload_len).ok_or(WireError::InvalidSourceSymbolLength)?;
    if end > symbol.len() {
        return Err(WireError::InvalidSourceSymbolLength);
    }
    Ok(&symbol[SOURCE_LENGTH_LEN..end])
}

pub fn source_datagram_payload(source: &[u8]) -> Result<&[u8], WireError> {
    if source.len() < SOURCE_LENGTH_LEN {
        return Err(WireError::InvalidSourceDatagramLength);
    }
    let payload_len = u16::from_be_bytes([source[0], source[1]]) as usize;
    let end =
        SOURCE_LENGTH_LEN.checked_add(payload_len).ok_or(WireError::InvalidSourceDatagramLength)?;
    if end != source.len() {
        return Err(WireError::InvalidSourceDatagramLength);
    }
    Ok(&source[SOURCE_LENGTH_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(codec: WireCodec) -> WireProfile {
        WireProfile { epoch: 7, codec, source_count: 64, total_count: 80, interleave_depth: 4 }
    }

    #[test]
    fn mode_selection_preserves_codec_boundaries() {
        assert_eq!(WireCodec::for_mode(WireMode::Light, 12), Ok(WireCodec::Gf4));
        assert_eq!(WireCodec::for_mode(WireMode::Light, 16), Ok(WireCodec::Gf8));
        assert_eq!(WireCodec::for_mode(WireMode::Ultra, 256), Ok(WireCodec::Gf16));
        assert_eq!(WireCodec::for_mode(WireMode::Zero, 0), Err(WireError::ZeroModeMustRemainRaw));
    }

    #[test]
    fn packet_round_trip_preserves_metadata_and_payload() {
        let meta = WirePacketMeta {
            profile: profile(WireCodec::Gf8),
            window: 0,
            sequence: 3,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 3,
            systematic: true,
        };
        let mut output = [0u8; HEADER_LEN + 3];
        let written = write_packet(meta, &[1, 2, 3], &mut output).expect("wire packet");
        let parsed = parse_packet(&output[..written]).expect("parse packet");
        assert_eq!(parsed.meta, meta);
        assert_eq!(parsed.payload, &[1, 2, 3]);
    }

    #[test]
    fn source_symbol_round_trip_rejects_trailing_bytes() {
        let mut symbol = [0u8; SOURCE_LENGTH_LEN + 3];
        let written = write_source_symbol(&[4, 5, 6], &mut symbol).expect("source symbol");
        assert_eq!(source_symbol_payload(&symbol[..written]).expect("payload"), &[4, 5, 6]);
        let mut trailing = [0u8; SOURCE_LENGTH_LEN + 4];
        trailing[..written].copy_from_slice(&symbol[..written]);
        assert_eq!(source_datagram_payload(&trailing), Err(WireError::InvalidSourceDatagramLength));
    }
}

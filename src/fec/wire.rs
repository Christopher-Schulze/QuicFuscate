//! Versioned, MTU-bounded wire framing for active forward error correction.
//!
//! Zero mode deliberately bypasses this module. Active modes use a fixed-size
//! header and derive repair coefficients from the transmitted profile and
//! repair ordinal. Source lengths are protected inside each coded symbol so a
//! recovered variable-length QUIC datagram can be restored exactly.

use super::{FecMode, FecPacket, FecRuntimePolicy, MemoryPool};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;

pub const MAGIC: [u8; 2] = [0xF1, 0xEC];
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const SOURCE_LENGTH_LEN: usize = 2;
pub const MAX_DATAGRAM_OVERHEAD: usize = HEADER_LEN + SOURCE_LENGTH_LEN;
pub const SYSTEMATIC_REPAIR_INDEX: u16 = u16::MAX;
pub const MAX_SOURCE_COUNT: u16 = 2048;
pub const MAX_TOTAL_COUNT: u16 = 12_288;
pub const MAX_GF8_BLOCK_SOURCE_COUNT: usize = u8::MAX as usize;

const FLAG_SYSTEMATIC: u8 = 1 << 0;
const KNOWN_FLAGS: u8 = FLAG_SYSTEMATIC;
const RECEIVE_WINDOW_LIMIT: usize = 4;

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
    pub fn for_mode(mode: FecMode, block_source_count: usize) -> Result<Self, WireError> {
        match mode {
            FecMode::Zero => Err(WireError::ZeroModeMustRemainRaw),
            FecMode::Light if block_source_count <= 15 => Ok(Self::Gf4),
            FecMode::Light
            | FecMode::Normal
            | FecMode::Medium
            | FecMode::Strong
            | FecMode::Extreme
            | FecMode::Ultra
                if block_source_count <= MAX_GF8_BLOCK_SOURCE_COUNT =>
            {
                Ok(Self::Gf8)
            }
            FecMode::Light
            | FecMode::Normal
            | FecMode::Medium
            | FecMode::Strong
            | FecMode::Extreme
            | FecMode::Ultra => Ok(Self::Gf16),
            FecMode::Fountain => Ok(Self::Fountain),
            FecMode::Streaming => Ok(Self::StreamingGf8),
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
        let coefficient_len = self.coefficient_len(block_source_count)?;
        if output.len() < coefficient_len {
            return Err(WireError::BufferTooShort);
        }
        match self {
            Self::Gf4 => {
                for (source_index, coefficient) in output[..coefficient_len].iter_mut().enumerate()
                {
                    let product =
                        repair_index.wrapping_add(1).wrapping_mul(source_index as u16 + 1);
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
                                1u8 + (((repair_index as u8).wrapping_add(1))
                                    .wrapping_mul((source_index as u8).wrapping_add(1))
                                    % 255)
                            },
                            |y| super::gf_tables::gf_inv8((source_index as u8) ^ (y as u8)),
                        );
                }
            }
            Self::Gf16 => {
                let y = block_source_count.wrapping_add(repair_index);
                for source_index in 0..block_source_count as usize {
                    let coefficient = super::gf_tables::gf16_inv((source_index as u16) ^ y);
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
        let block_source_count = self.source_count / self.interleave_depth as u16;
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
        self.source_count / self.interleave_depth as u16
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
                if self.profile.codec == WireCodec::StreamingGf8 {
                    if self.sequence % self.profile.interleave_depth as u64
                        != self.block_index as u64
                    {
                        return Err(WireError::InvalidRepairMetadata);
                    }
                } else {
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

struct ReceiveWindow {
    profile: WireProfile,
    window: u32,
    decoder: super::internal::InterleavedDecoder,
    delivered: HashSet<u64>,
    seen_repairs: HashSet<(u64, u16, u8)>,
    mem_pool: Arc<MemoryPool>,
}

impl ReceiveWindow {
    fn new(
        profile: WireProfile,
        window: u32,
        mem_pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self {
            profile,
            window,
            decoder: super::internal::InterleavedDecoder::new_for_wire(
                profile,
                Arc::clone(&mem_pool),
                policy,
            ),
            delivered: HashSet::with_capacity(profile.source_count as usize),
            seen_repairs: HashSet::new(),
            mem_pool,
        }
    }

    fn window_start(&self) -> u64 {
        self.window as u64 * self.profile.source_count as u64
    }

    fn block_anchor(&self, block_index: u8) -> u64 {
        self.window_start().saturating_add(block_index as u64).saturating_add(
            (self.profile.block_source_count() as u64)
                .saturating_sub(1)
                .saturating_mul(self.profile.interleave_depth as u64),
        )
    }

    fn source_packet(&self, meta: WirePacketMeta, payload: &[u8]) -> Result<FecPacket, WireError> {
        let symbol_len =
            SOURCE_LENGTH_LEN.checked_add(payload.len()).ok_or(WireError::PayloadTooLarge)?;
        if symbol_len > self.mem_pool.block_size() {
            return Err(WireError::ResourceExhausted);
        }
        let mut symbol = self.mem_pool.alloc();
        write_source_symbol(payload, &mut symbol)?;
        let internal_id = if meta.profile.codec == WireCodec::Fountain {
            meta.sequence - self.window_start()
        } else {
            meta.sequence
        };
        let mut packet = FecPacket::new(
            internal_id,
            Some(symbol),
            symbol_len,
            true,
            None,
            0,
            Arc::clone(&self.mem_pool),
        );
        packet.seq = meta.sequence;
        Ok(packet)
    }

    fn repair_packet(&self, meta: WirePacketMeta, payload: &[u8]) -> Result<FecPacket, WireError> {
        if payload.len() > self.mem_pool.block_size() {
            return Err(WireError::ResourceExhausted);
        }
        if meta.profile.codec != WireCodec::Fountain
            && meta.profile.codec.coefficient_len(meta.profile.block_source_count())?
                > self.mem_pool.block_size()
        {
            return Err(WireError::ResourceExhausted);
        }
        let data = self.mem_pool.alloc_from_slice(payload);
        let (coefficients, coefficient_len) = if meta.profile.codec == WireCodec::Fountain {
            (None, 0)
        } else {
            let mut coefficients = self.mem_pool.alloc();
            let coefficient_len = meta.profile.codec.write_repair_coefficients(
                meta.profile.block_source_count(),
                meta.repair_index,
                &mut coefficients,
            )?;
            if meta.profile.codec == WireCodec::StreamingGf8 {
                let block_start = self.window_start().saturating_add(meta.block_index as u64);
                let span =
                    meta.sequence
                        .saturating_sub(block_start)
                        .checked_div(meta.profile.interleave_depth as u64)
                        .unwrap_or(0)
                        .saturating_add(1)
                        .min(meta.profile.block_source_count() as u64) as usize;
                coefficients[span..coefficient_len].fill(0);
            }
            (Some(coefficients), coefficient_len)
        };
        let decoder_anchor = if meta.profile.codec == WireCodec::StreamingGf8 {
            self.block_anchor(meta.block_index)
        } else {
            meta.sequence
        };
        let mut packet = FecPacket::new(
            decoder_anchor,
            Some(data),
            payload.len(),
            false,
            coefficients,
            coefficient_len,
            Arc::clone(&self.mem_pool),
        );
        packet.seq = ((meta.repair_index as u64) << 4) | meta.block_index as u64;
        Ok(packet)
    }

    fn emit_recovered(
        &mut self,
        packet: FecPacket,
        output: &mut Vec<FecPacket>,
    ) -> Result<(), WireError> {
        let global_id = if self.profile.codec == WireCodec::Fountain {
            self.window_start().saturating_add(packet.id)
        } else {
            packet.id
        };
        if !self.delivered.insert(global_id) {
            return Ok(());
        }
        let symbol = packet.payload_slice().ok_or(WireError::InvalidSourceSymbolLength)?;
        let payload = source_symbol_payload(symbol)?;
        let mut recovered = FecPacket::from_block(global_id, payload, Arc::clone(&self.mem_pool));
        recovered.seq = global_id;
        output.push(recovered);
        Ok(())
    }

    fn streaming_repair_has_missing_source(&self, meta: WirePacketMeta) -> bool {
        let depth = self.profile.interleave_depth as u64;
        let mut sequence = self.window_start().saturating_add(meta.block_index as u64);
        while sequence <= meta.sequence {
            if !self.delivered.contains(&sequence) {
                return true;
            }
            let next = sequence.saturating_add(depth);
            if next == sequence {
                break;
            }
            sequence = next;
        }
        false
    }

    fn receive(
        &mut self,
        meta: WirePacketMeta,
        payload: &[u8],
        output: &mut Vec<FecPacket>,
    ) -> Result<(), WireError> {
        let systematic = meta.systematic;
        if systematic && self.delivered.contains(&meta.sequence) {
            return Ok(());
        }
        if !systematic
            && meta.profile.codec == WireCodec::StreamingGf8
            && !self.streaming_repair_has_missing_source(meta)
        {
            return Ok(());
        }
        let repair_key = (meta.sequence, meta.repair_index, meta.block_index);
        if !systematic && self.seen_repairs.contains(&repair_key) {
            return Ok(());
        }
        let packet = if systematic {
            self.source_packet(meta, payload)?
        } else {
            self.repair_packet(meta, payload)?
        };
        if !systematic {
            self.seen_repairs.insert(repair_key);
        }

        self.decoder.take_packet(packet);
        if systematic && self.delivered.insert(meta.sequence) {
            let mut original =
                FecPacket::from_block(meta.sequence, payload, Arc::clone(&self.mem_pool));
            original.seq = meta.sequence;
            output.push(original);
        }

        if self.decoder.recovery_needed() {
            let recovered = if self.decoder.full_recovery_needed() {
                self.decoder.get_result().unwrap_or_default()
            } else {
                self.decoder.get_partial_result()
            };
            for packet in recovered {
                self.emit_recovered(packet, output)?;
            }
        }
        Ok(())
    }
}

pub struct WireFecReceiver {
    windows: VecDeque<ReceiveWindow>,
    mem_pool: Arc<MemoryPool>,
    policy: FecRuntimePolicy,
}

impl WireFecReceiver {
    pub fn new(mem_pool: Arc<MemoryPool>) -> Self {
        Self {
            windows: VecDeque::with_capacity(RECEIVE_WINDOW_LIMIT),
            mem_pool,
            policy: FecRuntimePolicy::detect(),
        }
    }

    pub fn receive(
        &mut self,
        datagram: &[u8],
        output: &mut Vec<FecPacket>,
    ) -> Result<(), WireError> {
        output.clear();
        let parsed = parse_packet(datagram)?;
        if self.windows.iter().any(|window| {
            window.profile.epoch == parsed.meta.profile.epoch
                && window.profile != parsed.meta.profile
        }) {
            return Err(WireError::EpochProfileMismatch);
        }
        let key = (parsed.meta.profile, parsed.meta.window);
        let window_index = self
            .windows
            .iter()
            .position(|window| (window.profile, window.window) == key)
            .unwrap_or_else(|| {
                if self.windows.len() == RECEIVE_WINDOW_LIMIT {
                    self.windows.pop_front();
                }
                self.windows.push_back(ReceiveWindow::new(
                    parsed.meta.profile,
                    parsed.meta.window,
                    Arc::clone(&self.mem_pool),
                    &self.policy,
                ));
                self.windows.len() - 1
            });
        self.windows[window_index].receive(parsed.meta, parsed.payload, output)
    }

    #[cfg(test)]
    fn retained_windows(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_packet(id: u64, payload: &[u8], pool: &Arc<MemoryPool>) -> FecPacket {
        let mut symbol = pool.alloc();
        let symbol_len = write_source_symbol(payload, &mut symbol).expect("source symbol");
        let mut packet =
            FecPacket::new(id, Some(symbol), symbol_len, true, None, 0, Arc::clone(pool));
        packet.seq = id;
        packet
    }

    fn profile(codec: WireCodec) -> WireProfile {
        WireProfile { epoch: 7, codec, source_count: 64, total_count: 80, interleave_depth: 4 }
    }

    #[test]
    fn active_wire_packet_round_trips_without_variable_metadata() {
        let meta = WirePacketMeta {
            profile: profile(WireCodec::Gf8),
            window: 1,
            sequence: 77,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 1,
            systematic: true,
        };
        let payload = [0x40, 0x11, 0x22, 0x33];
        let mut wire = [0u8; 128];

        let written = write_packet(meta, &payload, &mut wire).expect("wire packet must encode");
        let parsed = parse_packet(&wire[..written]).expect("wire packet must decode");

        assert_eq!(written, HEADER_LEN + payload.len());
        assert_eq!(parsed.meta, meta);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn source_length_survives_zero_padded_recovery_symbol() {
        let payload = [0x40, 0xAA, 0xBB];
        let mut symbol = [0u8; 32];
        let written = write_source_symbol(&payload, &mut symbol).expect("symbol must encode");

        assert_eq!(written, SOURCE_LENGTH_LEN + payload.len());
        assert_eq!(source_symbol_payload(&symbol).expect("symbol must decode"), payload);
    }

    #[test]
    fn malformed_metadata_fails_closed() {
        let meta = WirePacketMeta {
            profile: profile(WireCodec::Gf8),
            window: 0,
            sequence: 8,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let mut wire = [0u8; 64];
        let written = write_packet(meta, &[1, 2, 3], &mut wire).expect("wire packet must encode");

        wire[5] = 0;
        assert_eq!(parse_packet(&wire[..written]), Err(WireError::InvalidInterleaveDepth));
    }

    #[test]
    fn profile_limits_bound_decoder_memory_before_allocation() {
        let oversized_source = WireProfile {
            epoch: 1,
            codec: WireCodec::Gf16,
            source_count: MAX_SOURCE_COUNT + 1,
            total_count: MAX_SOURCE_COUNT + 2,
            interleave_depth: 1,
        };
        let oversized_total = WireProfile {
            epoch: 1,
            codec: WireCodec::Fountain,
            source_count: 4,
            total_count: MAX_TOTAL_COUNT + 1,
            interleave_depth: 1,
        };

        assert_eq!(oversized_source.validate(), Err(WireError::InvalidSourceCount));
        assert_eq!(oversized_total.validate(), Err(WireError::InvalidTotalCount));
    }

    #[test]
    fn oversized_repair_fails_before_dedup_state_changes() {
        let pool = Arc::new(MemoryPool::new(8, 2048));
        let oversized_payload_len = pool.block_size() + 1;
        let mut receiver = WireFecReceiver::new(pool);
        let meta = WirePacketMeta {
            profile: WireProfile {
                epoch: 1,
                codec: WireCodec::Gf8,
                source_count: 64,
                total_count: 65,
                interleave_depth: 1,
            },
            window: 0,
            sequence: 63,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let payload = vec![0xA5; oversized_payload_len];
        let mut datagram = vec![0; HEADER_LEN + payload.len()];
        let written = write_packet(meta, &payload, &mut datagram).expect("wire packet must encode");
        let mut output = Vec::new();

        assert_eq!(
            receiver.receive(&datagram[..written], &mut output),
            Err(WireError::ResourceExhausted)
        );
        assert_eq!(
            receiver.receive(&datagram[..written], &mut output),
            Err(WireError::ResourceExhausted),
            "failed repairs must not poison duplicate suppression"
        );
    }

    #[test]
    fn codec_cascade_reserves_fountain_for_rescue_mode() {
        assert_eq!(WireCodec::for_mode(FecMode::Light, 12), Ok(WireCodec::Gf4));
        assert_eq!(WireCodec::for_mode(FecMode::Light, 16), Ok(WireCodec::Gf8));
        assert_eq!(WireCodec::for_mode(FecMode::Normal, 64), Ok(WireCodec::Gf8));
        assert_eq!(WireCodec::for_mode(FecMode::Strong, 128), Ok(WireCodec::Gf8));
        assert_eq!(WireCodec::for_mode(FecMode::Extreme, 128), Ok(WireCodec::Gf8));
        assert_eq!(WireCodec::for_mode(FecMode::Ultra, 256), Ok(WireCodec::Gf16));
        assert_eq!(WireCodec::for_mode(FecMode::Fountain, 2048), Ok(WireCodec::Fountain));
        assert_eq!(WireCodec::for_mode(FecMode::Zero, 0), Err(WireError::ZeroModeMustRemainRaw));
    }

    #[test]
    fn block_coefficients_are_reconstructed_from_compact_metadata() {
        let mut coefficients = [0u8; 32];

        let gf4_len = WireCodec::Gf4
            .write_repair_coefficients(4, 2, &mut coefficients)
            .expect("GF4 coefficients must derive");
        assert_eq!(&coefficients[..gf4_len], &[4, 7, 10, 13]);

        let gf8_len = WireCodec::Gf8
            .write_repair_coefficients(4, 2, &mut coefficients)
            .expect("GF8 coefficients must derive");
        let expected_gf8 = (0..4)
            .map(|source_index| super::super::gf_tables::gf_inv8(source_index ^ 6))
            .collect::<Vec<_>>();
        assert_eq!(&coefficients[..gf8_len], expected_gf8);

        let gf16_len = WireCodec::Gf16
            .write_repair_coefficients(4, 2, &mut coefficients)
            .expect("GF16 coefficients must derive");
        let expected_gf16 = (0..4u16)
            .flat_map(|source_index| {
                super::super::gf_tables::gf16_inv(source_index ^ 6).to_be_bytes()
            })
            .collect::<Vec<_>>();
        assert_eq!(&coefficients[..gf16_len], expected_gf16);
    }

    #[test]
    fn gf4_product_row_uses_every_nonzero_field_element_once() {
        let mut coefficients = [0u8; 15];
        let written = WireCodec::Gf4
            .write_repair_coefficients(15, 0, &mut coefficients)
            .expect("GF4 product row");
        let mut sorted = coefficients;
        sorted.sort_unstable();

        assert_eq!(written, 15);
        assert_eq!(sorted, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn configured_mtu_reservation_covers_repair_length_symbol() {
        let outer_mtu = 1200usize;
        let max_inner_quic = outer_mtu - MAX_DATAGRAM_OVERHEAD;
        let max_repair_payload = max_inner_quic + SOURCE_LENGTH_LEN;

        assert_eq!(HEADER_LEN + max_repair_payload, outer_mtu);
    }

    #[test]
    fn receiver_recovers_exact_variable_length_source_without_wire_coefficients() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x10; 31], vec![0x20; 47], vec![0x30; 63], vec![0x40; 79]];
        let mut encoder = super::super::Encoder8::new(4, 6);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("repair packet must encode");
        let profile = WireProfile {
            epoch: 11,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
        let mut wire = vec![0u8; 256];
        let mut decoded = Vec::new();
        let mut recovered = None;

        for source_id in [0usize, 2, 3] {
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: source_id as u64,
                repair_index: SYSTEMATIC_REPAIR_INDEX,
                block_index: 0,
                systematic: true,
            };
            let written = write_packet(meta, &sources[source_id], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        let repair_meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: repair.id,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let repair_payload = repair.payload_slice().expect("repair payload");
        let written = write_packet(repair_meta, repair_payload, &mut wire).expect("repair wire");
        receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
        for packet in decoded {
            if packet.id == 1 {
                recovered = packet.payload_slice().map(<[u8]>::to_vec);
            }
        }

        assert_eq!(recovered, Some(sources[1].clone()));
    }

    #[test]
    fn gf4_receiver_recovers_exact_source_from_compact_repair_metadata() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x11; 31], vec![0x22; 47], vec![0x33; 63], vec![0x44; 79]];
        let mut encoder = super::super::Encoder4::new(4, 6);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("GF4 repair");
        let profile = WireProfile {
            epoch: 12,
            codec: WireCodec::Gf4,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
        let mut wire = vec![0u8; 256];
        let mut decoded = Vec::new();

        for source_id in [0usize, 2, 3] {
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: source_id as u64,
                repair_index: SYSTEMATIC_REPAIR_INDEX,
                block_index: 0,
                systematic: true,
            };
            let written = write_packet(meta, &sources[source_id], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        let repair_meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: repair.id,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let written =
            write_packet(repair_meta, repair.payload_slice().expect("repair payload"), &mut wire)
                .expect("repair wire");
        receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
        let recovered = decoded
            .iter()
            .find(|packet| packet.id == 1)
            .and_then(FecPacket::payload_slice)
            .map(<[u8]>::to_vec);

        assert_eq!(recovered, Some(sources[1].clone()));
    }

    #[test]
    fn streaming_repair_maps_partial_window_coefficients_to_exact_source_ids() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x10; 31], vec![0x20; 47]];
        let mut encoder = super::super::Encoder8::new(4, 8);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("streaming repair");
        let profile = WireProfile {
            epoch: 12,
            codec: WireCodec::StreamingGf8,
            source_count: 4,
            total_count: 8,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
        let mut wire = vec![0u8; 256];
        let mut decoded = Vec::new();

        let source_meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: 0,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let written = write_packet(source_meta, &sources[0], &mut wire).expect("source wire");
        receiver.receive(&wire[..written], &mut decoded).expect("source receive");

        let repair_meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: repair.id,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let written =
            write_packet(repair_meta, repair.payload_slice().expect("repair payload"), &mut wire)
                .expect("repair wire");
        receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
        let recovered = decoded
            .iter()
            .find(|packet| packet.id == 1)
            .and_then(FecPacket::payload_slice)
            .map(<[u8]>::to_vec);

        assert_eq!(recovered, Some(sources[1].clone()));
    }

    #[test]
    fn gf16_recovery_preserves_odd_final_source_byte() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x51; 30], vec![0x62; 47], vec![0x73; 62], vec![0x84; 78]];
        let mut encoder = super::super::Encoder16::new(4, 6);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("GF16 repair");
        let profile = WireProfile {
            epoch: 13,
            codec: WireCodec::Gf16,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
        let mut wire = vec![0u8; 256];
        let mut decoded = Vec::new();

        for source_id in [0usize, 2, 3] {
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: source_id as u64,
                repair_index: SYSTEMATIC_REPAIR_INDEX,
                block_index: 0,
                systematic: true,
            };
            let written = write_packet(meta, &sources[source_id], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        let repair_meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: repair.id,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let written =
            write_packet(repair_meta, repair.payload_slice().expect("repair payload"), &mut wire)
                .expect("repair wire");
        receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
        let recovered = decoded
            .iter()
            .find(|packet| packet.id == 1)
            .and_then(FecPacket::payload_slice)
            .map(<[u8]>::to_vec);

        assert_eq!(recovered, Some(sources[1].clone()));
        assert_eq!(recovered.as_ref().and_then(|payload| payload.last()), Some(&0x62));
    }

    #[test]
    fn gf16_decoder_recovers_odd_source_symbol_prefix() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x51; 30], vec![0x62; 47], vec![0x73; 62], vec![0x84; 78]];
        let mut encoder = super::super::Encoder16::new(4, 6);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("GF16 repair");
        let mut decoder = super::super::Decoder16::new(4, Arc::clone(&pool));
        for source_id in [0usize, 2, 3] {
            decoder.take_packet(source_packet(source_id as u64, &sources[source_id], &pool));
        }
        decoder.take_packet(repair);
        let decoded = decoder.get_result().expect("GF16 window must decode");
        let recovered = decoded
            .iter()
            .find(|packet| packet.id == 1)
            .and_then(FecPacket::payload_slice)
            .expect("missing source must decode");

        assert_eq!(
            source_symbol_payload(recovered),
            Ok(sources[1].as_slice()),
            "recovered prefix bytes: {:?}",
            &recovered[..4]
        );
    }

    #[test]
    fn receiver_bounds_late_epoch_and_window_state() {
        let pool = crate::optimize::global_pool();
        let profile = WireProfile {
            epoch: 3,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(pool);
        let mut wire = [0u8; 64];
        let mut decoded = Vec::new();

        for window in 0..8u32 {
            let meta = WirePacketMeta {
                profile,
                window,
                sequence: window as u64 * profile.source_count as u64,
                repair_index: SYSTEMATIC_REPAIR_INDEX,
                block_index: 0,
                systematic: true,
            };
            let written = write_packet(meta, &[window as u8], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        assert_eq!(receiver.retained_windows(), RECEIVE_WINDOW_LIMIT);
    }

    #[test]
    fn receiver_rejects_profile_mutation_inside_retained_epoch() {
        let pool = crate::optimize::global_pool();
        let first_profile = WireProfile {
            epoch: 21,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let mutated_profile = WireProfile { total_count: 7, ..first_profile };
        let mut receiver = WireFecReceiver::new(pool);
        let mut wire = [0u8; 64];
        let mut decoded = Vec::new();
        let first_meta = WirePacketMeta {
            profile: first_profile,
            window: 0,
            sequence: 0,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let written = write_packet(first_meta, &[1], &mut wire).expect("first source wire");
        receiver.receive(&wire[..written], &mut decoded).expect("first source receive");

        let mutated_meta = WirePacketMeta { profile: mutated_profile, ..first_meta };
        let written = write_packet(mutated_meta, &[2], &mut wire).expect("mutated source wire");

        assert_eq!(
            receiver.receive(&wire[..written], &mut decoded),
            Err(WireError::EpochProfileMismatch)
        );
    }

    #[test]
    fn fountain_rescue_recovers_multiple_losses_from_seed_only() {
        let pool = crate::optimize::global_pool();
        let sources = [vec![0x11; 37], vec![0x22; 53], vec![0x33; 71], vec![0x44; 89]];
        let mut encoder = super::super::internal::EncoderVariant::new(FecMode::Fountain, 4, 20);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let profile = WireProfile {
            epoch: 12,
            codec: WireCodec::Fountain,
            source_count: 4,
            total_count: 36,
            interleave_depth: 1,
        };
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
        let mut wire = vec![0u8; 256];
        let mut decoded = Vec::new();
        let mut recovered = std::collections::HashMap::new();

        for source_id in [0usize, 2] {
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: source_id as u64,
                repair_index: SYSTEMATIC_REPAIR_INDEX,
                block_index: 0,
                systematic: true,
            };
            let written = write_packet(meta, &sources[source_id], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        for repair_index in 0..32u16 {
            let repair = encoder
                .generate_repair_packet(repair_index as usize, &pool)
                .expect("fountain repair");
            let payload = repair.payload_slice().expect("repair payload");
            assert!(
                payload.len() <= sources.iter().map(Vec::len).max().unwrap() + SOURCE_LENGTH_LEN
            );
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: repair.id,
                repair_index,
                block_index: 0,
                systematic: false,
            };
            let written = write_packet(meta, payload, &mut wire).expect("repair wire");
            receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
            for packet in decoded.drain(..) {
                if let Some(payload) = packet.payload_slice() {
                    recovered.insert(packet.id, payload.to_vec());
                }
            }
            if recovered.contains_key(&1) && recovered.contains_key(&3) {
                break;
            }
        }

        assert_eq!(recovered.get(&1), Some(&sources[1]));
        assert_eq!(recovered.get(&3), Some(&sources[3]));
    }
}

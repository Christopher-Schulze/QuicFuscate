//! Versioned, MTU-bounded wire framing for active forward error correction.
//!
//! Zero mode deliberately bypasses this module. Active modes use a fixed-size
//! header and derive repair coefficients from the transmitted profile and
//! repair ordinal. Source lengths are protected inside each coded symbol so a
//! recovered variable-length QUIC datagram can be restored exactly.

use crate::{FecMode, FecPacket, FecRuntimePolicy, DEFAULT_FOUNTAIN_SEED};
use qf_memory_pool::{MemoryPool, PooledBlock};
use qf_telemetry as telemetry;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

const RECEIVE_WINDOW_LIMIT: usize = 4;
type RepairKey = (u64, u16, u8);

pub use crate::wire::{
    is_framed, parse_packet, source_symbol_payload, write_packet, write_source_symbol,
    ParsedWirePacket, WireCodec, WireError, WirePacketMeta, WireProfile, WireReceiveReport,
    HEADER_LEN, MAGIC, MAX_DATAGRAM_OVERHEAD, MAX_GF8_BLOCK_SOURCE_COUNT, MAX_SOURCE_COUNT,
    MAX_TOTAL_COUNT, SOURCE_LENGTH_LEN, SYSTEMATIC_REPAIR_INDEX, VERSION,
};
use crate::wire::{source_datagram_payload, WireMode};

fn copy_to_pooled_block(pool: &Arc<MemoryPool>, data: &[u8]) -> Option<PooledBlock> {
    if data.len() > pool.block_size() {
        return None;
    }
    let mut block = PooledBlock::new(Arc::clone(pool));
    block[..data.len()].copy_from_slice(data);
    Some(block)
}

#[doc(hidden)]
pub fn codec_for_mode(mode: FecMode, block_source_count: usize) -> Result<WireCodec, WireError> {
    let mode = match mode {
        FecMode::Zero => WireMode::Zero,
        FecMode::Light => WireMode::Light,
        FecMode::Normal => WireMode::Normal,
        FecMode::Medium => WireMode::Medium,
        FecMode::Strong => WireMode::Strong,
        FecMode::Extreme => WireMode::Extreme,
        FecMode::Ultra => WireMode::Ultra,
        FecMode::Fountain => WireMode::Fountain,
        FecMode::Streaming => WireMode::Streaming,
    };
    WireCodec::for_mode(mode, block_source_count)
}

struct ReceiveWindow {
    profile: WireProfile,
    window: u32,
    decoder: crate::InterleavedDecoder,
    delivered: HashSet<u64>,
    seen_repairs: HashSet<RepairKey>,
    seen_repair_order: VecDeque<RepairKey>,
    seen_repairs_limit: usize,
    fountain_repair_ids: Vec<Option<u64>>,
    fountain_symbol_ids: HashSet<u64>,
    mem_pool: Arc<MemoryPool>,
}

impl ReceiveWindow {
    fn new(
        profile: WireProfile,
        window: u32,
        mem_pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        fountain_seed: u64,
    ) -> Self {
        let seen_repairs_limit = (profile.total_count - profile.source_count) as usize;
        let fountain_repair_limit =
            if profile.codec == WireCodec::Fountain { seen_repairs_limit } else { 0 };
        Self {
            profile,
            window,
            decoder: crate::InterleavedDecoder::new_for_wire(
                profile,
                Arc::clone(&mem_pool),
                policy,
                fountain_seed,
            ),
            delivered: HashSet::with_capacity(profile.source_count as usize),
            seen_repairs: HashSet::with_capacity(seen_repairs_limit),
            seen_repair_order: VecDeque::with_capacity(seen_repairs_limit),
            seen_repairs_limit,
            fountain_repair_ids: vec![None; fountain_repair_limit],
            fountain_symbol_ids: HashSet::with_capacity(fountain_repair_limit),
            mem_pool,
        }
    }

    fn fountain_repair_seen(&self, meta: WirePacketMeta) -> bool {
        let ordinal = meta.repair_index as usize;
        self.fountain_repair_ids.get(ordinal).and_then(|symbol_id| *symbol_id).is_some()
            || self.fountain_symbol_ids.contains(&meta.sequence)
    }

    fn remember_fountain_repair(&mut self, meta: WirePacketMeta) -> bool {
        if self.fountain_repair_seen(meta) {
            telemetry::FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS.inc();
            return false;
        }
        let ordinal = meta.repair_index as usize;
        let Some(slot) = self.fountain_repair_ids.get_mut(ordinal) else {
            return false;
        };
        *slot = Some(meta.sequence);
        self.fountain_symbol_ids.insert(meta.sequence);
        true
    }

    fn remember_repair(&mut self, key: RepairKey) -> bool {
        if self.seen_repairs.contains(&key) {
            return false;
        }
        if self.seen_repairs_limit > 0 && self.seen_repairs.len() >= self.seen_repairs_limit {
            if let Some(oldest) = self.seen_repair_order.pop_front() {
                self.seen_repairs.remove(&oldest);
                telemetry::FEC_DECODER_DEDUP_EVICTIONS.inc();
            }
        }
        self.seen_repairs.insert(key);
        self.seen_repair_order.push_back(key);
        true
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
        let mut symbol = PooledBlock::new(Arc::clone(&self.mem_pool));
        write_source_symbol(payload, &mut symbol)?;
        let internal_id = if meta.profile.codec == WireCodec::Fountain {
            // Fountain keeps the global sequence on the wire and needs a window-relative internal
            // id. `WirePacketMeta::validate()` already binds systematic sequences to the window,
            // but this conversion must not depend on a caller invariant: an unchecked subtraction
            // would panic in debug and mint a wrapped internal source id in release.
            let offset = meta
                .sequence
                .checked_sub(self.window_start())
                .ok_or(WireError::SourceOutsideWindow)?;
            if offset >= meta.profile.source_count as u64 {
                return Err(WireError::SourceOutsideWindow);
            }
            offset
        } else {
            meta.sequence
        };
        let mut packet = FecPacket::from_pooled_blocks(
            internal_id,
            Some(symbol),
            symbol_len,
            true,
            None,
            0,
            Arc::clone(&self.mem_pool),
        )
        .map_err(|_| WireError::ResourceExhausted)?;
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
        let data =
            copy_to_pooled_block(&self.mem_pool, payload).ok_or(WireError::ResourceExhausted)?;
        let (coefficients, coefficient_len) = if meta.profile.codec == WireCodec::Fountain {
            (None, 0)
        } else {
            let mut coefficients = PooledBlock::new(Arc::clone(&self.mem_pool));
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
                if span > coefficient_len {
                    return Err(WireError::ResourceExhausted);
                }
                coefficients[span..coefficient_len].fill(0);
            }
            (Some(coefficients), coefficient_len)
        };
        let decoder_anchor = if meta.profile.codec == WireCodec::StreamingGf8 {
            self.block_anchor(meta.block_index)
        } else {
            meta.sequence
        };
        let mut packet = FecPacket::from_pooled_blocks(
            decoder_anchor,
            Some(data),
            payload.len(),
            false,
            coefficients,
            coefficient_len,
            Arc::clone(&self.mem_pool),
        )
        .map_err(|_| WireError::ResourceExhausted)?;
        packet.seq = ((meta.repair_index as u64) << 4) | meta.block_index as u64;
        Ok(packet)
    }

    fn emit_recovered(
        &mut self,
        packet: FecPacket,
        output: &mut Vec<FecPacket>,
    ) -> Result<Option<usize>, WireError> {
        let global_id = if self.profile.codec == WireCodec::Fountain {
            self.window_start().saturating_add(packet.id)
        } else {
            packet.id
        };
        let symbol = packet.payload_slice().ok_or(WireError::InvalidSourceSymbolLength)?;
        let protected_payload = source_symbol_payload(symbol)?;
        let payload = source_datagram_payload(protected_payload)?;
        if !self.delivered.insert(global_id) {
            return Ok(None);
        }
        let payload_len = payload.len();
        let mut recovered = FecPacket::from_block(global_id, payload, Arc::clone(&self.mem_pool))
            .map_err(|_| WireError::PayloadTooLarge)?;
        recovered.seq = global_id;
        output.push(recovered);
        Ok(Some(payload_len))
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
    ) -> Result<WireReceiveReport, WireError> {
        let systematic_payload =
            if meta.systematic { Some(source_datagram_payload(payload)?) } else { None };
        let mut report = WireReceiveReport {
            systematic: meta.systematic,
            source_payload_bytes: systematic_payload.map_or(0, <[u8]>::len),
            wire_bytes: HEADER_LEN + payload.len(),
            ..WireReceiveReport::default()
        };
        let systematic = meta.systematic;
        if systematic && self.delivered.contains(&meta.sequence) {
            return Ok(report);
        }
        if !systematic
            && meta.profile.codec == WireCodec::StreamingGf8
            && !self.streaming_repair_has_missing_source(meta)
        {
            return Ok(report);
        }
        let repair_key = (meta.sequence, meta.repair_index, meta.block_index);
        if !systematic && self.seen_repairs.contains(&repair_key) {
            return Ok(report);
        }
        if !systematic
            && meta.profile.codec == WireCodec::Fountain
            && self.fountain_repair_seen(meta)
        {
            telemetry::FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS.inc();
            return Ok(report);
        }
        let packet = if systematic {
            self.source_packet(meta, payload)?
        } else {
            self.repair_packet(meta, payload)?
        };
        if !systematic {
            let admitted = if meta.profile.codec == WireCodec::Fountain {
                self.remember_fountain_repair(meta)
            } else {
                self.remember_repair(repair_key)
            };
            if !admitted {
                return Ok(report);
            }
        }

        self.decoder.take_packet(packet);
        if systematic && self.delivered.insert(meta.sequence) {
            let payload = systematic_payload.ok_or(WireError::InvalidSourceDatagramLength)?;
            let mut original =
                FecPacket::from_block(meta.sequence, payload, Arc::clone(&self.mem_pool))
                    .map_err(|_| WireError::PayloadTooLarge)?;
            original.seq = meta.sequence;
            output.push(original);
            report.decoded_packets += 1;
        }

        if self.decoder.recovery_needed() {
            let mut recovered = if self.decoder.full_recovery_needed() {
                self.decoder.get_result().unwrap_or_default()
            } else {
                self.decoder.get_partial_result()
            };
            // Some backends (Fountain, GF16) may have partial progress even when a full
            // recovery attempt returns no new packets. Drain the partial queue too, so
            // any recovered sources are not lost when the window advances.
            if recovered.is_empty() {
                recovered = self.decoder.get_partial_result();
            }
            for packet in recovered {
                if let Some(payload_len) = self.emit_recovered(packet, output)? {
                    report.decoded_packets += 1;
                    report.recovered_packets += 1;
                    report.recovered_payload_bytes += payload_len;
                }
            }
        }
        Ok(report)
    }
}

pub struct WireFecReceiver {
    windows: VecDeque<ReceiveWindow>,
    mem_pool: Arc<MemoryPool>,
    policy: FecRuntimePolicy,
    fountain_seed: u64,
}

impl WireFecReceiver {
    pub fn new(mem_pool: Arc<MemoryPool>) -> Self {
        crate::gf_tables::init_tables();
        Self {
            windows: VecDeque::with_capacity(RECEIVE_WINDOW_LIMIT),
            mem_pool,
            policy: FecRuntimePolicy::detect(),
            fountain_seed: DEFAULT_FOUNTAIN_SEED,
        }
    }

    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        if self.fountain_seed == seed {
            return;
        }
        self.fountain_seed = seed;
        self.windows.clear();
    }

    pub fn receive(
        &mut self,
        datagram: &[u8],
        output: &mut Vec<FecPacket>,
    ) -> Result<WireReceiveReport, WireError> {
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
                    self.fountain_seed,
                ));
                self.windows.len() - 1
            });
        self.windows[window_index].receive(parsed.meta, parsed.payload, output)
    }

    /// Parse a framed peer datagram while local recovery policy is Off.
    ///
    /// Systematic payloads remain deliverable to QUIC, but repairs are discarded
    /// without allocating decoder state or retaining a receive window.
    pub fn receive_source_only(
        &self,
        datagram: &[u8],
        output: &mut Vec<FecPacket>,
    ) -> Result<WireReceiveReport, WireError> {
        output.clear();
        let parsed = parse_packet(datagram)?;
        let mut report = WireReceiveReport {
            systematic: parsed.meta.systematic,
            wire_bytes: HEADER_LEN + parsed.payload.len(),
            ..WireReceiveReport::default()
        };
        if !parsed.meta.systematic {
            return Ok(report);
        }

        let payload = source_datagram_payload(parsed.payload)?;
        report.source_payload_bytes = payload.len();
        report.decoded_packets = 1;
        let mut packet =
            FecPacket::try_from_block(parsed.meta.sequence, payload, Arc::clone(&self.mem_pool))
                .map_err(|_| WireError::ResourceExhausted)?;
        packet.seq = parsed.meta.sequence;
        output.push(packet);
        Ok(report)
    }

    #[cfg(test)]
    fn retained_windows(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> Arc<MemoryPool> {
        Arc::new(MemoryPool::new(64, 8192))
    }

    fn source_packet(id: u64, payload: &[u8], pool: &Arc<MemoryPool>) -> FecPacket {
        let mut data = pool.alloc();
        let data_len = write_source_symbol(payload, &mut data).expect("source symbol");
        let mut packet = FecPacket::new(id, Some(data), data_len, true, None, 0, Arc::clone(pool));
        packet.seq = id;
        packet
    }

    fn protected_datagram(payload: &[u8]) -> Vec<u8> {
        let payload_len = u16::try_from(payload.len()).expect("test datagram length");
        let mut protected = Vec::with_capacity(SOURCE_LENGTH_LEN + payload.len());
        protected.extend_from_slice(&payload_len.to_be_bytes());
        protected.extend_from_slice(payload);
        protected
    }

    fn profile(codec: WireCodec) -> WireProfile {
        WireProfile { epoch: 7, codec, source_count: 64, total_count: 80, interleave_depth: 4 }
    }

    #[test]
    fn seen_repairs_are_bounded_by_profile_repair_capacity() {
        let pool = test_pool();
        let policy = FecRuntimePolicy::detect();
        let profile = profile(WireCodec::Gf8);
        let limit = (profile.total_count - profile.source_count) as usize;
        let mut window = ReceiveWindow::new(profile, 0, pool, &policy, DEFAULT_FOUNTAIN_SEED);

        for ordinal in 0..limit.saturating_mul(3) {
            assert!(window.remember_repair((ordinal as u64, ordinal as u16, 0)));
            assert!(window.seen_repairs.len() <= limit);
            assert!(window.seen_repair_order.len() <= limit);
        }
        assert_eq!(window.seen_repairs.len(), limit);
    }

    #[test]
    fn fountain_admission_binds_global_ids_to_bounded_ordinals() {
        let pool = test_pool();
        let policy = FecRuntimePolicy::detect();
        let profile = WireProfile {
            epoch: 7,
            codec: WireCodec::Fountain,
            source_count: 4,
            total_count: 36,
            interleave_depth: 1,
        };
        let limit = (profile.total_count - profile.source_count) as usize;
        let mut window = ReceiveWindow::new(profile, 0, pool, &policy, DEFAULT_FOUNTAIN_SEED);

        for symbol_id in 0..100_000u64 {
            let meta = WirePacketMeta {
                profile,
                window: 0,
                sequence: symbol_id,
                repair_index: (symbol_id as usize % limit) as u16,
                block_index: 0,
                systematic: false,
            };
            if symbol_id < limit as u64 {
                assert!(window.remember_fountain_repair(meta));
            } else {
                assert!(!window.remember_fountain_repair(meta));
            }
        }

        assert_eq!(window.fountain_symbol_ids.len(), limit);
        assert_eq!(window.fountain_repair_ids.iter().flatten().count(), limit);
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
    fn source_only_receive_delivers_sources_and_never_retains_repair_state() {
        let pool = test_pool();
        let receiver = WireFecReceiver::new(pool);
        let wire_profile = profile(WireCodec::Gf8);
        let mut wire = [0u8; 256];
        let mut output = Vec::new();
        let source_payload = protected_datagram(&[0x40, 0x11, 0x22, 0x33]);
        let source_meta = WirePacketMeta {
            profile: wire_profile,
            window: 1,
            sequence: 64,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let source_len =
            write_packet(source_meta, &source_payload, &mut wire).expect("source wire");

        let source_report = receiver
            .receive_source_only(&wire[..source_len], &mut output)
            .expect("source-only receive");
        assert!(source_report.systematic);
        assert_eq!(source_report.decoded_packets, 1);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].payload_slice(), Some(&[0x40, 0x11, 0x22, 0x33][..]));
        assert_eq!(receiver.retained_windows(), 0);

        let repair_meta =
            WirePacketMeta { systematic: false, sequence: 124, repair_index: 0, ..source_meta };
        let repair_len = write_packet(repair_meta, &[7; 16], &mut wire).expect("repair wire");
        let repair_report =
            receiver.receive_source_only(&wire[..repair_len], &mut output).expect("repair discard");
        assert!(!repair_report.systematic);
        assert!(output.is_empty());
        assert_eq!(receiver.retained_windows(), 0);
    }

    #[test]
    fn source_only_receive_rejects_payload_larger_than_pool_block() {
        let pool = Arc::new(MemoryPool::new(2, 32));
        let receiver = WireFecReceiver::new(Arc::clone(&pool));
        let profile = WireProfile {
            epoch: 1,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let payload = protected_datagram(&vec![0xA5; pool.block_size() + 1]);
        let meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: 0,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let mut datagram = vec![0u8; HEADER_LEN + payload.len()];
        let written = write_packet(meta, &payload, &mut datagram).expect("source wire");
        let mut output = Vec::new();
        assert_eq!(
            receiver.receive_source_only(&datagram[..written], &mut output),
            Err(WireError::ResourceExhausted)
        );
        assert!(output.is_empty());
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
        let before = pool.accounting_snapshot();
        let oversized_payload_len = pool.block_size() + 1;
        let mut receiver = WireFecReceiver::new(Arc::clone(&pool));
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
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn codec_cascade_reserves_fountain_for_rescue_mode() {
        assert_eq!(codec_for_mode(FecMode::Light, 12), Ok(WireCodec::Gf4));
        assert_eq!(codec_for_mode(FecMode::Light, 16), Ok(WireCodec::Gf8));
        assert_eq!(codec_for_mode(FecMode::Normal, 64), Ok(WireCodec::Gf8));
        assert_eq!(codec_for_mode(FecMode::Strong, 128), Ok(WireCodec::Gf8));
        assert_eq!(codec_for_mode(FecMode::Extreme, 128), Ok(WireCodec::Gf8));
        assert_eq!(codec_for_mode(FecMode::Ultra, 256), Ok(WireCodec::Gf16));
        assert_eq!(codec_for_mode(FecMode::Fountain, 2048), Ok(WireCodec::Fountain));
        assert_eq!(codec_for_mode(FecMode::Zero, 0), Err(WireError::ZeroModeMustRemainRaw));
    }

    #[test]
    fn direct_wire_helpers_reject_invalid_dimensions_and_ordinals() {
        let invalid_profile = WireProfile {
            epoch: 1,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 8,
            interleave_depth: 0,
        };
        assert_eq!(
            invalid_profile.try_block_source_count(),
            Err(WireError::InvalidInterleaveDepth)
        );
        assert_eq!(invalid_profile.block_source_count(), 0);
        assert_eq!(WireCodec::Gf8.coefficient_len(0), Err(WireError::InvalidSourceCount));
        assert_eq!(
            WireCodec::Gf16.coefficient_len(MAX_SOURCE_COUNT + 1),
            Err(WireError::InvalidSourceCount)
        );
        assert_eq!(codec_for_mode(FecMode::Normal, 0), Err(WireError::InvalidSourceCount));

        let mut coefficients = [0u8; 8];
        assert_eq!(
            WireCodec::Gf16.write_repair_coefficients(
                4,
                SYSTEMATIC_REPAIR_INDEX,
                &mut coefficients
            ),
            Err(WireError::InvalidRepairMetadata)
        );
        assert_eq!(
            WireCodec::Gf16.write_repair_coefficients(4, u16::MAX - 1, &mut coefficients),
            Err(WireError::InvalidRepairMetadata)
        );
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
            .map(|source_index| crate::gf_tables::gf_inv8(source_index ^ 6))
            .collect::<Vec<_>>();
        assert_eq!(&coefficients[..gf8_len], expected_gf8);

        let gf16_len = WireCodec::Gf16
            .write_repair_coefficients(4, 2, &mut coefficients)
            .expect("GF16 coefficients must derive");
        let expected_gf16 = (0..4u16)
            .flat_map(|source_index| crate::gf_tables::gf16_inv(source_index ^ 6).to_be_bytes())
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
    fn configured_mtu_reservation_covers_both_repair_length_symbols() {
        let outer_mtu = 1200usize;
        let max_inner_quic = outer_mtu - MAX_DATAGRAM_OVERHEAD;
        let max_repair_payload = max_inner_quic + (2 * SOURCE_LENGTH_LEN);

        assert_eq!(HEADER_LEN + max_repair_payload, outer_mtu);
    }

    #[test]
    fn receiver_recovers_exact_variable_length_source_without_wire_coefficients() {
        let pool = test_pool();
        let sources = [vec![0x10; 31], vec![0x20; 47], vec![0x30; 63], vec![0x40; 79]];
        let protected_sources = sources.each_ref().map(|source| protected_datagram(source));
        let mut encoder = crate::Encoder8::new(4, 6);
        for (id, _) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, &protected_sources[id], &pool));
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
            let written =
                write_packet(meta, &protected_sources[source_id], &mut wire).expect("source wire");
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
        let report = receiver.receive(&wire[..written], &mut decoded).expect("repair receive");
        for packet in decoded {
            if packet.id == 1 {
                recovered = packet.payload_slice().map(<[u8]>::to_vec);
            }
        }

        assert_eq!(recovered, Some(sources[1].clone()));
        assert!(!report.systematic);
        assert_eq!(report.wire_bytes, written);
        assert_eq!(report.decoded_packets, 1);
        assert_eq!(report.recovered_packets, 1);
        assert_eq!(report.recovered_payload_bytes, sources[1].len());
    }

    #[test]
    fn receiver_report_counts_accepted_source_once_and_duplicate_as_no_output() {
        let pool = test_pool();
        let mut receiver = WireFecReceiver::new(pool);
        let profile = WireProfile {
            epoch: 30,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: 0,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let payload = [0x40, 0x11, 0x22, 0x33];
        let protected_payload = protected_datagram(&payload);
        let mut wire = [0u8; 128];
        let written = write_packet(meta, &protected_payload, &mut wire).expect("source wire");
        let mut decoded = Vec::new();

        let first = receiver.receive(&wire[..written], &mut decoded).expect("first source");
        assert_eq!(
            first,
            WireReceiveReport {
                systematic: true,
                source_payload_bytes: payload.len(),
                wire_bytes: written,
                decoded_packets: 1,
                recovered_packets: 0,
                recovered_payload_bytes: 0,
            }
        );
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload_slice(), Some(&payload[..]));

        let duplicate = receiver.receive(&wire[..written], &mut decoded).expect("duplicate source");
        assert_eq!(duplicate.decoded_packets, 0);
        assert_eq!(duplicate.recovered_packets, 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn receiver_rejects_systematic_datagram_with_invalid_inner_length() {
        let pool = test_pool();
        let profile = WireProfile {
            epoch: 31,
            codec: WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: 0,
            repair_index: SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let mut wire = [0u8; 128];
        let written =
            write_packet(meta, &[0, 5, 0x40], &mut wire).expect("source wire must encode");
        let mut receiver = WireFecReceiver::new(pool);
        let mut decoded = Vec::new();

        assert_eq!(
            receiver.receive(&wire[..written], &mut decoded),
            Err(WireError::InvalidSourceDatagramLength)
        );
        assert!(decoded.is_empty());
    }

    #[test]
    fn gf4_receiver_recovers_exact_source_from_compact_repair_metadata() {
        let pool = test_pool();
        let sources = [vec![0x11; 31], vec![0x22; 47], vec![0x33; 63], vec![0x44; 79]];
        let protected_sources = sources.each_ref().map(|source| protected_datagram(source));
        let mut encoder = crate::Encoder4::new(4, 6);
        for (id, _) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, &protected_sources[id], &pool));
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
            let written =
                write_packet(meta, &protected_sources[source_id], &mut wire).expect("source wire");
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
        let pool = test_pool();
        let sources = [vec![0x10; 31], vec![0x20; 47]];
        let protected_sources = sources.each_ref().map(|source| protected_datagram(source));
        let mut encoder = crate::Encoder8::new(4, 8);
        for (id, _) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, &protected_sources[id], &pool));
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
        let written =
            write_packet(source_meta, &protected_sources[0], &mut wire).expect("source wire");
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
        let pool = test_pool();
        let sources = [vec![0x51; 30], vec![0x62; 47], vec![0x73; 62], vec![0x84; 78]];
        let protected_sources = sources.each_ref().map(|source| protected_datagram(source));
        let mut encoder = crate::Encoder16::new(4, 6);
        for (id, _) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, &protected_sources[id], &pool));
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
            let written =
                write_packet(meta, &protected_sources[source_id], &mut wire).expect("source wire");
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
        let pool = test_pool();
        let sources = [vec![0x51; 30], vec![0x62; 47], vec![0x73; 62], vec![0x84; 78]];
        let mut encoder = crate::Encoder16::new(4, 6);
        for (id, payload) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, payload, &pool));
        }
        let repair = encoder.generate_repair_packet(0, &pool).expect("GF16 repair");
        let mut decoder = crate::Decoder16::new(4, Arc::clone(&pool));
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

        assert_eq!(source_symbol_payload(recovered), Ok(sources[1].as_slice()));
    }

    #[test]
    fn receiver_bounds_late_epoch_and_window_state() {
        let pool = test_pool();
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
            let payload = protected_datagram(&[window as u8]);
            let written = write_packet(meta, &payload, &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        assert_eq!(receiver.retained_windows(), RECEIVE_WINDOW_LIMIT);
    }

    #[test]
    fn receiver_rejects_profile_mutation_inside_retained_epoch() {
        let pool = test_pool();
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
        let first_payload = protected_datagram(&[1]);
        let written =
            write_packet(first_meta, &first_payload, &mut wire).expect("first source wire");
        receiver.receive(&wire[..written], &mut decoded).expect("first source receive");

        let mutated_meta = WirePacketMeta { profile: mutated_profile, ..first_meta };
        let mutated_payload = protected_datagram(&[2]);
        let written =
            write_packet(mutated_meta, &mutated_payload, &mut wire).expect("mutated source wire");

        assert_eq!(
            receiver.receive(&wire[..written], &mut decoded),
            Err(WireError::EpochProfileMismatch)
        );
    }

    #[test]
    fn fountain_rescue_recovers_multiple_losses_from_seed_only() {
        let pool = test_pool();
        let sources = [vec![0x11; 37], vec![0x22; 53], vec![0x33; 71], vec![0x44; 89]];
        let protected_sources = sources.each_ref().map(|source| protected_datagram(source));
        let mut encoder = crate::EncoderVariant::new(FecMode::Fountain, 4, 20);
        for (id, _) in sources.iter().enumerate() {
            encoder.take_packet(source_packet(id as u64, &protected_sources[id], &pool));
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
            let written =
                write_packet(meta, &protected_sources[source_id], &mut wire).expect("source wire");
            receiver.receive(&wire[..written], &mut decoded).expect("source receive");
        }

        for repair_index in 0..32u16 {
            let repair = encoder
                .generate_repair_packet(repair_index as usize, &pool)
                .expect("fountain repair");
            let payload = repair.payload_slice().expect("repair payload");
            assert!(
                payload.len()
                    <= protected_sources.iter().map(Vec::len).max().unwrap() + SOURCE_LENGTH_LEN
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

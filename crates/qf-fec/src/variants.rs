//! FEC backend dispatch for block and fountain codecs.
//!
//! The product root keeps lazy and interleaved orchestration. This module owns
//! the mode-to-codec variants so those orchestrators depend on a leaf contract.

use crate::codecs::{Encoder, Encoder16, Encoder4, FecMode, FecPacket, GF8};
use crate::decoders::{Decoder16, Decoder4, Decoder8};
use crate::fountain_codes::{LTDecoder, LTEncoder};
use crate::policy::FecRuntimePolicy;
use crate::target::{
    fec_backend_family, low_cost_block_uses_gf4, target_from_mode, FecBackendFamily,
};
use crate::wire::WireCodec;
use crate::{ZeroDecoder, ZeroEncoder};
use qf_memory_pool::{MemoryPool, PooledBlock};
use qf_telemetry as telemetry;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static REPAIR_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_repair_id() -> u64 {
    REPAIR_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn copy_to_pooled_block(pool: &Arc<MemoryPool>, data: &[u8]) -> Option<PooledBlock> {
    if data.len() > pool.block_size() {
        return None;
    }
    let mut block = PooledBlock::new(Arc::clone(pool));
    block[..data.len()].copy_from_slice(data);
    Some(block)
}

/// LT fountain encoder alias for internal FEC variant dispatch.
#[doc(hidden)]
pub type FountainEncoder = LTEncoder;
/// LT fountain decoder alias for internal FEC variant dispatch.
#[doc(hidden)]
pub type FountainDecoder = LTDecoder;

/// Encoder variant for different FEC modes.
#[doc(hidden)]
pub enum EncoderVariant {
    /// Zero-overhead passthrough (no repairs generated).
    Zero(ZeroEncoder),
    /// GF(2^8) block encoder for moderate loss.
    GF8(Encoder<GF8>),
    /// GF(2^16) block encoder for high loss.
    GF16(Encoder16),
    /// GF(2^4) block encoder for ultra-low loss.
    GF4(Encoder4),
    /// LT fountain rateless encoder for extreme loss.
    Fountain(FountainEncoder),
}

impl EncoderVariant {
    /// Create a test encoder variant with auto-detected policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new(mode: FecMode, k: usize, n: usize) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, n, &policy)
    }

    /// Create an encoder variant matching the given FEC mode with explicit policy.
    #[doc(hidden)]
    pub fn new_with_policy(mode: FecMode, k: usize, n: usize, policy: &FecRuntimePolicy) -> Self {
        let target = target_from_mode(mode, k);
        match fec_backend_family(mode) {
            FecBackendFamily::Fountain => {
                let symbol_size = policy.fountain_symbol_size;
                telemetry::FOUNTAIN_SYMBOL_SIZE.store(symbol_size as u64, Ordering::Relaxed);
                Self::Fountain(FountainEncoder::new(k, symbol_size))
            }
            FecBackendFamily::Zero => Self::Zero(ZeroEncoder::new(k, n)),
            FecBackendFamily::LowCostBlock => {
                if low_cost_block_uses_gf4(target) && k <= 15 {
                    Self::GF4(Encoder4::new(k, n))
                } else {
                    Self::GF8(Encoder::<GF8>::new(k, n))
                }
            }
            FecBackendFamily::HeavyBlock => {
                if k <= 255 {
                    Self::GF8(Encoder::<GF8>::new(k, n))
                } else {
                    Self::GF16(Encoder16::new(k, n))
                }
            }
            FecBackendFamily::Streaming => Self::GF8(Encoder::<GF8>::new(k, n)),
        }
    }

    /// Feed a source packet into the active encoder backend.
    pub fn take_packet(&mut self, packet: FecPacket) {
        match self {
            Self::Zero(encoder) => encoder.take_packet(packet),
            Self::GF8(encoder) => encoder.take_packet(packet),
            Self::GF16(encoder) => encoder.take_packet(packet),
            Self::GF4(encoder) => encoder.take_packet(packet),
            Self::Fountain(encoder) => {
                if let Some(data) = packet.payload_slice() {
                    let _ = encoder.add_source_symbol(data.to_vec());
                }
            }
        }
    }

    /// Generate the i-th repair packet from the active encoder backend.
    pub fn generate_repair_packet(
        &mut self,
        index: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        match self {
            Self::Zero(encoder) => encoder.generate_repair_packet(index, pool),
            Self::GF8(encoder) => encoder.generate_repair_packet(index, pool),
            Self::GF16(encoder) => encoder.generate_repair_packet(index, pool),
            Self::GF4(encoder) => encoder.generate_repair_packet(index, pool),
            Self::Fountain(encoder) => {
                let symbol_id = next_repair_id();
                let (encoded_data, indices) = encoder.generate_symbol_with_indices(symbol_id);
                let coefficient_len = indices.len().checked_mul(4)?;
                if coefficient_len > pool.block_size() {
                    return None;
                }
                let data_block = copy_to_pooled_block(pool, &encoded_data)?;
                let mut coefficient_block = PooledBlock::new(Arc::clone(pool));
                for (offset, index) in indices.iter().enumerate() {
                    let bytes = u32::try_from(*index).ok()?.to_be_bytes();
                    let start = offset * 4;
                    coefficient_block[start..start + 4].copy_from_slice(&bytes);
                }
                FecPacket::from_pooled_blocks(
                    symbol_id,
                    Some(data_block),
                    encoded_data.len(),
                    false,
                    Some(coefficient_block),
                    coefficient_len,
                    Arc::clone(pool),
                )
                .ok()
            }
        }
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn backend_kind(&self) -> &'static str {
        match self {
            Self::Zero(_) => "zero",
            Self::GF4(_) => "gf4",
            Self::GF8(_) => "gf8",
            Self::GF16(_) => "gf16",
            Self::Fountain(_) => "fountain",
        }
    }

    /// Clear all source packets from the encoding window.
    pub fn clear_window(&mut self) {
        match self {
            Self::Zero(encoder) => encoder.clear_window(),
            Self::GF8(encoder) => encoder.clear_window(),
            Self::GF16(encoder) => encoder.clear_window(),
            Self::GF4(encoder) => encoder.clear_window(),
            Self::Fountain(encoder) => encoder.clear_window(),
        }
    }

    /// Return the number of source packets currently in the encoding window.
    pub fn packets_in_window(&self) -> usize {
        match self {
            Self::Zero(encoder) => encoder.packets_in_window(),
            Self::GF8(encoder) => encoder.packets_in_window(),
            Self::GF16(encoder) => encoder.packets_in_window(),
            Self::GF4(encoder) => encoder.packets_in_window(),
            Self::Fountain(encoder) => encoder.packets_in_window(),
        }
    }

    /// Update the connection-local fountain seed when this variant uses LT coding.
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        if let Self::Fountain(encoder) = self {
            encoder.set_seed(seed);
        }
    }
}

/// Decoder variant for different FEC modes.
#[doc(hidden)]
pub enum DecoderVariant {
    /// Zero-overhead passthrough (no decoding, just gap detection).
    Zero(ZeroDecoder),
    /// GF(2^8) block decoder for moderate loss recovery.
    GF8(Decoder8),
    /// GF(2^16) block decoder for high loss recovery.
    GF16(Decoder16),
    /// GF(2^4) block decoder for ultra-low loss recovery.
    GF4(Decoder4),
    /// LT fountain rateless decoder for extreme loss recovery.
    Fountain(FountainDecoder),
}

impl DecoderVariant {
    /// Construct a decoder from a validated wire codec.
    #[doc(hidden)]
    pub fn new_for_wire(
        codec: WireCodec,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
        seed: u64,
        fountain_repair_limit: usize,
    ) -> Self {
        match codec {
            WireCodec::Gf4 => Self::GF4(Decoder4::new_with_depth(k, pool, depth)),
            WireCodec::Gf8 | WireCodec::StreamingGf8 => {
                Self::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
            }
            WireCodec::Gf16 => Self::GF16(Decoder16::new_with_depth(k, pool, depth)),
            WireCodec::Fountain => Self::Fountain(FountainDecoder::new_with_repair_limit(
                k,
                policy.fountain_symbol_size,
                pool,
                seed,
                fountain_repair_limit,
            )),
        }
    }

    /// Create a test decoder variant with auto-detected policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    /// Create a decoder variant with explicit policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self::new_with_depth(mode, k, pool, policy, 1)
    }

    /// Create a decoder variant with explicit interleave depth.
    #[doc(hidden)]
    pub fn new_with_depth(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        let target = target_from_mode(mode, k);
        match fec_backend_family(mode) {
            FecBackendFamily::Fountain => {
                let symbol_size = policy.fountain_symbol_size;
                telemetry::FOUNTAIN_SYMBOL_SIZE.store(symbol_size as u64, Ordering::Relaxed);
                Self::Fountain(FountainDecoder::new(k, symbol_size, Arc::clone(&pool)))
            }
            FecBackendFamily::Zero => Self::Zero(ZeroDecoder::new(k, pool)),
            FecBackendFamily::LowCostBlock => {
                if low_cost_block_uses_gf4(target) && k <= 15 {
                    Self::GF4(Decoder4::new_with_depth(k, pool, depth))
                } else {
                    Self::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
                }
            }
            FecBackendFamily::HeavyBlock => {
                if k <= 255 {
                    Self::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
                } else {
                    Self::GF16(Decoder16::new_with_depth(k, pool, depth))
                }
            }
            FecBackendFamily::Streaming => {
                Self::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
            }
        }
    }

    /// Feed a received packet into the active decoder backend.
    pub fn take_packet(&mut self, packet: FecPacket) {
        if !packet.is_systematic {
            telemetry::FEC_DECODER_EQUATIONS.inc();
        }
        match self {
            Self::Zero(decoder) => decoder.take_packet(packet),
            Self::GF8(decoder) => decoder.take_packet(packet),
            Self::GF16(decoder) => decoder.take_packet(packet),
            Self::GF4(decoder) => decoder.take_packet(packet),
            Self::Fountain(decoder) => {
                if let Some(data) = packet.payload_slice() {
                    let payload = data.to_vec();
                    if packet.is_systematic {
                        match usize::try_from(packet.id) {
                            Ok(source_index) => {
                                let _ = decoder.add_source_symbol(source_index, payload);
                            }
                            Err(_) => {
                                log::debug!(
                                    "dropping Fountain source symbol with id {} that exceeds usize",
                                    packet.id
                                );
                            }
                        }
                    } else {
                        let source_indices = decoder.source_indices(packet.id);
                        let _ = decoder.add_encoded_symbol(packet.id, payload, source_indices);
                    }
                }
            }
        }
    }

    /// Update the connection-local fountain seed when this variant uses LT coding.
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        if let Self::Fountain(decoder) = self {
            decoder.set_seed(seed);
        }
    }

    /// Attempt full recovery and return decoded packets, or None if incomplete.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        match self {
            Self::Zero(decoder) => decoder.get_result(),
            Self::GF8(decoder) => decoder.get_result(),
            Self::GF16(decoder) => decoder.get_result(),
            Self::GF4(decoder) => decoder.get_result(),
            Self::Fountain(decoder) => {
                let _ = decoder.belief_propagation_decode();
                if let Some(symbols) = decoder.get_decoded_indexed() {
                    telemetry::FOUNTAIN_PROGRESS.store(1_000_000, Ordering::Relaxed);
                    let mut packets = VecDeque::new();
                    for (source_index, symbol) in symbols {
                        let pool = decoder.memory_pool();
                        let data = copy_to_pooled_block(&pool, &symbol)?;
                        let packet = FecPacket::from_pooled_blocks(
                            source_index as u64,
                            Some(data),
                            symbol.len(),
                            true,
                            None,
                            0,
                            pool,
                        )
                        .ok()?;
                        packets.push_back(packet);
                    }
                    Some(packets)
                } else {
                    let progress = (decoder.decoding_progress() * 1_000_000.0) as u64;
                    telemetry::FOUNTAIN_PROGRESS.store(progress, Ordering::Relaxed);
                    None
                }
            }
        }
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn backend_kind(&self) -> &'static str {
        match self {
            Self::Zero(_) => "zero",
            Self::GF4(_) => "gf4",
            Self::GF8(_) => "gf8",
            Self::GF16(_) => "gf16",
            Self::Fountain(_) => "fountain",
        }
    }

    /// Drain any available decoded packets without requiring full recovery.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        match self {
            Self::Zero(decoder) => decoder.get_partial_result(),
            Self::GF8(decoder) => decoder.get_partial_result(),
            Self::GF16(decoder) => decoder.get_partial_result(),
            Self::GF4(decoder) => decoder.get_partial_result(),
            Self::Fountain(decoder) => {
                let _ = decoder.belief_propagation_step();
                let mut partial = VecDeque::new();
                for (source_index, symbol) in decoder.get_partial_indexed() {
                    let pool = decoder.memory_pool();
                    let Some(data) = copy_to_pooled_block(&pool, &symbol) else {
                        continue;
                    };
                    let Some(packet) = FecPacket::from_pooled_blocks(
                        source_index as u64,
                        Some(data),
                        symbol.len(),
                        true,
                        None,
                        0,
                        pool,
                    )
                    .ok() else {
                        continue;
                    };
                    partial.push_back(packet);
                }
                let progress = (decoder.decoding_progress() * 1_000_000.0) as u64;
                telemetry::FOUNTAIN_PROGRESS.store(progress, Ordering::Relaxed);
                partial
            }
        }
    }
}

//! Interleaved block encoding for burst-loss protection.

use crate::codecs::{FecMode, FecPacket};
use crate::policy::FecRuntimePolicy;
use crate::variants::EncoderVariant;
use qf_memory_pool::MemoryPool;
use std::sync::Arc;

/// Bits reserved at the bottom of an interleaved repair identity for the lane index.
///
/// Interleave depth is clamped to `1..=8`, so four bits always hold the lane.
#[doc(hidden)]
pub const REPAIR_LANE_BITS: u32 = 4;

/// Largest repair ordinal that still fits above [`REPAIR_LANE_BITS`] in a `u64` identity.
///
/// An ordinal beyond this would shift out of range and alias an unrelated repair packet, so the
/// interleaved encoder refuses to mint one.
#[doc(hidden)]
pub const MAX_REPAIR_ORDINAL: u64 = u64::MAX >> REPAIR_LANE_BITS;

/// InterleavedEncoder distributes packets across multiple FEC blocks to protect against burst
/// losses. With `interleave_depth=4`, a burst of four consecutive losses leaves at most one loss
/// per block.
#[doc(hidden)]
pub struct InterleavedEncoder {
    blocks: Vec<EncoderVariant>,
    depth: usize,
    packet_idx: usize,
    /// Sources actually represented across all lanes (`block_k * depth`).
    k: usize,
    /// Total symbols actually represented across all lanes (`block_n * depth`).
    n: usize,
}

impl InterleavedEncoder {
    /// Create an interleaved encoder with explicit runtime policy.
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        n: usize,
        depth: usize,
        policy: &FecRuntimePolicy,
    ) -> Self {
        let actual_depth = if policy.interleave_enabled { depth.clamp(1, 8) } else { 1 };
        let block_k = (k / actual_depth).max(1);
        let block_n = (n / actual_depth).max(block_k);
        let blocks = (0..actual_depth)
            .map(|_| EncoderVariant::new_with_policy(mode, block_k, block_n, policy))
            .collect();
        let represented_k = block_k.saturating_mul(actual_depth);
        let represented_n = block_n.saturating_mul(actual_depth).max(represented_k);

        if (represented_k, represented_n) != (k, n) {
            log::warn!(
                "interleave depth {actual_depth} does not divide the requested FEC shape \
                 (k={k}, n={n}); representing (k={represented_k}, n={represented_n})"
            );
        }

        Self { blocks, depth: actual_depth, packet_idx: 0, k: represented_k, n: represented_n }
    }

    /// Return the `(k, n)` parameters the encoder actually represents across its lanes.
    pub fn params(&self) -> (usize, usize) {
        (self.k, self.n)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Distribute a source packet round-robin across interleaved blocks.
    pub fn take_packet(&mut self, packet: FecPacket) {
        let block_idx = self.packet_idx % self.depth;
        self.blocks[block_idx].take_packet(packet);
        self.packet_idx = self.packet_idx.wrapping_add(1);
    }

    /// Generate a single repair packet, delegating to the lane selected by `i % depth`.
    pub fn generate_repair_packet(
        &mut self,
        i: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        let block_idx = i % self.depth;
        let repair_idx = i / self.depth;
        if repair_idx as u64 > MAX_REPAIR_ORDINAL {
            return None;
        }
        if let Some(mut repair) =
            self.blocks.get_mut(block_idx)?.generate_repair_packet(repair_idx, pool)
        {
            repair.seq = ((repair_idx as u64) << REPAIR_LANE_BITS) | block_idx as u64;
            Some(repair)
        } else {
            None
        }
    }

    /// Clear all interleaved block windows and reset the packet counter.
    pub fn clear_window(&mut self) {
        for block in &mut self.blocks {
            block.clear_window();
        }
        self.packet_idx = 0;
    }

    /// Total number of packets buffered across all interleaved blocks.
    pub fn packets_in_window(&self) -> usize {
        self.blocks.iter().map(EncoderVariant::packets_in_window).sum()
    }

    /// Update the connection-local fountain seed on every lane.
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        for block in &mut self.blocks {
            block.set_fountain_seed(seed);
        }
    }

    /// Return the fountain symbol size of the first block.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn first_block_fountain_symbol_size(&self) -> Option<usize> {
        match self.blocks.first()? {
            EncoderVariant::Fountain(encoder) => Some(encoder.symbol_size()),
            _ => None,
        }
    }
}

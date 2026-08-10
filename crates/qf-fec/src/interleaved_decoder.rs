//! Interleaved block decoding for burst-loss recovery.

use crate::codecs::{FecMode, FecPacket};
use crate::decoders::{validate_decoder_dimensions, MAX_DECODER_SOURCE_COUNT};
use crate::lazy::LazyDecoder;
use crate::policy::FecRuntimePolicy;
use crate::wire::WireProfile;
use qf_memory_pool::MemoryPool;
use std::collections::VecDeque;
use std::sync::Arc;

/// InterleavedDecoder routes sources and repairs to independent lazy decoder lanes.
#[doc(hidden)]
pub struct InterleavedDecoder {
    blocks: Vec<LazyDecoder>,
    depth: usize,
}

impl InterleavedDecoder {
    /// Construct a decoder from a validated wire profile.
    #[doc(hidden)]
    pub fn new_for_wire(
        profile: WireProfile,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        seed: u64,
    ) -> Self {
        let Ok(profile) = profile.validate() else {
            return Self {
                blocks: vec![LazyDecoder::new_with_depth(FecMode::Zero, 0, pool, policy, 1)],
                depth: 1,
            };
        };
        let depth = profile.interleave_depth as usize;
        let block_k = profile.try_block_source_count().unwrap_or(0) as usize;
        let fountain_repair_limit = (profile.total_count - profile.source_count) as usize;
        let blocks = (0..depth)
            .map(|_| {
                LazyDecoder::new_for_wire(
                    profile.codec,
                    block_k,
                    Arc::clone(&pool),
                    policy,
                    depth,
                    seed,
                    fountain_repair_limit,
                )
            })
            .collect();
        Self { blocks, depth }
    }

    /// Create a test interleaved decoder with auto-detected policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, depth, &policy)
    }

    /// Create an interleaved decoder with explicit runtime policy.
    #[doc(hidden)]
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        depth: usize,
        policy: &FecRuntimePolicy,
    ) -> Self {
        let actual_depth = if policy.interleave_enabled { depth.clamp(1, 8) } else { 1 };
        let dimensions_valid =
            validate_decoder_dimensions(k, actual_depth, MAX_DECODER_SOURCE_COUNT).is_ok();
        let effective_k = if dimensions_valid { k } else { 0 };
        let effective_depth = if dimensions_valid { actual_depth } else { 1 };
        let block_k = if effective_k == 0 { 0 } else { (effective_k / effective_depth).max(1) };
        let blocks = (0..effective_depth)
            .map(|_| {
                LazyDecoder::new_with_depth(
                    mode,
                    block_k,
                    Arc::clone(&pool),
                    policy,
                    effective_depth,
                )
            })
            .collect();
        Self { blocks, depth: effective_depth }
    }

    /// Update the connection-local fountain seed on every lane.
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        for block in &mut self.blocks {
            block.set_fountain_seed(seed);
        }
    }

    /// Route a received packet to the correct interleaved block by sequence number.
    pub fn take_packet(&mut self, packet: FecPacket) {
        let block_idx = if packet.is_systematic {
            (packet.seq % self.depth as u64) as usize
        } else {
            (packet.seq & 0x0F) as usize
        };
        if block_idx < self.blocks.len() {
            let mut packet = packet;
            if !packet.is_systematic {
                packet.seq >>= 4;
            }
            self.blocks[block_idx].take_packet(packet);
        }
    }

    /// Collect fully recovered packets from all interleaved blocks.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        let mut combined = VecDeque::new();
        let mut any_result = false;
        for block in &mut self.blocks {
            if block.full_recovery_needed() {
                if let Some(results) = block.get_result() {
                    any_result = true;
                    combined.extend(results);
                }
            } else if block.recovery_needed() {
                let results = block.get_partial_result();
                if !results.is_empty() {
                    any_result = true;
                    combined.extend(results);
                }
            }
        }
        any_result.then_some(combined)
    }

    /// Drain all available packets from interleaved blocks, including partial results.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let mut combined = VecDeque::new();
        for block in &mut self.blocks {
            combined.extend(block.get_partial_result());
        }
        combined
    }

    /// Whether any interleaved block has useful recovery work.
    #[inline]
    pub fn recovery_needed(&self) -> bool {
        self.blocks.iter().any(LazyDecoder::recovery_needed)
    }

    /// Whether any interleaved block needs a full heavy recovery attempt.
    #[inline]
    pub fn full_recovery_needed(&self) -> bool {
        self.blocks.iter().any(LazyDecoder::full_recovery_needed)
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn block_pending_repairs_len(&self, block_idx: usize) -> Option<usize> {
        self.blocks.get(block_idx).map(LazyDecoder::pending_repairs_len)
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn block_pending_sources_len(&self, block_idx: usize) -> Option<usize> {
        self.blocks.get(block_idx).map(LazyDecoder::pending_sources_len)
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn first_block_decoder_policy(&self) -> Option<&str> {
        self.blocks.first()?.decoder_policy()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn first_block_fountain_symbol_size(&self) -> Option<usize> {
        self.blocks.first()?.fountain_symbol_size()
    }
}

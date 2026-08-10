//! Lazy decoder orchestration for the FEC receive path.

use crate::codecs::{FecMode, FecPacket};
use crate::decoders::{validate_decoder_dimensions, MAX_DECODER_SOURCE_COUNT};
use crate::policy::FecRuntimePolicy;
use crate::target::{fec_backend_family, FecBackendFamily};
use crate::variants::DecoderVariant;
use crate::wire::WireCodec;
use qf_memory_pool::MemoryPool;
use qf_telemetry as telemetry;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

/// LazyDecoder defers heavy decoding until loss evidence makes recovery useful.
#[doc(hidden)]
pub struct LazyDecoder {
    inner: DecoderVariant,
    pending_sources: VecDeque<FecPacket>,
    pending_repairs: VecDeque<FecPacket>,
    seen_seqs: HashSet<u64>,
    seen_seq_min: Option<u64>,
    seen_seq_max: Option<u64>,
    k: usize,
    depth: usize,
    expected_seq: u64,
    max_pending: usize,
    lazy_enabled: bool,
    streaming_mode: bool,
    wire_streaming_loss_signaled: bool,
    repairs_skipped: u64,
    full_recovery_pending: bool,
    partial_recovery_pending: bool,
}

impl LazyDecoder {
    /// Construct a decoder from a validated wire codec and bounded wire profile values.
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
        let dimensions_valid =
            validate_decoder_dimensions(k, depth, MAX_DECODER_SOURCE_COUNT).is_ok();
        let effective_k = if dimensions_valid { k } else { 0 };
        let effective_depth = if dimensions_valid { depth } else { 1 };
        Self {
            inner: DecoderVariant::new_for_wire(
                codec,
                effective_k,
                pool,
                policy,
                effective_depth,
                seed,
                fountain_repair_limit,
            ),
            pending_sources: VecDeque::with_capacity(effective_k),
            pending_repairs: VecDeque::with_capacity(32),
            seen_seqs: HashSet::new(),
            seen_seq_min: None,
            seen_seq_max: None,
            k: effective_k,
            depth: effective_depth,
            expected_seq: 0,
            max_pending: 64,
            lazy_enabled: policy.lazy_enabled,
            streaming_mode: codec == WireCodec::StreamingGf8,
            wire_streaming_loss_signaled: codec == WireCodec::StreamingGf8,
            repairs_skipped: 0,
            full_recovery_pending: false,
            partial_recovery_pending: false,
        }
    }

    /// Create a test decoder with auto-detected policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    /// Create a test decoder with explicit policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self::new_with_depth(mode, k, pool, policy, 1)
    }

    /// Create a decoder with explicit interleave depth and runtime policy.
    #[doc(hidden)]
    pub fn new_with_depth(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        let dimensions_valid =
            validate_decoder_dimensions(k, depth, MAX_DECODER_SOURCE_COUNT).is_ok();
        let effective_k = if dimensions_valid { k } else { 0 };
        let effective_depth = if dimensions_valid { depth } else { 1 };
        Self {
            inner: DecoderVariant::new_with_depth(mode, effective_k, pool, policy, effective_depth),
            pending_sources: VecDeque::with_capacity(effective_k),
            pending_repairs: VecDeque::with_capacity(32),
            seen_seqs: HashSet::new(),
            seen_seq_min: None,
            seen_seq_max: None,
            k: effective_k,
            depth: effective_depth,
            expected_seq: 0,
            max_pending: 64,
            lazy_enabled: policy.lazy_enabled,
            streaming_mode: fec_backend_family(mode) == FecBackendFamily::Streaming,
            wire_streaming_loss_signaled: false,
            repairs_skipped: 0,
            full_recovery_pending: false,
            partial_recovery_pending: false,
        }
    }

    #[inline]
    fn source_block_seq(&self, seq: u64) -> u64 {
        seq / self.depth as u64
    }

    #[inline]
    fn has_gaps(&self) -> bool {
        let (Some(first), Some(last)) = (self.seen_seq_min, self.seen_seq_max) else {
            return false;
        };
        last.saturating_sub(first).saturating_add(1) > self.seen_seqs.len() as u64
    }

    fn flush_to_decoder(&mut self) -> bool {
        let mut flushed_repair = false;
        while let Some(source) = self.pending_sources.pop_front() {
            self.inner.take_packet(source);
        }
        while let Some(repair) = self.pending_repairs.pop_front() {
            self.inner.take_packet(repair);
            flushed_repair = true;
        }
        flushed_repair
    }

    #[inline]
    fn push_pending_source(&mut self, source: FecPacket) {
        if self.k == 0 {
            return;
        }
        if self.pending_sources.len() >= self.k {
            self.pending_sources.pop_front();
        }
        self.pending_sources.push_back(source);
    }

    /// Feed one source or repair packet into the lazy receive state machine.
    pub fn take_packet(&mut self, packet: FecPacket) {
        if self.k == 0 {
            return;
        }

        if packet.is_systematic {
            let block_seq = self.source_block_seq(packet.seq);
            self.seen_seqs.insert(block_seq);
            self.seen_seq_min = Some(self.seen_seq_min.map_or(block_seq, |min| min.min(block_seq)));
            self.seen_seq_max = Some(self.seen_seq_max.map_or(block_seq, |max| max.max(block_seq)));
            self.expected_seq = self.expected_seq.max(block_seq.saturating_add(1));

            if !self.lazy_enabled {
                self.inner.take_packet(packet);
                self.full_recovery_pending = true;
                return;
            }

            if self.has_gaps() {
                if !self.pending_repairs.is_empty() && self.flush_to_decoder() {
                    self.full_recovery_pending = true;
                    self.inner.take_packet(packet);
                    self.partial_recovery_pending = true;
                } else {
                    self.push_pending_source(packet);
                }
            } else {
                self.repairs_skipped += self.pending_repairs.len() as u64;
                self.pending_repairs.clear();
                if self.seen_seqs.len() >= self.k && self.seen_seqs.len().is_multiple_of(self.k) {
                    self.seen_seqs.clear();
                    self.seen_seq_min = None;
                    self.seen_seq_max = None;
                    self.pending_sources.clear();
                } else {
                    self.push_pending_source(packet);
                }
            }
        } else {
            if self.wire_streaming_loss_signaled {
                self.pending_repairs.push_back(packet);
                if self.flush_to_decoder() {
                    self.full_recovery_pending = true;
                }
                return;
            }
            if !self.lazy_enabled {
                self.inner.take_packet(packet);
                self.full_recovery_pending = true;
                return;
            }

            self.pending_repairs.push_back(packet);
            let incomplete_tail = !self.seen_seqs.len().is_multiple_of(self.k);
            let tail_loss_repair = if self.streaming_mode && incomplete_tail {
                let seen_in_block = self.seen_seqs.len() % self.k;
                let missing_tail_sources = self.k.saturating_sub(seen_in_block).max(1);
                self.pending_repairs.len() >= missing_tail_sources
            } else {
                incomplete_tail
            };
            if self.has_gaps() || self.pending_repairs.len() >= self.max_pending {
                if self.flush_to_decoder() {
                    self.full_recovery_pending = true;
                }
            } else if tail_loss_repair {
                self.full_recovery_pending = true;
            }
        }
    }

    /// Run full recovery after flushing lazy state into the active decoder.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        let _ = self.flush_to_decoder();
        telemetry::FEC_LAZY_SKIPPED
            .fetch_add(self.repairs_skipped, std::sync::atomic::Ordering::Relaxed);
        self.repairs_skipped = 0;
        let result = self.inner.get_result();
        self.full_recovery_pending = false;
        if result.is_some() {
            self.partial_recovery_pending = false;
        }
        result
    }

    /// Whether recovery work is currently useful.
    #[inline]
    pub fn recovery_needed(&self) -> bool {
        !self.lazy_enabled || self.full_recovery_pending || self.partial_recovery_pending
    }

    /// Whether callers should run full recovery rather than only drain peeled results.
    #[inline]
    pub fn full_recovery_needed(&self) -> bool {
        !self.lazy_enabled || self.full_recovery_pending
    }

    /// Drain available partial decoded packets.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let result = self.inner.get_partial_result();
        self.partial_recovery_pending = false;
        result
    }

    /// Update the connection-local fountain seed when the active decoder is fountain-based.
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
        self.inner.set_fountain_seed(seed);
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_repairs_capacity(&self) -> usize {
        self.pending_repairs.capacity()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_repairs_len(&self) -> usize {
        self.pending_repairs.len()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_sources_len(&self) -> usize {
        self.pending_sources.len()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn seen_seqs_len(&self) -> usize {
        self.seen_seqs.len()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_repairs_max(&self) -> usize {
        self.max_pending
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn full_recovery_pending(&self) -> bool {
        self.full_recovery_pending
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn partial_recovery_pending(&self) -> bool {
        self.partial_recovery_pending
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn decoder_policy(&self) -> Option<&str> {
        match &self.inner {
            DecoderVariant::GF8(decoder) => Some(decoder.decoder_policy.as_str()),
            _ => None,
        }
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn fountain_symbol_size(&self) -> Option<usize> {
        match &self.inner {
            DecoderVariant::Fountain(decoder) => Some(decoder.symbol_size()),
            _ => None,
        }
    }
}

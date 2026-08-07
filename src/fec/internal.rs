#![allow(private_interfaces)]
use super::*;
use std::collections::HashSet;
use std::sync::Arc;

/// LT fountain encoder alias for internal FEC variant dispatch.
pub type FountainEncoder = fountain_codes::LTEncoder;
/// LT fountain decoder alias for internal FEC variant dispatch.
pub type FountainDecoder = fountain_codes::LTDecoder;

// ===========================================================================================
// ULTRA-ZERO-MODE: Absolute Zero-Overhead FEC
// ===========================================================================================
// When loss rate is <0.1%, we don't need ANY FEC processing. ZeroEncoder/ZeroDecoder are
// pure passthrough with minimal tracking for seamless upgrade when loss is detected.
// CPU cost: ~2 nanoseconds per packet (single counter increment)
// ===========================================================================================

/// ZeroEncoder: Absolute zero-overhead encoder for zero-loss scenarios.
/// Generates NO repair packets, maintains NO coefficient matrices.
/// On loss detection, instantly upgrades to real encoder.
pub struct ZeroEncoder {
    /// Packets passed through (for telemetry only)
    packets_passed: u64,
}

impl ZeroEncoder {
    /// Create a zero-overhead encoder (parameters ignored, no state allocated).
    pub fn new(_k: usize, _n: usize) -> Self {
        Self { packets_passed: 0 }
    }

    /// Accept a packet with zero processing (counter increment only).
    #[inline(always)]
    pub fn take_packet(&mut self, _p: FecPacket) {
        // ZERO-OVERHEAD: Just count, no processing
        self.packets_passed = self.packets_passed.saturating_add(1);
    }

    /// Always returns None - zero mode never generates repair packets.
    #[inline(always)]
    pub fn generate_repair_packet(
        &mut self,
        _i: usize,
        _pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        // ZERO-OVERHEAD: Never generate repairs in zero-loss mode
        None
    }

    /// Reset the telemetry counter (no window state to clear).
    #[inline(always)]
    pub fn clear_window(&mut self) {
        // No window to clear
        self.packets_passed = 0;
    }

    /// Always returns 0 - zero mode maintains no encoding window.
    #[inline(always)]
    pub fn packets_in_window(&self) -> usize {
        0
    }
}

/// ZeroDecoder: Absolute zero-overhead decoder for zero-loss scenarios.
/// Assumes all packets arrive - pure passthrough with gap detection.
/// When gap detected, instantly upgrades to real decoder and replays buffered packets.
pub struct ZeroDecoder {
    /// Last seen sequence number
    last_seq: u64,
    /// Buffer of recent packets for replay on upgrade
    recent: VecDeque<FecPacket>,
    /// Max buffer size before forced trim
    max_buffer: usize,
    /// Has detected loss?
    loss_detected: bool,
}

impl ZeroDecoder {
    /// Create a zero-overhead decoder with gap detection and packet buffering.
    pub fn new(_k: usize, _pool: Arc<MemoryPool>) -> Self {
        Self {
            last_seq: 0,
            recent: VecDeque::with_capacity(32),
            max_buffer: 64,
            loss_detected: false,
        }
    }

    /// Accept a packet and detect sequence gaps for automatic mode upgrade.
    #[inline(always)]
    pub fn take_packet(&mut self, p: FecPacket) {
        // ZERO-OVERHEAD: Just track sequence for gap detection
        if p.is_systematic {
            // Check for gaps (non-contiguous sequence). Use saturating_add to stay
            // defined when last_seq reaches u64::MAX.
            if self.last_seq > 0 && p.seq > self.last_seq.saturating_add(1) {
                self.loss_detected = true;
            }
            self.last_seq = p.seq;
        }
        // Buffer for potential replay
        self.recent.push_back(p);
        if self.recent.len() > self.max_buffer {
            self.recent.pop_front();
        }
    }

    /// Return buffered packets if no loss detected, None if upgrade needed.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Zero mode: all packets arrived, nothing to recover
        if self.loss_detected {
            None // Need upgrade to real decoder
        } else {
            Some(std::mem::take(&mut self.recent))
        }
    }

    /// Drain all buffered packets regardless of loss detection state.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.recent)
    }
}

/// Encoder variant for different FEC modes
pub enum EncoderVariant {
    /// Zero-overhead passthrough (no repairs generated)
    Zero(ZeroEncoder),
    /// GF(2^8) block encoder for moderate loss.
    GF8(Encoder<GF8>),
    /// GF(2^16) block encoder for high loss.
    GF16(Encoder16),
    /// GF(2^4) block encoder for ultra-low loss (<2%).
    GF4(Encoder4),
    /// LT fountain rateless encoder for extreme loss.
    Fountain(FountainEncoder),
}

impl EncoderVariant {
    /// Create a test encoder variant with auto-detected policy.
    #[cfg(test)]
    pub fn new(mode: FecMode, k: usize, n: usize) -> Self {
        let policy = super::FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, n, &policy)
    }

    /// Create an encoder variant matching the given FEC mode with explicit policy.
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        n: usize,
        policy: &super::FecRuntimePolicy,
    ) -> Self {
        let target = super::target_from_mode(mode, k);
        match super::fec_backend_family(mode) {
            super::FecBackendFamily::Fountain => {
                let sym = policy.fountain_symbol_size;
                crate::telemetry::FOUNTAIN_SYMBOL_SIZE
                    .store(sym as u64, std::sync::atomic::Ordering::Relaxed);
                EncoderVariant::Fountain(FountainEncoder::new(k, sym))
            }
            // ULTRA-ZERO-MODE: Absolute zero overhead - no repairs, no matrices
            super::FecBackendFamily::Zero => EncoderVariant::Zero(ZeroEncoder::new(k, n)),
            super::FecBackendFamily::LowCostBlock => {
                if super::low_cost_block_uses_gf4(target) && k <= 15 {
                    EncoderVariant::GF4(Encoder4::new(k, n))
                } else {
                    EncoderVariant::GF8(Encoder::<GF8>::new(k, n))
                }
            }
            super::FecBackendFamily::HeavyBlock => {
                if k <= 255 {
                    EncoderVariant::GF8(Encoder::<GF8>::new(k, n))
                } else {
                    EncoderVariant::GF16(Encoder16::new(k, n))
                }
            }
            super::FecBackendFamily::Streaming => EncoderVariant::GF8(Encoder::<GF8>::new(k, n)),
        }
    }

    /// Feed a source packet into the active encoder backend.
    pub fn take_packet(&mut self, p: FecPacket) {
        match self {
            EncoderVariant::Zero(e) => e.take_packet(p),
            EncoderVariant::GF8(e) => e.take_packet(p),
            EncoderVariant::GF16(e) => e.take_packet(p),
            EncoderVariant::GF4(e) => e.take_packet(p),
            EncoderVariant::Fountain(e) => {
                // Add source symbol to LT encoder
                if let Some(data) = p.payload_slice() {
                    let _ = e.add_source_symbol(data.to_vec());
                }
            }
        }
    }

    /// Generate the i-th repair packet from the active encoder backend.
    pub fn generate_repair_packet(
        &mut self,
        i: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        match self {
            EncoderVariant::Zero(e) => e.generate_repair_packet(i, pool),
            EncoderVariant::GF8(e) => e.generate_repair_packet(i, pool),
            EncoderVariant::GF16(e) => e.generate_repair_packet(i, pool),
            EncoderVariant::GF4(e) => e.generate_repair_packet(i, pool),
            EncoderVariant::Fountain(ref mut enc) => {
                // **LT Fountain Codes**: Generate rateless encoded symbols with indices for BP
                let symbol_id = next_repair_id();
                let (encoded_data, indices) = enc.generate_symbol_with_indices(symbol_id);
                // Encode indices as u32 big-endian values
                let coeff_len = indices.len().checked_mul(4)?;
                if coeff_len > pool.block_size() {
                    return None;
                }
                let data_block = copy_to_pooled_block(pool, &encoded_data)?;
                let mut coeff_block = PooledBlock::new(Arc::clone(pool));
                for (i, idx) in indices.iter().enumerate() {
                    let be = u32::try_from(*idx).ok()?.to_be_bytes();
                    let off = i * 4;
                    coeff_block[off..off + 4].copy_from_slice(&be);
                }
                FecPacket::from_pooled_blocks(
                    symbol_id,
                    Some(data_block),
                    encoded_data.len(),
                    false,
                    Some(coeff_block),
                    coeff_len,
                    Arc::clone(pool),
                )
                .ok()
            }
        }
    }

    #[cfg(test)]
    pub fn backend_kind(&self) -> &'static str {
        match self {
            EncoderVariant::Zero(_) => "zero",
            EncoderVariant::GF4(_) => "gf4",
            EncoderVariant::GF8(_) => "gf8",
            EncoderVariant::GF16(_) => "gf16",
            EncoderVariant::Fountain(_) => "fountain",
        }
    }

    /// Clear all source packets from the encoding window.
    pub fn clear_window(&mut self) {
        match self {
            EncoderVariant::Zero(e) => e.clear_window(),
            EncoderVariant::GF8(e) => e.clear_window(),
            EncoderVariant::GF16(e) => e.clear_window(),
            EncoderVariant::GF4(e) => e.clear_window(),
            EncoderVariant::Fountain(e) => {
                // Clear source symbols for new window
                e.clear_window();
            }
        }
    }

    /// Return the number of source packets currently in the encoding window.
    pub fn packets_in_window(&self) -> usize {
        match self {
            EncoderVariant::Zero(e) => e.packets_in_window(),
            EncoderVariant::GF8(e) => e.packets_in_window(),
            EncoderVariant::GF16(e) => e.packets_in_window(),
            EncoderVariant::GF4(e) => e.packets_in_window(),
            EncoderVariant::Fountain(e) => e.packets_in_window(),
        }
    }

    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        if let EncoderVariant::Fountain(encoder) = self {
            encoder.set_seed(seed);
        }
    }
}

/// Decoder variant for different FEC modes
pub enum DecoderVariant {
    /// Zero-overhead passthrough (no decoding, just gap detection)
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
    fn new_for_wire(
        codec: wire::WireCodec,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &super::FecRuntimePolicy,
        depth: usize,
        seed: u64,
        fountain_repair_limit: usize,
    ) -> Self {
        match codec {
            wire::WireCodec::Gf4 => DecoderVariant::GF4(Decoder4::new_with_depth(k, pool, depth)),
            wire::WireCodec::Gf8 | wire::WireCodec::StreamingGf8 => {
                DecoderVariant::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
            }
            wire::WireCodec::Gf16 => {
                DecoderVariant::GF16(Decoder16::new_with_depth(k, pool, depth))
            }
            wire::WireCodec::Fountain => {
                DecoderVariant::Fountain(FountainDecoder::new_with_repair_limit(
                    k,
                    policy.fountain_symbol_size,
                    pool,
                    seed,
                    fountain_repair_limit,
                ))
            }
        }
    }

    /// Create a test decoder variant with auto-detected policy.
    #[cfg(test)]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = super::FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    /// Create a test decoder variant with explicit policy.
    #[cfg(test)]
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &super::FecRuntimePolicy,
    ) -> Self {
        Self::new_with_depth(mode, k, pool, policy, 1)
    }

    /// Create a decoder variant with explicit interleave depth.
    /// depth=1 is non-interleaved; depth>1 enables interleaved source ID mapping.
    pub fn new_with_depth(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &super::FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        let target = super::target_from_mode(mode, k);
        match super::fec_backend_family(mode) {
            super::FecBackendFamily::Fountain => {
                let sym = policy.fountain_symbol_size;
                crate::telemetry::FOUNTAIN_SYMBOL_SIZE
                    .store(sym as u64, std::sync::atomic::Ordering::Relaxed);
                DecoderVariant::Fountain(FountainDecoder::new(k, sym, Arc::clone(&pool)))
            }
            // ULTRA-ZERO-MODE: Absolute zero overhead - no decoding, gap detection only
            super::FecBackendFamily::Zero => DecoderVariant::Zero(ZeroDecoder::new(k, pool)),
            super::FecBackendFamily::LowCostBlock => {
                if super::low_cost_block_uses_gf4(target) && k <= 15 {
                    DecoderVariant::GF4(Decoder4::new_with_depth(k, pool, depth))
                } else {
                    DecoderVariant::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
                }
            }
            super::FecBackendFamily::HeavyBlock => {
                if k <= 255 {
                    DecoderVariant::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
                } else {
                    DecoderVariant::GF16(Decoder16::new_with_depth(k, pool, depth))
                }
            }
            super::FecBackendFamily::Streaming => {
                DecoderVariant::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
            }
        }
    }

    /// Feed a received packet into the active decoder backend.
    pub fn take_packet(&mut self, p: FecPacket) {
        if !p.is_systematic {
            crate::telemetry::FEC_DECODER_EQUATIONS.inc();
        }
        match self {
            DecoderVariant::Zero(d) => d.take_packet(p),
            DecoderVariant::GF8(d) => d.take_packet(p),
            DecoderVariant::GF16(d) => d.take_packet(p),
            DecoderVariant::GF4(d) => d.take_packet(p),
            DecoderVariant::Fountain(d) => {
                if let Some(data) = p.payload_slice() {
                    let payload = data.to_vec();
                    if p.is_systematic {
                        // The admission check inside `add_source_symbol` compares against `k` as a
                        // `usize`. On a 32-bit target an `as usize` cast would truncate an id above
                        // `u32::MAX` first, so an out-of-range id could alias a valid source index.
                        // Convert fallibly and drop what does not fit.
                        match usize::try_from(p.id) {
                            Ok(source_index) => {
                                let _ = d.add_source_symbol(source_index, payload);
                            }
                            Err(_) => {
                                log::debug!(
                                    "dropping Fountain source symbol with id {} that exceeds usize",
                                    p.id
                                );
                            }
                        }
                    } else {
                        let source_indices = d.source_indices(p.id);
                        let _ = d.add_encoded_symbol(p.id, payload, source_indices);
                    }
                }
            }
        }
    }

    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        if let DecoderVariant::Fountain(decoder) = self {
            decoder.set_seed(seed);
        }
    }

    /// Attempt full recovery and return decoded packets, or None if incomplete.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        match self {
            DecoderVariant::Zero(d) => d.get_result(),
            DecoderVariant::GF8(d) => d.get_result(),
            DecoderVariant::GF16(d) => d.get_result(),
            DecoderVariant::GF4(d) => d.get_result(),
            DecoderVariant::Fountain(d) => {
                // Run BP to completion if possible
                let _ = d.belief_propagation_decode();
                // Convert decoded symbols to FecPackets
                if let Some(symbols) = d.get_decoded_indexed() {
                    // Telemetry: completed
                    crate::telemetry::FOUNTAIN_PROGRESS
                        .store(1_000_000, std::sync::atomic::Ordering::Relaxed);
                    let mut packets = VecDeque::new();
                    for (source_index, symbol) in symbols {
                        let pool = Arc::clone(&d.mem_pool);
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
                    // Update progress gauge
                    let prog = (d.decoding_progress() * 1_000_000.0) as u64;
                    crate::telemetry::FOUNTAIN_PROGRESS
                        .store(prog, std::sync::atomic::Ordering::Relaxed);
                    None
                }
            }
        }
    }

    #[cfg(test)]
    pub fn backend_kind(&self) -> &'static str {
        match self {
            DecoderVariant::Zero(_) => "zero",
            DecoderVariant::GF4(_) => "gf4",
            DecoderVariant::GF8(_) => "gf8",
            DecoderVariant::GF16(_) => "gf16",
            DecoderVariant::Fountain(_) => "fountain",
        }
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        match self {
            DecoderVariant::Zero(d) => d.get_partial_result(),
            DecoderVariant::GF8(d) => d.get_partial_result(),
            DecoderVariant::GF16(d) => d.get_partial_result(),
            DecoderVariant::GF4(d) => d.get_partial_result(),
            DecoderVariant::Fountain(d) => {
                // Attempt one BP step for incremental progress
                let _ = d.belief_propagation_step();
                // Return partial decoding progress
                let mut partial = VecDeque::new();
                for (source_index, symbol) in d.get_partial_indexed() {
                    let pool = Arc::clone(&d.mem_pool);
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
                // Update progress gauge with current progress
                let prog = (d.decoding_progress() * 1_000_000.0) as u64;
                crate::telemetry::FOUNTAIN_PROGRESS
                    .store(prog, std::sync::atomic::Ordering::Relaxed);
                partial
            }
        }
    }

    // is_complete() removed; use get_result()/get_partial_result() paths
}

// =========================================================================
// LAZY DECODING: 0 CPU when no packet loss detected
// =========================================================================

/// LazyDecoder wraps DecoderVariant and defers actual decoding until loss is detected.
/// This saves ~99% CPU when there is no packet loss.
pub struct LazyDecoder {
    inner: DecoderVariant,
    /// Buffered source packets replayed into the heavy decoder only after a
    /// gap or tail-loss repair makes recovery useful.
    pending_sources: VecDeque<FecPacket>,
    /// Buffered repair packets (only decoded when gaps detected)
    pending_repairs: VecDeque<FecPacket>,
    /// Tracks seen source packet sequence numbers
    seen_seqs: HashSet<u64>,
    seen_seq_min: Option<u64>,
    seen_seq_max: Option<u64>,
    /// Source packets per decoder block. Used to distinguish clean full
    /// blocks from tail-loss blocks where no later systematic packet can reveal
    /// a sequence gap.
    k: usize,
    /// Interleave depth used by the parent decoder. A single lazy block sees
    /// source packet sequences spaced by this depth, so gap tracking normalizes
    /// source sequence numbers by this value.
    depth: usize,
    /// Expected next sequence number
    expected_seq: u64,
    /// Maximum buffered repairs before forced flush
    max_pending: usize,
    /// Whether lazy mode is enabled (always true by default)
    lazy_enabled: bool,
    /// Streaming mode emits repairs continuously before a block is complete.
    /// Those early repairs are not tail-loss evidence and must not wake the
    /// heavy decoder unless a real sequence gap exists.
    streaming_mode: bool,
    /// Wire v1 pre-filters clean streaming coverage. Repairs reaching this
    /// decoder are therefore explicit loss evidence.
    wire_streaming_loss_signaled: bool,
    /// Telemetry: repairs skipped (no loss)
    repairs_skipped: u64,
    /// A repair was flushed into the heavy decoder and should trigger a full
    /// recovery attempt exactly once.
    full_recovery_pending: bool,
    /// A systematic packet arrived after a gap and may have peeled already
    /// buffered equations. Drain partial results, but do not run full
    /// elimination unless a repair was also flushed.
    partial_recovery_pending: bool,
}

impl LazyDecoder {
    fn new_for_wire(
        codec: wire::WireCodec,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
        seed: u64,
        fountain_repair_limit: usize,
    ) -> Self {
        let dimensions_valid =
            super::validate_decoder_dimensions(k, depth, super::MAX_DECODER_SOURCE_COUNT).is_ok();
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
            streaming_mode: codec == wire::WireCodec::StreamingGf8,
            wire_streaming_loss_signaled: codec == wire::WireCodec::StreamingGf8,
            repairs_skipped: 0,
            full_recovery_pending: false,
            partial_recovery_pending: false,
        }
    }

    /// Create a test decoder with auto-detected policy.
    #[cfg(test)]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    /// Create a test lazy decoder with explicit policy.
    #[cfg(test)]
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self::new_with_depth(mode, k, pool, policy, 1)
    }

    pub fn new_with_depth(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        let lazy_enabled = policy.lazy_enabled;
        let streaming_mode = super::fec_backend_family(mode) == super::FecBackendFamily::Streaming;
        let dimensions_valid =
            super::validate_decoder_dimensions(k, depth, super::MAX_DECODER_SOURCE_COUNT).is_ok();
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
            lazy_enabled,
            streaming_mode,
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

    /// Check if there are gaps in the received sequence
    #[inline]
    fn has_gaps(&self) -> bool {
        let (Some(first), Some(last)) = (self.seen_seq_min, self.seen_seq_max) else {
            return false;
        };
        // Gap exists if we've seen N sequences but range is > N.
        // Compare in u64 to avoid narrowing the span on 32-bit targets.
        last.saturating_sub(first).saturating_add(1) > self.seen_seqs.len() as u64
    }

    /// Flush pending repairs to actual decoder (when loss detected)
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
            // Rejected/Zero decoder: drop the packet to avoid unbounded buffering.
            return;
        }
        if self.k > 0 && self.pending_sources.len() >= self.k {
            self.pending_sources.pop_front();
        }
        self.pending_sources.push_back(source);
    }

    pub fn take_packet(&mut self, p: FecPacket) {
        // A rejected or Zero decoder has nothing to recover. Drop packets
        // immediately to keep seen_seqs / pending_sources / pending_repairs
        // from growing without bound.
        if self.k == 0 {
            return;
        }

        if p.is_systematic {
            let block_seq = self.source_block_seq(p.seq);
            // Source packet - track sequence
            self.seen_seqs.insert(block_seq);
            self.seen_seq_min = Some(self.seen_seq_min.map_or(block_seq, |min| min.min(block_seq)));
            self.seen_seq_max = Some(self.seen_seq_max.map_or(block_seq, |max| max.max(block_seq)));
            // Update expected sequence
            self.expected_seq = self.expected_seq.max(block_seq.saturating_add(1));

            // If lazy disabled, forward to decoder
            if !self.lazy_enabled {
                self.inner.take_packet(p);
                self.full_recovery_pending = true;
                return;
            }

            // Check if we detect gaps now
            if self.has_gaps() {
                // Loss detected. Only wake the heavy decoder when a repair is
                // actually available; a gap with only systematic packets has
                // nothing recoverable yet and should stay on the lazy path.
                if !self.pending_repairs.is_empty() && self.flush_to_decoder() {
                    self.full_recovery_pending = true;
                    self.inner.take_packet(p);
                    self.partial_recovery_pending = true;
                } else {
                    self.push_pending_source(p);
                }
            } else {
                // No loss - drop pending repairs (they're not needed)
                let skipped = self.pending_repairs.len() as u64;
                self.repairs_skipped += skipped;
                self.pending_repairs.clear();
                if self.k > 0
                    && self.seen_seqs.len() >= self.k
                    && self.seen_seqs.len().is_multiple_of(self.k)
                {
                    self.seen_seqs.clear();
                    self.seen_seq_min = None;
                    self.seen_seq_max = None;
                    self.pending_sources.clear();
                } else {
                    self.push_pending_source(p);
                }
            }
        } else {
            if self.wire_streaming_loss_signaled {
                // The wire receiver filters clean coverage before dispatch.
                // A streaming repair reaching this layer therefore proves a
                // missing source inside the repair's explicit coverage span.
                self.pending_repairs.push_back(p);
                if self.flush_to_decoder() {
                    self.full_recovery_pending = true;
                }
                return;
            }
            // Repair packet - buffer it
            if !self.lazy_enabled {
                self.inner.take_packet(p);
                self.full_recovery_pending = true;
                return;
            }

            // Buffer repair packet
            self.pending_repairs.push_back(p);

            // Flush only when repair data can actually advance recovery: a
            // known gap, a tail-loss block that ended before k sources arrived,
            // or a safety flush when the buffer reaches its cap.
            let incomplete_tail = self.k > 0 && !self.seen_seqs.len().is_multiple_of(self.k);
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

    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Flush any pending repairs before getting result
        let _ = self.flush_to_decoder();
        // Update telemetry
        crate::telemetry::FEC_LAZY_SKIPPED
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
    ///
    /// In lazy mode, polling the heavy decoder on every clean systematic packet
    /// defeats the lazy fast path because `get_result()` flushes pending repairs
    /// into the decoder. Recovery is only useful once a sequence gap exists. If
    /// lazy mode is disabled, preserve the eager behavior and let callers poll.
    #[inline]
    pub fn recovery_needed(&self) -> bool {
        if !self.lazy_enabled {
            return true;
        }

        self.full_recovery_pending || self.partial_recovery_pending
    }

    /// Whether the caller should run full recovery rather than only draining
    /// partial peeled results.
    #[inline]
    pub fn full_recovery_needed(&self) -> bool {
        !self.lazy_enabled || self.full_recovery_pending
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let result = self.inner.get_partial_result();
        self.partial_recovery_pending = false;
        result
    }

    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        self.inner.set_fountain_seed(seed);
    }

    #[cfg(test)]
    pub fn pending_repairs_capacity(&self) -> usize {
        self.pending_repairs.capacity()
    }

    #[cfg(test)]
    pub fn pending_repairs_len(&self) -> usize {
        self.pending_repairs.len()
    }

    #[cfg(test)]
    pub fn pending_sources_len(&self) -> usize {
        self.pending_sources.len()
    }

    #[cfg(test)]
    pub fn seen_seqs_len(&self) -> usize {
        self.seen_seqs.len()
    }

    #[cfg(test)]
    pub fn pending_repairs_max(&self) -> usize {
        self.max_pending
    }

    #[cfg(test)]
    pub fn full_recovery_pending(&self) -> bool {
        self.full_recovery_pending
    }

    #[cfg(test)]
    pub fn partial_recovery_pending(&self) -> bool {
        self.partial_recovery_pending
    }
}

// =========================================================================
// INTERLEAVED ENCODING: Better burst loss protection
// =========================================================================

/// InterleavedEncoder distributes packets across multiple FEC blocks
/// to protect against burst losses (consecutive packet drops).
///
/// With interleave_depth=4:
/// - Block 0: P0, P4, P8, ...
/// - Block 1: P1, P5, P9, ...
/// - etc.
///
/// A burst of 4 consecutive packets in loss = max 1 per block = recoverable!
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
        let enabled = policy.interleave_enabled;

        let actual_depth = if enabled { depth.clamp(1, 8) } else { 1 };

        // CRITICAL: Each block receives k/depth packets, so scale block size accordingly
        let block_k = (k / actual_depth).max(1);
        let block_n = (n / actual_depth).max(block_k);

        let blocks = (0..actual_depth)
            .map(|_| EncoderVariant::new_with_policy(mode, block_k, block_n, policy))
            .collect();

        // A non-divisible request floors to `block_k` per lane, so the encoder represents
        // `block_k * depth` sources, not the requested `k`. Store what is actually represented so
        // window checks, repair scheduling, and the emitted wire profile all agree with the
        // blocks. Reporting the request here would let a non-divisible `k` produce a wire
        // `source_count` that its own interleave depth does not divide.
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

    /// Return the (k, n) parameters the encoder actually represents across its lanes.
    ///
    /// A non-divisible request floors to `k / depth` per lane, so this can be smaller than what
    /// the caller asked for. The construction path logs that case; reporting the request here
    /// would let a non-divisible `k` reach the wire profile as a `source_count` that its own
    /// interleave depth does not divide.
    pub fn params(&self) -> (usize, usize) {
        (self.k, self.n)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Distribute a source packet round-robin across interleaved blocks.
    pub fn take_packet(&mut self, p: FecPacket) {
        // Distribute packets round-robin across blocks
        let block_idx = self.packet_idx % self.depth;
        self.blocks[block_idx].take_packet(p);
        self.packet_idx = self.packet_idx.wrapping_add(1);
    }

    /// API compatibility: generate single repair packet (delegates to block i % depth)
    pub fn generate_repair_packet(
        &mut self,
        i: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        let block_idx = i % self.depth;
        let repair_idx = i / self.depth;
        // The identity packs the lane into the low four bits and the ordinal above them. Depth is
        // clamped to `1..=8`, so the lane always fits, but an unbounded ordinal would shift out of
        // `u64` and alias a different repair. Reject beyond the representable range instead.
        if repair_idx as u64 > MAX_REPAIR_ORDINAL {
            return None;
        }
        if block_idx < self.blocks.len() {
            if let Some(mut repair) =
                self.blocks[block_idx].generate_repair_packet(repair_idx, pool)
            {
                // The high bits carry the repair ordinal. Coefficients can then
                // be regenerated from compact wire metadata at the receiver.
                repair.seq = ((repair_idx as u64) << REPAIR_LANE_BITS) | (block_idx as u64);
                return Some(repair);
            }
        }
        None
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
        self.blocks.iter().map(|b| b.packets_in_window()).sum()
    }

    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        for block in &mut self.blocks {
            block.set_fountain_seed(seed);
        }
    }

    /// Return the fountain symbol size of the first block (test helper).
    #[cfg(test)]
    pub fn first_block_fountain_symbol_size(&self) -> Option<usize> {
        match self.blocks.first()? {
            EncoderVariant::Fountain(enc) => Some(enc.symbol_size()),
            _ => None,
        }
    }
}

/// InterleavedDecoder reverses the interleaving on receive side
pub struct InterleavedDecoder {
    blocks: Vec<LazyDecoder>,
    depth: usize,
}

impl InterleavedDecoder {
    pub(crate) fn new_for_wire(
        profile: wire::WireProfile,
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
    #[cfg(test)]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, depth, &policy)
    }

    /// Create an interleaved decoder with explicit runtime policy.
    pub fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        depth: usize,
        policy: &FecRuntimePolicy,
    ) -> Self {
        let enabled = policy.interleave_enabled;

        let actual_depth = if enabled { depth.clamp(1, 8) } else { 1 };
        let dimensions_valid =
            super::validate_decoder_dimensions(k, actual_depth, super::MAX_DECODER_SOURCE_COUNT)
                .is_ok();
        let effective_k = if dimensions_valid { k } else { 0 };
        let effective_depth = if dimensions_valid { actual_depth } else { 1 };

        // CRITICAL: Scale decoder k same as encoder
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

    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        for block in &mut self.blocks {
            block.set_fountain_seed(seed);
        }
    }

    /// Route a received packet to the correct interleaved block by sequence number.
    pub fn take_packet(&mut self, p: FecPacket) {
        // Extract block index from seq (low 4 bits for repair, high bits for source)
        let block_idx = if p.is_systematic {
            // Source packets: use seq modulo depth, computed in u64 so 32-bit targets
            // do not truncate the sequence before the modulo.
            (p.seq % self.depth as u64) as usize
        } else {
            // Repair packets: block index encoded in low 4 bits
            (p.seq & 0x0F) as usize
        };

        if block_idx < self.blocks.len() {
            // Restore original seq for repair packets
            let mut packet = p;
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
                    for pkt in results {
                        combined.push_back(pkt);
                    }
                }
            } else if block.recovery_needed() {
                let results = block.get_partial_result();
                if !results.is_empty() {
                    any_result = true;
                    for pkt in results {
                        combined.push_back(pkt);
                    }
                }
            }
        }

        if any_result {
            Some(combined)
        } else {
            None
        }
    }

    /// Drain all available packets from interleaved blocks (including partial).
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let mut combined = VecDeque::new();
        for block in &mut self.blocks {
            for pkt in block.get_partial_result() {
                combined.push_back(pkt);
            }
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

    #[cfg(test)]
    pub fn block_pending_repairs_len(&self, block_idx: usize) -> Option<usize> {
        self.blocks.get(block_idx).map(LazyDecoder::pending_repairs_len)
    }

    #[cfg(test)]
    pub fn first_block_decoder_policy(&self) -> Option<&str> {
        match &self.blocks.first()?.inner {
            DecoderVariant::GF8(decoder) => Some(decoder.decoder_policy.as_str()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn first_block_fountain_symbol_size(&self) -> Option<usize> {
        match &self.blocks.first()?.inner {
            DecoderVariant::Fountain(decoder) => Some(decoder.symbol_size()),
            _ => None,
        }
    }
}

/// Mode manager for adaptive FEC
pub struct ModeManager {
    current_mode: FecMode,
    loss_history: VecDeque<f32>,
    window_size: usize,
    window_history: VecDeque<usize>,
    switch_threshold: f32,
    switch_min_up_ms: u64,
    switch_min_down_ms: u64,
    auto_gf4_enabled: bool,
    last_switch_time: std::time::Instant,
}

impl ModeManager {
    /// Create a test mode manager with auto-detected policy.
    #[cfg(test)]
    pub fn with_switch_threshold(initial_mode: FecMode, switch_threshold: f32) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::with_runtime_policy(initial_mode, switch_threshold, &policy)
    }

    /// Create a mode manager with explicit runtime policy overrides.
    pub fn with_runtime_policy(
        initial_mode: FecMode,
        switch_threshold: f32,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self {
            current_mode: initial_mode,
            loss_history: VecDeque::with_capacity(100),
            window_size: Self::params_for(initial_mode, 64).0,
            window_history: VecDeque::with_capacity(10),
            switch_threshold: policy
                .switch_threshold_override
                .unwrap_or(switch_threshold)
                .clamp(0.0, 1.0),
            switch_min_up_ms: policy.switch_min_up_ms,
            switch_min_down_ms: policy.switch_min_down_ms,
            auto_gf4_enabled: policy.auto_gf4_enabled,
            last_switch_time: crate::time_source::now_instant(),
        }
    }

    #[inline]
    fn target_for_loss(avg_loss: f32, auto_gf4: bool) -> FecProtectionTarget {
        continuous_fec_target(avg_loss, auto_gf4, false, 2048, 1024, 0, 0.0)
    }

    #[inline]
    fn min_switch_interval_ms(
        &self,
        current: FecProtectionTarget,
        target: FecProtectionTarget,
    ) -> u64 {
        if current.family == FecBackendFamily::Zero {
            return 0;
        }
        if target_rank(target) > target_rank(current) {
            self.switch_min_up_ms
        } else {
            self.switch_min_down_ms
        }
    }

    /// Resolve (mode, k, n) parameters from a continuous protection target.
    pub fn params_for_target(
        target: FecProtectionTarget,
        default_window: usize,
        auto_gf4: bool,
    ) -> (FecMode, usize, usize) {
        let mode = mode_for_target(target, auto_gf4);
        let k = if target.family == FecBackendFamily::Zero {
            0
        } else if target.effective_window > 0 {
            target.effective_window
        } else if default_window > 0 {
            default_window
        } else {
            target_from_mode(mode, default_window).effective_window
        };
        let n = if k == 0 {
            0
        } else if target.redundancy.is_finite() && target.redundancy >= 0.0 {
            ((k as f32) * target.redundancy).ceil().min(wire::MAX_TOTAL_COUNT as f32).max(0.0)
                as usize
        } else {
            // NaN and infinity must not silently become the maximum repair budget. `f32::min`
            // returns the other operand for NaN, so the previous clamp turned a non-finite
            // redundancy into `MAX_TOTAL_COUNT`, the most expensive possible answer. Fall back to
            // systematic-only instead, which `n.max(k)` below turns into exactly `k`.
            log::warn!(
                "FEC redundancy {} is not a usable finite ratio; falling back to systematic-only",
                target.redundancy
            );
            0
        };
        (mode, k, n.max(k))
    }

    /// Resolve (k, n) window parameters for a given FEC mode.
    pub fn params_for(mode: FecMode, default_window: usize) -> (usize, usize) {
        let target = target_from_mode(mode, default_window);
        let (_, k, n) = Self::params_for_target(target, default_window, false);
        (k, n)
    }

    #[cfg(test)]
    pub fn overhead_for(mode: FecMode) -> f32 {
        target_from_mode(mode, 0).redundancy
    }

    /// Feed a new loss observation and return the previous (mode, window) if a switch occurred.
    pub fn update(&mut self, loss_rate: f32) -> Option<(FecMode, usize)> {
        let loss_rate = if loss_rate.is_finite() { loss_rate.clamp(0.0, 1.0) } else { 0.0 };
        self.loss_history.push_back(loss_rate);
        if self.loss_history.len() > 100 {
            self.loss_history.pop_front();
        }

        // Calculate moving average
        let avg_loss = if self.loss_history.len() >= 10 {
            self.loss_history.iter().rev().take(10).sum::<f32>() / 10.0
        } else {
            loss_rate
        };

        // Determine target mode based on loss (Auto includes Streaming for low loss)
        // GF4 auto-selection for ultra-low loss (<2%) - 4x faster than GF8
        let auto_gf4 = self.auto_gf4_enabled;
        // Consolidated auto cascade: Zero below 0.1%, Light below 2%, Normal below
        // 10%, Strong below 22%, Extreme below 25%, then Fountain rescue. Streaming
        // replaces the block tier for measured burst loss. Medium/Ultra remain valid
        // explicit modes but are not selected by the automatic controller.
        let current_target = target_from_mode(self.current_mode, self.window_size);
        let target = Self::target_for_loss(avg_loss, auto_gf4);
        let target_mode = mode_for_target(target, auto_gf4);

        // Respect switching thresholds and minimum time between transitions.
        // Anti-flap strategy:
        // - De-escalation requires longer dwell + stronger hysteresis than escalation.
        // - If the target mode is stable across recent samples, allow switch even
        //   when instantaneous delta is small.
        let now = crate::time_source::now_instant();
        let min_ms = self.min_switch_interval_ms(current_target, target);
        let time_ok = now.checked_duration_since(self.last_switch_time).unwrap_or_default()
            >= std::time::Duration::from_millis(min_ms);
        let last_avg = if self.loss_history.len() >= 2 {
            let mut s = 0.0f32;
            let mut c = 0;
            for v in self.loss_history.iter().rev().skip(1).take(10) {
                s += *v;
                c += 1;
            }
            if c > 0 {
                s / (c as f32)
            } else {
                avg_loss
            }
        } else {
            avg_loss
        };
        let rank_cur = target_rank(current_target);
        let rank_tgt = target_rank(target);
        let hysteresis = self.switch_threshold.max(0.0025);
        let diff_ok = if rank_tgt > rank_cur {
            (avg_loss - last_avg) >= hysteresis
        } else if rank_tgt < rank_cur {
            (last_avg - avg_loss) >= hysteresis * 1.5
        } else {
            false
        };
        let stable_needed = if rank_tgt < rank_cur { 4 } else { 3 };
        let stable_hits = self
            .loss_history
            .iter()
            .rev()
            .take(stable_needed)
            .filter(|v| {
                let stable_target = Self::target_for_loss(**v, auto_gf4);
                stable_target.family == target.family
                    && target_rank(stable_target) == target_rank(target)
            })
            .count();
        let stable_ok = stable_hits >= stable_needed;
        let (_, target_window, _target_n) =
            Self::params_for_target(target, self.window_size, auto_gf4);
        let switch_ok = if rank_tgt < rank_cur { stable_ok } else { diff_ok || stable_ok };
        let state_changes = self.current_mode != target_mode || self.window_size != target_window;
        if state_changes && time_ok && switch_ok {
            let old_mode = self.current_mode;
            let old_window = self.window_size;
            self.current_mode = target_mode;
            self.last_switch_time = now;
            self.window_size = target_window;
            self.window_history.push_back(target_window);
            if self.window_history.len() > 10 {
                self.window_history.pop_front();
            }
            Some((old_mode, old_window))
        } else {
            None
        }
    }

    /// Return the currently selected FEC mode.
    pub fn current_mode(&self) -> FecMode {
        self.current_mode
    }

    /// Return the current source block window size.
    pub fn current_window(&self) -> usize {
        self.window_size
    }

    /// Force a specific mode and window, bypassing hysteresis and cooldown.
    pub fn force_state(&mut self, mode: FecMode, window: usize) {
        self.current_mode = mode;
        self.window_size = if mode == FecMode::Zero {
            0
        } else {
            window.max(1).min(wire::MAX_SOURCE_COUNT as usize)
        };
        self.last_switch_time = crate::time_source::now_instant();
        self.window_history.push_back(self.window_size);
        if self.window_history.len() > 10 {
            self.window_history.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::test_support::*;

    fn test_policy() -> FecRuntimePolicy {
        FecRuntimePolicy {
            decoder_policy: "auto".to_string(),
            lazy_enabled: false,
            interleave_enabled: false,
            switch_threshold_override: None,
            switch_min_up_ms: 0,
            switch_min_down_ms: 0,
            auto_gf4_enabled: true,
            fountain_window: 2048,
            extreme_window: 1024,
            fountain_symbol_size: 1500,
            stream_every_override: None,
            interleave_depth_override: None,
            partial_enabled: true,
            kalman_q_override: None,
            kalman_r_override: None,
        }
    }

    // --- ZeroEncoder tests ---

    #[test]
    fn test_zero_encoder_never_generates_repairs() {
        let pool = make_pool();
        let mut enc = ZeroEncoder::new(64, 80);
        for i in 0..10 {
            let pkt = mk_src_packet(i, 100, &pool);
            enc.take_packet(pkt);
        }
        // Zero encoder should never produce repair packets
        for i in 0..10 {
            assert!(enc.generate_repair_packet(i, &pool).is_none());
        }
    }

    #[test]
    fn test_zero_encoder_window_always_zero() {
        let mut enc = ZeroEncoder::new(64, 80);
        assert_eq!(enc.packets_in_window(), 0);
        let pool = make_pool();
        enc.take_packet(mk_src_packet(0, 100, &pool));
        // Window is always 0 - zero mode tracks nothing
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn test_zero_encoder_clear_resets_counter() {
        let pool = make_pool();
        let mut enc = ZeroEncoder::new(64, 80);
        enc.take_packet(mk_src_packet(0, 100, &pool));
        enc.take_packet(mk_src_packet(1, 100, &pool));
        assert_eq!(enc.packets_passed, 2);
        enc.clear_window();
        assert_eq!(enc.packets_passed, 0);
    }

    // --- ZeroDecoder tests ---

    #[test]
    fn test_zero_decoder_no_loss_returns_packets() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        // Feed contiguous source packets (seq 1, 2, 3)
        for seq in 1..=3 {
            let mut pkt = mk_src_packet(seq, 100, &pool);
            pkt.seq = seq;
            pkt.is_systematic = true;
            dec.take_packet(pkt);
        }
        let result = dec.get_result();
        assert!(result.is_some());
        assert_eq!(result.as_ref().map(|r| r.len()), Some(3));
    }

    #[test]
    fn test_zero_decoder_gap_triggers_loss_detection() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        // Feed seq 1, then skip to seq 5 (gap of 3)
        let mut p1 = mk_src_packet(1, 100, &pool);
        p1.seq = 1;
        p1.is_systematic = true;
        dec.take_packet(p1);

        let mut p2 = mk_src_packet(5, 100, &pool);
        p2.seq = 5;
        p2.is_systematic = true;
        dec.take_packet(p2);

        // Loss detected - get_result returns None (needs upgrade)
        assert!(dec.get_result().is_none());
    }

    #[test]
    fn test_zero_decoder_partial_result_drains_buffer() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        let mut pkt = mk_src_packet(1, 100, &pool);
        pkt.seq = 1;
        pkt.is_systematic = true;
        dec.take_packet(pkt);
        let partial = dec.get_partial_result();
        assert_eq!(partial.len(), 1);
        // Buffer should be drained after get_partial_result
        let partial2 = dec.get_partial_result();
        assert_eq!(partial2.len(), 0);
    }

    // --- EncoderVariant tests ---

    #[test]
    fn test_encoder_variant_zero_backend_kind() {
        let policy = test_policy();
        let enc = EncoderVariant::new_with_policy(FecMode::Zero, 0, 0, &policy);
        assert_eq!(enc.backend_kind(), "zero");
    }

    #[test]
    fn test_encoder_variant_gf8_takes_and_counts_packets() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = EncoderVariant::new_with_policy(FecMode::Normal, 4, 6, &policy);
        assert_eq!(enc.packets_in_window(), 0);

        for i in 0..4 {
            enc.take_packet(mk_src_packet(i, 100, &pool));
        }
        assert_eq!(enc.packets_in_window(), 4);

        enc.clear_window();
        assert_eq!(enc.packets_in_window(), 0);
    }

    // --- DecoderVariant tests ---

    #[test]
    fn test_decoder_variant_zero_backend_kind() {
        let pool = make_pool();
        let policy = test_policy();
        let dec = DecoderVariant::new_with_policy(FecMode::Zero, 0, pool, &policy);
        assert_eq!(dec.backend_kind(), "zero");
    }

    // --- LazyDecoder tests ---

    #[test]
    fn test_lazy_decoder_buffers_repairs_until_loss() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        // Feed a repair packet (non-systematic) - should be buffered
        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);
        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "buffered repair alone must not force recovery");

        // Feed contiguous source packet - no gap, pending repairs get cleared
        let mut src = mk_src_packet(1, 100, &pool);
        src.is_systematic = true;
        src.seq = 1;
        dec.take_packet(src);
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 1);
        assert!(!dec.recovery_needed(), "contiguous source path must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_flushes_on_gap() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        // Feed source seq=1
        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        // Feed a buffered repair
        let mut repair = mk_src_packet(200, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 200;
        dec.take_packet(repair);
        assert_eq!(dec.pending_repairs_len(), 1);

        // Feed source seq=5 (gap: 2,3,4 missing)
        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        // Gap detected -> repairs flushed to inner decoder
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 0);
        assert!(dec.recovery_needed(), "gap must enable recovery polling");
        assert!(dec.full_recovery_pending(), "flushed repair must request full recovery");
    }

    #[test]
    fn test_lazy_decoder_gap_without_repair_stays_lazy() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        assert_eq!(
            dec.pending_sources_len(),
            2,
            "gap without repair should retain bounded source context"
        );
        assert!(
            !dec.recovery_needed(),
            "gap without repair should stay lazy because no recovery is possible yet"
        );
        assert!(
            !dec.partial_recovery_pending(),
            "gap without repair must not trigger partial decoder polling"
        );
        assert!(
            !dec.full_recovery_pending(),
            "gap without new repair must not trigger full matrix recovery"
        );
    }

    #[test]
    fn test_lazy_decoder_repair_after_gap_requests_full_recovery_once() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        let mut repair = mk_src_packet(200, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 200;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 0, "repair should flush after a known gap");
        assert!(dec.full_recovery_pending(), "new repair must request full recovery");

        let _ = dec.get_result();
        assert!(
            !dec.full_recovery_pending(),
            "full recovery request must be consumed after one get_result call"
        );
    }

    #[test]
    fn test_lazy_decoder_prunes_clean_complete_blocks() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        for seq in 1..=4u64 {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }

        assert_eq!(dec.seen_seqs_len(), 0, "complete clean block should be pruned");
        assert_eq!(dec.pending_sources_len(), 0, "complete clean block should drop source buffer");

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "repair after clean full block must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_depth_normalizes_interleaved_clean_sources() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_depth(FecMode::Normal, 4, pool.clone(), &policy, 4);

        for seq in [0_u64, 4, 8, 12] {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
            assert!(
                !dec.recovery_needed(),
                "interleaved clean source sequence {seq} must not look like a loss gap"
            );
        }

        assert_eq!(dec.seen_seqs_len(), 0, "complete interleaved clean block should be pruned");
        assert_eq!(
            dec.pending_sources_len(),
            0,
            "complete interleaved clean block should drop source buffer"
        );

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "repair after interleaved clean block must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_tail_loss_replays_buffered_sources_on_recovery() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        for seq in 1..=3u64 {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }
        assert_eq!(dec.pending_sources_len(), 3);

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert_eq!(dec.pending_sources_len(), 3);
        assert!(dec.full_recovery_pending(), "tail-loss repair must request full recovery");

        let _ = dec.get_result();

        assert_eq!(dec.pending_sources_len(), 0, "get_result must replay buffered sources");
        assert_eq!(dec.pending_repairs_len(), 0, "get_result must replay buffered repairs");
        assert!(
            !dec.full_recovery_pending(),
            "full recovery request must be consumed after get_result"
        );
    }

    #[test]
    fn test_lazy_decoder_streaming_repair_requests_immediate_recovery() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let profile = wire::WireProfile {
            epoch: 1,
            codec: wire::WireCodec::StreamingGf8,
            source_count: 4,
            total_count: 8,
            interleave_depth: 1,
        };
        let mut dec = LazyDecoder::new_for_wire(
            profile.codec,
            profile.block_source_count() as usize,
            pool.clone(),
            &policy,
            profile.interleave_depth as usize,
            DEFAULT_FOUNTAIN_SEED,
            0,
        );

        {
            let seq = 0_u64;
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }
        assert_eq!(dec.pending_sources_len(), 1);

        let mut repair = mk_src_packet(1, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 0;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 0);
        assert!(
            dec.full_recovery_pending(),
            "wire-filtered streaming repair must request immediate recovery"
        );
        assert!(
            dec.recovery_needed(),
            "streaming loss evidence must wake the decoder without waiting for block end"
        );
    }

    // --- ModeManager tests ---

    #[test]
    fn test_mode_manager_initial_state() {
        let policy = test_policy();
        let mgr = ModeManager::with_runtime_policy(FecMode::Normal, 0.05, &policy);
        assert_eq!(mgr.current_mode(), FecMode::Normal);
        assert!(mgr.current_window() > 0);
    }

    #[test]
    fn test_mode_manager_force_state() {
        let policy = test_policy();
        let mut mgr = ModeManager::with_runtime_policy(FecMode::Normal, 0.05, &policy);
        mgr.force_state(FecMode::Strong, 256);
        assert_eq!(mgr.current_mode(), FecMode::Strong);
        assert_eq!(mgr.current_window(), 256);
    }

    #[test]
    fn test_mode_manager_params_for_zero_mode() {
        let (k, n) = ModeManager::params_for(FecMode::Zero, 0);
        // Zero mode: no window needed
        assert_eq!(k, 0);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_mode_manager_params_for_normal_mode() {
        let (k, n) = ModeManager::params_for(FecMode::Normal, 64);
        // Normal mode with default window 64: n >= k (redundancy >= 1.0)
        assert!(k > 0);
        assert!(n >= k, "n={} must be >= k={}", n, k);
    }

    // --- InterleavedEncoder tests ---

    #[test]
    fn test_interleaved_encoder_round_robin_distribution() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);

        // Feed 4 packets - should distribute 2 per block
        for i in 0..4 {
            enc.take_packet(mk_src_packet(i, 100, &pool));
        }
        assert_eq!(enc.packets_in_window(), 4);

        enc.clear_window();
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn test_interleaved_encoder_params() {
        let policy = test_policy();
        let enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);
        let (k, n) = enc.params();
        assert_eq!(k, 8);
        assert_eq!(n, 12);
    }

    #[test]
    fn test_interleaved_encoder_reports_the_shape_it_actually_represents() {
        let mut policy = test_policy();
        policy.interleave_enabled = true;

        // 10 sources over 4 lanes floors to 2 per lane, so only 8 are represented. Reporting the
        // request here would emit a wire source_count that its own interleave depth cannot divide.
        let enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 10, 14, 4, &policy);
        assert_eq!(enc.params(), (8, 12), "params must describe the represented lanes");
        let (represented_k, _) = enc.params();
        assert_eq!(
            represented_k % enc.depth(),
            0,
            "represented sources must divide by depth so the wire profile cannot report an \
             uneven interleave"
        );

        // A divisible request is represented exactly.
        let exact = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 4, &policy);
        assert_eq!(exact.params(), (8, 12));
    }

    #[test]
    fn test_interleaved_encoder_refuses_aliasing_repair_ordinals() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);

        // `i / depth` is the ordinal and `i % depth` the lane. An ordinal above the representable
        // range would shift out of the u64 identity and collide with an unrelated repair.
        let aliasing_index = ((crate::fec::MAX_REPAIR_ORDINAL as usize) + 1)
            .saturating_mul(enc.depth())
            .saturating_add(1);
        assert!(
            enc.generate_repair_packet(aliasing_index, &pool).is_none(),
            "out-of-range repair ordinal must be refused, not aliased"
        );
    }

    #[test]
    fn test_params_for_target_rejects_non_finite_redundancy() {
        let base = FecProtectionTarget {
            family: FecBackendFamily::HeavyBlock,
            redundancy: 1.5,
            effective_window: 16,
            stream_every: None,
        };

        let (_, k, n) = ModeManager::params_for_target(base, 16, false);
        assert_eq!(k, 16);
        assert_eq!(n, 24, "a finite ratio still scales the total count");

        // NaN previously survived `f32::min`, which returns the other operand for NaN, so the
        // clamp produced MAX_TOTAL_COUNT: the most expensive possible repair budget.
        for broken in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let target = FecProtectionTarget { redundancy: broken, ..base };
            let (_, k, n) = ModeManager::params_for_target(target, 16, false);
            assert_eq!(k, 16);
            assert_eq!(
                n, k,
                "non-finite redundancy {broken} must fall back to systematic-only, not to the maximum"
            );
        }
    }

    #[test]
    fn test_mode_manager_force_state_preserves_zero_semantics() {
        let policy = test_policy();
        let mut mgr = ModeManager::with_runtime_policy(FecMode::Zero, 0.1, &policy);
        mgr.force_state(FecMode::Zero, 5);
        assert_eq!(mgr.current_window(), 0);
        mgr.force_state(FecMode::Zero, 0);
        assert_eq!(mgr.current_window(), 0);
        mgr.force_state(FecMode::Normal, 0);
        assert_eq!(mgr.current_window(), 1);
        mgr.force_state(FecMode::Strong, crate::fec::wire::MAX_SOURCE_COUNT as usize + 10);
        assert_eq!(mgr.current_window(), crate::fec::wire::MAX_SOURCE_COUNT as usize);
    }

    #[test]
    fn test_lazy_decoder_rejected_zero_does_not_buffer() {
        let mut policy = test_policy();
        policy.lazy_enabled = true;
        let pool = make_pool();
        let mut dec = LazyDecoder::new_with_policy(FecMode::Zero, 0, Arc::clone(&pool), &policy);

        for i in 0..100u64 {
            dec.take_packet(mk_src_packet(i, 100, &pool));
        }

        for i in 0..50u64 {
            let repair = FecPacket::new(1000 + i, None, 0, false, None, 0, Arc::clone(&pool));
            dec.take_packet(repair);
        }

        assert_eq!(dec.pending_sources_len(), 0);
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.seen_seqs_len(), 0);
        assert!(dec.get_result().is_some_and(|v| v.is_empty()));
        assert!(dec.get_partial_result().is_empty());
    }

    #[test]
    fn test_interleaved_decoder_routes_large_source_sequences_in_u64() {
        let mut policy = test_policy();
        policy.interleave_enabled = true;
        policy.lazy_enabled = true;
        let pool = make_pool();
        let mut dec =
            InterleavedDecoder::new_with_policy(FecMode::Normal, 4, Arc::clone(&pool), 2, &policy);

        // u64::MAX is odd, so with depth 2 it must route to block 1.
        dec.take_packet(mk_src_packet(u64::MAX, 100, &pool));
        assert_eq!(dec.blocks[1].pending_sources_len(), 1);
        assert_eq!(dec.blocks[0].pending_sources_len(), 0);

        // u64::MAX - 1 is even, so it must route to block 0.
        dec.take_packet(mk_src_packet(u64::MAX - 1, 100, &pool));
        assert_eq!(dec.blocks[0].pending_sources_len(), 1);
        assert_eq!(dec.blocks[1].pending_sources_len(), 1);
    }
}

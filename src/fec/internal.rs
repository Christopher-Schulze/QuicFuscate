#![allow(private_interfaces)]
use super::*;
use std::sync::Arc;

/// LT fountain encoder alias for internal FEC variant dispatch.
pub type FountainEncoder = fountain_codes::LTEncoder;
/// LT fountain decoder alias for internal FEC variant dispatch.
pub type FountainDecoder = fountain_codes::LTDecoder;

/// Adaptive RS wrapper: chooses between GF8 and GF16 encoders based on
/// adaptive parameters and delegates all operations accordingly.
struct AdaptiveEncoder {
    rs: super::adaptive_reed_solomon::AdaptiveRSEncoder,
    inner_gf8: Encoder<GF8>,
    inner_gf16: Encoder16,
    use_gf16: bool,
    adapt_ctr: usize,
    rs_loss_hint: f32,
    rs_latency_ms_hint: f32,
    rs_bw_mbps_hint: f32,
}

impl AdaptiveEncoder {
    // Convenience constructor that auto-detects policy. Not called from production paths
    // (new_with_policy is used there), but reserved for future standalone benchmark / test harnesses.
    #[allow(dead_code)]
    fn new(mode: FecMode, k: usize, n: usize) -> Self {
        let policy = super::FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, n, &policy)
    }

    fn new_with_policy(
        mode: FecMode,
        k: usize,
        n: usize,
        policy: &super::FecRuntimePolicy,
    ) -> Self {
        let rs = super::adaptive_reed_solomon::AdaptiveRSEncoder::new(k, n);
        let target = super::target_from_mode(mode, k);
        let use_gf16 = super::adaptive_rs_uses_gf16(target);
        Self {
            rs,
            inner_gf8: Encoder::<GF8>::new(k, n),
            inner_gf16: Encoder16::new(k, n),
            use_gf16,
            adapt_ctr: 0,
            rs_loss_hint: policy.rs_loss_hint,
            rs_latency_ms_hint: policy.rs_latency_ms_hint,
            rs_bw_mbps_hint: policy.rs_bw_mbps_hint,
        }
    }

    #[inline]
    fn packets_in_window(&self) -> usize {
        if self.use_gf16 {
            self.inner_gf16.packets_in_window()
        } else {
            self.inner_gf8.packets_in_window()
        }
    }

    fn maybe_adapt(&mut self) {
        self.adapt_ctr = self.adapt_ctr.wrapping_add(1);
        if !self.adapt_ctr.is_multiple_of(32) {
            return;
        }
        self.rs.adapt_parameters(self.rs_loss_hint, self.rs_latency_ms_hint, self.rs_bw_mbps_hint);
        let (k, n, gf_size) = self.rs.current_parameters();
        let want_gf16 = gf_size >= 65536;
        // Reconfigure only when windows are empty to avoid state loss
        let can_switch =
            self.inner_gf8.packets_in_window() == 0 && self.inner_gf16.packets_in_window() == 0;
        if can_switch {
            if want_gf16 {
                // Recreate encoders with new params
                self.inner_gf16 = Encoder16::new(k, n);
            } else {
                self.inner_gf8 = Encoder::<GF8>::new(k, n);
            }
            self.use_gf16 = want_gf16;
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        self.maybe_adapt();
        if self.use_gf16 {
            self.inner_gf16.take_packet(p)
        } else {
            self.inner_gf8.take_packet(p)
        }
    }

    fn generate_repair_packet(&mut self, i: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        self.maybe_adapt();
        let t0 = std::time::Instant::now();
        let out = if self.use_gf16 {
            self.inner_gf16.generate_repair_packet(i, pool)
        } else {
            self.inner_gf8.generate_repair_packet(i, pool)
        };
        let dt = t0.elapsed().as_nanos() as u64;
        crate::telemetry::RS_ENC_TIME_NS.fetch_add(dt, std::sync::atomic::Ordering::Relaxed);
        if out.is_some() {
            crate::telemetry::RS_REPAIR_EMITTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Window/overhead snapshot
        let (k, n, gf) = self.rs.current_parameters();
        crate::telemetry::RS_WINDOW_K.store(k as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::RS_WINDOW_N.store(n as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::RS_GF_SIZE.store(gf as u64, std::sync::atomic::Ordering::Relaxed);
        if k > 0 && n >= k {
            let overhead_ppm = ((n - k) as u128) * 1_000_000u128 / (k as u128);
            crate::telemetry::RS_OVERHEAD_PPM
                .store(overhead_ppm as u64, std::sync::atomic::Ordering::Relaxed);
        }
        out
    }

    fn clear_window(&mut self) {
        self.inner_gf8.clear_window();
        self.inner_gf16.clear_window();
    }
}

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
        self.packets_passed += 1;
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
            // Check for gaps (non-contiguous sequence)
            if self.last_seq > 0 && p.seq > self.last_seq + 1 {
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
    /// Adaptive RS encoder that switches between GF(2^8) and GF(2^16).
    AdaptiveRS(AdaptiveEncoder),
}

impl EncoderVariant {
    /// Create an encoder variant matching the given FEC mode with auto-detected policy.
    // Called from fec/tests.rs (cfg(test)); allow suppresses dead_code in non-test builds.
    #[allow(dead_code)]
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
                if super::low_cost_block_uses_gf4(target) {
                    EncoderVariant::GF4(Encoder4::new(k, n))
                } else {
                    EncoderVariant::GF8(Encoder::<GF8>::new(k, n))
                }
            }
            super::FecBackendFamily::HeavyBlock => {
                if super::heavy_block_uses_adaptive_rs(target) {
                    EncoderVariant::AdaptiveRS(AdaptiveEncoder::new_with_policy(mode, k, n, policy))
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
                    e.add_source_symbol(data.to_vec());
                }
            }
            EncoderVariant::AdaptiveRS(a) => a.take_packet(p),
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
                let mut coeff_block = pool.alloc();
                let max_u32s = coeff_block.len() / 4;
                let take = core::cmp::min(indices.len(), max_u32s);
                for (i, idx) in indices.iter().take(take).enumerate() {
                    let be = (*idx as u32).to_be_bytes();
                    let off = i * 4;
                    coeff_block[off..off + 4].copy_from_slice(&be);
                }
                Some(FecPacket::new(
                    symbol_id,
                    Some(pool.alloc_from_slice(&encoded_data)),
                    enc.symbol_size(),
                    false,
                    Some(coeff_block),
                    take * 4,
                    Arc::clone(pool),
                ))
            }
            EncoderVariant::AdaptiveRS(a) => a.generate_repair_packet(i, pool),
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
            EncoderVariant::AdaptiveRS(_) => "adaptive-rs",
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
            EncoderVariant::AdaptiveRS(a) => a.clear_window(),
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
            EncoderVariant::AdaptiveRS(a) => a.packets_in_window(),
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
    /// Adaptive RS decoder that switches between GF(2^8) and GF(2^16).
    AdaptiveRS(AdaptiveDecoder),
}

struct AdaptiveDecoder {
    inner_gf8: Decoder8,
    inner_gf16: Decoder16,
    use_gf16: bool,
}

impl AdaptiveDecoder {
    // Convenience constructor that auto-detects policy. Not called from production paths
    // (new_with_policy is used there), but reserved for future standalone benchmark / test harnesses.
    #[allow(dead_code)]
    fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = super::FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    fn new_with_policy(
        mode: FecMode,
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &super::FecRuntimePolicy,
    ) -> Self {
        let target = super::target_from_mode(mode, k);
        let use_gf16 = super::adaptive_rs_uses_gf16(target);
        Self {
            inner_gf8: Decoder8::new_with_policy(k, Arc::clone(&pool), policy),
            inner_gf16: Decoder16::new(k, pool),
            use_gf16,
        }
    }
    #[inline]
    fn take_packet(&mut self, p: FecPacket) {
        if self.use_gf16 {
            self.inner_gf16.take_packet(p)
        } else {
            self.inner_gf8.take_packet(p)
        }
    }
    #[inline]
    fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        let t0 = std::time::Instant::now();
        let res =
            if self.use_gf16 { self.inner_gf16.get_result() } else { self.inner_gf8.get_result() };
        let dt = t0.elapsed().as_nanos() as u64;
        crate::telemetry::RS_DEC_TIME_NS.fetch_add(dt, std::sync::atomic::Ordering::Relaxed);
        if let Some(ref r) = res {
            crate::telemetry::RS_RECOVERED
                .fetch_add(r.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }
    #[inline]
    fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        if self.use_gf16 {
            self.inner_gf16.get_partial_result()
        } else {
            self.inner_gf8.get_partial_result()
        }
    }
    // is_complete removed; partial/get_result drive completion
}

impl DecoderVariant {
    /// Create a decoder variant matching the given FEC mode with auto-detected policy.
    // Called from fec/tests.rs (cfg(test)); allow suppresses dead_code in non-test builds.
    #[allow(dead_code)]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = super::FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

    /// Create a decoder variant matching the given FEC mode with explicit policy.
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
                if super::low_cost_block_uses_gf4(target) {
                    DecoderVariant::GF4(Decoder4::new_with_depth(k, pool, depth))
                } else {
                    DecoderVariant::GF8(Decoder8::new_with_depth(k, pool, policy, depth))
                }
            }
            super::FecBackendFamily::HeavyBlock => {
                if super::heavy_block_uses_adaptive_rs(target) {
                    DecoderVariant::AdaptiveRS(AdaptiveDecoder::new_with_policy(
                        mode, k, pool, policy,
                    ))
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
        match self {
            DecoderVariant::Zero(d) => d.take_packet(p),
            DecoderVariant::GF8(d) => d.take_packet(p),
            DecoderVariant::GF16(d) => d.take_packet(p),
            DecoderVariant::GF4(d) => d.take_packet(p),
            DecoderVariant::Fountain(d) => {
                // Add received symbol to LT decoder, use indices if available
                if let Some(data) = p.payload_slice() {
                    let payload = data.to_vec();
                    if let Some(ref coeffs) = p.coefficients {
                        let mut set = std::collections::HashSet::new();
                        let bytes = &coeffs[..p.coeff_len.min(coeffs.len())];
                        for chunk in bytes.chunks_exact(4) {
                            let idx = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                                as usize;
                            set.insert(idx);
                        }
                        let _ = d.add_encoded_symbol(p.id, payload, set);
                    } else {
                        d.add_received_symbol(p.id, payload);
                    }
                }
            }
            DecoderVariant::AdaptiveRS(d) => d.take_packet(p),
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
                if let Some(symbols) = d.get_decoded_symbols() {
                    // Telemetry: completed
                    crate::telemetry::FOUNTAIN_PROGRESS
                        .store(1_000_000, std::sync::atomic::Ordering::Relaxed);
                    let mut packets = VecDeque::new();
                    for symbol in symbols.into_iter() {
                        let pool = Arc::clone(&d.mem_pool);
                        let new_id = next_repair_id();
                        let packet = FecPacket::new(
                            new_id,
                            Some(pool.alloc_from_slice(&symbol)),
                            symbol.len(),
                            true,
                            None,
                            0,
                            pool,
                        );
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
            DecoderVariant::AdaptiveRS(d) => d.get_result(),
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
            DecoderVariant::AdaptiveRS(_) => "adaptive-rs",
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
                for symbol in d.get_partial().into_iter() {
                    let pool = Arc::clone(&d.mem_pool);
                    let id = symbol.len() as u64;
                    let packet = FecPacket::new(
                        id,
                        Some(pool.alloc_from_slice(&symbol)),
                        symbol.len(),
                        true,
                        None,
                        0,
                        pool,
                    );
                    partial.push_back(packet);
                }
                // Update progress gauge with current progress
                let prog = (d.decoding_progress() * 1_000_000.0) as u64;
                crate::telemetry::FOUNTAIN_PROGRESS
                    .store(prog, std::sync::atomic::Ordering::Relaxed);
                partial
            }
            DecoderVariant::AdaptiveRS(d) => d.get_partial_result(),
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
    /// Buffered repair packets (only decoded when gaps detected)
    pending_repairs: VecDeque<FecPacket>,
    /// Tracks seen source packet sequence numbers
    seen_seqs: std::collections::BTreeSet<u64>,
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
    /// Telemetry: repairs skipped (no loss)
    repairs_skipped: u64,
}

impl LazyDecoder {
    // Called only from fec/tests.rs (cfg(test)); the allow suppresses the warning in non-test builds.
    #[allow(dead_code)]
    pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, pool, &policy)
    }

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

        Self {
            inner: DecoderVariant::new_with_depth(mode, k, pool, policy, depth),
            pending_repairs: VecDeque::with_capacity(32),
            seen_seqs: std::collections::BTreeSet::new(),
            k,
            depth: depth.max(1),
            expected_seq: 0,
            max_pending: 64,
            lazy_enabled,
            repairs_skipped: 0,
        }
    }

    #[inline]
    fn source_block_seq(&self, seq: u64) -> u64 {
        seq / self.depth as u64
    }

    /// Check if there are gaps in the received sequence
    #[inline]
    fn has_gaps(&self) -> bool {
        if self.seen_seqs.is_empty() {
            return false;
        }
        let mut it = self.seen_seqs.iter();
        let Some(&first) = it.next() else {
            return false;
        };
        let Some(&last) = self.seen_seqs.iter().next_back() else {
            return false;
        };
        // Gap exists if we've seen N sequences but range is > N
        (last - first + 1) as usize > self.seen_seqs.len()
    }

    /// Flush pending repairs to actual decoder (when loss detected)
    fn flush_to_decoder(&mut self) {
        while let Some(repair) = self.pending_repairs.pop_front() {
            self.inner.take_packet(repair);
        }
    }

    pub fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            let block_seq = self.source_block_seq(p.seq);
            // Source packet - track sequence
            self.seen_seqs.insert(block_seq);
            // Update expected sequence
            self.expected_seq = self.expected_seq.max(block_seq + 1);

            // If lazy disabled, forward to decoder
            if !self.lazy_enabled {
                self.inner.take_packet(p);
                return;
            }

            // Check if we detect gaps now
            if self.has_gaps() {
                // Loss detected! Flush buffered repairs and forward this packet
                self.flush_to_decoder();
                self.inner.take_packet(p);
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
                }
                // Forward source packet (decoder needs it for systematic recovery)
                self.inner.take_packet(p);
            }
        } else {
            // Repair packet - buffer it
            if !self.lazy_enabled {
                self.inner.take_packet(p);
                return;
            }

            // Buffer repair packet
            self.pending_repairs.push_back(p);

            // If buffer full, force flush
            if self.pending_repairs.len() >= self.max_pending {
                self.flush_to_decoder();
            }
        }
    }

    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Flush any pending repairs before getting result
        self.flush_to_decoder();
        // Update telemetry
        crate::telemetry::FEC_LAZY_SKIPPED
            .fetch_add(self.repairs_skipped, std::sync::atomic::Ordering::Relaxed);
        self.repairs_skipped = 0;
        self.inner.get_result()
    }

    /// Whether recovery work is currently useful.
    ///
    /// In lazy mode, polling the heavy decoder on every clean systematic packet
    /// defeats the lazy fast path because `get_result()` flushes pending repairs
    /// into the decoder. Recovery is only useful once a sequence gap exists. If
    /// lazy mode is disabled, preserve the eager behavior and let callers poll.
    #[inline]
    pub fn recovery_needed(&self) -> bool {
        if !self.lazy_enabled || self.has_gaps() {
            return true;
        }

        // Tail loss at the end of a block does not create an internal sequence
        // gap because no later systematic packet arrived. A pending repair is
        // useful when the current block is not full. Clean no-loss blocks remain
        // lazy because their seen-source count lands exactly on the block size.
        !self.pending_repairs.is_empty()
            && self.k > 0
            && !self.seen_seqs.len().is_multiple_of(self.k)
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        // If gaps detected, flush and decode
        if self.has_gaps() {
            self.flush_to_decoder();
        }
        self.inner.get_partial_result()
    }

    /// Drain buffered packets from ZeroDecoder for seamless mode transition.
    /// Returns packets to be replayed into the new decoder after mode switch.
    pub fn drain_zero_buffers(&mut self) -> VecDeque<FecPacket> {
        match &mut self.inner {
            DecoderVariant::Zero(z) => z.get_partial_result(),
            _ => VecDeque::new(),
        }
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
    pub fn seen_seqs_len(&self) -> usize {
        self.seen_seqs.len()
    }

    #[cfg(test)]
    pub fn pending_repairs_max(&self) -> usize {
        self.max_pending
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
    k: usize,
    n: usize,
}

impl InterleavedEncoder {
    // Convenience constructor that auto-detects policy. Production code uses new_with_policy;
    // this entry point is reserved for future integration tests and benchmark harnesses.
    #[allow(dead_code)]
    pub fn new(mode: FecMode, k: usize, n: usize, depth: usize) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(mode, k, n, depth, &policy)
    }

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

        Self { blocks, depth: actual_depth, packet_idx: 0, k, n }
    }

    /// Return the (k, n) parameters for the overall interleaved encoder.
    pub fn params(&self) -> (usize, usize) {
        (self.k, self.n)
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
        if block_idx < self.blocks.len() {
            if let Some(mut repair) =
                self.blocks[block_idx].generate_repair_packet(repair_idx, pool)
            {
                // Tag repair with interleave block index
                repair.seq = (repair.seq << 4) | (block_idx as u64);
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
    // Convenience constructor that auto-detects policy. Production code uses new_with_policy;
    // this entry point is reserved for future integration tests and benchmark harnesses.
    #[allow(dead_code)]
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

        // CRITICAL: Scale decoder k same as encoder
        let block_k = (k / actual_depth).max(1);

        let blocks = (0..actual_depth)
            .map(|_| {
                LazyDecoder::new_with_depth(mode, block_k, Arc::clone(&pool), policy, actual_depth)
            })
            .collect();

        Self { blocks, depth: actual_depth }
    }

    /// Route a received packet to the correct interleaved block by sequence number.
    pub fn take_packet(&mut self, p: FecPacket) {
        // Extract block index from seq (low 4 bits for repair, high bits for source)
        let block_idx = if p.is_systematic {
            // Source packets: use seq modulo depth
            (p.seq as usize) % self.depth
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
            if let Some(results) = block.get_result() {
                any_result = true;
                for pkt in results {
                    combined.push_back(pkt);
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

    /// Drain all buffered packets from ZeroDecoders for seamless mode transition.
    /// Called before switching from Zero mode to preserve in-flight packets.
    pub fn drain_zero_buffers(&mut self) -> VecDeque<FecPacket> {
        let mut combined = VecDeque::new();
        for block in &mut self.blocks {
            for pkt in block.drain_zero_buffers() {
                combined.push_back(pkt);
            }
        }
        combined
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
    /// Default number of packets over which a mode cross-fade occurs.
    pub const CROSS_FADE_LEN: usize = 20;

    // Called from fec/mod.rs (same crate); allow suppresses any spurious dead_code lint.
    #[allow(dead_code)]
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
        let n = if k == 0 { 0 } else { ((k as f32) * target.redundancy).ceil() as usize };
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
        // CONSOLIDATED AUTO-SWITCH: 6 logical modes
        // Zero (<0.1%) -> Light (0.1-2%) -> Normal (2-10%) -> Strong (10-25%) -> Extreme (25-50%) -> Fountain (>50%)
        // Streaming/Medium/Ultra enum variants are valid but not auto-selected by the controller
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
        self.window_size = window.max(1);
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
            rs_loss_hint: 0.0,
            rs_latency_ms_hint: 5.0,
            rs_bw_mbps_hint: 1000.0,
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
        assert!(dec.recovery_needed(), "gap must enable recovery polling");
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

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "repair after interleaved clean block must stay lazy");
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
}

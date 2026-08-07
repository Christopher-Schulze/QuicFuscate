/// Vectorized GF(2^16) scalar multiply-and-xor over big-endian byte slices.
/// out_xor[j..j+2] ^= gf16_mul(coeff, src[j..j+2]) for all j in steps of 2.
#[inline]
pub(crate) fn gf16_mul_scalar_slice_u16(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let len = src.len().min(out_xor.len());
    let packet_u16_len = len / 2;
    if coeff == 0 || packet_u16_len == 0 {
        return;
    }

    if coeff == 1 {
        // Simple XOR
        for (x, y) in src[..len].iter().zip(out_xor[..len].iter_mut()) {
            *y ^= *x;
        }
        return;
    }

    let vector_threshold = gf16_vector_threshold_words();

    // Chunk size for stack buffer (64 u16 = 128 bytes)
    const CHUNK_SIZE: usize = 64;

    if vector_threshold != usize::MAX && packet_u16_len >= vector_threshold {
        let mut i = 0;
        while i < packet_u16_len {
            let chunk_len = (packet_u16_len - i).min(CHUNK_SIZE);

            // Stack buffers to avoid heap allocation
            let mut src_tmp = [0u16; CHUNK_SIZE];
            let mut dst_tmp = [0u16; CHUNK_SIZE];

            // 1. Gather & Swap Bytes (BE -> Native)
            // Manual loop is reliable and auto-vectorizes well on modern compilers
            for (k, (src_slot, dst_slot)) in
                src_tmp.iter_mut().zip(dst_tmp.iter_mut()).take(chunk_len).enumerate()
            {
                let offset = (i + k) * 2;
                // Safety: Bounds checked by loop limits
                *src_slot = u16::from_be_bytes([src[offset], src[offset + 1]]);
                *dst_slot = u16::from_be_bytes([out_xor[offset], out_xor[offset + 1]]);
            }

            // 2. SIMD Multiply (Native u16)
            gf16_mul_slice(coeff, &src_tmp[..chunk_len], &mut dst_tmp[..chunk_len]);

            // 3. Swap Bytes & Store (Native -> BE)
            for (k, val) in dst_tmp[..chunk_len].iter().enumerate() {
                let offset = (i + k) * 2;
                let bytes = val.to_be_bytes();
                out_xor[offset] = bytes[0];
                out_xor[offset + 1] = bytes[1];
            }

            i += chunk_len;
        }
    } else {
        // Scalar fallback (packet too small or SIMD disabled)
        let mut j = 0;
        while j + 1 < len {
            let s = u16::from_be_bytes([src[j], src[j + 1]]);
            let r = u16::from_be_bytes([out_xor[j], out_xor[j + 1]]);
            let v = gf_tables::gf16_mul_add(coeff, s, r);
            let b = v.to_be_bytes();
            out_xor[j] = b[0];
            out_xor[j + 1] = b[1];
            j += 2;
        }
    }
}

#[inline]
fn gf16_mul_scalar_slice_padded(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let source_len = src.len().min(out_xor.len());
    let even_len = source_len & !1;
    if even_len > 0 {
        gf16_mul_scalar_slice_u16(coeff, &src[..even_len], &mut out_xor[..even_len]);
    }
    if source_len != even_len && even_len + 1 < out_xor.len() {
        let product = gf_tables::gf16_mul(coeff, u16::from_be_bytes([src[even_len], 0]));
        let bytes = product.to_be_bytes();
        out_xor[even_len] ^= bytes[0];
        out_xor[even_len + 1] ^= bytes[1];
    }
}

#[inline(always)]
fn gf16_vector_threshold_words() -> usize {
    let features = FeatureDetector::instance().features_full();
    gf16_vector_threshold_words_for_features(features)
}

#[inline(always)]
fn fec_simd_level_for_features(features: &crate::optimize::CpuFeatures) -> SimdLevel {
    let matrix = features.simd_dispatch_matrix();

    if matrix.avx512_vbmi2 {
        SimdLevel::Avx512Vbmi2
    } else if matrix.avx512_vbmi {
        SimdLevel::Avx512Vbmi
    } else if matrix.avx2 {
        SimdLevel::Avx2
    } else if features.sse2 {
        SimdLevel::Sse2
    } else if matrix.sve2 {
        SimdLevel::Sve2
    } else if matrix.neon {
        SimdLevel::Neon
    } else {
        SimdLevel::None
    }
}

#[inline(always)]
fn gf16_vector_threshold_words_for_features(
    features: &crate::optimize::CpuFeatures,
) -> usize {
    match fec_simd_level_for_features(features) {
        SimdLevel::Avx512Vbmi2 => GF16_VBMI2_MIN_WORDS,
        SimdLevel::Avx512Vbmi => GF16_AVX512_MIN_WORDS,
        SimdLevel::Avx2 => GF16_AVX2_MIN_WORDS,
        SimdLevel::Sse2 => GF16_SSE2_MIN_WORDS,
        SimdLevel::Sve2 => GF16_SVE2_MIN_WORDS,
        SimdLevel::Neon => GF16_NEON_MIN_WORDS,
        SimdLevel::None => usize::MAX,
    }
}

#[inline(always)]
fn bounded_u16_len(src: &[u16], dst: &[u16], requested: usize) -> usize {
    requested.min(src.len()).min(dst.len())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI2 support. `src` and
/// `dst` must remain valid for the duration of the call; `len` is bounded to
/// both slice lengths before any vector access.
unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);

    if len == 0 {
        return;
    }

    #[repr(align(64))]
    struct Table([u16; 32]);

    let mut table0_a = Table([0u16; 32]);
    let mut table0_b = Table([0u16; 32]);
    let mut table1_b = Table([0u16; 32]);
    let mut table2_b = Table([0u16; 32]);
    let mut table3_b = Table([0u16; 32]);

    for nib in 0..16u16 {
        let base = nib as usize;
        let contrib0 = gf_tables::gf16_mul(coeff, nib);
        table0_a.0[base] = contrib0;
        table0_a.0[base + 16] = contrib0;
        table0_b.0[base] = contrib0;
        table0_b.0[base + 16] = contrib0;

        let contrib1 = gf_tables::gf16_mul(coeff, nib << 4);
        table1_b.0[base] = contrib1;
        table1_b.0[base + 16] = contrib1;

        let contrib2 = gf_tables::gf16_mul(coeff, nib << 8);
        table2_b.0[base] = contrib2;
        table2_b.0[base + 16] = contrib2;

        let contrib3 = gf_tables::gf16_mul(coeff, nib << 12);
        table3_b.0[base] = contrib3;
        table3_b.0[base + 16] = contrib3;
    }

    let tbl0_a = _mm512_loadu_si512(table0_a.0.as_ptr() as *const __m512i);
    let tbl0_b = _mm512_loadu_si512(table0_b.0.as_ptr() as *const __m512i);
    let tbl1_a = _mm512_setzero_si512();
    let tbl1_b = _mm512_loadu_si512(table1_b.0.as_ptr() as *const __m512i);
    let tbl2_a = _mm512_setzero_si512();
    let tbl2_b = _mm512_loadu_si512(table2_b.0.as_ptr() as *const __m512i);
    let tbl3_a = _mm512_setzero_si512();
    let tbl3_b = _mm512_loadu_si512(table3_b.0.as_ptr() as *const __m512i);

    let mask_nibble = _mm512_set1_epi16(0x000F);
    let offset32 = _mm512_set1_epi16(32);

    let mut i = 0usize;
    while i + 32 <= len {
        let src_vec = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
        let dst_vec = _mm512_loadu_si512(dst.as_ptr().add(i) as *const __m512i);

        let nib0 = _mm512_and_si512(src_vec, mask_nibble);
        let nib1 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 4), mask_nibble);
        let nib2 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 8), mask_nibble);
        let nib3 = _mm512_srli_epi16(src_vec, 12);

        let idx1 = _mm512_add_epi16(nib1, offset32);
        let idx2 = _mm512_add_epi16(nib2, offset32);
        let idx3 = _mm512_add_epi16(nib3, offset32);

        let contrib0 = _mm512_permutex2var_epi16(tbl0_a, nib0, tbl0_b);
        let contrib1 = _mm512_permutex2var_epi16(tbl1_a, idx1, tbl1_b);
        let contrib2 = _mm512_permutex2var_epi16(tbl2_a, idx2, tbl2_b);
        let contrib3 = _mm512_permutex2var_epi16(tbl3_a, idx3, tbl3_b);

        let partial = _mm512_xor_si512(_mm512_xor_si512(contrib0, contrib1), contrib2);
        let prod = _mm512_xor_si512(partial, contrib3);
        let result = _mm512_xor_si512(dst_vec, prod);

        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, result);
        i += 32;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }

    crate::telemetry::FEC_GF16_VBMI2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vbmi")]
/// # Safety
///
/// The caller must prove AVX512F and AVX512VBMI support. `src` and `dst` must
/// remain valid for the duration of the call; `len` is bounded to both slice
/// lengths before the loop accesses either slice.
unsafe fn gf16_mul_slice_avx512(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
    crate::telemetry::FEC_AVX512_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_avx2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
    crate::telemetry::FEC_AVX2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_sse2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove AArch64 NEON support. `src` and `dst` must remain
/// valid for the duration of the call; `len` is bounded to both slice lengths
/// before vector loads, stores, or scalar tail accesses.
unsafe fn gf16_mul_slice_neon(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::aarch64::*;
    let len = bounded_u16_len(src, dst, len);
    let one = vdupq_n_u16(1);
    let poly = vdupq_n_u16(0x100b);
    let mut i = 0;

    while i + 8 <= len {
        let mut multiplicand = vld1q_u16(src.as_ptr().add(i));
        let mut factor = vdupq_n_u16(coeff);
        let mut product = vdupq_n_u16(0);
        let dst_vec = vld1q_u16(dst.as_ptr().add(i));

        for _ in 0..16 {
            let factor_mask = vceqq_u16(vandq_u16(factor, one), one);
            product = veorq_u16(product, vandq_u16(multiplicand, factor_mask));
            let carry_mask = vceqq_u16(vshrq_n_u16(multiplicand, 15), one);
            multiplicand = veorq_u16(vshlq_n_u16(multiplicand, 1), vandq_u16(poly, carry_mask));
            factor = vshrq_n_u16(factor, 1);
        }

        let result = veorq_u16(dst_vec, product);
        vst1q_u16(dst.as_mut_ptr().add(i), result);
        i += 8;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
    crate::telemetry::FEC_NEON_OPS.inc();
}

#[cfg(target_arch = "aarch64")]
/// # Safety
///
/// On builds that include the SVE2 block, the caller must prove AArch64 SVE2
/// support. `src` and `dst` must remain valid for the duration of the call;
/// `len` is bounded to both slice lengths before predicated accesses. Builds
/// without SVE2 compile to the NEON fallback, which has its own NEON contract.
unsafe fn gf16_mul_slice_sve2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if len == 0 {
            return;
        }

        let coeff_vec = svdup_n_u16(coeff);
        let poly = svdup_n_u16(0x000B);
        let mut offset = 0usize;
        let vl = svcnth() as usize;

        while offset < len {
            let pg = svwhilelt_b16(offset as u64, len as u64);
            if !svptest_any(svptrue_b16(), pg) {
                break;
            }

            let src_vec = svld1_u16(pg, src.as_ptr().add(offset));
            let dst_vec = svld1_u16(pg, dst.as_ptr().add(offset));

            let lo = svmul_u16_x(pg, coeff_vec, src_vec);
            let hi = svmulh_u16_x(pg, coeff_vec, src_vec);
            let red = svmul_u16_x(pg, hi, poly);
            let prod = sveor_u16_m(pg, lo, lo, red);
            let result = sveor_u16_m(pg, dst_vec, dst_vec, prod);

            svst1_u16(pg, dst.as_mut_ptr().add(offset), result);
            offset += vl;
        }

        crate::optimize::telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf16_mul_slice_neon(coeff, src, dst, len);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
/// # Safety
///
/// The caller must prove PCLMULQDQ support. The scalar inputs are valid for
/// the duration of the call and the target-feature intrinsic is not executed
/// unless the shared FEC dispatch policy has selected this backend.
unsafe fn gf16_mul_pclmul(a: u16, b: u16) -> u16 {
    use std::arch::x86_64::*;
    let a_vec = _mm_cvtsi32_si128(a as i32);
    let b_vec = _mm_cvtsi32_si128(b as i32);
    let product = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
    let mut reduced = _mm_cvtsi128_si64(product) as u32;

    for shift in (0..=14).rev() {
        let coefficient = (reduced >> (shift + 16)) & 1;
        let mask = 0u32.wrapping_sub(coefficient);
        reduced ^= (0x1_100B_u32 << shift) & mask;
    }

    reduced as u16
}

// Removed gf16_mul_neon scalar shim; NEON paths use slice/vector kernels above.

impl AdaptiveFec {
    fn emit_streaming_repair(&mut self, output_queue: &mut VecDeque<FecPacket>) {
        let mut encoder = self.encoder.lock();

        if encoder.packets_in_window() > 0 {
            let coeff = self.stream_idx;
            if coeff < 255 {
                // Generic repair generation; backend selection is internal.
                if let Some(repair) = encoder.generate_repair_packet(coeff, &self.mem_pool) {
                    output_queue.push_back(repair);
                }
                self.stream_idx = self.stream_idx.wrapping_add(1);
            }
        }
    }

    // Removed packet_to_fec_packet (unused).

    /// Update RTT estimate for stream_every scaling.
    /// Called by transport when a new RTT sample is available.
    pub fn set_rtt_hint(&mut self, rtt_ms: u32) {
        self.rtt_ms = rtt_ms;
    }

    /// Bandwidth-aware overhead control (TODO-428).
    ///
    /// Adjusts FEC redundancy based on bandwidth scarcity signals. When bandwidth
    /// is scarce (high RTT, low throughput), FEC overhead is reduced to preserve
    /// useful throughput. When bandwidth is plentiful, FEC can use full redundancy.
    ///
    /// Signals:
    /// - `rtt_trend`: +1.0 if RTT increasing (congestion), -1.0 if decreasing, 0.0 stable
    /// - `cwnd_trend`: +1.0 if cwnd growing, -1.0 if shrinking, 0.0 stable
    /// - `throughput_trend`: +1.0 if throughput increasing, -1.0 if decreasing, 0.0 stable
    ///
    /// The function adjusts `red_ppm_hint` to guide streaming repair emission.
    /// It never reduces redundancy below the minimum required for current loss level.
    pub fn bandwidth_aware_overhead_adjustment(
        &mut self,
        rtt_trend: f32,
        cwnd_trend: f32,
        throughput_trend: f32,
    ) {
        if self.control_policy == FecControlPolicy::Off {
            self.red_ppm_hint = 0;
            return;
        }
        // Combine signals: negative sum = bandwidth scarce, positive = plentiful
        let signal = rtt_trend + cwnd_trend + throughput_trend;

        // Current loss estimate from estimator
        let current_loss = self.loss_estimator.smoothed_loss();

        // Minimum redundancy for current loss level (parts-per-million)
        // At 0% loss: 0 ppm (Zero mode)
        // At 5% loss: ~50,000 ppm (5% overhead)
        // At 25% loss: ~300,000 ppm (30% overhead)
        // At 50% loss: ~600,000 ppm (60% overhead)
        let min_ppm: u32 = match current_loss {
            l if l < 0.01 => 0,
            l if l < 0.05 => 50_000,
            l if l < 0.10 => 100_000,
            l if l < 0.25 => 300_000,
            l if l < 0.50 => 600_000,
            _ => 1_000_000,
        };

        // Target redundancy based on bandwidth signal
        // Scarce bandwidth (signal < -1.5): reduce to minimum
        // Plentiful bandwidth (signal > 1.5): increase to maximum
        // Neutral: use moderate overhead
        let target_ppm = if signal < -1.5 {
            // Bandwidth scarce: minimize overhead
            min_ppm
        } else if signal > 1.5 {
            // Bandwidth plentiful: full redundancy
            min_ppm.saturating_mul(2)
        } else {
            // Neutral: moderate overhead (1.5x minimum)
            (min_ppm as f32 * 1.5) as u32
        };

        // Smooth adjustment: move 25% toward target each call
        let current = self.red_ppm_hint;
        let adjusted = if target_ppm > current {
            current + ((target_ppm - current) / 4).max(10_000)
        } else if target_ppm < current {
            current.saturating_sub(((current - target_ppm) / 4).max(10_000))
        } else {
            current
        };

        self.red_ppm_hint = adjusted;
    }

    /// Report observed packet loss to update the estimator and drive adaptive mode switching.
    pub fn report_loss(&mut self, lost: usize, total: usize) {
        let observed_lost = lost.min(total) as u64;
        let observed_total = total as u64;
        if self.telemetry.enabled {
            self.telemetry.observed_lost_packets =
                self.telemetry.observed_lost_packets.saturating_add(observed_lost);
            self.telemetry.observed_packets =
                self.telemetry.observed_packets.saturating_add(observed_total);
            crate::telemetry::fec_observe_loss(observed_lost, observed_total);
        }
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        // Update estimator with current observation and drive mode via smoothed loss
        self.loss_estimator.report(lost, total);
        let estimated_loss = self.loss_estimator.smoothed_loss();
        self.update_mode(estimated_loss, false);
        self.update_stream_interval(self.policy_loss_estimate(estimated_loss));
    }

    /// Consume transport-owned counters and its congestion controller's smoothed loss signal.
    pub(crate) fn report_transport_loss(
        &mut self,
        sent_packets: usize,
        acknowledged_packets: usize,
        lost_packets: usize,
        smoothed_loss: f32,
    ) {
        self.report_transport_loss_inner(
            sent_packets,
            acknowledged_packets,
            lost_packets,
            smoothed_loss,
            false,
        );
    }

    pub(crate) fn report_transport_loss_with_slow_phase_diagnostics(
        &mut self,
        sent_packets: usize,
        acknowledged_packets: usize,
        lost_packets: usize,
        smoothed_loss: f32,
    ) {
        self.report_transport_loss_inner(
            sent_packets,
            acknowledged_packets,
            lost_packets,
            smoothed_loss,
            true,
        );
    }

    fn report_transport_loss_inner(
        &mut self,
        sent_packets: usize,
        acknowledged_packets: usize,
        lost_packets: usize,
        smoothed_loss: f32,
        diagnostics_enabled: bool,
    ) {
        let feedback_started = diagnostics_enabled.then(std::time::Instant::now);
        let observed_total = sent_packets as u64;
        let observed_lost = lost_packets as u64;
        if self.telemetry.enabled {
            self.telemetry.observed_packets =
                self.telemetry.observed_packets.saturating_add(observed_total);
            self.telemetry.observed_lost_packets =
                self.telemetry.observed_lost_packets.saturating_add(observed_lost);
            crate::telemetry::fec_observe_transport_loss(observed_lost, observed_total);
        }
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        Self::run_feedback_phase(diagnostics_enabled, "estimator-actual", || {
            self.loss_estimator.report_actual_observation(acknowledged_packets, lost_packets);
        });
        let observation_weight = sent_packets.max(lost_packets);
        Self::run_feedback_phase(diagnostics_enabled, "estimator-smoothed", || {
            self.loss_estimator.report_smoothed_rate(smoothed_loss, observation_weight);
        });
        let estimated_loss = Self::run_feedback_phase(
            diagnostics_enabled,
            "estimator-read",
            || self.loss_estimator.smoothed_loss(),
        );
        Self::run_feedback_phase(diagnostics_enabled, "mode-update-total", || {
            self.update_mode(estimated_loss, diagnostics_enabled);
        });
        Self::run_feedback_phase(diagnostics_enabled, "stream-interval-update", || {
            self.update_stream_interval(self.policy_loss_estimate(estimated_loss));
        });
        if let Some(started) = feedback_started {
            let elapsed = started.elapsed();
            if elapsed >= std::time::Duration::from_millis(100) {
                log::info!(
                    "FEC transport feedback slow total: duration_ms={} sent={} acked={} lost={} transport_loss={:.6} estimated_loss={:.6} active_mode={:?} pending_transition={}",
                    elapsed.as_millis(),
                    sent_packets,
                    acknowledged_packets,
                    lost_packets,
                    smoothed_loss,
                    estimated_loss,
                    self.active_mode,
                    self.pending_transition.is_some()
                );
            }
        }
    }

    /// Return the currently active FEC protection mode.
    pub fn current_mode(&self) -> FecMode {
        self.active_mode
    }

    /// Return the immutable operator-owned control policy.
    pub fn control_policy(&self) -> FecControlPolicy {
        self.control_policy
    }

    /// Install the connection-local fountain seed before the first protected window.
    pub(crate) fn set_fountain_seed(&mut self, seed: u64) {
        if self.fountain_seed == seed {
            return;
        }
        self.fountain_seed = seed;
        self.encoder.lock().set_fountain_seed(seed);
        self.decoder.lock().set_fountain_seed(seed);
    }

    /// Replace controller, encoder, decoder, repair-retention, and loss-history
    /// state with a validated Zero-mode bootstrap for `policy`.
    ///
    /// The connection owner must serialize this with send and receive. Cumulative
    /// wire evidence is preserved, while stale adaptation evidence is not.
    pub fn set_control_policy(&mut self, policy: FecControlPolicy) -> FecPolicyChange {
        let previous_policy = self.control_policy;
        let previous_mode = self.active_mode;
        if previous_policy == policy {
            return FecPolicyChange {
                previous_policy,
                previous_mode,
                effective_policy: previous_policy,
                effective_mode: previous_mode,
            };
        }

        let previous_telemetry = self.telemetry;
        let mut config = self.config.clone();
        config.control_policy = policy;
        config.initial_mode = FecMode::Zero;
        config.force_on = false;

        let fountain_seed = self.fountain_seed;
        let mut replacement = Self::new(config);
        replacement.set_fountain_seed(fountain_seed);
        replacement.telemetry = FecTelemetrySnapshot {
            control_policy: policy,
            active_mode: FecMode::Zero,
            effective_window: 0,
            mode_transitions: previous_telemetry
                .mode_transitions
                .saturating_add(u64::from(previous_mode != FecMode::Zero)),
            policy_transitions: previous_telemetry.policy_transitions.saturating_add(1),
            ..previous_telemetry
        };
        *self = replacement;

        crate::telemetry::FEC_POLICY_TRANSITIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if previous_mode != FecMode::Zero {
            crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        FecPolicyChange {
            previous_policy,
            previous_mode,
            effective_policy: self.control_policy,
            effective_mode: self.active_mode,
        }
    }

    /// Return exact connection-local FEC evidence.
    pub fn telemetry_snapshot(&self) -> FecTelemetrySnapshot {
        self.telemetry
    }

    pub(crate) fn telemetry_enabled(&self) -> bool {
        self.telemetry.enabled
    }

    pub(crate) fn observe_wire_send(
        &mut self,
        systematic: bool,
        source_payload_bytes: usize,
        wire_bytes: usize,
    ) {
        if !self.telemetry.enabled {
            return;
        }
        if systematic {
            self.telemetry.source_packets_sent =
                self.telemetry.source_packets_sent.saturating_add(1);
            self.telemetry.source_payload_bytes_sent = self
                .telemetry
                .source_payload_bytes_sent
                .saturating_add(source_payload_bytes as u64);
            self.telemetry.source_wire_bytes_sent =
                self.telemetry.source_wire_bytes_sent.saturating_add(wire_bytes as u64);
        } else {
            self.telemetry.repair_packets_sent =
                self.telemetry.repair_packets_sent.saturating_add(1);
            self.telemetry.repair_wire_bytes_sent =
                self.telemetry.repair_wire_bytes_sent.saturating_add(wire_bytes as u64);
        }
        crate::telemetry::fec_observe_wire_send(
            systematic,
            source_payload_bytes as u64,
            wire_bytes as u64,
        );
    }

    pub(crate) fn observe_wire_receive(&mut self, report: wire::WireReceiveReport) {
        if !self.telemetry.enabled {
            return;
        }
        if report.systematic {
            self.telemetry.source_packets_received =
                self.telemetry.source_packets_received.saturating_add(1);
            self.telemetry.source_payload_bytes_received = self
                .telemetry
                .source_payload_bytes_received
                .saturating_add(report.source_payload_bytes as u64);
            self.telemetry.source_wire_bytes_received =
                self.telemetry.source_wire_bytes_received.saturating_add(report.wire_bytes as u64);
        } else {
            self.telemetry.repair_packets_received =
                self.telemetry.repair_packets_received.saturating_add(1);
            self.telemetry.repair_wire_bytes_received =
                self.telemetry.repair_wire_bytes_received.saturating_add(report.wire_bytes as u64);
        }
        self.telemetry.decoded_packets =
            self.telemetry.decoded_packets.saturating_add(report.decoded_packets as u64);
        self.telemetry.recovered_packets =
            self.telemetry.recovered_packets.saturating_add(report.recovered_packets as u64);
        self.telemetry.recovered_payload_bytes = self
            .telemetry
            .recovered_payload_bytes
            .saturating_add(report.recovered_payload_bytes as u64);
        crate::telemetry::fec_observe_wire_receive(
            report.systematic,
            report.source_payload_bytes as u64,
            report.wire_bytes as u64,
            report.decoded_packets as u64,
            report.recovered_packets as u64,
            report.recovered_payload_bytes as u64,
        );
    }

    pub fn wire_profile(&mut self, epoch: u32) -> Result<wire::WireProfile, wire::WireError> {
        self.commit_pending_target_if_ready();
        let encoder = self.encoder.lock();
        let (source_count, configured_total_count) = encoder.params();
        let interleave_depth = encoder.depth();
        let block_source_count = source_count / interleave_depth.max(1);
        let codec = wire::WireCodec::for_mode(self.active_mode, block_source_count)?;
        let total_count = match codec {
            wire::WireCodec::Gf4 => configured_total_count,
            wire::WireCodec::StreamingGf8 => configured_total_count.saturating_add(source_count),
            _ => configured_total_count.saturating_add(4),
        };
        let profile = wire::WireProfile {
            epoch,
            codec,
            source_count: u16::try_from(source_count)
                .map_err(|_| wire::WireError::InvalidSourceCount)?,
            total_count: u16::try_from(total_count)
                .map_err(|_| wire::WireError::InvalidTotalCount)?,
            interleave_depth: u8::try_from(interleave_depth)
                .map_err(|_| wire::WireError::InvalidInterleaveDepth)?,
        };
        profile.validate()
    }

    /// Returns true while a target is waiting for the current source block to complete.
    pub fn is_transitioning(&self) -> bool {
        self.pending_transition.is_some()
    }

    /// Force a specific FEC mode for testing (bypasses adaptive controller).
    #[cfg(test)]
    pub fn force_mode_for_test(&mut self, mode: FecMode) {
        self.active_mode = mode;
        self.telemetry.active_mode = mode;
        self.mode_manager =
            Arc::new(Mutex::new(internal::ModeManager::with_switch_threshold(mode, 0.02)));
    }

    fn run_feedback_phase<T>(
        diagnostics_enabled: bool,
        phase: &'static str,
        operation: impl FnOnce() -> T,
    ) -> T {
        if !diagnostics_enabled {
            return operation();
        }
        let started = std::time::Instant::now();
        let result = operation();
        let elapsed = started.elapsed();
        if elapsed >= std::time::Duration::from_millis(100) {
            log::info!(
                "FEC transport feedback slow phase: phase={phase} duration_ms={}",
                elapsed.as_millis()
            );
        }
        result
    }

    fn update_mode(&mut self, estimated_loss: f32, diagnostics_enabled: bool) {
        let estimated_loss = self.policy_loss_estimate(estimated_loss);
        let (prev, current_mode, current_window) =
            Self::run_feedback_phase(diagnostics_enabled, "mode-manager-update", || {
                let mut mode_mgr = self.mode_manager.lock();
                let prev = mode_mgr.update(estimated_loss);
                let cur_mode = mode_mgr.current_mode();
                let cur_window = mode_mgr.current_window();
                (prev, cur_mode, cur_window)
            });
        // Derive target mode/window from mode manager and apply policy overrides.
        let mut switched = prev.is_some();
        let (controller_target, reason) =
            Self::run_feedback_phase(diagnostics_enabled, "mode-target", || {
                let mut reason = FecSwitchReason::Adaptive;
                let desired_target = continuous_fec_target(
                    estimated_loss,
                    self.runtime_policy.auto_gf4_enabled,
                    self.loss_estimator.disturbance_detected(),
                    self.fountain_window,
                    self.extreme_window,
                    self.rtt_ms,
                    self.loss_estimator.burst_variance(),
                );
                let mut controller_target = if prev.is_some() {
                    desired_target
                } else {
                    target_from_mode(current_mode, current_window)
                };

                if self.force_on && desired_target.family == FecBackendFamily::Zero {
                    controller_target = target_from_mode(FecMode::Normal, 64);
                    reason = FecSwitchReason::ForceOnPolicy;
                }
                if estimated_loss >= FOUNTAIN_LOSS_THRESHOLD {
                    controller_target =
                        target_from_mode(FecMode::Fountain, self.fountain_window);
                    reason = FecSwitchReason::ExtremeLossPolicy;
                } else if self.loss_estimator.disturbance_detected() && estimated_loss >= 0.15 {
                    controller_target = target_from_mode(FecMode::Streaming, self.extreme_window)
                        .with_window(self.extreme_window);
                    reason = FecSwitchReason::DisturbancePolicy;
                }
                (controller_target, reason)
            });
        let (new_mode, new_window, _n) =
            Self::run_feedback_phase(diagnostics_enabled, "mode-parameters", || {
                internal::ModeManager::params_for_target(
                    controller_target,
                    current_window,
                    self.runtime_policy.auto_gf4_enabled,
                )
            });
        switched = switched || current_mode != new_mode || current_window != new_window;
        let k = new_window;

        if switched {
            Self::run_feedback_phase(diagnostics_enabled, "mode-manager-force", || {
                self.mode_manager.lock().force_state(new_mode, new_window);
            });
        }

        if let Some(stream_every) = controller_target.stream_every {
            Self::run_feedback_phase(diagnostics_enabled, "mode-stream-cadence", || {
                self.set_stream_every_internal(stream_every);
            });
        }

        // Auto control tuning stays connection-local. Process-global environment
        // mutation here would serialize unrelated connections and race their policy.
        if self.control_policy == FecControlPolicy::Auto {
            Self::run_feedback_phase(diagnostics_enabled, "mode-auto-tuning", || {
                self.apply_auto_tuning(k, estimated_loss, controller_target);
            });
        }

        if switched {
            Self::run_feedback_phase(diagnostics_enabled, "mode-transition-total", || {
                self.transition_to_target_with_reason_inner(
                    controller_target,
                    reason,
                    diagnostics_enabled,
                );
            });
        }
    }

    fn policy_loss_estimate(&self, estimated_loss: f32) -> f32 {
        if estimated_loss < FOUNTAIN_LOSS_THRESHOLD || self.loss_estimator.fountain_ready() {
            estimated_loss
        } else {
            FOUNTAIN_LOSS_THRESHOLD - f32::EPSILON
        }
    }

    pub(crate) fn force_streaming_mode(&mut self) {
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        let target = target_from_mode(FecMode::Streaming, 64);
        let target_mode = mode_for_target(target, self.runtime_policy.auto_gf4_enabled);
        self.transition_to_target_with_reason(target, FecSwitchReason::StreamingHint);
        if self.active_mode != target_mode {
            log::debug!(
                "Queued streaming mode until the active FEC source block reaches its boundary"
            );
            return;
        }
        log::info!("Forced switch to streaming mode for minimal latency");
    }

    /// Enable SIMD acceleration based on CPU features
    pub(crate) fn enable_simd_acceleration(&mut self) {
        // Centralized detection via optimize::FeatureDetector
        let det = crate::optimize::FeatureDetector::instance();
        let features = det.features_full();
        self.simd_level = fec_simd_level_for_features(features);
        self.simd_enabled = self.simd_level != SimdLevel::None;
        crate::telemetry::SIMD_ACTIVE
            .store(self.simd_enabled as u64, std::sync::atomic::Ordering::Relaxed);

        match self.simd_level {
            SimdLevel::Avx512Vbmi2 => {
                log::info!("FEC: AVX-512 VBMI2 SIMD acceleration enabled")
            }
            SimdLevel::Avx512Vbmi => {
                log::info!("FEC: AVX-512 VBMI SIMD acceleration enabled")
            }
            SimdLevel::Avx2 => log::info!("FEC: AVX2 SIMD acceleration enabled"),
            SimdLevel::Sse2 => log::info!("FEC: SSE2 SIMD acceleration enabled"),
            SimdLevel::Sve2 => log::info!("FEC: SVE2 SIMD acceleration enabled"),
            SimdLevel::Neon => log::info!("FEC: NEON SIMD acceleration enabled"),
            SimdLevel::None => {}
        }
        // Telemetry: report SIMD level
        let lvl = self.simd_level();
        match lvl {
            "AVX-512 VBMI2" | "AVX-512 VBMI" => crate::telemetry::SIMD_USAGE_AVX512
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            "AVX2" => {
                crate::telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SSE2" => {
                crate::telemetry::SIMD_USAGE_SSE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SVE2" => {
                crate::telemetry::SIMD_USAGE_SVE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "NEON" => {
                crate::telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            _ => crate::telemetry::SIMD_USAGE_SCALAR
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
    }

    /// Get current SIMD acceleration level
    pub(crate) fn simd_level(&self) -> &str {
        match self.simd_level {
            SimdLevel::None => "scalar",
            SimdLevel::Sse2 => "SSE2",
            SimdLevel::Avx2 => "AVX2",
            SimdLevel::Avx512Vbmi2 => "AVX-512 VBMI2",
            SimdLevel::Avx512Vbmi => "AVX-512 VBMI",
            SimdLevel::Sve2 => "SVE2",
            SimdLevel::Neon => "NEON",
        }
    }

    // Removed associated test; proper tests are in #[cfg(test)] modules.

    fn apply_auto_tuning(&mut self, k: usize, loss: f32, target: FecProtectionTarget) {
        let big_k = k > self.wiedemann_threshold;
        let (decoder_policy, stream_every) = if target.family == FecBackendFamily::Zero {
            ("gauss", 4)
        } else if target.family == FecBackendFamily::LowCostBlock && loss < 0.01 {
            (if big_k { "auto" } else { "gauss" }, 3)
        } else if matches!(
            target.family,
            FecBackendFamily::LowCostBlock | FecBackendFamily::HeavyBlock
        ) && loss < 0.05
        {
            ("auto", 2)
        } else {
            ("wiedemann", target.stream_every.unwrap_or(1))
        };

        if self.decoder_policy_tunable && self.runtime_policy.decoder_policy != decoder_policy {
            self.runtime_policy.decoder_policy.clear();
            self.runtime_policy.decoder_policy.push_str(decoder_policy);
        }
        self.set_stream_every_internal(stream_every);
    }
}

impl Drop for AdaptiveFec {
    fn drop(&mut self) {
        if self.telemetry.enabled {
            crate::telemetry::fec_instance_closed(
                self.active_mode.telemetry_id(),
                self.telemetry.effective_window,
            );
        }
    }
}

// --- FEC Configuration ---

#[derive(Debug, Clone)]
/// Configuration for Adaptive FEC behavior and controller settings.
pub struct FecConfig {
    /// Operator-owned control policy. This is never inferred from the active codec mode.
    pub control_policy: FecControlPolicy,
    /// FEC window size per mode (source packets per block).
    pub window_sizes: HashMap<FecMode, usize>,
    /// EMA smoothing factor for loss estimation (0..1).
    pub lambda: f32,
    /// Sliding window capacity for burst-loss detection.
    pub burst_window: usize,
    /// Minimum loss delta required to trigger a mode switch.
    pub hysteresis: f32,
    /// FEC mode to use at startup before adaptation kicks in.
    pub initial_mode: FecMode,
    /// When true, FEC will never downshift to `Zero`. This is used for "FEC On"
    /// policy (manual) without exposing low-level tuning in the UI.
    pub force_on: bool,
    /// Enable Kalman filter for loss rate smoothing.
    pub kalman_enabled: bool,
    /// Kalman process noise covariance.
    pub kalman_q: f32,
    /// Kalman measurement noise covariance.
    pub kalman_r: f32,
    /// Override for streaming repair emission interval (packets between repairs).
    pub configured_stream_every: Option<usize>,
}

impl FecConfig {
    fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut m = HashMap::new();
        m.insert(Zero, 0);
        m.insert(Light, 15);
        m.insert(Normal, 64);
        m.insert(Medium, 128);
        m.insert(Strong, 512);
        m.insert(Extreme, 1024);
        m.insert(Ultra, 1024);
        m.insert(Fountain, DEFAULT_FOUNTAIN_WINDOW);
        m.insert(Streaming, 64);
        m
    }

    fn product_windows(section: &crate::engine::FecSection) -> HashMap<FecMode, usize> {
        let mut windows = Self::default_windows();
        windows.insert(FecMode::Zero, 0);
        if section.window_excellent > 0 {
            windows.insert(FecMode::Light, section.window_excellent);
        }
        windows.insert(FecMode::Normal, section.window_good.max(1));
        windows.insert(FecMode::Medium, section.window_fair.max(section.window_good).max(1));
        windows.insert(FecMode::Strong, section.window_poor.max(1));
        windows.insert(
            FecMode::Extreme,
            section.window_poor.saturating_mul(2).max(section.window_poor).max(1),
        );
        windows.insert(FecMode::Ultra, 1024);
        windows.insert(FecMode::Fountain, DEFAULT_FOUNTAIN_WINDOW);
        windows.insert(FecMode::Streaming, section.window_fair.max(1));
        windows
    }

    /// Build FEC config from the engine's `[fec]` TOML section.
    pub fn from_engine_section(section: &crate::engine::FecSection) -> Self {
        let initial_mode = match section.mode {
            crate::engine::FecMode::Off => FecMode::Zero,
            crate::engine::FecMode::Auto => FecMode::Zero,
        };

        Self {
            control_policy: match section.mode {
                crate::engine::FecMode::Off => FecControlPolicy::Off,
                crate::engine::FecMode::Auto => FecControlPolicy::Auto,
            },
            window_sizes: Self::product_windows(section),
            lambda: 0.15,
            burst_window: 16,
            hysteresis: if section.enable_hysteresis { 0.1 } else { 0.0 },
            initial_mode,
            force_on: false,
            kalman_enabled: section.enable_kalman,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: Some(section.stream_every.max(1)),
        }
    }

    /// Return the production-default FEC configuration.
    pub fn product_default() -> Self {
        Self::from_engine_section(&crate::engine::FecSection::default())
    }

    /// Override operator policy and its compatible bootstrap mode.
    pub fn apply_engine_mode(&mut self, mode: crate::engine::FecMode) {
        (self.control_policy, self.initial_mode) = match mode {
            crate::engine::FecMode::Off => (FecControlPolicy::Off, FecMode::Zero),
            crate::engine::FecMode::Auto => (FecControlPolicy::Auto, FecMode::Zero),
        };
        self.force_on = false;
    }

    /// Parse FEC configuration from a TOML string containing `[adaptive_fec]`.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Root {
            adaptive_fec: Adaptive,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Adaptive {
            #[serde(alias = "policy")]
            control_policy: Option<String>,
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            stream_every: Option<usize>,
            initial_mode: Option<String>,
            modes: Option<Vec<ModeSection>>,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let mut windows = FecConfig::default_windows();
        if let Some(modes) = af.modes {
            for msec in modes {
                let mode = parse_fec_mode_name(&msec.name, "modes[].name")?;
                windows.insert(mode, msec.w0);
            }
        }
        let initial_mode = af.initial_mode.as_deref().unwrap_or("auto").trim();
        let initial_mode = match initial_mode.to_ascii_lowercase().as_str() {
            "auto" | "off" => FecMode::Zero,
            "on" => FecMode::Normal,
            _ => parse_fec_mode_name(initial_mode, "initial_mode")?,
        };
        let control_policy = match af.control_policy.as_deref().map(str::trim) {
            None | Some("") | Some("auto") => FecControlPolicy::Auto,
            Some("off") => FecControlPolicy::Off,
            Some(value) => {
                return Err(format!(
                    "adaptive_fec.control_policy must be 'off' or 'auto', got '{value}'"
                )
                .into());
            }
        };
        Ok(FecConfig {
            control_policy,
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            initial_mode,
            force_on: false,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            configured_stream_every: af.stream_every,
            window_sizes: windows,
        })
    }

    /// Load FEC configuration from a TOML file on disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            control_policy: FecControlPolicy::Auto,
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            initial_mode: FecMode::Zero,
            force_on: false,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: None,
            window_sizes: FecConfig::default_windows(),
        }
    }
}

impl FecConfig {
    /// Validate all configuration parameters, returning an error message on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if self.control_policy == FecControlPolicy::Off && self.force_on {
            return Err("force_on cannot be enabled while FEC control policy is off".into());
        }
        if !(0.0..=1.0).contains(&self.lambda) {
            return Err("lambda must be between 0 and 1".into());
        }
        if self.burst_window == 0 {
            return Err("burst_window must be > 0".into());
        }
        if !self.hysteresis.is_finite() || self.hysteresis < 0.0 || self.hysteresis >= 1.0 {
            return Err("hysteresis must be between 0 (inclusive) and 1".into());
        }
        if !self.kalman_q.is_finite() || self.kalman_q <= 0.0 {
            return Err("kalman_q must be finite and positive".into());
        }
        if !self.kalman_r.is_finite() || self.kalman_r <= 0.0 {
            return Err("kalman_r must be finite and positive".into());
        }
        if matches!(self.configured_stream_every, Some(0)) {
            return Err("configured_stream_every must be > 0".into());
        }
        for (mode, window) in &self.window_sizes {
            if *window > wire::MAX_SOURCE_COUNT as usize {
                return Err(format!(
                    "window_sizes.{mode:?} must be <= {}",
                    wire::MAX_SOURCE_COUNT
                ));
            }
            if *mode == FecMode::Zero {
                if *window != 0 {
                    return Err("window_sizes.Zero must be 0".into());
                }
            } else if *window == 0 {
                return Err(format!("window_sizes.{mode:?} must be > 0"));
            }
            if *mode == FecMode::Fountain && *window > MAX_FOUNTAIN_WINDOW {
                return Err(format!(
                    "window_sizes.Fountain must be <= {}",
                    MAX_FOUNTAIN_WINDOW
                ));
            }
        }
        Ok(())
    }
}

fn parse_fec_mode_name(raw: &str, field: &str) -> Result<FecMode, std::io::Error> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "zero" => Ok(FecMode::Zero),
        "light" => Ok(FecMode::Light),
        "normal" => Ok(FecMode::Normal),
        "medium" => Ok(FecMode::Medium),
        "strong" => Ok(FecMode::Strong),
        "extreme" => Ok(FecMode::Extreme),
        "ultra" => Ok(FecMode::Ultra),
        "fountain" => Ok(FecMode::Fountain),
        "streaming" => Ok(FecMode::Streaming),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "adaptive_fec.{field} contains unsupported FEC mode '{raw}' (expected zero, light, normal, medium, strong, extreme, ultra, fountain, or streaming)"
            ),
        )),
    }
}

impl Decoder8 {
    /// Attempt recovery via Gaussian elimination and return recovered packets.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Try basic recovery first
        self.try_eliminate();

        // Return any recovered packets
        if !self.emit_q.is_empty() {
            Some(std::mem::take(&mut self.emit_q))
        } else {
            None
        }
    }

    /// Drain all currently queued recovered packets without further elimination.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    /// Returns true if enough source packets have been recovered to fill the block.
    #[cfg(test)]
    pub fn is_complete(&self) -> bool {
        self.known.len() >= self.k
    }
}

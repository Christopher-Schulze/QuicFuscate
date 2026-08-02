
// ============================================================================
// Transport Integration: FecTransportObserver
// Collects lightweight transport telemetry (ACK delay, ECN) and exposes a
// policy hook to tune transport parameters with minimal overhead.
// This does not change any FEC algorithm semantics; it merely adjusts
// ACK emission aggressiveness for CPU/latency balance.
// ============================================================================

#[derive(Default, Debug, Clone)]
struct FecObsSnapshot {
    ack_delay_ewma_us: f64,
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    ack_events: u64,
}

#[derive(Default, Debug)]
struct FecObsState {
    snap: FecObsSnapshot,
    last_redundancy_ppm: u32,
}

#[derive(Clone, Copy, Debug)]
struct FecObserverAmbientInputs {
    profile: FecObserverProfilePolicy,
    base_stream_interval: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct FecObserverPlatformHints {
    mobile_os: bool,
    containerized_server: bool,
}

impl FecObserverPlatformHints {
    fn detect() -> Self {
        let mobile_os = cfg!(any(target_os = "ios", target_os = "android"));

        #[cfg(target_os = "linux")]
        let containerized_server = std::path::Path::new("/run/.containerenv").exists();

        #[cfg(not(target_os = "linux"))]
        let containerized_server = false;

        Self { mobile_os, containerized_server }
    }
}

#[derive(Clone, Copy, Debug)]
enum FecObserverProfilePolicy {
    Explicit(TransportProfile),
    Ambient(TransportProfile),
}

impl FecObserverProfilePolicy {
    fn from_sources(
        profile_override: Option<&str>,
        platform_hints: FecObserverPlatformHints,
    ) -> Self {
        if let Some(profile) = profile_override {
            return Self::Explicit(match profile {
                "mobile" => TransportProfile::Mobile,
                "server" => TransportProfile::Server,
                _ => TransportProfile::Desktop,
            });
        }

        if platform_hints.mobile_os {
            return Self::Ambient(TransportProfile::Mobile);
        }
        if platform_hints.containerized_server {
            return Self::Ambient(TransportProfile::Server);
        }

        Self::Ambient(TransportProfile::Desktop)
    }

    fn detect() -> Self {
        let platform_hints = FecObserverPlatformHints::detect();
        match std::env::var("QUICFUSCATE_PROFILE") {
            Ok(profile) => Self::from_sources(Some(profile.as_str()), platform_hints),
            Err(_) => Self::from_sources(None, platform_hints),
        }
    }

    fn profile(self) -> TransportProfile {
        match self {
            Self::Explicit(profile) | Self::Ambient(profile) => profile,
        }
    }
}

impl FecObserverAmbientInputs {
    fn new(profile: FecObserverProfilePolicy, base_stream_interval: u32) -> Self {
        Self { profile, base_stream_interval }
    }

    fn from_runtime_policy(
        runtime_policy: &FecRuntimePolicy,
        profile: FecObserverProfilePolicy,
    ) -> Self {
        let base_stream_interval = runtime_policy
            .stream_every_override
            .map(|value| value as u32)
            .unwrap_or(8)
            .clamp(1, 32);

        Self::new(profile, base_stream_interval)
    }

    fn detect() -> Self {
        let runtime_policy = FecRuntimePolicy::detect();
        Self::from_runtime_policy(&runtime_policy, FecObserverProfilePolicy::detect())
    }
}

pub(crate) struct FecTransportObserver {
    state: RwLock<FecObsState>,
    ambient: FecObserverAmbientInputs,
    brain_hints: OnceLock<Arc<BrainFecHints>>,
}

impl FecTransportObserver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(FecObsState::default()),
            ambient: FecObserverAmbientInputs::detect(),
            brain_hints: OnceLock::new(),
        })
    }

    /// Attach the Brain hints belonging to this connection.
    pub(crate) fn attach_brain_hints(&self, hints: Arc<BrainFecHints>) {
        let _ = self.brain_hints.set(hints);
    }

    /// FEC streaming interval based on current network conditions.
    pub(crate) fn compute_streaming_interval(&self) -> u32 {
        let state = self.state.read();
        let s = &state.snap;

        // Base interval in packets.
        let mut interval = self.ambient.base_stream_interval;

        // Adaptive adjustment based on ECN and ACK delay.
        let total_ecn = s.ecn_ect0.saturating_add(s.ecn_ect1).saturating_add(s.ecn_ce);
        let ce_ratio = if total_ecn == 0 { 0.0 } else { (s.ecn_ce as f64) / (total_ecn as f64) };

        // Under high congestion signal: more aggressive streaming.
        if ce_ratio > 0.1 {
            interval = interval.saturating_sub(4u32).max(1u32); // minimum: 1 packet
        } else if ce_ratio > 0.05 {
            interval = interval.saturating_sub(2u32).max(2u32);
        } else if ce_ratio < 0.001 && s.ack_delay_ewma_us < 1000.0 {
            // Very clean path: less FEC.
            interval = interval.saturating_add(4u32).min(32u32);
        }

        let brain_hint = self
            .brain_hints
            .get()
            .map(|hints| hints.interval_pkts())
            .unwrap_or(0) as u32;
        if (1..=32).contains(&brain_hint) {
            interval = (((interval as u64 * 3) + (brain_hint as u64 * 2)) / 5).clamp(1, 32) as u32;
        }

        interval
    }

    /// Sync FEC-owned runtime hints into transport control deltas.
    ///
    /// This intentionally excludes generic transport actuators such as ACK threshold
    /// and external pacing. Those knobs are owned by the adaptive stealth/transport
    /// layer, while FEC keeps ownership of FEC-specific cadence and redundancy.
    pub(crate) fn sync_runtime_hints(&self, conn: &mut crate::transport::Connection) {
        // Retain the explicit observer profile snapshot as part of the observer audit
        // surface even though hint sync currently applies only FEC-owned deltas.
        let _profile = self.ambient.profile.profile();
        let mut state = self.state.write();

        let ppm_hint = self
            .brain_hints
            .get()
            .map(|hints| hints.redundancy_ppm())
            .unwrap_or(0);
        let pending_ppm = if ppm_hint > 0 && ppm_hint != state.last_redundancy_ppm {
            state.last_redundancy_ppm = ppm_hint;
            Some(ppm_hint)
        } else {
            None
        };
        drop(state);

        if let Some(ppm) = pending_ppm {
            conn.set_fec_redundancy_ppm(ppm);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportProfile {
    Mobile,  // Battery-optimized, higher latency tolerance
    Desktop, // Balanced performance
    Server,  // Maximum throughput, aggressive timing
}

impl TransportObserver for FecTransportObserver {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        // Update EWMA of ack delay (us). ack_delay is in quic units: actual_us = ack_delay << exponent
        // Transport already stored the exponent-applied value for telemetry; here we use an EWMA based on ack_delay.
        let mut st = self.state.write();
        let s = &mut st.snap;
        let alpha = 0.2f64;
        let sample = ack_delay as f64;
        s.ack_delay_ewma_us = if s.ack_events == 0 {
            sample
        } else {
            alpha * sample + (1.0 - alpha) * s.ack_delay_ewma_us
        };
        s.ack_events = s.ack_events.saturating_add(1);
        // After an ACK, transport resets the ECN counting cycle; keep counters flowing via on_ecn_update.
        // Optional: snapshotting/sliding-window logic could be implemented here.
    }

    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {
        // Hook reserved for future receive-side delivery-rate sampling.
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        // Track the current ECN counters since last ACK (transport resets after ACK emission)
        let mut st = self.state.write();
        st.snap.ecn_ect0 = ect0;
        st.snap.ecn_ect1 = ect1;
        st.snap.ecn_ce = ce;
    }
}

/// Thin public wrapper exposing the GF(2^8) streaming decoder for transport integration.
#[cfg(any(test, feature = "rust-tests"))]
pub struct FecDecoder8(Decoder8);

#[cfg(any(test, feature = "rust-tests"))]
impl FecDecoder8 {
    /// Create a new GF(2^8) decoder with the given source block size.
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self(Decoder8::new(k, pool))
    }
    /// Feed a received FEC packet (source or repair) into the decoder.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Drain all recovered packets from the decoder output queue.
    pub fn poll_recovered(&mut self) -> VecDeque<FecPacket> {
        self.0.get_partial_result()
    }
}

/// GF(2^16) multiply-accumulate over u16 slices: dst[i] ^= coeff * src[i]
#[inline(always)]
fn gf16_mul_slice(coeff: u16, src: &[u16], dst: &mut [u16]) {
    use crate::optimize;
    let len = core::cmp::min(src.len(), dst.len());
    optimize::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<optimize::Avx512Vbmi2>() && len >= GF16_VBMI2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_vbmi2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx512>() && len >= GF16_AVX512_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx512(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx2>() && len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Sse2>() && len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sse2(coeff, src, dst, len);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<optimize::Sve2>() && len >= GF16_SVE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sve2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Neon>() && len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_neon(coeff, src, dst, len);
                }
            }
        }
        // Scalar fallback with aggressive unrolling
        let mut i = 0;
        while i + 8 <= len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            dst[i + 1] ^= gf_tables::gf16_mul(coeff, src[i + 1]);
            dst[i + 2] ^= gf_tables::gf16_mul(coeff, src[i + 2]);
            dst[i + 3] ^= gf_tables::gf16_mul(coeff, src[i + 3]);
            dst[i + 4] ^= gf_tables::gf16_mul(coeff, src[i + 4]);
            dst[i + 5] ^= gf_tables::gf16_mul(coeff, src[i + 5]);
            dst[i + 6] ^= gf_tables::gf16_mul(coeff, src[i + 6]);
            dst[i + 7] ^= gf_tables::gf16_mul(coeff, src[i + 7]);
            i += 8;
        }
        while i < len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            i += 1;
        }
    });
}

/// GF(2^16) multiply-accumulate self-check entry point for SIMD verification.
#[cfg(feature = "simd-selfcheck")]
#[cfg(any(test, feature = "rust-tests"))]
pub fn gf16_mul_slice_selfcheck(coeff: u16, src: &[u16], dst: &mut [u16]) {
    gf16_mul_slice(coeff, src, dst);
}

// Transport imports removed - not needed for FEC module

// Loss estimation (EMA + Burst window + optional Kalman smoothing)
pub(crate) struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,
    burst_window: VecDeque<bool>,
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
    total_seen: u64,
    total_lost: u64,
    // Change-point detection & auto-tuning
    auto_tune: bool,
    mean: f32,
    m2: f32,
    count: u64,
    cusum_pos: f32,
    cusum_neg: f32,
    cusum_thresh: f32,
    stable_ctr: u32,
    base_lambda: f32,
    clean_streak: u32,
}

impl LossEstimator {
    /// Create with sensible defaults (lambda=0.2, burst_capacity=128, no Kalman)
    pub fn new() -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda: 0.2,
            burst_window: VecDeque::with_capacity(128),
            burst_capacity: 128,
            kalman: None,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: 0.2,
            clean_streak: 0,
        }
    }

    fn from_config(config: &FecConfig, ambient: &FecAmbientInputs) -> Self {
        let kalman = if config.kalman_enabled {
            Some(KalmanFilter::new(
                ambient.kalman_q_override.unwrap_or(config.kalman_q),
                ambient.kalman_r_override.unwrap_or(config.kalman_r),
            ))
        } else {
            None
        };

        Self {
            ema_loss_rate: 0.0,
            lambda: config.lambda,
            burst_window: VecDeque::with_capacity(config.burst_window),
            burst_capacity: config.burst_window,
            kalman,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: config.lambda,
            clean_streak: 0,
        }
    }
}

impl Default for LossEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl LossEstimator {
    /// Report aggregate observation (lost of total) to update smoothing state
    pub fn report(&mut self, lost: usize, total: usize) {
        if total == 0 {
            return;
        }
        let loss_now = lost.min(total) as f32 / total as f32;
        self.report_rate(loss_now, total, lost.min(total));
        self.report_actual_observation(total.saturating_sub(lost.min(total)), lost.min(total));
    }

    fn report_actual_observation(&mut self, acknowledged: usize, lost: usize) {
        // After 32 consecutive loss-free acknowledged packets the burst window is
        // stale history from a previous loss regime. Flush it so recent_loss_rate()
        // stops anchoring smoothed_loss() above the de-escalation threshold.
        // Only actual ACK/loss classifications drive this streak - sends are not
        // delivery evidence, and the CC smoothed-loss model decays asymptotically.
        if lost > 0 {
            self.clean_streak = 0;
        } else if acknowledged > 0 {
            self.clean_streak =
                self.clean_streak.saturating_add(acknowledged.min(u32::MAX as usize) as u32);
            if self.clean_streak >= 32 {
                self.burst_window.clear();
            }
        }
    }

    fn clean_link_confirmed(&self) -> bool {
        self.clean_streak >= 32
    }

    /// Report a pre-smoothed transport loss signal with its real observation weight.
    fn report_smoothed_rate(&mut self, loss_rate: f32, observation_weight: usize) {
        if observation_weight == 0 {
            return;
        }
        let loss_rate = loss_rate.clamp(0.0, 1.0);
        let estimated_lost = (loss_rate * observation_weight as f32).round() as usize;
        self.report_rate(loss_rate, observation_weight, estimated_lost);
    }

    fn report_rate(&mut self, mut loss_now: f32, total: usize, lost: usize) {
        if let Some(kf) = self.kalman.as_mut() {
            // Lightweight Kalman usage: treat measurement as scalar
            // (KalmanFilter provides update(measurement) -> smoothed)
            loss_now = kf.update(loss_now);
        }
        // Online statistics (Welford) for variance estimation
        self.count += 1;
        let delta = loss_now - self.mean;
        self.mean += delta / (self.count as f32);
        let delta2 = loss_now - self.mean;
        self.m2 += delta * delta2;
        let var = if self.count > 1 { self.m2 / ((self.count - 1) as f32) } else { 0.0 };
        // CUSUM change-point detection (two-sided)
        let k_cusum = (var.sqrt() * 0.5).clamp(0.005, 0.1); // slack parameter
        self.cusum_pos = (self.cusum_pos + (loss_now - self.mean) - k_cusum).max(0.0);
        self.cusum_neg = (self.cusum_neg - (loss_now - self.mean) - k_cusum).max(0.0);
        let change_detected =
            self.cusum_pos > self.cusum_thresh || self.cusum_neg > self.cusum_thresh;
        if self.auto_tune {
            if change_detected {
                // react faster; increase process noise
                self.lambda = 0.85f32.max(self.lambda);
                if let Some(kf) = self.kalman.as_mut() {
                    kf.q = (kf.q * 1.5).clamp(1e-6, 0.25);
                }
                self.cusum_pos = 0.0;
                self.cusum_neg = 0.0;
                self.stable_ctr = 0;
                // Re-anchor Welford statistics to the current regime so the
                // running mean does not stay pinned to the previous loss level
                // and immediately re-trigger false change-points.
                self.mean = loss_now;
                self.m2 = 0.0;
                self.count = 1;
            } else {
                self.stable_ctr = self.stable_ctr.saturating_add(1);
                if self.stable_ctr > 128 {
                    // calm down smoothing to reduce jitter
                    self.lambda = (self.lambda * 0.9 + self.base_lambda * 0.1).clamp(0.05, 0.85);
                    if let Some(kf) = self.kalman.as_mut() {
                        kf.q = (kf.q * 0.9).clamp(1e-8, 0.1);
                    }
                    self.stable_ctr = 0;
                }
            }
        }
        self.ema_loss_rate = self.lambda * loss_now + (1.0 - self.lambda) * self.ema_loss_rate;
        self.total_seen = self.total_seen.saturating_add(total as u64);
        self.total_lost = self.total_lost.saturating_add(lost as u64);
        // Update burst window using a bounded aggregate projection rather than raw packet counts.
        // Aggregate observations like 120/1000 must not saturate the whole burst window with
        // loss-only entries just because the sample was large.
        let sample_slots = total.min(self.burst_capacity).max(1);
        let projected_loss_slots =
            ((sample_slots as f32) * loss_now).round().clamp(0.0, sample_slots as f32) as usize;
        for i in 0..sample_slots {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(i < projected_loss_slots);
        }
    }

    /// Return smoothed point estimate; conservative: max(EMA, recent-burst-rate).
    /// After 32 consecutive clean actual observations the link is proven clean -
    /// return zero regardless of the CC model's asymptotic decay residue.
    pub fn smoothed_loss(&self) -> f32 {
        if self.clean_link_confirmed() {
            return 0.0;
        }
        self.ema_loss_rate.max(self.recent_loss_rate())
    }

    fn recent_loss_rate(&self) -> f32 {
        if self.burst_window.is_empty() {
            0.0
        } else {
            let l = self.burst_window.iter().filter(|&&b| b).count();
            l as f32 / self.burst_window.len() as f32
        }
    }

    fn fountain_ready(&self) -> bool {
        self.total_seen >= FOUNTAIN_MIN_RECENT_OBSERVATIONS
            && self.ema_loss_rate >= FOUNTAIN_LOSS_THRESHOLD
            && self.recent_loss_rate() >= FOUNTAIN_LOSS_THRESHOLD
    }

    /// Returns true if a significant change/burst was detected recently.
    pub fn disturbance_detected(&self) -> bool {
        if self.clean_link_confirmed() {
            return false;
        }
        self.cusum_pos > self.cusum_thresh
            || self.cusum_neg > self.cusum_thresh
            || self.stable_ctr == 0
    }

    /// Returns a normalized burst variance estimate [0.0, 1.0].
    /// High values indicate bursty loss patterns (clustered losses),
    /// low values indicate uniform/random loss.
    /// Computed as the variance of run lengths between loss events in the burst window.
    pub fn burst_variance(&self) -> f32 {
        if self.burst_window.len() < 8 {
            return 0.0;
        }
        // Compute run-length variance: lengths of consecutive non-loss runs
        let mut runs: Vec<u32> = Vec::new();
        let mut current_run = 0u32;
        for &lost in &self.burst_window {
            if lost {
                if current_run > 0 {
                    runs.push(current_run);
                }
                current_run = 0;
            } else {
                current_run += 1;
            }
        }
        if runs.is_empty() {
            return 0.0;
        }
        let n = runs.len() as f32;
        let mean = runs.iter().map(|&r| r as f32).sum::<f32>() / n;
        let variance = runs.iter().map(|&r| (r as f32 - mean).powi(2)).sum::<f32>() / n;
        // Normalize: variance / (mean^2 + 1) gives a coefficient-of-variation-like metric
        (variance / (mean * mean + 1.0)).min(1.0)
    }
}

// Kalman Filter with configurable process/measurement noise
#[derive(Debug)]
pub(crate) struct KalmanFilter {
    q: f32, // Process noise covariance
    r: f32, // Measurement noise covariance
    x: f32, // state estimate
    p: f32, // estimate covariance
}

impl KalmanFilter {
    pub(crate) fn new(q: f32, r: f32) -> Self {
        Self { q, r, x: 0.0, p: 1.0 }
    }

    /// One-dimensional Kalman update: returns the smoothed estimate
    pub(crate) fn update(&mut self, z: f32) -> f32 {
        // Predict
        self.p += self.q;
        // Update
        let k = self.p / (self.p + self.r);
        self.x = self.x + k * (z - self.x);
        self.p *= 1.0 - k;
        self.x
    }
}

/// Unified FEC packet carrying source or repair data with pool-managed buffers.
pub struct FecPacket {
    /// Unique packet identifier (source ID or repair window anchor).
    pub id: u64,
    /// Aligned payload buffer, recycled to the memory pool when the last handle drops.
    pub(crate) data: Option<SharedFecBuffer>,
    /// Actual byte count of valid payload within `data`.
    pub data_len: usize,
    /// True for original source packets, false for repair/coded packets.
    pub is_systematic: bool,
    /// GF coefficient vector for repair packets (None for source packets).
    pub coefficients: Option<AlignedBox<[u8]>>,
    /// Number of valid bytes in the coefficients buffer.
    pub coeff_len: usize,
    /// Shared memory pool for buffer allocation and recycling.
    pub mem_pool: Arc<MemoryPool>,
    /// Transport-level sequence number for ordering and gap detection.
    pub seq: u64,
    /// Creation timestamp for latency tracking.
    pub timestamp: std::time::Instant,
}

impl Drop for FecPacket {
    fn drop(&mut self) {
        // Payload buffers recycle when the last SharedFecBuffer handle drops.
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}

impl FecPacket {
    /// Construct a new FEC packet, upsizing buffers if declared lengths exceed capacity.
    pub fn new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        // Ensure provided buffers can accommodate declared lengths and keep pool accounting correct.
        let data = match data {
            Some(d) => {
                if data_len > d.len() {
                    match AlignedBox::<[u8]>::slice_from_default(data_len, 64) {
                        Ok(mut bigger) => {
                            let copy = d.len();
                            bigger[..copy].copy_from_slice(&d[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(d);
                            Some(bigger)
                        }
                        Err(_) => {
                            log::warn!("FEC: data buffer upsizing failed, returning original");
                            mem_pool.free(d);
                            None
                        }
                    }
                } else {
                    Some(d)
                }
            }
            None => None,
        };

        let coefficients = match coefficients {
            Some(c) => {
                if coeff_len > c.len() {
                    match AlignedBox::<[u8]>::slice_from_default(coeff_len, 64) {
                        Ok(mut bigger) => {
                            let copy = c.len();
                            bigger[..copy].copy_from_slice(&c[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(c);
                            Some(bigger)
                        }
                        Err(_) => {
                            log::warn!(
                                "FEC: coefficient buffer upsizing failed, returning original"
                            );
                            mem_pool.free(c);
                            None
                        }
                    }
                } else {
                    Some(c)
                }
            }
            None => None,
        };

        let data = data.map(|buf| SharedFecBuffer::new(buf, Arc::clone(&mem_pool)));

        Self {
            id,
            data,
            data_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
            seq: id, // Default: seq = id
            timestamp: std::time::Instant::now(),
        }
    }

    /// Payload bytes for this packet (up to `data_len`).
    #[inline]
    pub fn payload_slice(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|shared| shared.bytes(self.data_len))
    }

    /// Mutable payload view when this packet is the sole owner of the shared buffer.
    #[inline]
    pub(crate) fn payload_mut_unique(&mut self) -> Option<&mut [u8]> {
        let shared = self.data.as_mut()?;
        let inner = Arc::get_mut(&mut shared.inner)?;
        let buf = inner.buf.as_mut()?;
        let end = self.data_len.min(buf.len());
        Some(&mut buf[..end])
    }

    /// Create a systematic FEC packet from a raw byte block, copying into a pool buffer.
    pub fn from_block(id: u64, block: &[u8], mem_pool: Arc<MemoryPool>) -> Self {
        let mut dst = mem_pool.alloc();
        let n = block.len().min(dst.len());
        dst[..n].copy_from_slice(&block[..n]);
        Self::new(id, Some(dst), n, true, None, 0, mem_pool)
    }

    /// Copy only the payload into `buf` (no headers). This is NOT the
    /// Legacy streaming format retained for compatibility tests. Production
    /// transport framing uses [`wire::write_packet`].
    pub fn to_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        if let Some(data) = self.payload_slice() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Err("No data available".to_string())
        }
    }

    /// Serialize a streaming-friendly raw format for transport DATAGRAM:
    /// [magic:2=0xF1EC][is_systematic:1][base_id:8][seq:8][coeff_len:2][coeffs (coeff_len bytes)][payload]
    pub fn to_stream_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut off = 0usize;
        if buf.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        // Magic for safe demultiplexing of FEC datagrams
        buf[0] = 0xF1;
        buf[1] = 0xEC;
        off += 2;
        buf[off] = if self.is_systematic { 1 } else { 0 };
        off += 1;
        // base_id conveys the equation window anchor (id of the last source in window at sender)
        buf[off..off + 8].copy_from_slice(&self.id.to_be_bytes());
        off += 8;
        // seq conveys the transport sequence (used by InterleavedDecoder for block routing)
        buf[off..off + 8].copy_from_slice(&self.seq.to_be_bytes());
        off += 8;
        let coeff_len: u16 = self.coeff_len as u16;
        if buf.len() < off + 2 {
            return Err("BufferTooShort".into());
        }
        buf[off..off + 2].copy_from_slice(&coeff_len.to_be_bytes());
        off += 2;
        if let Some(ref coeffs) = self.coefficients {
            if buf.len() < off + self.coeff_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + self.coeff_len].copy_from_slice(&coeffs[..self.coeff_len]);
            off += self.coeff_len;
        } else if self.coeff_len > 0 {
            return Err("coeff_len>0 but no coefficients present".into());
        }
        if let Some(data) = self.payload_slice() {
            let n = data.len().min(buf.len().saturating_sub(off));
            if n < self.data_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + n].copy_from_slice(&data[..n]);
            off += n;
            Ok(off)
        } else {
            Err("No data available".into())
        }
    }

    /// Parse streaming-friendly raw format from transport DATAGRAM.
    /// Returns a FecPacket owning aligned buffers allocated from the pool.
    pub fn from_stream_raw(input: &[u8], pool: Arc<MemoryPool>) -> Result<Self, String> {
        if input.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        if input[0] != 0xF1 || input[1] != 0xEC {
            return Err("BadMagic".into());
        }
        let mut off = 2usize;
        let is_systematic = input[off] != 0;
        off += 1;
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&input[off..off + 8]);
        let base_id = u64::from_be_bytes(id_bytes);
        off += 8;
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&input[off..off + 8]);
        let seq = u64::from_be_bytes(seq_bytes);
        off += 8;
        let mut cl_bytes = [0u8; 2];
        cl_bytes.copy_from_slice(&input[off..off + 2]);
        off += 2;
        let coeff_len = u16::from_be_bytes(cl_bytes) as usize;
        if input.len() < off + coeff_len {
            return Err("BufferTooShort".into());
        }
        let coeffs = if coeff_len > 0 {
            let mut cbuf = pool.alloc();
            if cbuf.len() < coeff_len {
                return Err("CoeffBufferTooSmall".into());
            }
            cbuf[..coeff_len].copy_from_slice(&input[off..off + coeff_len]);
            off += coeff_len;
            Some(cbuf)
        } else {
            None
        };
        let payload_len = input.len().saturating_sub(off);
        let mut dbuf = pool.alloc();
        if dbuf.len() < payload_len {
            return Err("DataBufferTooSmall".into());
        }
        dbuf[..payload_len].copy_from_slice(&input[off..]);
        let mut pkt =
            Self::new(base_id, Some(dbuf), payload_len, is_systematic, coeffs, coeff_len, pool);
        pkt.seq = seq;
        Ok(pkt)
    }

    /// Returns the payload length in bytes.
    pub fn len(&self) -> usize {
        self.data_len
    }
    /// Returns true if the packet carries no payload data.
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }
}

impl Clone for FecPacket {
    fn clone(&self) -> Self {
        let data_clone = self.data.clone();

        let coeffs_clone = if let Some(ref coeffs) = self.coefficients {
            let mut buf = self.mem_pool.alloc();
            let m = self.coeff_len.min(buf.len());
            buf[..m].copy_from_slice(&coeffs[..m]);
            Some(buf)
        } else {
            None
        };

        Self {
            id: self.id,
            data: data_clone,
            data_len: self.data_len,
            is_systematic: self.is_systematic,
            coefficients: coeffs_clone,
            coeff_len: self.coeff_len,
            mem_pool: Arc::clone(&self.mem_pool),
            seq: self.seq,
            timestamp: self.timestamp,
        }
    }
}

/// Forward error correction operating mode controlling redundancy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
#[repr(u8)]
pub enum FecMode {
    /// No FEC - zero overhead passthrough for loss-free links.
    Zero,
    /// Minimal redundancy for excellent conditions (<2% loss).
    Light,
    /// Standard block-code protection for moderate loss (2-10%).
    Normal,
    /// Increased redundancy for fair conditions.
    Medium,
    /// High redundancy for poor conditions (10-25% loss).
    Strong,
    /// Very high redundancy for severe loss (25-50%).
    Extreme,
    /// Maximum redundancy for extreme conditions.
    Ultra,
    /// Rateless LT fountain codes for >50% loss.
    Fountain,
    /// Continuous streaming repair emission for low-latency recovery.
    Streaming,
}

impl FecMode {
    /// Stable public codec-mode order used by telemetry and runtime evidence.
    pub const ALL: [Self; 9] = [
        Self::Zero,
        Self::Light,
        Self::Normal,
        Self::Medium,
        Self::Strong,
        Self::Extreme,
        Self::Ultra,
        Self::Fountain,
        Self::Streaming,
    ];

    /// Stable public numeric telemetry ID.
    pub const fn telemetry_id(self) -> u8 {
        self as u8
    }

    /// Stable public telemetry label.
    pub const fn telemetry_name(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Light => "light",
            Self::Normal => "normal",
            Self::Medium => "medium",
            Self::Strong => "strong",
            Self::Extreme => "extreme",
            Self::Ultra => "ultra",
            Self::Fountain => "fountain",
            Self::Streaming => "streaming",
        }
    }
}

/// Operator-owned FEC control policy, independent from the active codec mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FecControlPolicy {
    /// Keep the connection in raw Zero mode for its full lifetime.
    Off,
    /// Allow the adaptive controller to select the cheapest sufficient codec.
    #[default]
    Auto,
}

// Galois field marker types
/// GF(2^4) - For low loss (<5%), 4x less computation than GF(2^8)
struct GF4;
/// GF(2^8) - Standard field for moderate loss
struct GF8;
/// GF(2^16) - For high loss scenarios, larger symbol space
struct GF16;

// Core FEC encoder/decoder types
struct Encoder<F> {
    k: usize,
    window: VecDeque<FecPacket>,
    _field: std::marker::PhantomData<F>,
}

impl<F> Encoder<F> {
    /// Create a new encoder with source block size `k` and sliding window capacity.
    pub fn new(k: usize, _n: usize) -> Self {
        Self { k, window: VecDeque::with_capacity(k), _field: std::marker::PhantomData }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if self.window.len() < self.k {
            self.window.push_back(p);
        } else {
            // Sliding window: drop oldest, push newest (used by Streaming mode)
            let _ = self.window.pop_front();
            self.window.push_back(p);
        }
    }

    fn clear_window(&mut self) {
        self.window.clear();
    }

    fn packets_in_window(&self) -> usize {
        self.window.len()
    }
}

struct Encoder16 {
    inner: Encoder<GF16>,
    coeff_rows: Vec<u8>,
    coeff_stride: usize,
}

/// Public wrapper for GF(2^8) encoder used by transport integration.
#[cfg(any(test, feature = "rust-tests"))]
pub struct Encoder8(Encoder<GF8>);

#[cfg(any(test, feature = "rust-tests"))]
impl Encoder8 {
    /// Create a new GF(2^8) encoder with source block size `k` and total codeword size `n`.
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF8>::new(k, n))
    }
    /// Feed a source packet into the encoding window.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Generate the `idx`-th repair packet from the current encoding window.
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF8>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF8> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        // Determine max payload length among window packets
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        for b in &mut out[..max_len] {
            *b = 0;
        }

        // Coefficients (GF(2^8)), length = k
        let mut coeff_box = pool.alloc();
        if coeff_box.len() < self.k {
            return None;
        }
        let block_source_count = u16::try_from(self.k).ok()?;
        let repair_index = u16::try_from(idx).ok()?;
        wire::WireCodec::Gf8
            .write_repair_coefficients(block_source_count, repair_index, &mut coeff_box)
            .ok()?;
        let wlen = self.window.len().min(self.k);

        // Apply coefficients to data using optimized matrix helper
        // row is 1xK (one repair packet depends on K source packets)
        // We can just iterate and accumulate.
        // matrix_multiply_scalar expects matrix arguments, but here we generate one row.

        // Manual row accumulation
        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];
                // Accumulate: out[i] ^= c * data[i]
                gf_tables::gf_mul_scalar_slice(c, &data[..len], &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

/// Internal GF(2^4) encoder for low-loss adaptive runtime paths.
pub(crate) struct Encoder4(Encoder<GF4>);

impl Encoder4 {
    pub(crate) fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF4>::new(k, n))
    }
    pub(crate) fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub(crate) fn clear_window(&mut self) {
        self.0.clear_window()
    }
    pub(crate) fn packets_in_window(&self) -> usize {
        self.0.packets_in_window()
    }
    pub(crate) fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF4>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF4> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        out[..max_len].fill(0);

        // Coefficients (GF(2^4))
        // We store them as u8 (1..15)
        let mut coeff_box = pool.alloc();
        let block_source_count = u16::try_from(self.k).ok()?;
        let repair_index = u16::try_from(idx).ok()?;
        wire::WireCodec::Gf4
            .write_repair_coefficients(block_source_count, repair_index, &mut coeff_box)
            .ok()?;
        let wlen = self.window.len().min(self.k);

        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];
                crate::simd::galois::gf4_mul_xor(&data[..len], c, &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

impl Encoder16 {
    fn new(k: usize, n: usize) -> Self {
        let mut encoder =
            Self { inner: Encoder::<GF16>::new(k, n), coeff_rows: Vec::new(), coeff_stride: 0 };
        encoder.prepare_coeff_rows(n.saturating_sub(k));
        encoder
    }

    #[inline]
    fn take_packet(&mut self, p: FecPacket) {
        self.inner.take_packet(p);
    }

    #[inline]
    fn clear_window(&mut self) {
        self.inner.clear_window();
    }

    #[inline]
    fn packets_in_window(&self) -> usize {
        self.inner.packets_in_window()
    }

    fn prepare_coeff_rows(&mut self, repair_rows: usize) {
        let stride = 2 * self.inner.k;
        self.coeff_stride = stride;
        let Ok(block_source_count) = u16::try_from(self.inner.k) else {
            self.coeff_rows.clear();
            return;
        };
        if stride == 0 || repair_rows == 0 || repair_rows > u16::MAX as usize {
            self.coeff_rows.clear();
            return;
        }
        self.coeff_rows.resize(repair_rows * stride, 0);
        for idx in 0..repair_rows {
            let row = &mut self.coeff_rows[idx * stride..(idx + 1) * stride];
            let result = wire::WireCodec::Gf16.write_repair_coefficients(
                block_source_count,
                idx as u16,
                row,
            );
            debug_assert_eq!(result, Ok(stride));
        }
    }

    fn ensure_coeff_row(&mut self, idx: usize) -> bool {
        if self.coeff_stride != 2 * self.inner.k {
            self.prepare_coeff_rows(idx.saturating_add(1));
            return self.coeff_rows.len()
                >= idx.saturating_add(1).saturating_mul(self.coeff_stride);
        }
        let rows = self.coeff_rows.len().checked_div(self.coeff_stride).unwrap_or(0);
        if rows <= idx {
            let old_len = self.coeff_rows.len();
            self.coeff_rows.resize((idx + 1) * self.coeff_stride, 0);
            let Ok(block_source_count) = u16::try_from(self.inner.k) else {
                self.coeff_rows.clear();
                return false;
            };
            for row_idx in rows..=idx {
                let Ok(repair_index) = u16::try_from(row_idx) else {
                    self.coeff_rows.clear();
                    return false;
                };
                let start = row_idx * self.coeff_stride;
                let row = &mut self.coeff_rows[start..start + self.coeff_stride];
                let result = wire::WireCodec::Gf16.write_repair_coefficients(
                    block_source_count,
                    repair_index,
                    row,
                );
                debug_assert_eq!(result, Ok(self.coeff_stride));
            }
            debug_assert_eq!(old_len % self.coeff_stride, 0);
        }
        true
    }

    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.inner.window.len() < self.inner.k || self.inner.k == 0 {
            return None;
        }
        let max_len = self.inner.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        // Pad the final GF16 word instead of truncating an odd source byte.
        // The protected source-length prefix removes this zero padding after recovery.
        let max_len_even = max_len.saturating_add(max_len % 2);
        if max_len_even == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len_even {
            return None;
        }
        for b in &mut out[..max_len_even] {
            *b = 0;
        }

        // Coefficients (GF(2^16)) stored as big-endian bytes, length = 2*k
        let mut coeff_box = pool.alloc();
        let coeff_bytes = 2 * self.inner.k;
        if coeff_box.len() < coeff_bytes {
            return None;
        }
        if !self.ensure_coeff_row(idx) {
            return None;
        }
        let row_start = idx * self.coeff_stride;
        coeff_box[..coeff_bytes]
            .copy_from_slice(&self.coeff_rows[row_start..row_start + coeff_bytes]);

        // Accumulate
        let wlen = self.inner.window.len().min(self.inner.k);
        if max_len_even >= (PAR_THRESHOLD * 4) && wlen >= 8 {
            let chunk = 16384usize; // bytes, will align down to even length
            let parts: Vec<(usize, Vec<u8>)> = (0..max_len_even.div_ceil(chunk))
                .into_par_iter()
                .map(|ci| {
                    let mut start = ci * chunk;
                    let mut end = (start + chunk).min(max_len_even);
                    // enforce even boundaries
                    if !start.is_multiple_of(2) {
                        start += 1;
                    }
                    if !end.is_multiple_of(2) {
                        end -= 1;
                    }
                    if end <= start {
                        return (start, Vec::new());
                    }
                    let mut acc = vec![0u8; end - start];
                    for (j, pkt) in self.inner.window.iter().enumerate().take(wlen) {
                        if let Some(data) = pkt.payload_slice() {
                            let s_len = data.len().min(max_len_even);
                            if start < s_len {
                                let len = (s_len - start).min(acc.len());
                                if len >= 2 {
                                    let c = u16::from_be_bytes([
                                        coeff_box[2 * j],
                                        coeff_box[2 * j + 1],
                                    ]);
                                    gf16_mul_scalar_slice_padded(
                                        c,
                                        &data[start..start + len],
                                        &mut acc[..],
                                    );
                                }
                            }
                        }
                    }
                    (start, acc)
                })
                .collect();
            for (start, acc) in parts.into_iter() {
                let len = acc.len();
                if len > 0 {
                    // Vectorized XOR combine
                    fast_xor_inplace(&acc[..], &mut out[start..start + len]);
                }
            }
        } else {
            for (j, pkt) in self.inner.window.iter().enumerate().take(self.inner.k) {
                if let Some(data) = pkt.payload_slice() {
                    let s_len = data.len().min(max_len_even);
                    if s_len < 2 {
                        continue;
                    }
                    let c = u16::from_be_bytes([coeff_box[2 * j], coeff_box[2 * j + 1]]);
                    gf16_mul_scalar_slice_padded(c, &data[..s_len], &mut out[..max_len_even]);
                }
            }
        }

        let id = self.inner.window.back().map(|p| p.id).unwrap_or(0);
        Some(FecPacket::new(
            id,
            Some(out),
            max_len_even,
            false,
            Some(coeff_box),
            coeff_bytes,
            Arc::clone(pool),
        ))
    }
}


// Forward declare types - will be defined in internal module below

/// Adaptive FEC controller with seamless mode transitions and burst-loss protection.
pub struct AdaptiveFec {
    /// Validated construction contract retained for rare active-policy changes.
    /// The packet path never reads or clones this value.
    config: FecConfig,
    // Using InterleavedEncoder for burst loss protection (default depth=4)
    encoder: Arc<Mutex<internal::InterleavedEncoder>>,
    // Using InterleavedDecoder (wraps LazyDecoder) for burst loss recovery
    decoder: Arc<Mutex<internal::InterleavedDecoder>>,
    active_mode: FecMode,
    mode_manager: Arc<Mutex<internal::ModeManager>>,
    mem_pool: Arc<MemoryPool>,
    pending_transition: Option<PendingFecTransition>,
    window_complete: bool,
    stream_every: usize,
    _stream_every_base: usize,
    stream_every_override: Option<usize>,
    stream_last_adjust: Instant,
    stream_ctr: usize,
    stream_idx: usize,
    streaming_mode: bool,
    partial_enabled: bool,
    runtime_policy: FecRuntimePolicy,
    decoder_policy_tunable: bool,
    wiedemann_threshold: usize,
    emitted_ids: std::collections::HashSet<u64>,
    emitted_order: VecDeque<u64>,
    loss_estimator: LossEstimator,
    control_policy: FecControlPolicy,
    force_on: bool,
    simd_enabled: bool,
    simd_level: SimdLevel,
    /// Reused queue for streaming repair emission to avoid per-packet allocations
    stream_repair_scratch: VecDeque<FecPacket>,
    red_ppm_hint: u32,
    /// Interleave depth (default 4 for burst protection)
    interleave_depth: usize,
    fountain_window: usize,
    extreme_window: usize,
    /// Current RTT estimate in milliseconds (0 = unknown/unset).
    /// Fed by transport via `set_rtt_hint()` and used to scale `stream_every`.
    rtt_ms: u32,
    /// Connection-local seed shared by the sender and receiver fountain paths.
    fountain_seed: u64,
    telemetry: FecTelemetrySnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SimdLevel {
    None,
    Sse2,
    Avx2,
    Avx512Vbmi2,
    Avx512Vbmi,
    Sve2,
    Neon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FecSwitchReason {
    Adaptive,
    ForceOnPolicy,
    ExtremeLossPolicy,
    DisturbancePolicy,
    StreamingHint,
}

impl FecSwitchReason {
    fn observe(self) {
        use std::sync::atomic::Ordering;
        match self {
            FecSwitchReason::Adaptive => {
                crate::telemetry::FEC_SWITCH_REASON_ADAPTIVE.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ForceOnPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_FORCE_ON.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ExtremeLossPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_EXTREME.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::DisturbancePolicy => {
                crate::telemetry::FEC_SWITCH_REASON_DISTURBANCE.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::StreamingHint => {
                crate::telemetry::FEC_SWITCH_REASON_STREAMING_HINT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingFecTransition {
    target: FecProtectionTarget,
    reason: FecSwitchReason,
}

/// Connection-local FEC evidence. Packet counters remain zero when runtime
/// telemetry collection was disabled before the connection was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecTelemetrySnapshot {
    /// Whether packet-level collection is enabled for this connection.
    pub enabled: bool,
    /// Operator-owned control policy.
    pub control_policy: FecControlPolicy,
    /// Currently committed codec mode.
    pub active_mode: FecMode,
    /// Effective source-packet window for the committed mode.
    pub effective_window: usize,
    /// Cumulative packets covered by loss-controller observations.
    pub observed_packets: u64,
    /// Cumulative lost packets covered by loss-controller observations.
    pub observed_lost_packets: u64,
    /// Committed codec transitions.
    pub mode_transitions: u64,
    /// Accepted operator-policy transitions.
    pub policy_transitions: u64,
    /// Source datagrams serialized into the network-facing output buffer.
    pub source_packets_sent: u64,
    /// Repair datagrams serialized into the network-facing output buffer.
    pub repair_packets_sent: u64,
    /// Original QUIC payload bytes represented by sent source datagrams.
    pub source_payload_bytes_sent: u64,
    /// Source wire bytes serialized for transmission.
    pub source_wire_bytes_sent: u64,
    /// Repair wire bytes serialized for transmission.
    pub repair_wire_bytes_sent: u64,
    /// Accepted source datagrams received.
    pub source_packets_received: u64,
    /// Accepted repair datagrams received.
    pub repair_packets_received: u64,
    /// Original QUIC payload bytes represented by received source datagrams.
    pub source_payload_bytes_received: u64,
    /// Accepted source wire bytes received.
    pub source_wire_bytes_received: u64,
    /// Accepted repair wire bytes received.
    pub repair_wire_bytes_received: u64,
    /// Source packets delivered to QUIC, originals plus recoveries.
    pub decoded_packets: u64,
    /// Source packets reconstructed from repair data.
    pub recovered_packets: u64,
    /// Original QUIC payload bytes reconstructed from repair data.
    pub recovered_payload_bytes: u64,
}

/// Atomic result of changing one live connection's operator-owned FEC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecPolicyChange {
    /// Policy effective before the command.
    pub previous_policy: FecControlPolicy,
    /// Codec mode effective before the command.
    pub previous_mode: FecMode,
    /// Policy effective when the command returned.
    pub effective_policy: FecControlPolicy,
    /// Codec mode effective when the command returned.
    pub effective_mode: FecMode,
}

impl FecTelemetrySnapshot {
    fn new(
        enabled: bool,
        control_policy: FecControlPolicy,
        active_mode: FecMode,
        effective_window: usize,
    ) -> Self {
        Self {
            enabled,
            control_policy,
            active_mode,
            effective_window,
            observed_packets: 0,
            observed_lost_packets: 0,
            mode_transitions: 0,
            policy_transitions: 0,
            source_packets_sent: 0,
            repair_packets_sent: 0,
            source_payload_bytes_sent: 0,
            source_wire_bytes_sent: 0,
            repair_wire_bytes_sent: 0,
            source_packets_received: 0,
            repair_packets_received: 0,
            source_payload_bytes_received: 0,
            source_wire_bytes_received: 0,
            repair_wire_bytes_received: 0,
            decoded_packets: 0,
            recovered_packets: 0,
            recovered_payload_bytes: 0,
        }
    }
}

struct FecAmbientInputs {
    mem_pool: Arc<MemoryPool>,
    compute_profile: FecComputeProfile,
    runtime_policy: FecRuntimePolicy,
    stream_every_override: Option<usize>,
    interleave_depth_override: Option<usize>,
    partial_enabled: bool,
    kalman_q_override: Option<f32>,
    kalman_r_override: Option<f32>,
}

#[derive(Clone, Copy, Debug)]
struct FecComputeProfile {
    cpu_profile: CpuProfile,
    has_neon: bool,
}

impl FecComputeProfile {
    fn new(cpu_profile: CpuProfile, has_neon: bool) -> Self {
        Self { cpu_profile, has_neon }
    }

    fn detect() -> Self {
        let detector = crate::optimize::FeatureDetector::instance();
        Self::new(detector.profile(), detector.has_feature(crate::optimize::CpuFeature::NEON))
    }

    fn cpu_profile(self) -> CpuProfile {
        self.cpu_profile
    }

    fn has_neon(self) -> bool {
        self.has_neon
    }
}

impl FecAmbientInputs {
    fn new(
        mem_pool: Arc<MemoryPool>,
        compute_profile: FecComputeProfile,
        runtime_policy: FecRuntimePolicy,
    ) -> Self {
        Self {
            mem_pool,
            compute_profile,
            stream_every_override: runtime_policy.stream_every_override,
            interleave_depth_override: runtime_policy.interleave_depth_override,
            partial_enabled: runtime_policy.partial_enabled,
            kalman_q_override: runtime_policy.kalman_q_override,
            kalman_r_override: runtime_policy.kalman_r_override,
            runtime_policy,
        }
    }

    #[cfg(test)]
    fn detect() -> Self {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::detect_with_snapshot(&environment)
    }

    fn detect_with_snapshot(environment: &crate::env_utils::EnvSnapshot) -> Self {
        Self::new(
            crate::optimize::global_pool(),
            FecComputeProfile::detect(),
            FecRuntimePolicy::detect_with_snapshot(environment),
        )
    }
}

struct FecRuntimePlan {
    mode: FecMode,
    control_policy: FecControlPolicy,
    force_on: bool,
    k: usize,
    n: usize,
    mem_pool: Arc<MemoryPool>,
    base_stream_every: usize,
    stream_every_override: Option<usize>,
    stream_every: usize,
    interleave_depth: usize,
    partial_enabled: bool,
    runtime_policy: FecRuntimePolicy,
    loss_estimator: LossEstimator,
    fountain_window: usize,
    extreme_window: usize,
}

impl FecRuntimePlan {
    fn resolve(config: &FecConfig, ambient: &FecAmbientInputs) -> Self {
        let control_policy = config.control_policy;
        let configured_initial_mode = if control_policy == FecControlPolicy::Off {
            FecMode::Zero
        } else {
            config.initial_mode
        };
        let mut initial_target = target_from_mode(
            configured_initial_mode,
            config.window_sizes.get(&configured_initial_mode).copied().unwrap_or(64),
        );
        if control_policy == FecControlPolicy::Auto
            && config.force_on
            && initial_target.family == FecBackendFamily::Zero
        {
            initial_target = target_from_mode(FecMode::Normal, 64);
        }
        let force_on = control_policy == FecControlPolicy::Auto && config.force_on;
        let (mode, requested_k, requested_n) = internal::ModeManager::params_for_target(
            initial_target,
            config.window_sizes.get(&configured_initial_mode).copied().unwrap_or(64),
            ambient.runtime_policy.auto_gf4_enabled,
        );
        let mem_pool = Arc::clone(&ambient.mem_pool);

        let base_stream_every = match ambient.compute_profile.cpu_profile() {
            crate::optimize::CpuProfile::X86_P3a
            | crate::optimize::CpuProfile::X86_P3b
            | crate::optimize::CpuProfile::X86_P3c
            | crate::optimize::CpuProfile::X86_P3d
            | crate::optimize::CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => 1,
            crate::optimize::CpuProfile::X86_P2a
            | crate::optimize::CpuProfile::X86_P2b
            | crate::optimize::CpuProfile::Apple_M => 2,
            crate::optimize::CpuProfile::X86_P1a
            | crate::optimize::CpuProfile::X86_P1b
            | crate::optimize::CpuProfile::X86_P1f => 3,
            crate::optimize::CpuProfile::ARM_A1a
            | crate::optimize::CpuProfile::ARM_A1b
            | crate::optimize::CpuProfile::ARM_A1c
            | crate::optimize::CpuProfile::ARM_A1d => {
                if ambient.compute_profile.has_neon() {
                    2
                } else {
                    4
                }
            }
            crate::optimize::CpuProfile::ARM_A2 => 1,
            _ => 2,
        };
        let stream_every_override =
            ambient.stream_every_override.or(config.configured_stream_every);
        let stream_every = stream_every_override.unwrap_or(base_stream_every).clamp(1, 32);
        let base_interleave_depth = if mode == FecMode::Fountain {
            1
        } else if requested_k > 16 {
            4
        } else {
            1
        };
        let requested_interleave_depth =
            ambient.interleave_depth_override.unwrap_or(base_interleave_depth).clamp(1, 8);
        let (k, n, interleave_depth) = wire_safe_encoder_params(
            mode,
            requested_k,
            requested_n,
            requested_interleave_depth,
            ambient.runtime_policy.interleave_enabled,
        );
        let partial_enabled = ambient.partial_enabled;
        let runtime_policy = ambient.runtime_policy.clone();
        let loss_estimator = LossEstimator::from_config(config, ambient);
        let fountain_window = ambient.runtime_policy.fountain_window;
        let extreme_window = ambient.runtime_policy.extreme_window;

        Self {
            mode,
            control_policy,
            force_on,
            k,
            n,
            mem_pool,
            base_stream_every,
            stream_every_override,
            stream_every,
            interleave_depth,
            partial_enabled,
            runtime_policy,
            loss_estimator,
            fountain_window,
            extreme_window,
        }
    }
}

impl AdaptiveFec {
    /// Create a new adaptive FEC instance from the given configuration.
    pub fn new(config: FecConfig) -> Self {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_snapshot(config, &environment)
    }

    pub(crate) fn new_with_snapshot(
        mut config: FecConfig,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Self {
        if let Err(error) = config.validate() {
            log::warn!("FecConfig validation failed: {error}; using product defaults");
            config = FecConfig::product_default();
        }
        let global_resources = FecGlobalResources::detect_with_snapshot(environment);
        global_resources.initialize();
        let ambient = FecAmbientInputs::detect_with_snapshot(environment);
        let plan = FecRuntimePlan::resolve(&config, &ambient);
        Self::from_runtime_plan(config, plan, environment)
    }

    fn from_runtime_plan(
        config: FecConfig,
        plan: FecRuntimePlan,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Self {
        let FecRuntimePlan {
            mode,
            control_policy,
            force_on,
            k,
            n,
            mem_pool,
            base_stream_every,
            stream_every_override,
            stream_every,
            interleave_depth,
            partial_enabled,
            runtime_policy,
            loss_estimator,
            fountain_window,
            extreme_window,
        } = plan;

        let telemetry_enabled =
            crate::telemetry::TELEMETRY_ENABLED.load(std::sync::atomic::Ordering::Relaxed);
        let decoder_policy_tunable = runtime_policy.decoder_policy.eq_ignore_ascii_case("auto");
        let wiedemann_threshold = environment
            .parse::<usize>("QUICFUSCATE_FEC_WIEDEMANN_K")
            .unwrap_or(256);
        let fec = Self {
            config: config.clone(),
            // InterleavedEncoder for burst loss protection
            encoder: Arc::new(Mutex::new(internal::InterleavedEncoder::new_with_policy(
                mode,
                k,
                n,
                interleave_depth,
                &runtime_policy,
            ))),
            // InterleavedDecoder for burst loss recovery (wraps LazyDecoder)
            decoder: Arc::new(Mutex::new(internal::InterleavedDecoder::new_with_policy(
                mode,
                k,
                Arc::clone(&mem_pool),
                interleave_depth,
                &runtime_policy,
            ))),
            active_mode: mode,
            mode_manager: Arc::new(Mutex::new(internal::ModeManager::with_runtime_policy(
                mode,
                config.hysteresis,
                &runtime_policy,
            ))),
            mem_pool,
            pending_transition: None,
            window_complete: false,
            stream_every,
            _stream_every_base: base_stream_every,
            stream_every_override,
            stream_last_adjust: crate::time_source::now_instant(),
            stream_ctr: 0,
            stream_idx: 0,
            streaming_mode: fec_backend_family(mode) == FecBackendFamily::Streaming,
            partial_enabled,
            runtime_policy,
            decoder_policy_tunable,
            wiedemann_threshold,
            emitted_ids: std::collections::HashSet::new(),
            emitted_order: VecDeque::new(),
            loss_estimator,
            control_policy,
            force_on,
            simd_enabled: false,
            simd_level: SimdLevel::None,
            stream_repair_scratch: VecDeque::with_capacity(16),
            red_ppm_hint: 0,
            interleave_depth,
            fountain_window,
            extreme_window,
            rtt_ms: 0,
            fountain_seed: DEFAULT_FOUNTAIN_SEED,
            telemetry: FecTelemetrySnapshot::new(telemetry_enabled, control_policy, mode, k),
        };
        if telemetry_enabled {
            crate::telemetry::fec_instance_opened(mode.telemetry_id(), k);
        }
        fec
    }

    /// **SEAMLESS** Process outgoing packet through FEC encoder with smooth mode transitions.
    ///
    /// Compatibility wrapper for callers that need an owned output vector. Hot-path callers
    /// should prefer [`AdaptiveFec::on_send_into`] and reuse their output allocation.
    pub fn on_send(&mut self, packet: FecPacket) -> Vec<FecPacket> {
        let mut output = Vec::with_capacity(1);
        self.on_send_into(packet, &mut output);
        output
    }

    /// Process an outgoing packet through the FEC encoder, writing emitted packets into
    /// `output` without allocating a fresh vector on every send.
    ///
    /// `output` is cleared first, but its allocation is retained. This keeps the core send
    /// path allocation-free for the common Zero/no-repair case while preserving the exact
    /// packet emission semantics of [`AdaptiveFec::on_send`].
    pub fn on_send_into(&mut self, packet: FecPacket, output: &mut Vec<FecPacket>) {
        output.clear();
        self.commit_pending_target_if_ready();

        // **ZERO-CPU FAST PATH**: Ultra-optimized pass-through
        let mode = self.active_mode;
        if mode == FecMode::Zero {
            // Absolute zero overhead: direct return without any processing
            output.push(packet);
            return;
        }

        // Normal path: forward systematic and feed encoder
        output.push(packet.clone());
        let mut encoder = self.encoder.lock();
        encoder.take_packet(packet);

        // Check if we should generate repair packets
        let (k, n) = encoder.params();
        if encoder.packets_in_window() >= k {
            let base = n.saturating_sub(k);
            if base > 0 {
                // Extra repairs scale with redundancy hint (ppm)
                let extra = if mode == FecMode::Light {
                    0
                } else if self.red_ppm_hint > 120_000 {
                    ((self.red_ppm_hint - 120_000) / 50_000) as usize
                } else {
                    0
                };
                let total = (base + extra.min(4)).min(base + 4);
                let free = output.capacity().saturating_sub(output.len());
                if free < total {
                    output.reserve_exact(total - free);
                }
                for repair_index in 0..total {
                    if let Some(repair) =
                        encoder.generate_repair_packet(repair_index, &self.mem_pool)
                    {
                        output.push(repair);
                    }
                }
            }
            encoder.clear_window();
            if mode == FecMode::Streaming {
                self.stream_idx = 0;
            }
            self.window_complete = true;
        }
        drop(encoder);

        // **ADAPTIVE STREAMING**: Dynamic stream_every based on loss rate
        if mode == FecMode::Streaming {
            self.stream_ctr += 1;
            let effective_every = self.stream_every;
            if self.stream_ctr >= effective_every {
                self.stream_ctr = 0;
                let mut repair_queue = std::mem::take(&mut self.stream_repair_scratch);
                self.emit_streaming_repair(&mut repair_queue);
                if !repair_queue.is_empty() {
                    output.extend(repair_queue.drain(..));
                }
                self.stream_repair_scratch = repair_queue;
            }
        }

        // Telemetry: queue length plus repair-symbol uniqueness/order depth.
        // The common systematic-only path must not pay HashSet/VecDeque cost:
        // repair-symbol diagnostics are only meaningful for emitted repairs.
        crate::telemetry::FEC_EMITTED_QUEUE
            .store(output.len() as u64, std::sync::atomic::Ordering::Relaxed);
        for p in output.iter().filter(|p| !p.is_systematic) {
            self.emitted_ids.insert(p.id);
            self.emitted_order.push_back(p.id);
            if self.emitted_order.len() > 4096 {
                if let Some(old_id) = self.emitted_order.pop_front() {
                    self.emitted_ids.remove(&old_id);
                }
            }
        }
        crate::telemetry::FEC_EMITTED_ORDER_DEPTH
            .store(self.emitted_order.len() as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_EMITTED_UNIQUE
            .store(self.emitted_ids.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Process incoming FEC packet through the decoder and return any recovered packets.
    ///
    /// Compatibility wrapper for callers that need an owned output vector. Hot-path callers
    /// should prefer [`AdaptiveFec::on_receive_into`] and reuse their output allocation.
    #[inline]
    pub fn on_receive(&mut self, packet: FecPacket) -> Result<Vec<FecPacket>, String> {
        if self.active_mode == FecMode::Zero {
            return Ok(vec![packet]);
        }

        let mut output = Vec::with_capacity(1);
        self.on_receive_into(packet, &mut output)?;
        Ok(output)
    }

    /// Process incoming FEC packet through the decoder, writing emitted packets into
    /// `output` without allocating a fresh vector on every receive.
    ///
    /// `output` is cleared first, but its allocation is retained. This mirrors
    /// [`AdaptiveFec::on_send_into`] for the receive hot path while preserving
    /// the exact packet emission semantics of [`AdaptiveFec::on_receive`].
    #[inline]
    pub fn on_receive_into(
        &mut self,
        packet: FecPacket,
        output: &mut Vec<FecPacket>,
    ) -> Result<(), String> {
        output.clear();

        // Zero mode has no repair packets to consume and cannot recover old
        // zero-mode payloads. Keep the receive path a true ownership-preserving
        // passthrough so the QUIC core can decrypt/header-unprotect in place
        // instead of falling back to a copy because the decoder retained an Arc
        // clone of the pooled buffer.
        if self.active_mode == FecMode::Zero {
            output.push(packet);
            return Ok(());
        }

        // Systematic (source) packets must always be forwarded to the QUIC stack
        // immediately, regardless of FEC decoder state. The decoder receives a
        // cheap shared-buffer clone for recovery tracking, while the original is
        // returned directly so handshake/data flow is not stalled. Repair packets
        // are moved into the decoder directly because they are never forwarded as
        // originals.
        let is_systematic = packet.is_systematic;
        let packet_id = packet.id;
        let mut systematic_packet = None;

        let mut decoder = self.decoder.lock();
        if is_systematic {
            decoder.take_packet(packet.clone());
            systematic_packet = Some(packet);
        } else {
            decoder.take_packet(packet);
        }

        if !decoder.recovery_needed() {
            if let Some(source) = systematic_packet.take() {
                output.push(source);
            }
            return Ok(());
        }

        if decoder.full_recovery_needed() {
            if let Some(result) = decoder.get_result() {
                output.extend(result);
            } else if self.partial_enabled {
                output.extend(decoder.get_partial_result());
            }
        } else if self.partial_enabled {
            output.extend(decoder.get_partial_result());
        }

        // Always ensure the systematic packet is forwarded. Block decoders only
        // emit "recovered" packets in get_result/get_partial_result, so systematic
        // packets that arrived intact would be silently dropped without this.
        if is_systematic && !output.iter().any(|p| p.id == packet_id) {
            if let Some(source) = systematic_packet.take() {
                output.push(source);
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn stream_repair_scratch_capacity(&self) -> usize {
        self.stream_repair_scratch.capacity()
    }

    #[cfg(test)]
    fn stream_repair_scratch_len(&self) -> usize {
        self.stream_repair_scratch.len()
    }
    fn stream_interval_target(&self, estimated_loss: f32) -> usize {
        let target = continuous_fec_target(
            estimated_loss,
            self.runtime_policy.auto_gf4_enabled,
            self.loss_estimator.disturbance_detected(),
            self.fountain_window,
            self.extreme_window,
            self.rtt_ms,
            self.loss_estimator.burst_variance(),
        );

        match target.family {
            FecBackendFamily::Zero => 8,
            FecBackendFamily::LowCostBlock => {
                if target.redundancy <= 1.10 {
                    6
                } else {
                    4
                }
            }
            FecBackendFamily::HeavyBlock => {
                if target.redundancy >= 3.0 {
                    1
                } else if target.redundancy >= 2.0 {
                    2
                } else {
                    3
                }
            }
            FecBackendFamily::Streaming => target.stream_every.unwrap_or(2),
            FecBackendFamily::Fountain => 1,
        }
    }

    /// Queue a target for a block boundary, except transport-confirmed clean Zero.
    #[cfg(test)]
    fn transition_to_target(&mut self, target: FecProtectionTarget) {
        self.transition_to_target_with_reason(target, FecSwitchReason::Adaptive);
    }

    fn transition_to_target_with_reason(
        &mut self,
        target: FecProtectionTarget,
        reason: FecSwitchReason,
    ) {
        self.transition_to_target_with_reason_inner(target, reason, false);
    }

    fn transition_to_target_with_reason_inner(
        &mut self,
        target: FecProtectionTarget,
        reason: FecSwitchReason,
        diagnostics_enabled: bool,
    ) {
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        self.pending_transition = Some(PendingFecTransition { target, reason });
        self.commit_pending_target_if_ready_inner(diagnostics_enabled);
    }

    fn commit_pending_target_if_ready(&mut self) {
        self.commit_pending_target_if_ready_inner(false);
    }

    fn commit_pending_target_if_ready_inner(&mut self, diagnostics_enabled: bool) {
        let Some(pending) = self.pending_transition else {
            return;
        };
        let clean_zero_transition = pending.target.family == FecBackendFamily::Zero
            && self.loss_estimator.clean_link_confirmed();
        let active_window_blocks_transition = Self::run_feedback_phase(
            diagnostics_enabled,
            "transition-encoder-window",
            || {
                let mut encoder = self.encoder.lock();
                if encoder.packets_in_window() != 0 {
                    if !clean_zero_transition {
                        return true;
                    }
                    // Systematic packets were already sent and framed repairs are
                    // self-describing at the receiver. Once transport ACKs prove the
                    // path clean, retaining a partial repair-only window cannot improve
                    // delivery and must not delay the bounded return to raw Zero mode.
                    encoder.clear_window();
                }
                false
            },
        );
        if active_window_blocks_transition {
            return;
        }
        let target = pending.target;
        let (mode, k, n, depth) = Self::run_feedback_phase(
            diagnostics_enabled,
            "transition-parameters",
            || {
                let current_window = self.mode_manager.lock().current_window().max(1);
                let (mode, requested_k, requested_n) =
                    internal::ModeManager::params_for_target(
                        target,
                        current_window,
                        self.runtime_policy.auto_gf4_enabled,
                    );
                let (k, n, depth) = wire_safe_encoder_params(
                    mode,
                    requested_k,
                    requested_n,
                    self.interleave_depth,
                    self.runtime_policy.interleave_enabled,
                );
                (mode, k, n, depth)
            },
        );
        let old_mode = self.active_mode;
        let old_window = self.telemetry.effective_window;
        self.pending_transition = None;
        if old_mode == mode && old_window == k {
            return;
        }
        Self::run_feedback_phase(diagnostics_enabled, "transition-encoder-replace", || {
            let mut encoder = internal::InterleavedEncoder::new_with_policy(
                mode,
                k,
                n,
                depth,
                &self.runtime_policy,
            );
            encoder.set_fountain_seed(self.fountain_seed);
            self.encoder = Arc::new(Mutex::new(encoder));
        });
        Self::run_feedback_phase(diagnostics_enabled, "transition-decoder-replace", || {
            let mut decoder = internal::InterleavedDecoder::new_with_policy(
                mode,
                k,
                Arc::clone(&self.mem_pool),
                depth,
                &self.runtime_policy,
            );
            decoder.set_fountain_seed(self.fountain_seed);
            self.decoder = Arc::new(Mutex::new(decoder));
        });
        self.active_mode = mode;
        self.streaming_mode = mode == FecMode::Streaming;
        self.window_complete = false;
        Self::run_feedback_phase(diagnostics_enabled, "transition-mode-commit", || {
            self.mode_manager.lock().force_state(mode, k);
        });

        self.telemetry.active_mode = mode;
        self.telemetry.effective_window = k;
        if self.telemetry.enabled {
            crate::telemetry::fec_instance_transition(
                old_mode.telemetry_id(),
                old_window,
                mode.telemetry_id(),
                k,
            );
        }
        if old_mode != mode {
            self.telemetry.mode_transitions = self.telemetry.mode_transitions.saturating_add(1);
            crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            pending.reason.observe();
        }
    }

    /// **GRADUAL MODE SWITCHING**: Initiate seamless transition to new mode
    #[cfg(test)]
    fn transition_to_mode(&mut self, new_mode: FecMode) {
        self.transition_to_target(target_from_mode(new_mode, 64));
    }

    /// Adjust streaming repair emission interval (every N systematic packets). Clamped to [1, 32]
    pub(crate) fn set_stream_every(&mut self, every: usize) {
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        let clamped = every.clamp(1, 32);
        self.stream_every_override = Some(clamped);
        self.set_stream_every_internal(clamped);
    }
    /// Set redundancy hint in parts-per-million (100_000 = 1.0x). Influences streaming burst.
    pub(crate) fn set_redundancy_ppm(&mut self, ppm: u32) {
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        self.red_ppm_hint = ppm;
    }

    /// Get current redundancy hint in parts-per-million (TODO-428).
    pub fn redundancy_ppm(&self) -> u32 {
        self.red_ppm_hint
    }
    fn set_stream_every_internal(&mut self, val: usize) {
        self.stream_every = val.clamp(1, 32);
        self.stream_ctr = 0;
        self.stream_last_adjust = crate::time_source::now_instant();
    }

    fn update_stream_interval(&mut self, estimated_loss: f32) {
        if self.stream_every_override.is_some() {
            return;
        }
        if crate::time_source::now_instant()
            .checked_duration_since(self.stream_last_adjust)
            .unwrap_or_default()
            < Duration::from_millis(STREAM_ADJUST_MIN_MS)
        {
            return;
        }
        let target_every = self.stream_interval_target(estimated_loss);
        if target_every == self.stream_every {
            return;
        }
        let delta = if target_every < self.stream_every { -2 } else { 1 };
        let new_every = (self.stream_every as isize + delta).clamp(1, 8) as usize;
        if new_every != self.stream_every {
            self.set_stream_every_internal(new_every);
            log::debug!("FEC: adjusted stream interval to every {} packets", new_every);
        }
    }
}

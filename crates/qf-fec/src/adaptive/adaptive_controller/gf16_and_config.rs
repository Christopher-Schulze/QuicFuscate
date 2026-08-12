use super::*;

impl AdaptiveFec {
    pub(super) fn emit_streaming_repair(&mut self, output_queue: &mut VecDeque<FecPacket>) {
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
        // Reject non-finite trend inputs by treating them as neutral.
        let clamp_trend = |v: f32| if v.is_finite() { v.clamp(-1.0, 1.0) } else { 0.0 };
        let rtt_trend = clamp_trend(rtt_trend);
        let cwnd_trend = clamp_trend(cwnd_trend);
        let throughput_trend = clamp_trend(throughput_trend);

        // Combine signals: negative sum = bandwidth scarce, positive = plentiful
        let signal = rtt_trend + cwnd_trend + throughput_trend;

        // Current loss estimate from estimator
        let current_loss = self.loss_estimator.smoothed_loss().clamp(0.0, 1.0);

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
            qf_telemetry::fec_observe_loss(observed_lost, observed_total);
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
    #[doc(hidden)]
    pub fn report_transport_loss(
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

    #[doc(hidden)]
    pub fn report_transport_loss_with_slow_phase_diagnostics(
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
        // Normalize the feedback tuple so reported lost never exceeds sent. Acknowledged
        // packets are preserved as provided so that clean-ack proof (sent=0, ack>0) still
        // drives the clean-streak counter. Telemetry still records the raw caller values
        // so delayed or misattributed loss remains observable.
        let observed_total = sent_packets as u64;
        let observed_lost = lost_packets as u64;
        let adaptation_lost = lost_packets.min(sent_packets);
        if self.telemetry.enabled {
            self.telemetry.observed_packets =
                self.telemetry.observed_packets.saturating_add(observed_total);
            self.telemetry.observed_lost_packets =
                self.telemetry.observed_lost_packets.saturating_add(observed_lost);
            qf_telemetry::fec_observe_transport_loss(observed_lost, observed_total);
        }
        if self.control_policy == FecControlPolicy::Off {
            return;
        }
        Self::run_feedback_phase(diagnostics_enabled, "estimator-actual", || {
            self.loss_estimator.report_actual_observation(acknowledged_packets, adaptation_lost);
        });
        let observation_weight = sent_packets;
        Self::run_feedback_phase(diagnostics_enabled, "estimator-smoothed", || {
            self.loss_estimator.report_smoothed_rate(smoothed_loss, observation_weight);
        });
        let estimated_loss =
            Self::run_feedback_phase(diagnostics_enabled, "estimator-read", || {
                self.loss_estimator.smoothed_loss()
            });
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
    #[doc(hidden)]
    pub fn set_fountain_seed(&mut self, seed: u64) {
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
        let environment = qf_common::env_utils::EnvSnapshot::capture();
        let mut replacement =
            Self::new_with_snapshot_and_pool(config, &environment, Arc::clone(&self.mem_pool));
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

        qf_telemetry::FEC_POLICY_TRANSITIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if previous_mode != FecMode::Zero {
            qf_telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    #[doc(hidden)]
    pub fn telemetry_enabled(&self) -> bool {
        self.telemetry.enabled
    }

    #[doc(hidden)]
    pub fn observe_wire_send(
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
        qf_telemetry::fec_observe_wire_send(
            systematic,
            source_payload_bytes as u64,
            wire_bytes as u64,
        );
    }

    #[doc(hidden)]
    pub fn observe_wire_receive(&mut self, report: wire::WireReceiveReport) {
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
        qf_telemetry::fec_observe_wire_receive(
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
        let codec = codec_for_mode(self.active_mode, block_source_count)?;
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
    #[doc(hidden)]
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn force_mode_for_test(&mut self, mode: FecMode) {
        self.active_mode = mode;
        self.telemetry.active_mode = mode;
        self.mode_manager =
            Arc::new(Mutex::new(internal::ModeManager::with_switch_threshold(mode, 0.02)));
    }

    pub(super) fn run_feedback_phase<T>(
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
                    controller_target = target_from_mode(FecMode::Fountain, self.fountain_window);
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

    #[doc(hidden)]
    pub fn force_streaming_mode(&mut self) {
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
    #[doc(hidden)]
    pub fn enable_simd_acceleration(&mut self) {
        // Centralized detection via optimize::FeatureDetector
        let det = qf_cpu::FeatureDetector::instance();
        let features = det.features_full();
        self.simd_level = fec_simd_level_for_features(features);
        self.simd_enabled = self.simd_level != SimdLevel::None;
        qf_telemetry::SIMD_ACTIVE
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
            "AVX-512 VBMI2" | "AVX-512 VBMI" => {
                qf_telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "AVX2" => {
                qf_telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SSE2" => {
                qf_telemetry::SIMD_USAGE_SSE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SVE2" => {
                qf_telemetry::SIMD_USAGE_SVE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "NEON" => {
                qf_telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            _ => qf_telemetry::SIMD_USAGE_SCALAR.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
    }

    /// Get current SIMD acceleration level
    #[doc(hidden)]
    pub fn simd_level(&self) -> &str {
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

    #[doc(hidden)]
    pub fn apply_auto_tuning(&mut self, k: usize, loss: f32, target: FecProtectionTarget) {
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
            qf_telemetry::fec_instance_closed(
                self.active_mode.telemetry_id(),
                self.telemetry.effective_window,
            );
        }
    }
}

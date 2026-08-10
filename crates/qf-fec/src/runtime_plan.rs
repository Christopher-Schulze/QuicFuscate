use crate::config::FecConfig;
use crate::loss::LossEstimator;
use crate::manager::ModeManager;
use crate::policy::FecRuntimePolicy;
use crate::target::{target_from_mode, FecBackendFamily};
use crate::{FecControlPolicy, FecMode};
use qf_common::env_utils::EnvSnapshot;
use qf_cpu::{CpuFeature, CpuProfile, FeatureDetector};
use qf_memory_pool::MemoryPool;
use std::sync::Arc;

/// Compute capabilities captured once for a connection's FEC runtime plan.
#[derive(Clone, Copy, Debug)]
pub struct FecComputeProfile {
    cpu_profile: CpuProfile,
    has_neon: bool,
}

impl FecComputeProfile {
    /// Build a deterministic compute-profile snapshot.
    pub fn new(cpu_profile: CpuProfile, has_neon: bool) -> Self {
        Self { cpu_profile, has_neon }
    }

    /// Detect the host profile once for the connection plan.
    pub fn detect() -> Self {
        let detector = FeatureDetector::instance();
        Self::new(detector.profile(), detector.has_feature(CpuFeature::NEON))
    }

    /// Return the captured CPU profile.
    pub fn cpu_profile(self) -> CpuProfile {
        self.cpu_profile
    }

    /// Return whether NEON is available in the captured feature set.
    pub fn has_neon(self) -> bool {
        self.has_neon
    }
}

/// Ambient environment and pool inputs used to resolve one FEC runtime plan.
pub struct FecAmbientInputs {
    pub(crate) mem_pool: Arc<MemoryPool>,
    pub(crate) compute_profile: FecComputeProfile,
    pub(crate) runtime_policy: FecRuntimePolicy,
    pub(crate) stream_every_override: Option<usize>,
    pub(crate) interleave_depth_override: Option<usize>,
    pub(crate) partial_enabled: bool,
    pub(crate) kalman_q_override: Option<f32>,
    pub(crate) kalman_r_override: Option<f32>,
}

impl FecAmbientInputs {
    /// Build ambient inputs from an explicit pool and policy snapshot.
    pub fn new(
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

    /// Build deterministic test inputs without depending on the product-global pool.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn detect() -> Self {
        let environment = EnvSnapshot::capture();
        Self::detect_with_snapshot(Arc::new(MemoryPool::new(64, 8192)), &environment)
    }

    /// Resolve environment policy against a caller-owned pool and snapshot.
    pub fn detect_with_snapshot(mem_pool: Arc<MemoryPool>, environment: &EnvSnapshot) -> Self {
        Self::new(
            mem_pool,
            FecComputeProfile::detect(),
            FecRuntimePolicy::detect_with_snapshot(environment),
        )
    }
}

/// Runtime parameters resolved from one FEC configuration and ambient snapshot.
pub struct FecRuntimePlan {
    pub mode: FecMode,
    pub control_policy: FecControlPolicy,
    pub force_on: bool,
    pub k: usize,
    pub n: usize,
    pub mem_pool: Arc<MemoryPool>,
    pub base_stream_every: usize,
    pub stream_every_override: Option<usize>,
    pub stream_every: usize,
    pub interleave_depth: usize,
    pub partial_enabled: bool,
    pub runtime_policy: FecRuntimePolicy,
    pub loss_estimator: LossEstimator,
    pub fountain_window: usize,
    pub extreme_window: usize,
}

impl FecRuntimePlan {
    /// Resolve a complete runtime plan without mutating global environment or pool state.
    pub fn resolve(config: &FecConfig, ambient: &FecAmbientInputs) -> Self {
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
        let (mode, requested_k, requested_n) = ModeManager::params_for_target(
            initial_target,
            config.window_sizes.get(&configured_initial_mode).copied().unwrap_or(64),
            ambient.runtime_policy.auto_gf4_enabled,
        );
        let mem_pool = Arc::clone(&ambient.mem_pool);

        let base_stream_every = match ambient.compute_profile.cpu_profile() {
            CpuProfile::X86_P3a
            | CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => 1,
            CpuProfile::X86_P2a | CpuProfile::X86_P2b | CpuProfile::Apple_M => 2,
            CpuProfile::X86_P1a | CpuProfile::X86_P1b | CpuProfile::X86_P1f => 3,
            CpuProfile::ARM_A1a
            | CpuProfile::ARM_A1b
            | CpuProfile::ARM_A1c
            | CpuProfile::ARM_A1d => {
                if ambient.compute_profile.has_neon() {
                    2
                } else {
                    4
                }
            }
            CpuProfile::ARM_A2 => 1,
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
        let loss_estimator = LossEstimator::from_parameters(
            config.lambda,
            config.burst_window,
            config.kalman_enabled,
            ambient.kalman_q_override.unwrap_or(config.kalman_q),
            ambient.kalman_r_override.unwrap_or(config.kalman_r),
        );
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

/// Resolve encoder dimensions that remain safe for the wire receiver's block limits.
pub fn wire_safe_encoder_params(
    mode: FecMode,
    source_count: usize,
    total_count: usize,
    requested_depth: usize,
    interleave_enabled: bool,
) -> (usize, usize, usize) {
    let depth = if mode == FecMode::Fountain || !interleave_enabled {
        1
    } else {
        requested_depth.clamp(1, 8).min(source_count.max(1))
    };
    if mode != FecMode::Streaming || source_count == 0 {
        return (source_count, total_count, depth);
    }

    let max_source_count = crate::wire::MAX_GF8_BLOCK_SOURCE_COUNT.saturating_mul(depth);
    let bounded_source_count = source_count.min(max_source_count);
    let aligned_source_count = (bounded_source_count / depth).max(1).saturating_mul(depth);
    let scaled_total_count = aligned_source_count
        .saturating_mul(total_count)
        .div_ceil(source_count)
        .max(aligned_source_count);
    let aligned_total_count = scaled_total_count.div_ceil(depth).saturating_mul(depth);
    (aligned_source_count, aligned_total_count, depth)
}

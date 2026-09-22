//! Transport batch sizing from detected CPU features.

use super::{CpuFeatures, FeatureDetector};
use std::sync::OnceLock;

/// Cached hardware acceleration plans derived from detected CPU features.
#[derive(Debug)]
pub struct AccelerationPlans {
    /// Detected CPU feature flags.
    pub features: CpuFeatures,
    /// Selected transport batch plan used by the parity batch shim.
    pub transport: TransportPlan,
}

/// Singleton accessor for the global `AccelerationPlans`.
pub struct AccelerationPlanner;

impl AccelerationPlanner {
    /// Returns the lazily-initialized global acceleration plan.
    pub fn global() -> &'static AccelerationPlans {
        static PLANS: OnceLock<AccelerationPlans> = OnceLock::new();
        PLANS.get_or_init(AccelerationPlans::derive)
    }
}

impl AccelerationPlans {
    fn derive() -> Self {
        let detector = FeatureDetector::instance();
        let features = *detector.features_full();
        let transport = TransportPlan::new(&features);

        Self { features, transport }
    }

    /// Returns the transport batch size based on SIMD width.
    pub fn transport_batch_size(&self) -> usize {
        self.transport.batch_size
    }
}

/// SIMD-width-aware transport batching plan.
#[derive(Debug, Clone, Copy)]
pub struct TransportPlan {
    batch_size: usize,
}

impl TransportPlan {
    fn new(features: &CpuFeatures) -> Self {
        let has_avx512f = features.avx512f;
        let has_avx2 = features.avx2;
        let batch_size = if has_avx512f {
            64
        } else if has_avx2 {
            32
        } else {
            16
        };

        Self { batch_size }
    }
}

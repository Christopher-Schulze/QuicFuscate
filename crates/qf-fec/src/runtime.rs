//! Process-wide FEC runtime initialization shared by adaptive instances.

use qf_common::env_utils::EnvSnapshot;
use std::sync::Once;

static RAYON_INIT: Once = Once::new();

#[derive(Clone, Copy, Debug)]
enum FecRayonGlobalPolicy {
    Default,
    ThreadCap(usize),
}

impl FecRayonGlobalPolicy {
    fn detect_with_snapshot(environment: &EnvSnapshot) -> Self {
        environment
            .parse::<usize>("QUICFUSCATE_RAYON_THREADS")
            .filter(|threads| *threads > 0)
            .map(Self::ThreadCap)
            .unwrap_or(Self::Default)
    }

    fn initialize(self) {
        RAYON_INIT.call_once(|| {
            if let Self::ThreadCap(threads) = self {
                let _ = rayon::ThreadPoolBuilder::new().num_threads(threads).build_global();
            }
        });
    }
}

/// FEC process-wide initialization snapshot.
#[doc(hidden)]
pub struct FecGlobalResources {
    rayon: FecRayonGlobalPolicy,
}

impl FecGlobalResources {
    /// Capture bounded initialization policy from one environment snapshot.
    #[doc(hidden)]
    pub fn detect_with_snapshot(environment: &EnvSnapshot) -> Self {
        Self { rayon: FecRayonGlobalPolicy::detect_with_snapshot(environment) }
    }

    /// Initialize Galois tables and the optional global Rayon pool once.
    #[doc(hidden)]
    pub fn initialize(&self) {
        crate::gf_tables::init_tables();
        self.rayon.initialize();
    }
}

/// Minimum interval between adaptive streaming cadence adjustments.
#[doc(hidden)]
pub const STREAM_ADJUST_MIN_MS: u64 = 150;

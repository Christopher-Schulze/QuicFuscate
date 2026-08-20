//! Extracted SIMD `planner` submodule (TODO-563).

use super::{CpuFeatures, CpuProfile, CryptoAeadPlan, FeatureDetector};
use std::sync::OnceLock;

/// Cached hardware acceleration plans derived from detected CPU features.
#[derive(Debug)]
pub struct AccelerationPlans {
    /// Detected CPU feature flags.
    pub features: CpuFeatures,
    /// Selected crypto AEAD plan.
    pub crypto: CryptoPlan,
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
        let profile = detector.profile();
        let features = *detector.features_full();

        let crypto = CryptoPlan::new(profile, &features);
        let transport = TransportPlan::new(&features);

        Self { features, crypto, transport }
    }

    /// Returns the default AEAD plan without considering message length.
    pub fn crypto_default_aead(&self) -> CryptoAeadPlan {
        self.crypto.default_aead
    }

    /// Returns the optimal AEAD plan for a given payload length.
    pub fn crypto_aead_for_len(&self, len: usize) -> CryptoAeadPlan {
        self.crypto.for_length(len, &self.features)
    }

    /// Returns the transport batch size based on SIMD width.
    pub fn transport_batch_size(&self) -> usize {
        self.transport.batch_size
    }
}

/// Hardware-aware crypto AEAD selection policy.
#[derive(Debug, Clone, Copy)]
pub struct CryptoPlan {
    default_aead: CryptoAeadPlan,
}

impl CryptoPlan {
    const AEGIS_X4_MIN_LEN: usize = 192;
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    const AEGIS_X8_MIN_LEN: usize = 1024;

    fn new(profile: CpuProfile, features: &CpuFeatures) -> Self {
        let default = match profile {
            CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => Self::x86_default(features),
            CpuProfile::X86_P3a | CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
                Self::x86_default(features)
            }
            CpuProfile::X86_P1b | CpuProfile::X86_P1f => Self::x86_default(features),
            CpuProfile::X86_P1a => CryptoAeadPlan::Morus,
            CpuProfile::X86_P0a | CpuProfile::X86_P0b => CryptoAeadPlan::Morus,
            CpuProfile::ARM_A2
            | CpuProfile::Apple_M
            | CpuProfile::ARM_A1c
            | CpuProfile::ARM_A1b
            | CpuProfile::ARM_A1a
            | CpuProfile::ARM_A1d
            | CpuProfile::ARM_A0 => Self::arm_default(features),
            CpuProfile::RVV => CryptoAeadPlan::Morus,
            CpuProfile::Scalar => CryptoAeadPlan::Morus,
        };

        Self { default_aead: default }
    }

    fn for_length(&self, len: usize, features: &CpuFeatures) -> CryptoAeadPlan {
        #[cfg(target_arch = "x86_64")]
        {
            return Self::x86_for_length(len, features);
        }

        #[cfg(target_arch = "aarch64")]
        {
            return Self::arm_for_length(len, features);
        }

        #[allow(unreachable_code)]
        CryptoAeadPlan::Morus
    }

    fn x86_default(features: &CpuFeatures) -> CryptoAeadPlan {
        if !Self::x86_can_use_aegis(features) {
            return CryptoAeadPlan::Morus;
        }
        CryptoAeadPlan::Aegis128X4
    }

    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    fn x86_for_length(len: usize, features: &CpuFeatures) -> CryptoAeadPlan {
        if !Self::x86_can_use_aegis(features) {
            return CryptoAeadPlan::Morus;
        }
        if len < Self::AEGIS_X4_MIN_LEN {
            return CryptoAeadPlan::Aegis128L;
        }
        if len >= Self::AEGIS_X8_MIN_LEN && Self::x86_prefers_x8(features) {
            CryptoAeadPlan::Aegis128X8
        } else {
            CryptoAeadPlan::Aegis128X4
        }
    }

    fn x86_can_use_aegis(features: &CpuFeatures) -> bool {
        features.aesni
    }

    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    fn x86_prefers_x8(features: &CpuFeatures) -> bool {
        if !features.vaes {
            return false;
        }
        (features.avx512f && features.avx512vl) || features.avx2
    }

    fn arm_default(features: &CpuFeatures) -> CryptoAeadPlan {
        Self::arm_for_length(super::DEFAULT_DATA_PLANE_AEAD_LEN, features)
    }

    fn arm_for_length(_len: usize, _features: &CpuFeatures) -> CryptoAeadPlan {
        // Omega ARM/AArch64 Criterion evidence (TODO-500) shows MORUS
        // beats the retained AEGIS L/X4/X8 backends for 64B, 1024B, 1400B
        // and 8192B payloads across single-packet and batch8 seal/open
        // trait paths. Keep AEGIS available for explicit override and
        // x86/VAES paths, but choose MORUS automatically on AArch64.
        CryptoAeadPlan::Morus
    }
}

#[cfg(test)]
mod crypto_plan_tests {
    use super::*;

    fn x86_aes_features() -> CpuFeatures {
        CpuFeatures { aesni: true, ..CpuFeatures::default() }
    }

    #[test]
    fn x86_small_payload_uses_single_lane_aegis() {
        let features = x86_aes_features();
        assert_eq!(
            CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X4_MIN_LEN - 1, &features),
            CryptoAeadPlan::Aegis128L
        );
    }

    #[test]
    fn x86_mid_payload_uses_x4_when_aes_is_available() {
        let features = x86_aes_features();
        assert_eq!(
            CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X4_MIN_LEN, &features),
            CryptoAeadPlan::Aegis128X4
        );
    }

    #[test]
    fn x86_large_payload_uses_x8_only_when_hardware_supports_it() {
        let features =
            CpuFeatures { aesni: true, vaes: true, avx2: true, ..CpuFeatures::default() };
        assert_eq!(
            CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X8_MIN_LEN, &features),
            CryptoAeadPlan::Aegis128X8
        );
    }

    #[test]
    fn x86_large_payload_without_vaes_stays_x4() {
        let features = CpuFeatures { aesni: true, avx2: true, ..CpuFeatures::default() };
        assert_eq!(
            CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X8_MIN_LEN, &features),
            CryptoAeadPlan::Aegis128X4
        );
    }

    #[test]
    fn arm_payloads_use_morus_after_omega_backend_evidence() {
        let features = CpuFeatures { neon: true, aes: true, ..CpuFeatures::default() };
        assert_eq!(
            CryptoPlan::arm_for_length(CryptoPlan::AEGIS_X4_MIN_LEN - 1, &features),
            CryptoAeadPlan::Morus
        );
        assert_eq!(
            CryptoPlan::arm_for_length(crate::DEFAULT_DATA_PLANE_AEAD_LEN, &features),
            CryptoAeadPlan::Morus
        );
        assert_eq!(CryptoPlan::arm_for_length(8192, &features), CryptoAeadPlan::Morus);
    }

    // Regression guard: the data-plane AEAD auto-selection length must
    // clear the X8 threshold so wide backends are not under-selected on
    // VAES-capable hosts. The constant `DEFAULT_DATA_PLANE_AEAD_LEN` is
    // 1400 (matching `TYPICAL_1RTT_PAYLOAD_LEN`); this test ensures it
    // never drops below `AEGIS_X8_MIN_LEN`.
    #[test]
    fn x86_data_plane_length_selects_x8_with_vaes() {
        let features =
            CpuFeatures { aesni: true, vaes: true, avx2: true, ..CpuFeatures::default() };
        const _: () = {
            assert!(
                crate::DEFAULT_DATA_PLANE_AEAD_LEN >= CryptoPlan::AEGIS_X8_MIN_LEN,
                "data-plane length must reach the X8 threshold"
            );
        };
        assert_eq!(
            CryptoPlan::x86_for_length(crate::DEFAULT_DATA_PLANE_AEAD_LEN, &features),
            CryptoAeadPlan::Aegis128X8
        );
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

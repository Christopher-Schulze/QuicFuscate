use log::warn;
use qf_common::env_utils::EnvSnapshot;
use std::any::Any;
#[cfg(any(test, feature = "rust-tests"))]
use std::cell::RefCell;

use super::{telemetry, CpuFeature, FeatureDetector};

/// Represents the execution policy for SIMD operations.
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}

/// Marker struct for AVX-512 execution.
pub struct Avx512;
impl SimdPolicy for Avx512 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX2 execution.
pub struct Avx2;
impl SimdPolicy for Avx2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for SSE2 execution.
pub struct Sse2;
impl SimdPolicy for Sse2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// SSE2 marker removed - baseline is SSE4.2

/// Marker struct for PCLMULQDQ execution.
pub struct Pclmulqdq;
impl SimdPolicy for Pclmulqdq {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON execution.
pub struct Neon;
impl SimdPolicy for Neon {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512GFNI execution (Galois Field New Instructions).
pub struct Avx512Gfni;
impl SimdPolicy for Avx512Gfni {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512VBMI2 execution.
pub struct Avx512Vbmi2;
impl SimdPolicy for Avx512Vbmi2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE2 execution.
pub struct Sve2;
impl SimdPolicy for Sve2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE execution.
pub struct Sve;
impl SimdPolicy for Sve {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON Crypto execution.
pub struct NeonCrypto;
impl SimdPolicy for NeonCrypto {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for scalar (non-SIMD) execution.
pub struct Scalar;
impl SimdPolicy for Scalar {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Dispatches to the best available SIMD implementation at runtime.
/// The policies are ordered from most to least performant.
pub fn dispatch<F, R>(f: F) -> R
where
    F: Fn(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();
    let features = detector.features_full();
    let matrix = features.simd_dispatch_matrix();
    let has_avx10_512 = detector.features.contains(&CpuFeature::AVX10_1_512);
    let has_avx10_256 = detector.features.contains(&CpuFeature::AVX10_1_256);

    // Priority order: GFNI > VBMI2 > VBMI > AVX2 > SSE2 > SVE2 > SVE > NEON
    if features.avx512f && features.gfni {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Gfni)
    } else if matrix.avx512_vbmi2 {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Vbmi2)
    } else if matrix.avx512_vbmi {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512)
    } else if matrix.avx2 {
        telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if has_avx10_256 {
            telemetry::SIMD_USAGE_AVX10_256.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx2)
    // SSE2 removed - fallback directly to scalar
    } else if features.pclmulqdq {
        f(&Pclmulqdq)
    } else if matrix.sve2 {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve2)
    } else if features.sve {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve)
    } else if features.neon && features.aes && features.pmull {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&NeonCrypto)
    } else if matrix.neon {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Neon)
    } else {
        telemetry::SIMD_USAGE_SCALAR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Scalar)
    }
}

/// Dispatches specifically for GF bitsliced operations. AVX-512/AVX2/SSE2 and
/// the ARM NEON/SVE2 families are considered; all other architectures fall back
/// to scalar code.
static FEC_KERNEL_OVERRIDE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "rust-tests"))]
std::thread_local! {
    pub(crate) static TEST_FEC_KERNEL_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Test-only: overrides the FEC kernel SIMD dispatch policy.
#[cfg(any(test, feature = "rust-tests"))]
pub fn __test_set_fec_kernel_override(val: Option<&str>) {
    TEST_FEC_KERNEL_OVERRIDE.with(|value| {
        *value.borrow_mut() = val.map(str::to_lowercase);
    });
}

/// Dispatch a FEC bitslice operation through the selected SIMD policy.
pub fn dispatch_bitslice<F, R>(mut f: F) -> R
where
    F: FnMut(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();
    let features = detector.features_full();
    let matrix = features.simd_dispatch_matrix();

    // Resolve optional runtime override (test override takes precedence)
    let ov: Option<String> = {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            if let Some(s) = TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone()) {
                Some(s)
            } else {
                FEC_KERNEL_OVERRIDE
                    .get_or_init(|| {
                        EnvSnapshot::capture()
                            .first(["QUICFUSCATE_FEC_KERNEL"])
                            .map(|value| value.to_ascii_lowercase())
                    })
                    .clone()
            }
        }
        #[cfg(not(any(test, feature = "rust-tests")))]
        {
            FEC_KERNEL_OVERRIDE
                .get_or_init(|| {
                    EnvSnapshot::capture()
                        .first(["QUICFUSCATE_FEC_KERNEL"])
                        .map(|value| value.to_ascii_lowercase())
                })
                .clone()
        }
    };

    // If a valid override is present and supported, honor it; otherwise, warn and fall back
    if let Some(ref mode) = ov {
        match mode.as_str() {
            "ref" | "scalar" => {
                return f(&Scalar);
            }
            "avx512vbmi2" => {
                if matrix.avx512_vbmi2 {
                    return f(&Avx512Vbmi2);
                } else {
                    warn!(
                        "QUICFUSCATE_FEC_KERNEL=avx512vbmi2 requested but unsupported; falling back to auto"
                    );
                }
            }
            "avx512" => {
                if matrix.avx512_vbmi {
                    return f(&Avx512);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx512 requested but unsupported; falling back to auto");
                }
            }
            "avx2" => {
                if matrix.avx2 {
                    return f(&Avx2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx2 requested but unsupported; falling back to auto");
                }
            }
            "neon" => {
                if matrix.neon {
                    return f(&Neon);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=neon requested but unsupported; falling back to auto");
                }
            }
            "sve2" => {
                if matrix.sve2 {
                    return f(&Sve2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=sve2 requested but unsupported; falling back to auto");
                }
            }
            other => {
                warn!("Unknown QUICFUSCATE_FEC_KERNEL='{}'; falling back to auto", other);
            }
        }
    }

    // Default automatic selection path (unchanged ordering)
    if matrix.avx512_vbmi2 {
        f(&Avx512Vbmi2)
    } else if matrix.avx512_vbmi {
        f(&Avx512)
    } else if matrix.avx2 {
        f(&Avx2)
    } else if features.sse2 {
        f(&Sse2)
    } else if matrix.sve2 {
        f(&Sve2)
    } else if matrix.neon {
        f(&Neon)
    } else {
        f(&Scalar)
    }
}

/// Helper to return a short, human-readable tag of the active bitslice policy.
#[cfg(test)]
pub(crate) fn bitslice_policy_tag(p: &dyn SimdPolicy) -> &'static str {
    if p.as_any().is::<Avx512Vbmi2>() {
        "avx512vbmi2"
    } else if p.as_any().is::<Avx512>() {
        "avx512"
    } else if p.as_any().is::<Avx2>() {
        "avx2"
    } else if p.as_any().is::<Sse2>() {
        "sse2"
    } else if p.as_any().is::<Sve2>() {
        "sve2"
    } else if p.as_any().is::<Neon>() {
        "neon"
    } else {
        "scalar"
    }
}

#[cfg(test)]
pub(crate) fn with_override<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
    struct OverrideGuard(Option<String>);

    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            TEST_FEC_KERNEL_OVERRIDE.with(|value| {
                *value.borrow_mut() = self.0.take();
            });
        }
    }

    let previous = TEST_FEC_KERNEL_OVERRIDE
        .with(|value| std::mem::replace(&mut *value.borrow_mut(), val.map(str::to_lowercase)));
    let _guard = OverrideGuard(previous);
    f()
}

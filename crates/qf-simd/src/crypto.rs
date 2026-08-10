//! Extracted SIMD `crypto` submodule (TODO-563).

use super::*;

/// AES single block encryption
#[inline(always)]
pub fn aes_encrypt_block(state: &mut [u8; 16], key: &[u8; 16]) {
    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by runtime feature detection matching
    // the callee's `#[target_feature]`. Both `state` and `key` are fixed-size
    // arrays, so pointer validity and length are guaranteed by the type system.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        let matrix = full.simd_dispatch_matrix();
        if matrix.vaes_aes {
            return unsafe { super::x86::aes_encrypt_vaes(state, key) };
        }
        if full.aesni && full.sse2 {
            return unsafe { super::x86::aes_encrypt_aesni(state, key) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.features_full().aes {
            return unsafe { arm::aes_encrypt_neon(state, key) };
        }
    }

    scalar::aes_encrypt_block(state, key)
}

/// GHASH for GCM mode
#[inline(always)]
pub fn ghash(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
    tag.copy_from_slice(&qf_crypto::gcm::ghash(*h, &[], data));
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Sha256Backend {
    #[cfg(all(target_arch = "x86_64", not(windows)))]
    Avx2,
    #[cfg(all(target_arch = "x86_64", not(windows)))]
    Vnni,
    #[cfg(all(target_arch = "aarch64", not(windows)))]
    Neon,
    #[cfg(all(target_arch = "aarch64", not(windows)))]
    Sve2,
    Scalar,
}

#[derive(Copy, Clone, Debug)]
struct Sha256Plan {
    backend: Sha256Backend,
}

static SHA256_PLAN: OnceLock<Sha256Plan> = OnceLock::new();

fn sha256_plan() -> &'static Sha256Plan {
    SHA256_PLAN.get_or_init(|| {
        #[cfg(not(windows))]
        let features = FeatureDetector::instance();

        #[cfg(all(target_arch = "x86_64", not(windows)))]
        {
            let full = features.features_full();
            let matrix = full.simd_dispatch_matrix();
            if matrix.sha256_vnni {
                return Sha256Plan { backend: Sha256Backend::Vnni };
            }
            if matrix.avx2 {
                return Sha256Plan { backend: Sha256Backend::Avx2 };
            }
        }

        #[cfg(all(target_arch = "aarch64", not(windows)))]
        {
            // Linux exposes the Armv8 SHA-256 extension as `sha2` in
            // /proc/cpuinfo, while Apple and some probes expose `sha256`.
            // Both names represent the target feature required by
            // arm::sha256_hw and must select the same backend.
            let full = features.features_full();
            let has_sha256 = full.neon && full.sha2;
            if full.sve2 && has_sha256 {
                return Sha256Plan { backend: Sha256Backend::Sve2 };
            }
            if has_sha256 {
                return Sha256Plan { backend: Sha256Backend::Neon };
            }
        }

        Sha256Plan { backend: Sha256Backend::Scalar }
    })
}

#[inline(always)]
fn sha256_impl(backend: Sha256Backend, data: &[u8]) -> [u8; 32] {
    // SAFETY: The `backend` value is derived from `sha256_plan()` which
    // selects backends only when the matching CPU features are detected
    // at init time. Each callee reads `data` and returns a hash digest -
    // no pointer aliasing or alignment requirements beyond slice validity.
    match backend {
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Avx2 => unsafe { super::x86::sha256_avx2(data) },
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Vnni => unsafe { super::x86::sha256_vnni(data) },
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sha256Backend::Neon | Sha256Backend::Sve2 => unsafe { arm::sha256_hw(data) },
        Sha256Backend::Scalar => scalar::sha256(data),
    }
}

#[inline(always)]
fn hmac_sha256_impl(backend: Sha256Backend, key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;

    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = sha256_impl(backend, key);
        k0[..32].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256_impl(backend, &inner);

    let mut outer = [0u8; BLOCK + 32];
    outer[..BLOCK].copy_from_slice(&opad);
    outer[BLOCK..].copy_from_slice(&inner_hash);
    sha256_impl(backend, &outer)
}

/// SHA-256 hash
#[inline(always)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let backend = sha256_plan().backend;
    match backend {
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Avx2 => qf_telemetry::SHA256_AVX2_OPS.inc(),
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Vnni => qf_telemetry::SHA256_VNNI_OPS.inc(),
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sha256Backend::Neon => qf_telemetry::SHA256_NEON_OPS.inc(),
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sha256Backend::Sve2 => qf_telemetry::SHA256_SVE2_OPS.inc(),
        Sha256Backend::Scalar => qf_telemetry::SHA256_SCALAR_OPS.inc(),
    }
    sha256_impl(backend, data)
}

/// HMAC-SHA256 using the runtime-dispatched SHA-256 above.
#[inline(always)]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let backend = sha256_plan().backend;
    match backend {
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Avx2 => qf_telemetry::HMAC_SHA256_AVX2_OPS.inc(),
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Sha256Backend::Vnni => qf_telemetry::HMAC_SHA256_VNNI_OPS.inc(),
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sha256Backend::Neon => qf_telemetry::HMAC_SHA256_NEON_OPS.inc(),
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sha256Backend::Sve2 => qf_telemetry::HMAC_SHA256_SVE2_OPS.inc(),
        Sha256Backend::Scalar => qf_telemetry::HMAC_SHA256_SCALAR_OPS.inc(),
    }
    hmac_sha256_impl(backend, key, data)
}

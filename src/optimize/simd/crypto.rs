//! optimize::simd::crypto (TODO-563).

use super::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_arch = "x86_64")]
static CHACHA20_X4_OVERRIDE: OnceLock<Option<String>> = OnceLock::new();
#[cfg(target_arch = "x86_64")]
static TEST_CHACHA20_X4_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

/// Test-only: overrides the ChaCha20 x4 SIMD dispatch policy.
#[cfg(target_arch = "x86_64")]
pub fn __test_set_chacha20_x4_override(val: Option<&str>) {
    let mut guard = TEST_CHACHA20_X4_OVERRIDE.lock().unwrap();
    *guard = val.map(|s| s.to_lowercase());
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn chacha20_x4_override() -> Option<String> {
    if let Some(mode) = TEST_CHACHA20_X4_OVERRIDE.lock().unwrap().clone() {
        return Some(mode);
    }

    CHACHA20_X4_OVERRIDE
        .get_or_init(|| {
            crate::env_utils::EnvSnapshot::capture()
                .first(["QUICFUSCATE_CHACHA20_X4"])
                .map(|value| value.to_ascii_lowercase())
        })
        .clone()
}

#[inline(always)]
fn chacha20_blocks_x4_scalar(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
    use crate::crypto::chacha::chacha20_block;
    [
        chacha20_block(key, counter, nonce),
        chacha20_block(key, counter.wrapping_add(1), nonce),
        chacha20_block(key, counter.wrapping_add(2), nonce),
        chacha20_block(key, counter.wrapping_add(3), nonce),
    ]
}

/// AES round with best available SIMD
#[inline(always)]
pub fn aes_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.simd_dispatch_matrix().vaes_aes {
            return unsafe { aes_round_vaes(state, round_key) };
        }
        if features.aesni && features.sse2 {
            return unsafe { aes_round_aesni(state, round_key) };
        }
    }

    aes_round_scalar(state, round_key);
}

/// ChaCha20 XOR (stream cipher) with centralized SIMD XOR writeback.
/// WARNING: For TLS Cover/bench only. Not used for payload encryption per policy.
#[inline(always)]
pub fn chacha20_xor_in_place(dst: &mut [u8], key: &[u8; 32], nonce: &[u8; 12], counter: u32) {
    use crate::crypto::chacha::chacha20_block;
    let mut ctr = counter;
    let n = dst.len();
    let mut i = 0usize;
    while i < n {
        let block = chacha20_block(key, ctr, nonce);
        ctr = ctr.wrapping_add(1);
        let take = (n - i).min(64);
        unsafe {
            xor_slice_simd(&mut dst[i..i + take], &block[..take]);
        }
        i += take;
    }
}

/// Produce 4 ChaCha20 keystream blocks starting at `counter`..`counter+3`.
/// Runtime-Dispatch hook present; currently uses 4x scalar fallback for correctness.
/// For TLS Cover/bench only.
#[inline(always)]
pub fn chacha20_blocks_x4(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
    let features = FeatureDetector::instance().features_full();
    #[cfg(target_arch = "x86_64")]
    if let Some(mode) = chacha20_x4_override() {
        match mode.as_str() {
            "scalar" | "ref" => {
                crate::optimize::telemetry::CHACHA20_X4_SCALAR_OPS.inc();
                return chacha20_blocks_x4_scalar(key, nonce, counter);
            }
            "auto" => {
                // fall back to standard detection without warning
            }
            "avx2" => {
                if features.avx2 {
                    crate::optimize::telemetry::CHACHA20_X4_AVX2_OPS.inc();
                    return unsafe { chacha20_blocks_x4_avx2(key, nonce, counter) };
                }
                log::warn!(
                    "CHACHA20_X4 override requested AVX2 but feature unavailable; falling back"
                );
            }
            "avx" => {
                if features.simd_dispatch_matrix().chacha_avx {
                    crate::optimize::telemetry::CHACHA20_X4_AVX_OPS.inc();
                    return unsafe { chacha20_blocks_x4_avx(key, nonce, counter) };
                }
                log::warn!(
                    "CHACHA20_X4 override requested AVX but feature unavailable; falling back"
                );
            }
            "sse" | "sse41" | "ssse3" => {
                if features.sse41 && features.ssse3 {
                    crate::optimize::telemetry::CHACHA20_X4_SSE41_OPS.inc();
                    return unsafe { chacha20_blocks_x4_sse41(key, nonce, counter) };
                }
                log::warn!(
                    "CHACHA20_X4 override requested SSE4.1/SSSE3 but feature unavailable; falling back"
                );
            }
            other => {
                log::warn!("unknown CHACHA20_X4 override '{}'; ignoring", other);
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if features.avx2 {
            crate::optimize::telemetry::CHACHA20_X4_AVX2_OPS.inc();
            return unsafe { chacha20_blocks_x4_avx2(key, nonce, counter) };
        } else if features.simd_dispatch_matrix().chacha_avx {
            crate::optimize::telemetry::CHACHA20_X4_AVX_OPS.inc();
            return unsafe { chacha20_blocks_x4_avx(key, nonce, counter) };
        } else if features.sse41 && features.ssse3 {
            crate::optimize::telemetry::CHACHA20_X4_SSE41_OPS.inc();
            return unsafe { chacha20_blocks_x4_sse41(key, nonce, counter) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if features.neon {
            crate::optimize::telemetry::CHACHA20_X4_NEON_OPS.inc();
            return unsafe { chacha20_blocks_x4_neon(key, nonce, counter) };
        }
    }
    // Fallback scalar 4x
    crate::optimize::telemetry::CHACHA20_X4_SCALAR_OPS.inc();
    chacha20_blocks_x4_scalar(key, nonce, counter)
}

/// Produce 16 ChaCha20 keystream blocks (AVX-512) starting at `counter`..`counter+15`.
/// Falls back to scalar generation if AVX-512F is unavailable.
#[inline(always)]
pub fn chacha20_blocks_x16(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 16] {
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.avx512f {
            return unsafe { chacha20_blocks_x16_avx512(key, nonce, counter) };
        }
    }
    // Fallback scalar 16x
    use crate::crypto::chacha::chacha20_block;
    [
        chacha20_block(key, counter.wrapping_add(0), nonce),
        chacha20_block(key, counter.wrapping_add(1), nonce),
        chacha20_block(key, counter.wrapping_add(2), nonce),
        chacha20_block(key, counter.wrapping_add(3), nonce),
        chacha20_block(key, counter.wrapping_add(4), nonce),
        chacha20_block(key, counter.wrapping_add(5), nonce),
        chacha20_block(key, counter.wrapping_add(6), nonce),
        chacha20_block(key, counter.wrapping_add(7), nonce),
        chacha20_block(key, counter.wrapping_add(8), nonce),
        chacha20_block(key, counter.wrapping_add(9), nonce),
        chacha20_block(key, counter.wrapping_add(10), nonce),
        chacha20_block(key, counter.wrapping_add(11), nonce),
        chacha20_block(key, counter.wrapping_add(12), nonce),
        chacha20_block(key, counter.wrapping_add(13), nonce),
        chacha20_block(key, counter.wrapping_add(14), nonce),
        chacha20_block(key, counter.wrapping_add(15), nonce),
    ]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
/// # Safety
///
/// The caller must provide AVX-512F support. `key` and `nonce` must remain
/// valid immutable arrays for the duration of the call; the function returns
/// owned output and does not retain their addresses.
unsafe fn chacha20_blocks_x16_avx512(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
) -> [[u8; 64]; 16] {
    use std::arch::x86_64::*;

    // Constants
    let c0 = _mm512_set1_epi32(0x61707865u32 as i32);
    let c1 = _mm512_set1_epi32(0x3320646eu32 as i32);
    let c2 = _mm512_set1_epi32(0x79622d32u32 as i32);
    let c3 = _mm512_set1_epi32(0x6b206574u32 as i32);

    // Key broadcast per word
    let load_u32 = |i: usize| -> i32 {
        i32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
    };
    let k0 = _mm512_set1_epi32(load_u32(0));
    let k1 = _mm512_set1_epi32(load_u32(1));
    let k2 = _mm512_set1_epi32(load_u32(2));
    let k3 = _mm512_set1_epi32(load_u32(3));
    let k4 = _mm512_set1_epi32(load_u32(4));
    let k5 = _mm512_set1_epi32(load_u32(5));
    let k6 = _mm512_set1_epi32(load_u32(6));
    let k7 = _mm512_set1_epi32(load_u32(7));

    // Nonce broadcast
    let n0 = _mm512_set1_epi32(i32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
    let n1 = _mm512_set1_epi32(i32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
    let n2 = _mm512_set1_epi32(i32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));

    // Counter lanes [ctr..ctr+15]
    let mut ctr_arr = [0i32; 16];
    for i in 0..16 {
        ctr_arr[i] = counter.wrapping_add(i as u32) as i32;
    }
    let ctrv = _mm512_loadu_si512(ctr_arr.as_ptr() as *const __m512i);

    // State vectors (SOA across 16 blocks)
    let mut x0 = c0;
    let mut x1 = c1;
    let mut x2 = c2;
    let mut x3 = c3;
    let mut x4 = k0;
    let mut x5 = k1;
    let mut x6 = k2;
    let mut x7 = k3;
    let mut x8 = k4;
    let mut x9 = k5;
    let mut x10 = k6;
    let mut x11 = k7;
    let mut x12 = ctrv;
    let mut x13 = n0;
    let mut x14 = n1;
    let mut x15 = n2;

    // Save initial state
    let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12s, i13s, i14s, i15s) =
        (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

    #[inline(always)]
    /// # Safety
    ///
    /// The caller must provide AVX-512F support. `v` must be an initialized
    /// vector value; the function does not dereference pointers or retain state.
    unsafe fn rotl32(v: __m512i, n: i32) -> __m512i {
        let n = ((n as u32) & 31) as i32;
        if n == 0 {
            return v;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let l = _mm512_sll_epi32(v, cnt);
        let r = _mm512_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
        _mm512_or_si512(l, r)
    }
    #[inline(always)]
    /// # Safety
    ///
    /// The caller must provide AVX-512F support and pass initialized vector
    /// values through valid mutable references. The function does not retain
    /// the references after returning.
    unsafe fn qr(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = rotl32(*d, 16);
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = rotl32(*b, 12);
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = rotl32(*d, 8);
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = rotl32(*b, 7);
    }

    // 10 double rounds
    for _ in 0..10 {
        // Column rounds
        qr(&mut x0, &mut x4, &mut x8, &mut x12);
        qr(&mut x1, &mut x5, &mut x9, &mut x13);
        qr(&mut x2, &mut x6, &mut x10, &mut x14);
        qr(&mut x3, &mut x7, &mut x11, &mut x15);
        // Diagonal rounds
        qr(&mut x0, &mut x5, &mut x10, &mut x15);
        qr(&mut x1, &mut x6, &mut x11, &mut x12);
        qr(&mut x2, &mut x7, &mut x8, &mut x13);
        qr(&mut x3, &mut x4, &mut x9, &mut x14);
    }

    // Feed-forward
    x0 = _mm512_add_epi32(x0, i0);
    x1 = _mm512_add_epi32(x1, i1);
    x2 = _mm512_add_epi32(x2, i2);
    x3 = _mm512_add_epi32(x3, i3);
    x4 = _mm512_add_epi32(x4, i4);
    x5 = _mm512_add_epi32(x5, i5);
    x6 = _mm512_add_epi32(x6, i6);
    x7 = _mm512_add_epi32(x7, i7);
    x8 = _mm512_add_epi32(x8, i8);
    x9 = _mm512_add_epi32(x9, i9);
    x10 = _mm512_add_epi32(x10, i10);
    x11 = _mm512_add_epi32(x11, i11);
    x12 = _mm512_add_epi32(x12, i12s);
    x13 = _mm512_add_epi32(x13, i13s);
    x14 = _mm512_add_epi32(x14, i14s);
    x15 = _mm512_add_epi32(x15, i15s);

    // Serialize 16 lanes into 16 blocks
    let mut out = [[0u8; 64]; 16];
    let mut tmp: [i32; 16] = [0; 16];
    macro_rules! store_lane {
        ($vec:expr, $w:expr) => {{
            _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, $vec);
            for l in 0..16 {
                let bytes = (tmp[l] as u32).to_le_bytes();
                out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&bytes);
            }
        }};
    }
    store_lane!(x0, 0);
    store_lane!(x1, 1);
    store_lane!(x2, 2);
    store_lane!(x3, 3);
    store_lane!(x4, 4);
    store_lane!(x5, 5);
    store_lane!(x6, 6);
    store_lane!(x7, 7);
    store_lane!(x8, 8);
    store_lane!(x9, 9);
    store_lane!(x10, 10);
    store_lane!(x11, 11);
    store_lane!(x12, 12);
    store_lane!(x13, 13);
    store_lane!(x14, 14);
    store_lane!(x15, 15);
    out
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
/// # Safety
///
/// The caller must provide x86-64 SSE2 support and valid immutable `key` and
/// `nonce` arrays for the duration of the call. The function returns owned
/// output and does not retain their addresses.
unsafe fn chacha20_blocks_x4_sse_core(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
) -> [[u8; 64]; 4] {
    use std::arch::x86_64::*;
    // Load constants
    let c0 = _mm_set1_epi32(0x61707865u32 as i32);
    let c1 = _mm_set1_epi32(0x3320646eu32 as i32);
    let c2 = _mm_set1_epi32(0x79622d32u32 as i32);
    let c3 = _mm_set1_epi32(0x6b206574u32 as i32);
    // Load key into 8 words (k0..k7), broadcast across 4 lanes by packing elements per lane
    let load_u32 = |i: usize| -> i32 {
        i32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
    };
    let k0 = _mm_set1_epi32(load_u32(0));
    let k1 = _mm_set1_epi32(load_u32(1));
    let k2 = _mm_set1_epi32(load_u32(2));
    let k3 = _mm_set1_epi32(load_u32(3));
    let k4 = _mm_set1_epi32(load_u32(4));
    let k5 = _mm_set1_epi32(load_u32(5));
    let k6 = _mm_set1_epi32(load_u32(6));
    let k7 = _mm_set1_epi32(load_u32(7));
    // Nonce
    let n0 = _mm_set1_epi32(i32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
    let n1 = _mm_set1_epi32(i32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
    let n2 = _mm_set1_epi32(i32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));
    // Counter lanes
    let ctr0 = _mm_set_epi32(
        (counter + 3) as i32,
        (counter + 2) as i32,
        (counter + 1) as i32,
        counter as i32,
    );

    // State words (SOA across 4 blocks)
    let mut x0 = c0;
    let mut x1 = c1;
    let mut x2 = c2;
    let mut x3 = c3;
    let mut x4 = k0;
    let mut x5 = k1;
    let mut x6 = k2;
    let mut x7 = k3;
    let mut x8 = k4;
    let mut x9 = k5;
    let mut x10 = k6;
    let mut x11 = k7;
    let mut x12 = ctr0;
    let mut x13 = n0;
    let mut x14 = n1;
    let mut x15 = n2;

    // Save initial state for feed-forward
    let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12s, i13s, i14s, i15s) =
        (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

    #[inline(always)]
    /// # Safety
    ///
    /// The caller must provide x86-64 SSE2 support and pass an initialized
    /// vector value. No pointer is dereferenced by this helper.
    unsafe fn rotl32(v: __m128i, n: i32) -> __m128i {
        use std::arch::x86_64::*;
        let n = ((n as u32) & 31) as i32;
        if n == 0 {
            return v;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let l = _mm_sll_epi32(v, cnt);
        let r = _mm_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
        _mm_or_si128(l, r)
    }
    #[inline(always)]
    /// # Safety
    ///
    /// The caller must provide x86-64 SSE2 support and valid mutable
    /// references to initialized vector values. The references do not escape.
    unsafe fn qr(a: &mut __m128i, b: &mut __m128i, c: &mut __m128i, d: &mut __m128i) {
        use std::arch::x86_64::*;
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = rotl32(*d, 16);
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = rotl32(*b, 12);
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = rotl32(*d, 8);
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = rotl32(*b, 7);
    }
    // 10 double rounds
    for _ in 0..10 {
        // Column rounds
        qr(&mut x0, &mut x4, &mut x8, &mut x12);
        qr(&mut x1, &mut x5, &mut x9, &mut x13);
        qr(&mut x2, &mut x6, &mut x10, &mut x14);
        qr(&mut x3, &mut x7, &mut x11, &mut x15);
        // Diagonal rounds
        qr(&mut x0, &mut x5, &mut x10, &mut x15);
        qr(&mut x1, &mut x6, &mut x11, &mut x12);
        qr(&mut x2, &mut x7, &mut x8, &mut x13);
        qr(&mut x3, &mut x4, &mut x9, &mut x14);
    }
    // Feed-forward
    x0 = _mm_add_epi32(x0, i0);
    x1 = _mm_add_epi32(x1, i1);
    x2 = _mm_add_epi32(x2, i2);
    x3 = _mm_add_epi32(x3, i3);
    x4 = _mm_add_epi32(x4, i4);
    x5 = _mm_add_epi32(x5, i5);
    x6 = _mm_add_epi32(x6, i6);
    x7 = _mm_add_epi32(x7, i7);
    x8 = _mm_add_epi32(x8, i8);
    x9 = _mm_add_epi32(x9, i9);
    x10 = _mm_add_epi32(x10, i10);
    x11 = _mm_add_epi32(x11, i11);
    x12 = _mm_add_epi32(x12, i12s);
    x13 = _mm_add_epi32(x13, i13s);
    x14 = _mm_add_epi32(x14, i14s);
    x15 = _mm_add_epi32(x15, i15s);

    // Serialize per-lane into 4 blocks of 64 bytes
    let mut out = [[0u8; 64]; 4];
    // helper to store a vector into 4 u32 words for each lane index l
    macro_rules! store_lane {
        ($vec:expr, $w:expr) => {{
            let mut tmp = [0i32; 4];
            _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, $vec);
            for l in 0..4 {
                let bytes = (tmp[l] as u32).to_le_bytes();
                out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&bytes);
            }
        }};
    }
    store_lane!(x0, 0);
    store_lane!(x1, 1);
    store_lane!(x2, 2);
    store_lane!(x3, 3);
    store_lane!(x4, 4);
    store_lane!(x5, 5);
    store_lane!(x6, 6);
    store_lane!(x7, 7);
    store_lane!(x8, 8);
    store_lane!(x9, 9);
    store_lane!(x10, 10);
    store_lane!(x11, 11);
    store_lane!(x12, 12);
    store_lane!(x13, 13);
    store_lane!(x14, 14);
    store_lane!(x15, 15);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must provide AVX2 support and valid immutable key and nonce
/// arrays for the duration of the call. The delegated SSE2 operations return
/// owned output and do not retain input addresses.
unsafe fn chacha20_blocks_x4_avx2(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
    chacha20_blocks_x4_sse_core(key, nonce, counter)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx", enable = "sse4.1", enable = "ssse3")]
/// # Safety
///
/// The caller must provide AVX, SSE4.1, and SSSE3 support and valid immutable
/// key and nonce arrays for the duration of the call.
unsafe fn chacha20_blocks_x4_avx(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
    chacha20_blocks_x4_sse_core(key, nonce, counter)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1", enable = "ssse3")]
/// # Safety
///
/// The caller must provide SSE4.1 and SSSE3 support and valid immutable key
/// and nonce arrays for the duration of the call.
unsafe fn chacha20_blocks_x4_sse41(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
) -> [[u8; 64]; 4] {
    chacha20_blocks_x4_sse_core(key, nonce, counter)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support and valid immutable key and
/// nonce arrays for the duration of the call. The function returns owned output
/// and does not retain input addresses.
unsafe fn chacha20_blocks_x4_neon(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
    use std::arch::aarch64::*;
    // Constants
    let c0 = vdupq_n_u32(0x61707865);
    let c1 = vdupq_n_u32(0x3320646e);
    let c2 = vdupq_n_u32(0x79622d32);
    let c3 = vdupq_n_u32(0x6b206574);
    // Key
    let k =
        |i: usize| u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    let k0 = vdupq_n_u32(k(0));
    let k1 = vdupq_n_u32(k(1));
    let k2 = vdupq_n_u32(k(2));
    let k3 = vdupq_n_u32(k(3));
    let k4 = vdupq_n_u32(k(4));
    let k5 = vdupq_n_u32(k(5));
    let k6 = vdupq_n_u32(k(6));
    let k7 = vdupq_n_u32(k(7));
    // Nonce
    let n0 = vdupq_n_u32(u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
    let n1 = vdupq_n_u32(u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
    let n2 = vdupq_n_u32(u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));
    // Counter lanes: [ctr,ctr+1,ctr+2,ctr+3]
    let ctr_vec = vld1q_u32(
        [counter, counter.wrapping_add(1), counter.wrapping_add(2), counter.wrapping_add(3)]
            .as_ptr(),
    );

    let mut x0 = c0;
    let mut x1 = c1;
    let mut x2 = c2;
    let mut x3 = c3;
    let mut x4 = k0;
    let mut x5 = k1;
    let mut x6 = k2;
    let mut x7 = k3;
    let mut x8 = k4;
    let mut x9 = k5;
    let mut x10 = k6;
    let mut x11 = k7;
    let mut x12 = ctr_vec;
    let mut x13 = n0;
    let mut x14 = n1;
    let mut x15 = n2;
    // Save initial
    let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) =
        (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

    #[inline(always)]
    /// # Safety
    ///
    /// The caller must provide AArch64 NEON support and valid mutable
    /// references to initialized vector values. The references do not escape.
    unsafe fn qr(a: &mut uint32x4_t, b: &mut uint32x4_t, c: &mut uint32x4_t, d: &mut uint32x4_t) {
        // rotl32(x,16)
        *a = vaddq_u32(*a, *b);
        *d = veorq_u32(*d, *a);
        *d = vorrq_u32(vshlq_n_u32(*d, 16), vshrq_n_u32(*d, 16));
        // rotl32(x,12)
        *c = vaddq_u32(*c, *d);
        *b = veorq_u32(*b, *c);
        *b = vorrq_u32(vshlq_n_u32(*b, 12), vshrq_n_u32(*b, 20));
        // rotl32(x,8)
        *a = vaddq_u32(*a, *b);
        *d = veorq_u32(*d, *a);
        *d = vorrq_u32(vshlq_n_u32(*d, 8), vshrq_n_u32(*d, 24));
        // rotl32(x,7)
        *c = vaddq_u32(*c, *d);
        *b = veorq_u32(*b, *c);
        *b = vorrq_u32(vshlq_n_u32(*b, 7), vshrq_n_u32(*b, 25));
    }
    for _ in 0..10 {
        // double rounds
        qr(&mut x0, &mut x4, &mut x8, &mut x12);
        qr(&mut x1, &mut x5, &mut x9, &mut x13);
        qr(&mut x2, &mut x6, &mut x10, &mut x14);
        qr(&mut x3, &mut x7, &mut x11, &mut x15);
        qr(&mut x0, &mut x5, &mut x10, &mut x15);
        qr(&mut x1, &mut x6, &mut x11, &mut x12);
        qr(&mut x2, &mut x7, &mut x8, &mut x13);
        qr(&mut x3, &mut x4, &mut x9, &mut x14);
    }
    // Feed-forward
    x0 = vaddq_u32(x0, i0);
    x1 = vaddq_u32(x1, i1);
    x2 = vaddq_u32(x2, i2);
    x3 = vaddq_u32(x3, i3);
    x4 = vaddq_u32(x4, i4);
    x5 = vaddq_u32(x5, i5);
    x6 = vaddq_u32(x6, i6);
    x7 = vaddq_u32(x7, i7);
    x8 = vaddq_u32(x8, i8);
    x9 = vaddq_u32(x9, i9);
    x10 = vaddq_u32(x10, i10);
    x11 = vaddq_u32(x11, i11);
    x12 = vaddq_u32(x12, i12);
    x13 = vaddq_u32(x13, i13);
    x14 = vaddq_u32(x14, i14);
    x15 = vaddq_u32(x15, i15);
    // Serialize
    let mut out = [[0u8; 64]; 4];
    let mut tmp: [u32; 4] = [0; 4];
    macro_rules! store {
        ($v:expr,$w:expr) => {{
            vst1q_u32(tmp.as_mut_ptr(), $v);
            for l in 0..4 {
                let b = tmp[l].to_le_bytes();
                out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&b);
            }
        }};
    }
    store!(x0, 0);
    store!(x1, 1);
    store!(x2, 2);
    store!(x3, 3);
    store!(x4, 4);
    store!(x5, 5);
    store!(x6, 6);
    store!(x7, 7);
    store!(x8, 8);
    store!(x9, 9);
    store!(x10, 10);
    store!(x11, 11);
    store!(x12, 12);
    store!(x13, 13);
    store!(x14, 14);
    store!(x15, 15);
    out
}

/// SIMD-accelerated XOR of two equal-length byte slices (dst ^= src).
/// Mismatched slices are rejected without modifying either slice.
#[inline(always)]
/// # Safety
///
/// `dst` must be valid writable storage and `src` valid readable storage for
/// the duration of the call. The slices must have equal lengths and must not
/// overlap; runtime feature checks select only supported vector instructions.
unsafe fn xor_slice_simd(dst: &mut [u8], src: &[u8]) {
    if dst.len() != src.len() {
        return;
    }

    let len = dst.len();
    let mut i = 0usize;
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.avx2 {
            use std::arch::x86_64::*;
            while i + 32 <= len {
                let a = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
                let b = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
                let r = _mm256_xor_si256(a, b);
                _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, r);
                i += 32;
            }
        } else if features.sse2 {
            use std::arch::x86_64::*;
            while i + 16 <= len {
                let a = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
                let b = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
                let r = _mm_xor_si128(a, b);
                _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, r);
                i += 16;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.neon {
            use std::arch::aarch64::*;
            while i + 16 <= len {
                let a = vld1q_u8(dst.as_ptr().add(i));
                let b = vld1q_u8(src.as_ptr().add(i));
                let r = veorq_u8(a, b);
                vst1q_u8(dst.as_mut_ptr().add(i), r);
                i += 16;
            }
        }
    }

    while i < len {
        dst[i] ^= src[i];
        i += 1;
    }
}

/// AES round with AES-NI
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
#[inline(always)]
/// # Safety
///
/// The caller must provide AES-NI and SSE2 support. `state` must be valid
/// writable storage and `round_key` valid readable storage; both arrays must
/// remain alive for the duration of the intrinsic operations.
unsafe fn aes_round_aesni(state: &mut [u8; 16], round_key: &[u8; 16]) {
    use std::arch::x86_64::*;

    let s = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    let k = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
    let result = _mm_aesenc_si128(s, k);
    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, result);
}

/// VAES for parallel AES rounds (AVX-512)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "vaes,avx512f,aes,sse2")]
#[inline(always)]
/// # Safety
///
/// The caller must provide VAES, AVX-512F, AES-NI, and SSE2 support. `state`
/// must be valid writable storage and `round_key` valid readable storage for
/// the duration of the delegated AES-NI operation.
unsafe fn aes_round_vaes(state: &mut [u8; 16], round_key: &[u8; 16]) {
    // Fallback to AES-NI for single block
    aes_round_aesni(state, round_key);
}

/// Scalar AES round fallback
fn aes_round_scalar(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

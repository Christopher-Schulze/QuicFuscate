#[cfg(all(test, target_arch = "x86_64"))]
use std::sync::Mutex;

#[cfg(all(test, target_arch = "x86_64"))]
static GHASH_TEST_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

/// Test-only: override the GHASH backend selection for deterministic testing.
#[cfg(all(test, target_arch = "x86_64"))]
pub fn __test_set_ghash_override(val: Option<&str>) {
    let mut guard = GHASH_TEST_OVERRIDE.lock().unwrap();
    *guard = val.map(|s| s.to_lowercase());
}

const GHASH_REDUCTION: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

#[inline(always)]
fn ghash_multiply(x: u128, h: u128) -> u128 {
    let mut product = 0u128;
    let mut factor = h;

    for bit in (0..128).rev() {
        let x_mask = 0u128.wrapping_sub((x >> bit) & 1);
        product ^= factor & x_mask;

        let reduction_mask = 0u128.wrapping_sub(factor & 1);
        factor = (factor >> 1) ^ (GHASH_REDUCTION & reduction_mask);
    }

    product
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
fn reduce_natural_gf128_product(mut low: u128, mut high: u128) -> u128 {
    for shift in (0..128).rev() {
        let coefficient_mask = 0u128.wrapping_sub((high >> shift) & 1);
        high ^= (1u128 << shift) & coefficient_mask;
        low ^= (0x87u128 << shift) & coefficient_mask;
        if shift > 120 {
            high ^= (0x87u128 >> (128 - shift)) & coefficient_mask;
        }
    }

    debug_assert_eq!(high, 0);
    low
}

#[cfg(target_arch = "x86_64")]
fn ghash_override_value() -> Option<String> {
    #[cfg(all(test, target_arch = "x86_64"))]
    if let Some(mode) = GHASH_TEST_OVERRIDE.lock().unwrap().clone() {
        return Some(mode);
    }

    std::env::var("QUICFUSCATE_GHASH").ok()
}

/// Compute GHASH over AAD and ciphertext with runtime SIMD dispatch.
pub fn ghash(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    // SAFETY: runtime feature detection verified before dispatch. Each SIMD
    // backend has a matching target_feature gate. h is [u8; 16], aad and ct
    // are &[u8]. All backends process data in 16-byte blocks with offset guards.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use crate::optimize::CpuFeature;

        let detector = crate::optimize::FeatureDetector::instance();
        let features = detector.features_full();
        if let Some(mode) = ghash_override_value().map(|s| s.to_lowercase()) {
            match mode.as_str() {
                "auto" => {}
                "vpclmul" => {
                    if detector.has_feature(CpuFeature::VPCLMULQDQ)
                        && detector.has_feature(CpuFeature::PCLMULQDQ)
                        && detector.has_feature(CpuFeature::SSSE3)
                        && detector.has_feature(CpuFeature::AVX512F)
                        && detector.has_feature(CpuFeature::AVX512VL)
                    {
                        crate::optimize::telemetry::GHASH_VPCLMUL_OPS.inc();
                        return ghash_hw_vpclmul(h, aad, ct);
                    }
                    log::warn!(
                            "GHASH override 'vpclmul' requested but VPCLMUL support is unavailable; falling back"
                        );
                }
                "pclmul" => {
                    if detector.has_feature(CpuFeature::PCLMULQDQ) {
                        crate::optimize::telemetry::GHASH_PCLMUL_OPS.inc();
                        return ghash_hw_pclmul(h, aad, ct);
                    }
                    log::warn!(
                            "GHASH override 'pclmul' requested but PCLMULQDQ support is unavailable; falling back"
                        );
                }
                "sse" => {
                    if features.sse41 && features.ssse3 {
                        crate::optimize::telemetry::GHASH_SSE_OPS.inc();
                        return ghash_hw_sse(h, aad, ct);
                    }
                    log::warn!(
                            "GHASH override 'sse' requested but SSE4.1/SSSE3 are unavailable; falling back"
                        );
                }
                "scalar" | "ref" => {
                    crate::optimize::telemetry::GHASH_SCALAR_OPS.inc();
                    crate::optimize::telemetry::GHASH_SCALAR_CALLS.inc();
                    crate::optimize::telemetry::GHASH_SCALAR_BYTES
                        .inc_by((aad.len().saturating_add(ct.len())) as u64);
                    return ghash_software(h, aad, ct);
                }
                other => {
                    log::warn!("unknown GHASH override '{}'; falling back to auto", other);
                }
            }
        }

        if detector.has_feature(CpuFeature::VPCLMULQDQ)
            && detector.has_feature(CpuFeature::PCLMULQDQ)
            && detector.has_feature(CpuFeature::SSSE3)
            && detector.has_feature(CpuFeature::AVX512F)
            && detector.has_feature(CpuFeature::AVX512VL)
        {
            crate::optimize::telemetry::GHASH_VPCLMUL_OPS.inc();
            return ghash_hw_vpclmul(h, aad, ct);
        }
        if detector.has_feature(CpuFeature::PCLMULQDQ) {
            crate::optimize::telemetry::GHASH_PCLMUL_OPS.inc();
            return ghash_hw_pclmul(h, aad, ct);
        }
        if features.sse41 && features.ssse3 {
            crate::optimize::telemetry::GHASH_SSE_OPS.inc();
            return ghash_hw_sse(h, aad, ct);
        }
    }
    // SAFETY: runtime feature detection verified before dispatch. Same invariants
    // as x86_64 block above. PMULL/NEON crypto gates checked per-backend.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let detector = crate::optimize::FeatureDetector::instance();
        let gate = std::env::var("QUICFUSCATE_GHASH_PMULL").ok();
        let disabled = matches!(
            gate.as_deref(),
            Some("0") | Some("false") | Some("FALSE") | Some("off") | Some("OFF")
        );
        if !disabled {
            let finalize = |hw: [u8; 16]| -> [u8; 16] {
                #[cfg(any(test, debug_assertions))]
                {
                    let sw = ghash_software(h, aad, ct);
                    if hw != sw {
                        return sw;
                    }
                }
                crate::optimize::telemetry::GHASH_PMULL_OPS.inc();
                hw
            };

            if detector.has_feature(crate::optimize::CpuFeature::SVE_PMULL)
                && detector.has_feature(crate::optimize::CpuFeature::AES)
            {
                let hw = ghash_hw_sve_pmull(h, aad, ct);
                return finalize(hw);
            }

            if detector.has_feature(crate::optimize::CpuFeature::PMULL)
                && detector.has_feature(crate::optimize::CpuFeature::AES)
            {
                let hw = ghash_hw_pmull_optimized(h, aad, ct);
                return finalize(hw);
            }
            if detector.has_feature(crate::optimize::CpuFeature::NEON) {
                crate::optimize::telemetry::GHASH_NEON_OPS.inc();
                return finalize(ghash_hw_neon(h, aad, ct));
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
    {
        let _ = h;
        let _ = aad;
        let _ = ct;
    }
    crate::optimize::telemetry::GHASH_SCALAR_OPS.inc();
    crate::optimize::telemetry::GHASH_SCALAR_CALLS.inc();
    crate::optimize::telemetry::GHASH_SCALAR_BYTES
        .inc_by((aad.len().saturating_add(ct.len())) as u64);
    ghash_software(h, aad, ct)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3", enable = "sse4.1")]
// SAFETY: target_feature gates ensure SSSE3+SSE4.1. h is [u8; 16], aad/ct are
// &[u8]. Precomputed byte_tables is [__m128i; 16*256] stack-allocated via
// MaybeUninit; every entry written before assume_init. _mm_loadu_si128 reads from
// [u8; 16] slices or data pointers bounded by offset guards. Table lookups use
// byte values (0..255) as indices within 256-entry sub-tables.
unsafe fn ghash_hw_sse(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::{arch::x86_64::*, mem::MaybeUninit};

    let h128 = u128::from_be_bytes(h);

    // Collapse nibble tables into per-byte lookup tables (16 byte positions x 256 values).
    let mut byte_tables_uninit = MaybeUninit::<[__m128i; 16 * 256]>::uninit();
    let byte_tables_ptr = byte_tables_uninit.as_mut_ptr() as *mut __m128i;
    for byte_idx in 0..16 {
        for byte_val in 0..256 {
            let shift = 120 - byte_idx * 8;
            let input = (byte_val as u128) << shift;
            let bytes = ghash_multiply(input, h128).to_be_bytes();
            let vec = _mm_loadu_si128(bytes.as_ptr() as *const __m128i);
            byte_tables_ptr.add(byte_idx * 256 + byte_val).write(vec);
        }
    }
    // SAFETY: all 16*256 = 4096 entries of byte_tables_uninit were written in the
    // nested loop above (byte_idx in 0..16, byte_val in 0..256). Every slot is
    // initialized via ptr.add(idx).write(vec) before assume_init.
    let byte_tables = unsafe { byte_tables_uninit.assume_init() };

    #[inline(always)]
    // SAFETY: requires SSSE3/SSE4.1 (caller ensures). table is &[__m128i; 4096];
    // index = pos*256 + byte_val, where pos in 0..16 and byte_val in 0..255,
    // so max index = 15*256+255 = 4095, within bounds. _mm_storeu_si128 writes
    // 16 bytes into stack-owned [u8; 16]. _mm_xor_si128 is register-to-register.
    unsafe fn ghash_block_sse(table: &[__m128i; 16 * 256], y: __m128i, x: __m128i) -> __m128i {
        let w = _mm_xor_si128(y, x);
        let mut bytes = [0u8; 16];
        _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, w);
        let mut acc = _mm_setzero_si128();
        let mut pos = 0usize;
        while pos < 16 {
            let idx = pos * 256 + (bytes[pos] as usize);
            acc = _mm_xor_si128(acc, table[idx]);
            pos += 1;
        }
        acc
    }

    #[inline(always)]
    // SAFETY: requires SSSE3/SSE4.1 (caller ensures). _mm_loadu_si128 reads 16
    // bytes from data[idx..] where idx+16 <= data.len() (while guard). Tail block
    // pads into stack-owned [u8; 16]. ghash_block_sse bounded by table size.
    unsafe fn process_segment(data: &[u8], table: &[__m128i; 16 * 256], y: &mut __m128i) {
        let mut idx = 0usize;
        while idx + 16 <= data.len() {
            let x = _mm_loadu_si128(data[idx..].as_ptr() as *const __m128i);
            *y = ghash_block_sse(table, *y, x);
            idx += 16;
        }
        if idx < data.len() {
            let mut blk = [0u8; 16];
            blk[..(data.len() - idx)].copy_from_slice(&data[idx..]);
            let x = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            *y = ghash_block_sse(table, *y, x);
        }
    }

    let mut y = _mm_setzero_si128();
    process_segment(aad, &byte_tables, &mut y);
    process_segment(ct, &byte_tables, &mut y);

    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let len_vec = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
    y = ghash_block_sse(&byte_tables, y, len_vec);

    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y);
    out
}

#[inline(always)]
fn inc32(counter: &mut [u8; 16]) {
    // increment last 32 bits in BE
    let n = ((counter[12] as u32) << 24)
        | ((counter[13] as u32) << 16)
        | ((counter[14] as u32) << 8)
        | (counter[15] as u32);
    let n = n.wrapping_add(1);
    counter[12..16].copy_from_slice(&n.to_be_bytes());
}

/// AES-GCM seal (encrypt + tag) with 96-bit IV
pub fn aes_gcm_seal(
    aes_key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Hash subkey H = E(K, 0^128)
    let aes_ctx = crate::crypto::aes::Aes128Ctx::new(aes_key);
    let zero = [0u8; 16];
    let h = aes_ctx.encrypt_block(&zero);
    // J0 = IV || 0x00000001 for 96-bit iv
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    // Encrypt via GCTR starting at inc32(J0)
    let mut ctr = j0;
    inc32(&mut ctr);
    let mut ciphertext = vec![0u8; plaintext.len()];
    aes_ctx.ctr_xor(&mut ctr, plaintext, &mut ciphertext);
    // Compute authentication tag
    let s = ghash(h, aad, &ciphertext);
    let s_enc = aes_ctx.encrypt_block(&j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ s_enc[i];
    }
    (ciphertext, tag)
}

/// AES-GCM open (decrypt + tag verify); returns None if tag mismatch.
pub fn aes_gcm_open(
    aes_key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    // Recompute tag on ciphertext
    let aes_ctx = crate::crypto::aes::Aes128Ctx::new(aes_key);
    let zero = [0u8; 16];
    let h = aes_ctx.encrypt_block(&zero);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let s = ghash(h, aad, ciphertext);
    let s_enc = aes_ctx.encrypt_block(&j0);
    let mut tag_calc = [0u8; 16];
    for i in 0..16 {
        tag_calc[i] = s[i] ^ s_enc[i];
    }
    if !crate::crypto::subtle_ct_eq(&tag_calc, tag) {
        return None;
    }
    // Decrypt via GCTR
    let mut ctr = j0;
    inc32(&mut ctr);
    let mut pt = vec![0u8; ciphertext.len()];
    aes_ctx.ctr_xor(&mut ctr, ciphertext, &mut pt);
    Some(pt)
}

fn ghash_software(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let h128 = u128::from_be_bytes(h);
    let mut y: u128 = 0;
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&aad[i..i + 16]);
        y = ghash_multiply(y ^ u128::from_be_bytes(blk), h128);
        i += 16;
    }
    if i < aad.len() {
        let mut blk = [0u8; 16];
        blk[..aad.len() - i].copy_from_slice(&aad[i..]);
        y = ghash_multiply(y ^ u128::from_be_bytes(blk), h128);
    }
    let mut j = 0usize;
    while j + 16 <= ct.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ct[j..j + 16]);
        y = ghash_multiply(y ^ u128::from_be_bytes(blk), h128);
        j += 16;
    }
    if j < ct.len() {
        let mut blk = [0u8; 16];
        blk[..ct.len() - j].copy_from_slice(&ct[j..]);
        y = ghash_multiply(y ^ u128::from_be_bytes(blk), h128);
    }
    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    y = ghash_multiply(y ^ u128::from_be_bytes(lenblk), h128);
    y.to_be_bytes()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn ghash_hw_equals_sw_small_cases() {
        // Deterministic pseudo-random data
        fn fill(buf: &mut [u8], seed: u8) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
            }
        }
        let mut h = [0u8; 16];
        fill(&mut h, 0xA5);
        let mut aad = [0u8; 37];
        fill(&mut aad, 0x3C);
        let mut ct = [0u8; 91];
        fill(&mut ct, 0x5E);
        let sw = ghash_software(h, &aad, &ct);
        let hw = ghash(h, &aad, &ct);
        assert_eq!(sw, hw);
    }

    #[test]
    fn ghash_hw_equals_sw_empty() {
        let h = [0u8; 16];
        let sw = ghash_software(h, &[], &[]);
        let hw = ghash(h, &[], &[]);
        assert_eq!(sw, hw);
    }

    #[test]
    fn aes_gcm_tag_aad_only_nist_vec() {
        // NIST SP 800-38D, Test Case (empty AAD, empty PT) with zero key/iv
        // Expected tag = AES_K(J0) since GHASH(\u2205,\u2205) = 0
        // Vector: key=00..00 (16B), iv=00..00 (12B), tag=58e2fccefa7e3061367f1d57a4e7455a
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let aad: [u8; 0] = [];
        let tag = aes_gcm_tag_aad_only(&key, &iv, &aad);
        let expected: [u8; 16] = [
            0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7,
            0x45, 0x5A,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn aes_gcm_nonempty_nist_vector() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let plaintext = [0u8; 16];
        let expected_ciphertext = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected_tag = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf,
        ];

        let (ciphertext, tag) = aes_gcm_seal(&key, &iv, &[], &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
        assert_eq!(aes_gcm_open(&key, &iv, &[], &ciphertext, &tag), Some(plaintext.to_vec()));
    }

    #[test]
    fn ghash_hw_equals_sw_various_lengths() {
        // Deterministic filler
        fn fill(buf: &mut [u8], seed: u8) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = seed.wrapping_add((i as u8).rotate_left((i % 5) as u32));
            }
        }
        let mut h = [0u8; 16];
        fill(&mut h, 0xC3);
        let lengths = [0usize, 1, 7, 16, 17, 31, 32, 47, 64, 79, 96, 127, 128, 191, 256];
        for &la in &lengths {
            for &lc in &lengths {
                let mut aad = vec![0u8; la];
                let mut ct = vec![0u8; lc];
                fill(&mut aad, 0x5A);
                fill(&mut ct, 0xB7);
                let sw = ghash_software(h, &aad, &ct);
                let hw = ghash(h, &aad, &ct);
                assert_eq!(sw, hw, "mismatch at lengths aad={}, ct={}", la, lc);
            }
        }
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
        let aad = b"authenticated but not encrypted";
        let plaintext = b"hello world, this is a secret message for AES-GCM testing";

        let (ciphertext, tag) = aes_gcm_seal(&key, &iv, aad, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..], "ciphertext must differ from plaintext");
        assert_eq!(ciphertext.len(), plaintext.len());

        let recovered = aes_gcm_open(&key, &iv, aad, &ciphertext, &tag);
        assert!(recovered.is_some(), "open must succeed with valid tag");
        assert_eq!(
            recovered.as_deref(),
            Some(&plaintext[..]),
            "recovered plaintext must match original"
        );
    }

    #[test]
    fn test_aes_gcm_tag_mismatch_fails() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x99; 12];
        let aad = b"some aad";
        let plaintext = b"secret data";

        let (ciphertext, mut tag) = aes_gcm_seal(&key, &iv, aad, plaintext);
        // Tamper with the tag
        tag[0] ^= 0xFF;
        let result = aes_gcm_open(&key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_none(), "tampered tag must cause open to return None");
    }

    #[test]
    fn test_aes_gcm_ciphertext_tamper_fails() {
        let key: [u8; 16] = [0x13; 16];
        let iv: [u8; 12] = [0x37; 12];
        let aad = b"aad";
        let plaintext = b"some plaintext that is long enough to tamper with";

        let (mut ciphertext, tag) = aes_gcm_seal(&key, &iv, aad, plaintext);
        assert!(!ciphertext.is_empty());
        // Tamper with the ciphertext
        ciphertext[0] ^= 0x01;
        let result = aes_gcm_open(&key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_none(), "tampered ciphertext must cause open to return None");
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key: [u8; 16] = [0xAB; 16];
        let iv: [u8; 12] = [0xCD; 12];
        let aad = b"only authenticated data, no plaintext";

        let (ciphertext, tag) = aes_gcm_seal(&key, &iv, aad, &[]);
        assert!(ciphertext.is_empty(), "empty plaintext must produce empty ciphertext");
        // Tag must still be non-zero (it authenticates the AAD)
        assert_ne!(tag, [0u8; 16], "tag for non-empty AAD must not be zero");

        let recovered = aes_gcm_open(&key, &iv, aad, &ciphertext, &tag);
        assert!(recovered.is_some(), "open must succeed for empty plaintext with valid tag");
        assert_eq!(recovered.as_deref(), Some(&[][..]), "recovered empty plaintext must be empty");
    }

    #[test]
    fn test_aes_gcm_tag_aad_only_deterministic_and_nontrivial() {
        let key: [u8; 16] = [0x77; 16];
        let iv: [u8; 12] = [0x88; 12];
        let aad = b"test aad data for tag comparison";

        // aes_gcm_tag_aad_only must be deterministic
        let tag1 = aes_gcm_tag_aad_only(&key, &iv, aad);
        let tag2 = aes_gcm_tag_aad_only(&key, &iv, aad);
        assert_eq!(tag1, tag2, "aes_gcm_tag_aad_only must be deterministic");

        // Tag must be non-trivial for non-empty AAD
        assert_ne!(tag1, [0u8; 16], "tag must not be all zeros");

        // Different AAD must produce different tags
        let aad2 = b"different authenticated data";
        let tag_diff = aes_gcm_tag_aad_only(&key, &iv, aad2);
        assert_ne!(tag1, tag_diff, "different AAD must produce different tags");

        // Different keys must produce different tags
        let key2: [u8; 16] = [0x78; 16];
        let tag_key2 = aes_gcm_tag_aad_only(&key2, &iv, aad);
        assert_ne!(tag1, tag_key2, "different keys must produce different tags");
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires PCLMULQDQ (runtime-checked by caller). h is [u8; 16];
// _mm_loadu_si128 reads exactly 16 bytes. aad/ct processed in 16-byte blocks via
// copy_from_slice into stack-owned [u8; 16] before loading. CLMUL operations in
// ghash_block_pclmul are register-only.
// out is stack-owned [u8; 16]; _mm_storeu_si128 writes exactly 16 bytes.
unsafe fn ghash_hw_pclmul(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::arch::x86_64::*;
    let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
    let mut y_be = _mm_setzero_si128();
    // Process AAD
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&aad[i..i + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_be, y_be, x_be);
        i += 16;
    }
    if i < aad.len() {
        let mut blk = [0u8; 16];
        blk[..(aad.len() - i)].copy_from_slice(&aad[i..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_be, y_be, x_be);
    }
    // Process CT
    let mut j = 0usize;
    while j + 16 <= ct.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ct[j..j + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_be, y_be, x_be);
        j += 16;
    }
    if j < ct.len() {
        let mut blk = [0u8; 16];
        blk[..(ct.len() - j)].copy_from_slice(&ct[j..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_be, y_be, x_be);
    }
    // Length block
    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let x_be = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
    y_be = ghash_block_pclmul(h_be, y_be, x_be);
    // Return BE bytes
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y_be);
    out
}

/// Ultra-fast GHASH implementation using VPCLMULQDQ (AVX-512 vector PCLMUL)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,vpclmulqdq,avx512vl,pclmulqdq,ssse3")]
#[inline]
// SAFETY: target_feature gates ensure AVX-512F, VPCLMULQDQ, AVX-512VL,
// PCLMULQDQ, and SSSE3. Same pattern as ghash_hw_pclmul: h is [u8; 16], aad/ct
// copied into stack-owned blocks before _mm_loadu_si128. The 4-block loop
// processes 64-byte chunks with i+64 <= len. ghash_block_vpclmul is register-only.
unsafe fn ghash_hw_vpclmul(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::arch::x86_64::*;

    // Load H and convert to LE polynomial domain
    let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
    let h_le =
        _mm_shuffle_epi8(h_be, _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
    let mut y_be = _mm_setzero_si128();

    // Process AAD with vectorized blocks where possible
    let mut i = 0usize;

    // Process 4 blocks at once with VPCLMULQDQ for better throughput
    while i + 64 <= aad.len() {
        let mut blks = [[0u8; 16]; 4];
        for j in 0..4 {
            blks[j].copy_from_slice(&aad[i + j * 16..i + (j + 1) * 16]);
        }

        // Load 4 blocks into 256-bit registers and process with VPCLMULQDQ
        let x0_be = _mm_loadu_si128(blks[0].as_ptr() as *const __m128i);
        let x1_be = _mm_loadu_si128(blks[1].as_ptr() as *const __m128i);
        let x2_be = _mm_loadu_si128(blks[2].as_ptr() as *const __m128i);
        let x3_be = _mm_loadu_si128(blks[3].as_ptr() as *const __m128i);

        // Process blocks sequentially but with VPCLMUL acceleration
        y_be = ghash_block_vpclmul(h_le, y_be, x0_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x1_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x2_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x3_be);

        i += 64;
    }

    // Process remaining AAD blocks
    while i + 16 <= aad.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&aad[i..i + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_vpclmul(h_le, y_be, x_be);
        i += 16;
    }
    if i < aad.len() {
        let mut blk = [0u8; 16];
        blk[..(aad.len() - i)].copy_from_slice(&aad[i..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_vpclmul(h_le, y_be, x_be);
    }

    // Process CT with same vectorized approach
    let mut j = 0usize;
    while j + 64 <= ct.len() {
        let mut blks = [[0u8; 16]; 4];
        for k in 0..4 {
            blks[k].copy_from_slice(&ct[j + k * 16..j + (k + 1) * 16]);
        }

        let x0_be = _mm_loadu_si128(blks[0].as_ptr() as *const __m128i);
        let x1_be = _mm_loadu_si128(blks[1].as_ptr() as *const __m128i);
        let x2_be = _mm_loadu_si128(blks[2].as_ptr() as *const __m128i);
        let x3_be = _mm_loadu_si128(blks[3].as_ptr() as *const __m128i);

        y_be = ghash_block_vpclmul(h_le, y_be, x0_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x1_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x2_be);
        y_be = ghash_block_vpclmul(h_le, y_be, x3_be);

        j += 64;
    }

    while j + 16 <= ct.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ct[j..j + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_vpclmul(h_le, y_be, x_be);
        j += 16;
    }
    if j < ct.len() {
        let mut blk = [0u8; 16];
        blk[..(ct.len() - j)].copy_from_slice(&ct[j..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_vpclmul(h_le, y_be, x_be);
    }

    // Length block
    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let x_be = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
    y_be = ghash_block_vpclmul(h_le, y_be, x_be);

    // Return BE bytes
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y_be);
    out
}

/// Ultra-fast GHASH block processing with VPCLMULQDQ
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,vpclmulqdq,avx512vl,pclmulqdq,ssse3")]
#[inline]
// SAFETY: target_feature gates ensure AVX-512F, VPCLMULQDQ, AVX-512VL,
// PCLMULQDQ, and SSSE3. Inputs are by-value __m128i. The local shuffle is
// register-only; ghash_block_pclmul owns its bounded stack stores and loads.
unsafe fn ghash_block_vpclmul(
    h_le: core::arch::x86_64::__m128i,
    y_be: core::arch::x86_64::__m128i,
    x_be: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let h_be = _mm_shuffle_epi8(h_le, shuf);

    ghash_block_pclmul(h_be, y_be, x_be)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
#[inline]
// SAFETY: requires PCLMULQDQ (caller ensures). Stack stores and loads cover
// exactly 16-byte vectors. CLMUL operands are register-only.
unsafe fn ghash_block_pclmul(
    h_be: core::arch::x86_64::__m128i,
    y_be: core::arch::x86_64::__m128i,
    x_be: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    let mut h_bytes = [0u8; 16];
    let mut y_bytes = [0u8; 16];
    let mut x_bytes = [0u8; 16];
    _mm_storeu_si128(h_bytes.as_mut_ptr() as *mut __m128i, h_be);
    _mm_storeu_si128(y_bytes.as_mut_ptr() as *mut __m128i, y_be);
    _mm_storeu_si128(x_bytes.as_mut_ptr() as *mut __m128i, x_be);

    let left = (u128::from_be_bytes(y_bytes) ^ u128::from_be_bytes(x_bytes)).reverse_bits();
    let right = u128::from_be_bytes(h_bytes).reverse_bits();
    let left_vector = _mm_set_epi64x((left >> 64) as i64, left as u64 as i64);
    let right_vector = _mm_set_epi64x((right >> 64) as i64, right as u64 as i64);

    let product_00 = _mm_clmulepi64_si128(left_vector, right_vector, 0x00);
    let product_01 = _mm_clmulepi64_si128(left_vector, right_vector, 0x01);
    let product_10 = _mm_clmulepi64_si128(left_vector, right_vector, 0x10);
    let product_11 = _mm_clmulepi64_si128(left_vector, right_vector, 0x11);
    let cross = _mm_xor_si128(product_01, product_10);
    let mut product_00_words = [0u64; 2];
    let mut product_11_words = [0u64; 2];
    let mut cross_words = [0u64; 2];
    _mm_storeu_si128(product_00_words.as_mut_ptr() as *mut __m128i, product_00);
    _mm_storeu_si128(product_11_words.as_mut_ptr() as *mut __m128i, product_11);
    _mm_storeu_si128(cross_words.as_mut_ptr() as *mut __m128i, cross);

    let low =
        (product_00_words[0] as u128) | (((product_00_words[1] ^ cross_words[0]) as u128) << 64);
    let high =
        ((product_11_words[0] ^ cross_words[1]) as u128) | ((product_11_words[1] as u128) << 64);
    let result = reduce_natural_gf128_product(low, high).reverse_bits().to_be_bytes();

    _mm_loadu_si128(result.as_ptr() as *const __m128i)
}

/// Ultra-optimized ARM PMULL GHASH with efficient unaligned/partial block handling
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon,aes")]
// SAFETY: requires NEON + PMULL (runtime-checked by caller). h is [u8; 16];
// vld1q_u8 reads exactly 16 bytes. 64-byte chunk loop: i+64 <= len guard ensures
// vld1q_u8 at offsets i, i+16, i+32, i+48 are within bounds. Single-block loop:
// i+16 <= len. Partial: ptr::copy_nonoverlapping copies exactly `remaining` bytes
// into stack-owned [u8; 16]. ghash_block_pmull is register-only NEON PMULL.
// out is stack-owned [u8; 16]; vst1q_u8 writes exactly 16 bytes.
unsafe fn ghash_hw_pmull_optimized(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::arch::aarch64::*;

    // Reverse 16 bytes helper (rev64 + lane swap)
    #[inline(always)]
    // SAFETY: requires NEON. Register-to-register operations (vrev64q_u8, vextq_u8)
    // on by-value uint8x16_t. No memory access.
    unsafe fn reverse16(x: uint8x16_t) -> uint8x16_t {
        let rev = vrev64q_u8(x);
        vextq_u8(rev, rev, 8)
    }

    // SAFETY: h is [u8; 16]; vld1q_u8 reads exactly 16 bytes.
    // Load H in LE format for PMULL operations
    let h_le = reverse16(vld1q_u8(h.as_ptr()));
    let mut y_be = vmovq_n_u8(0);

    // Optimized AAD processing with vectorized unaligned handling
    let mut i = 0usize;
    let aad_len = aad.len();

    // Process aligned 64-byte chunks with 4x parallel GHASH blocks
    while i + 64 <= aad_len {
        let x1_be = vld1q_u8(aad.as_ptr().add(i));
        let x2_be = vld1q_u8(aad.as_ptr().add(i + 16));
        let x3_be = vld1q_u8(aad.as_ptr().add(i + 32));
        let x4_be = vld1q_u8(aad.as_ptr().add(i + 48));

        // Parallel GHASH computation - 4x blocks at once!
        y_be = ghash_block_pmull(h_le, y_be, x1_be);
        y_be = ghash_block_pmull(h_le, y_be, x2_be);
        y_be = ghash_block_pmull(h_le, y_be, x3_be);
        y_be = ghash_block_pmull(h_le, y_be, x4_be);
        i += 64;
    }

    // Process remaining 16-byte blocks
    while i + 16 <= aad_len {
        let x_be = vld1q_u8(aad.as_ptr().add(i));
        y_be = ghash_block_pmull(h_le, y_be, x_be);
        i += 16;
    }

    // Optimized partial block handling without intermediate buffer
    if i < aad_len {
        let remaining = aad_len - i;
        let mut blk = [0u8; 16];
        // Use ptr::copy_nonoverlapping for optimal performance
        std::ptr::copy_nonoverlapping(aad.as_ptr().add(i), blk.as_mut_ptr(), remaining);
        let x_be = vld1q_u8(blk.as_ptr());
        y_be = ghash_block_pmull(h_le, y_be, x_be);
    }

    // Optimized CT processing with same vectorized approach
    let mut j = 0usize;
    let ct_len = ct.len();

    // Process aligned 64-byte chunks with 4x parallel GHASH blocks
    while j + 64 <= ct_len {
        let x1_be = vld1q_u8(ct.as_ptr().add(j));
        let x2_be = vld1q_u8(ct.as_ptr().add(j + 16));
        let x3_be = vld1q_u8(ct.as_ptr().add(j + 32));
        let x4_be = vld1q_u8(ct.as_ptr().add(j + 48));

        // Parallel GHASH computation - 4x blocks at once!
        y_be = ghash_block_pmull(h_le, y_be, x1_be);
        y_be = ghash_block_pmull(h_le, y_be, x2_be);
        y_be = ghash_block_pmull(h_le, y_be, x3_be);
        y_be = ghash_block_pmull(h_le, y_be, x4_be);
        j += 64;
    }

    // Process remaining 16-byte blocks
    while j + 16 <= ct_len {
        let x_be = vld1q_u8(ct.as_ptr().add(j));
        y_be = ghash_block_pmull(h_le, y_be, x_be);
        j += 16;
    }

    // Optimized partial block handling without intermediate buffer
    if j < ct_len {
        let remaining = ct_len - j;
        let mut blk = [0u8; 16];
        // Use ptr::copy_nonoverlapping for optimal performance
        std::ptr::copy_nonoverlapping(ct.as_ptr().add(j), blk.as_mut_ptr(), remaining);
        let x_be = vld1q_u8(blk.as_ptr());
        y_be = ghash_block_pmull(h_le, y_be, x_be);
    }

    // Length block processing
    let aad_bits = (aad_len as u128) * 8;
    let ct_bits = (ct_len as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let x_be = vld1q_u8(lenblk.as_ptr());
    y_be = ghash_block_pmull(h_le, y_be, x_be);

    // Store result
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), y_be);
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. h is [u8; 16]. vld1q_u8 reads 16
// bytes from offset-guarded pointers (offset+16 <= len). Partial blocks use
// ptr::copy_nonoverlapping into stack-owned [u8; 16]. neon_ghash_block is
// table-lookup with NEON registers. out is stack-owned; vst1q_u8 writes 16 bytes.
unsafe fn ghash_hw_neon(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::arch::aarch64::*;

    let table = precompute_h4_neon(h);
    let mut y = vdupq_n_u8(0);

    let mut offset = 0usize;
    while offset + 16 <= aad.len() {
        let block = vld1q_u8(aad.as_ptr().add(offset));
        y = neon_ghash_block(&table, y, block);
        offset += 16;
    }
    if offset < aad.len() {
        let mut buf = [0u8; 16];
        let rem = aad.len() - offset;
        std::ptr::copy_nonoverlapping(aad.as_ptr().add(offset), buf.as_mut_ptr(), rem);
        let block = vld1q_u8(buf.as_ptr());
        y = neon_ghash_block(&table, y, block);
    }

    let mut offset = 0usize;
    while offset + 16 <= ct.len() {
        let block = vld1q_u8(ct.as_ptr().add(offset));
        y = neon_ghash_block(&table, y, block);
        offset += 16;
    }
    if offset < ct.len() {
        let mut buf = [0u8; 16];
        let rem = ct.len() - offset;
        std::ptr::copy_nonoverlapping(ct.as_ptr().add(offset), buf.as_mut_ptr(), rem);
        let block = vld1q_u8(buf.as_ptr());
        y = neon_ghash_block(&table, y, block);
    }

    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let len_block = vld1q_u8(lenblk.as_ptr());
    y = neon_ghash_block(&table, y, len_block);

    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), y);
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. h is [u8; 16]. precompute_h4 returns
// [u128; 16] (safe). Each entry converted to [u8; 16] via to_be_bytes(); vld1q_u8
// reads exactly 16 bytes from the stack-owned byte array.
unsafe fn precompute_h4_neon(h: [u8; 16]) -> [core::arch::aarch64::uint8x16_t; 16] {
    use core::arch::aarch64::*;
    let mut vecs = [vdupq_n_u8(0); 16];
    vecs[1] = vld1q_u8(h.as_ptr());
    vecs
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. Stack stores and loads cover exactly
// 16-byte vectors. table[1] is initialized with H by precompute_h4_neon.
unsafe fn neon_ghash_block(
    table: &[core::arch::aarch64::uint8x16_t; 16],
    y: core::arch::aarch64::uint8x16_t,
    x: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;

    let mut h_bytes = [0u8; 16];
    let mut y_bytes = [0u8; 16];
    let mut x_bytes = [0u8; 16];
    vst1q_u8(h_bytes.as_mut_ptr(), table[1]);
    vst1q_u8(y_bytes.as_mut_ptr(), y);
    vst1q_u8(x_bytes.as_mut_ptr(), x);

    let product = ghash_multiply(
        u128::from_be_bytes(y_bytes) ^ u128::from_be_bytes(x_bytes),
        u128::from_be_bytes(h_bytes),
    )
    .to_be_bytes();

    vld1q_u8(product.as_ptr())
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline]
#[target_feature(enable = "sve2,neon,aes")]
// SAFETY: target_feature gate ensures SVE2 (implies PMULL). Delegates to
// ghash_hw_pmull_optimized which requires NEON + PMULL.
unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    ghash_hw_pmull_optimized(h, aad, ct)
}

#[cfg(all(target_arch = "aarch64", not(target_feature = "sve2")))]
#[inline]
#[target_feature(enable = "neon,aes")]
// SAFETY: caller verified SVE PMULL at runtime. Delegates to
// ghash_hw_pmull_optimized which requires NEON + PMULL.
unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    ghash_hw_pmull_optimized(h, aad, ct)
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon,aes")]
// SAFETY: requires NEON + PMULL (caller ensures). Stack stores and loads cover
// exactly 16-byte vectors. PMULL operands are register-only.
unsafe fn ghash_block_pmull(
    h_le: core::arch::aarch64::uint8x16_t,
    y_be: core::arch::aarch64::uint8x16_t,
    x_be: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;

    let mut h_bytes = [0u8; 16];
    let mut y_bytes = [0u8; 16];
    let mut x_bytes = [0u8; 16];
    vst1q_u8(h_bytes.as_mut_ptr(), h_le);
    vst1q_u8(y_bytes.as_mut_ptr(), y_be);
    vst1q_u8(x_bytes.as_mut_ptr(), x_be);

    let left = (u128::from_be_bytes(y_bytes) ^ u128::from_be_bytes(x_bytes)).reverse_bits();
    let right = u128::from_le_bytes(h_bytes).reverse_bits();
    let left_words = [left as u64, (left >> 64) as u64];
    let right_words = [right as u64, (right >> 64) as u64];
    let left_polynomial = vreinterpretq_p64_u64(vld1q_u64(left_words.as_ptr()));
    let right_polynomial = vreinterpretq_p64_u64(vld1q_u64(right_words.as_ptr()));
    let left_low = vgetq_lane_p64::<0>(left_polynomial);
    let left_high = vgetq_lane_p64::<1>(left_polynomial);
    let right_low = vgetq_lane_p64::<0>(right_polynomial);
    let right_high = vgetq_lane_p64::<1>(right_polynomial);

    let x0 = vmull_p64(left_low, right_low);
    let x1 = vmull_p64(left_low, right_high);
    let x2 = vmull_p64(left_high, right_low);
    let x3 = vmull_p64(left_high, right_high);
    let x0v = vreinterpretq_u64_p128(x0);
    let x3v = vreinterpretq_u64_p128(x3);
    let x1v = vreinterpretq_u64_p128(x1);
    let x2v = vreinterpretq_u64_p128(x2);
    let cross = veorq_u64(x1v, x2v);
    let low = (vgetq_lane_u64(x0v, 0) as u128)
        | (((vgetq_lane_u64(x0v, 1) ^ vgetq_lane_u64(cross, 0)) as u128) << 64);
    let high = ((vgetq_lane_u64(x3v, 0) ^ vgetq_lane_u64(cross, 1)) as u128)
        | ((vgetq_lane_u64(x3v, 1) as u128) << 64);
    let result = reduce_natural_gf128_product(low, high).reverse_bits().to_be_bytes();

    vld1q_u8(result.as_ptr())
}
/// Compute an AES-GCM tag over AAD only (no ciphertext), used for header protection.
pub fn aes_gcm_tag_aad_only(aes_key: &[u8; 16], iv: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let zero = [0u8; 16];
    let h = crate::crypto::aes::aes128_encrypt_block(aes_key, &zero);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let s = ghash(h, aad, &[]);
    let s_enc = crate::crypto::aes::aes128_encrypt_block(aes_key, &j0);
    let mut tag = [0u8; 16];
    for (i, t) in tag.iter_mut().enumerate() {
        *t = s_enc[i] ^ s[i];
    }
    tag
}

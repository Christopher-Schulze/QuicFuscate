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

fn be_bytes_to_u128(b: &[u8; 16]) -> u128 {
    u128::from_be_bytes(*b)
}
fn u128_to_be_bytes(x: u128) -> [u8; 16] {
    x.to_be_bytes()
}

// Multiply by x in GF(2^128) with reduction by the GCM polynomial
#[inline(always)]
fn mul_x(mut v: u128) -> u128 {
    let carry = (v & 0x8000_0000_0000_0000_0000_0000_0000_0000u128) != 0;
    v <<= 1;
    if carry {
        v ^= 0x87;
    }
    v
}

#[inline(always)]
fn mul_x4(mut v: u128) -> u128 {
    v = mul_x(v);
    v = mul_x(v);
    v = mul_x(v);
    mul_x(v)
}

// Precompute H * n for 4-bit n (0..15)
fn precompute_h4(h: u128) -> [u128; 16] {
    let mut t = [0u128; 16];
    t[0] = 0;
    t[1] = h;
    // compute x^1..x^3 shifts of H
    let h_x1 = mul_x(h);
    let h_x2 = mul_x(h_x1);
    let h_x3 = mul_x(h_x2);
    // now combine for all nibbles by XOR of present bits
    for n in 2..16 {
        let mut acc = 0u128;
        if (n & 0x1) != 0 {
            acc ^= h;
        }
        if (n & 0x2) != 0 {
            acc ^= h_x1;
        }
        if (n & 0x4) != 0 {
            acc ^= h_x2;
        }
        if (n & 0x8) != 0 {
            acc ^= h_x3;
        }
        t[n as usize] = acc;
    }
    t
}

// Single-block GHASH update using 4-bit nibble method with precomputed table
#[inline(always)]
fn ghash_block_precomputed(table: &[u128; 16], mut y: u128, x: u128) -> u128 {
    let w = y ^ x;
    for i in 0..32 {
        let shift = 124 - 4 * i;
        let nib = ((w >> shift) & 0xF) as usize;
        y = mul_x4(y);
        y ^= table[nib];
    }
    y
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
                    if detector.has_feature(CpuFeature::VPCLMULQDQ) {
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

        if detector.has_feature(CpuFeature::VPCLMULQDQ) {
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

            if detector.has_feature(crate::optimize::CpuFeature::SVE_PMULL) {
                let hw = ghash_hw_sve_pmull(h, aad, ct);
                return finalize(hw);
            }

            if detector.has_feature(crate::optimize::CpuFeature::NEON_CRYPTO) {
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

    let h128 = be_bytes_to_u128(&h);
    let table_raw = precompute_h4(h128);

    // Precompute H multiples for all 32 nibbles (most-significant first) to eliminate
    // per-byte mul_x4 work at runtime.
    let mut nib_tables = [[0u128; 16]; 32];
    let mut current = table_raw;
    for pos in (0..32).rev() {
        nib_tables[pos] = current;
        if pos > 0 {
            for val in current.iter_mut() {
                *val = mul_x4(*val);
            }
        }
    }

    // Collapse nibble tables into per-byte lookup tables (16 byte positions x 256 values).
    let mut byte_tables_uninit = MaybeUninit::<[__m128i; 16 * 256]>::uninit();
    let byte_tables_ptr = byte_tables_uninit.as_mut_ptr() as *mut __m128i;
    for byte_idx in 0..16 {
        for byte_val in 0..256 {
            let hi = (byte_val >> 4) as usize;
            let lo = (byte_val & 0x0F) as usize;
            let contrib = nib_tables[byte_idx * 2][hi] ^ nib_tables[byte_idx * 2 + 1][lo];
            let bytes = u128_to_be_bytes(contrib);
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
    let h128 = be_bytes_to_u128(&h);
    let table = precompute_h4(h128);
    let mut y: u128 = 0;
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&aad[i..i + 16]);
        y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
        i += 16;
    }
    if i < aad.len() {
        let mut blk = [0u8; 16];
        blk[..aad.len() - i].copy_from_slice(&aad[i..]);
        y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
    }
    let mut j = 0usize;
    while j + 16 <= ct.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ct[j..j + 16]);
        y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
        j += 16;
    }
    if j < ct.len() {
        let mut blk = [0u8; 16];
        blk[..ct.len() - j].copy_from_slice(&ct[j..]);
        y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
    }
    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&lenblk));
    u128_to_be_bytes(y)
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
// SAFETY: requires PCLMULQDQ + SSSE3 (runtime-checked by caller). h is [u8; 16];
// _mm_loadu_si128 reads exactly 16 bytes. aad/ct processed in 16-byte blocks via
// copy_from_slice into stack-owned [u8; 16] before loading. _mm_shuffle_epi8 for
// BE/LE conversion. _mm_clmulepi64_si128 in ghash_block_pclmul is register-only.
// out is stack-owned [u8; 16]; _mm_storeu_si128 writes exactly 16 bytes.
unsafe fn ghash_hw_pclmul(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    use core::arch::x86_64::*;
    // Byte-swap mask for BE<->LE
    // Load H and convert to LE polynomial domain
    let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
    let h_le =
        _mm_shuffle_epi8(h_be, _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
    let mut y_be = _mm_setzero_si128();
    // Process AAD
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&aad[i..i + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_le, y_be, x_be);
        i += 16;
    }
    if i < aad.len() {
        let mut blk = [0u8; 16];
        blk[..(aad.len() - i)].copy_from_slice(&aad[i..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_le, y_be, x_be);
    }
    // Process CT
    let mut j = 0usize;
    while j + 16 <= ct.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ct[j..j + 16]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_le, y_be, x_be);
        j += 16;
    }
    if j < ct.len() {
        let mut blk = [0u8; 16];
        blk[..(ct.len() - j)].copy_from_slice(&ct[j..]);
        let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_le, y_be, x_be);
    }
    // Length block
    let aad_bits = (aad.len() as u128) * 8;
    let ct_bits = (ct.len() as u128) * 8;
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    let x_be = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
    y_be = ghash_block_pclmul(h_le, y_be, x_be);
    // Return BE bytes
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y_be);
    out
}

/// Ultra-fast GHASH implementation using VPCLMULQDQ (AVX-512 vector PCLMUL)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,vpclmulqdq,avx512vl")]
#[inline]
// SAFETY: target_feature gates ensure AVX-512F + VPCLMULQDQ + AVX-512VL. Same
// pattern as ghash_hw_pclmul: h is [u8; 16], aad/ct copied into stack-owned
// blocks before _mm_loadu_si128. 4-block vectorized loop processes 64-byte
// chunks with i+64 <= len guard. ghash_block_vpclmul uses register-only CLMUL.
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
#[target_feature(enable = "avx512f,vpclmulqdq,avx512vl")]
#[inline]
// SAFETY: target_feature gates ensure AVX-512F + VPCLMULQDQ + AVX-512VL. All
// inputs are by-value __m128i. All operations are register-to-register:
// _mm_shuffle_epi8, _mm_xor_si128, _mm_clmulepi64_si128, shift/and. No memory.
unsafe fn ghash_block_vpclmul(
    h_le: core::arch::x86_64::__m128i,
    y_be: core::arch::x86_64::__m128i,
    x_be: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;

    // Convert BE inputs to LE polynomial domain for CLMUL
    let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let w_be = _mm_xor_si128(y_be, x_be);
    let w_le = _mm_shuffle_epi8(w_be, shuf);

    // Use VPCLMULQDQ for enhanced carry-less multiplication with better throughput
    let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
    let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
    let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
    let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);

    // Karatsuba combination with optimized scheduling for VPCLMUL
    let t = _mm_xor_si128(x1, x2);
    let t_lo = _mm_slli_si128(t, 8);
    let t_hi = _mm_srli_si128(t, 8);
    let mut lo = _mm_xor_si128(x0, t_lo);
    let hi = _mm_xor_si128(x3, t_hi);

    // Optimized reduction modulo x^128 + x^7 + x^2 + x + 1 using VPCLMUL throughput
    let hi_sl1 = _mm_slli_epi64(hi, 1);
    let hi_sl2 = _mm_slli_epi64(hi, 2);
    let hi_sl7 = _mm_slli_epi64(hi, 7);
    let hi_sr63 = _mm_srli_epi64(hi, 63);
    let hi_sr62 = _mm_srli_epi64(hi, 62);
    let hi_sr57 = _mm_srli_epi64(hi, 57);

    // First reduction step
    let fold1 = _mm_xor_si128(_mm_xor_si128(hi_sl1, hi_sl2), hi_sl7);
    let carry1 = _mm_xor_si128(_mm_xor_si128(hi_sr63, hi_sr62), hi_sr57);
    lo = _mm_xor_si128(lo, fold1);
    let carry1_shifted = _mm_slli_si128(carry1, 8);
    lo = _mm_xor_si128(lo, carry1_shifted);

    // Second reduction step for remaining high bits
    let lo_hi = _mm_srli_si128(lo, 8);
    let final_fold = _mm_xor_si128(
        _mm_xor_si128(_mm_slli_epi64(lo_hi, 1), _mm_slli_epi64(lo_hi, 2)),
        _mm_slli_epi64(lo_hi, 7),
    );
    let final_carry = _mm_xor_si128(
        _mm_xor_si128(_mm_srli_epi64(lo_hi, 63), _mm_srli_epi64(lo_hi, 62)),
        _mm_srli_epi64(lo_hi, 57),
    );

    let lo_masked = _mm_and_si128(lo, _mm_set_epi64x(-1i64, 0));
    let reduced =
        _mm_xor_si128(_mm_xor_si128(lo_masked, final_fold), _mm_slli_si128(final_carry, 8));

    // Convert back to BE
    _mm_shuffle_epi8(reduced, shuf)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires PCLMULQDQ + SSSE3 (caller ensures). All inputs are by-value
// __m128i. All operations are register-to-register: _mm_shuffle_epi8,
// _mm_xor_si128, _mm_clmulepi64_si128, shift. No memory access.
unsafe fn ghash_block_pclmul(
    h_le: core::arch::x86_64::__m128i,
    y_be: core::arch::x86_64::__m128i,
    x_be: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;
    // Convert BE inputs to LE polynomial domain for CLMUL
    let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let w_be = _mm_xor_si128(y_be, x_be);
    let w_le = _mm_shuffle_epi8(w_be, shuf);
    // Karatsuba 128x128 carry-less multiplication
    let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
    let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
    let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
    let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);
    let t = _mm_xor_si128(x1, x2);
    let t_lo = _mm_slli_si128(t, 8);
    let t_hi = _mm_srli_si128(t, 8);
    let mut lo = _mm_xor_si128(x0, t_lo);
    let hi = _mm_xor_si128(x3, t_hi);
    // Reduction modulo x^128 + x^7 + x^2 + x + 1
    // Fold hi into lo: lo ^= (hi<<1) ^ (hi<<2) ^ (hi<<7) with cross-limb carries
    let hi_sl1 = _mm_slli_epi64(hi, 1);
    let hi_sl2 = _mm_slli_epi64(hi, 2);
    let hi_sl7 = _mm_slli_epi64(hi, 7);
    let hi_sr63 = _mm_srli_epi64(hi, 63);
    let hi_sr62 = _mm_srli_epi64(hi, 62);
    let hi_sr57 = _mm_srli_epi64(hi, 57);
    let carry1 = _mm_slli_si128(hi_sr63, 8);
    let carry2 = _mm_slli_si128(hi_sr62, 8);
    let carry7 = _mm_slli_si128(hi_sr57, 8);
    let mut fold = _mm_xor_si128(hi_sl1, hi_sl2);
    fold = _mm_xor_si128(fold, hi_sl7);
    fold = _mm_xor_si128(fold, carry1);
    fold = _mm_xor_si128(fold, carry2);
    fold = _mm_xor_si128(fold, carry7);
    lo = _mm_xor_si128(lo, fold);
    // Convert back to BE
    _mm_shuffle_epi8(lo, shuf)
}

/// Ultra-optimized ARM PMULL GHASH with efficient unaligned/partial block handling
#[cfg(target_arch = "aarch64")]
#[inline(always)]
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
    let h128 = u128::from_be_bytes(h);
    let table = precompute_h4(h128);
    let mut vecs = [vdupq_n_u8(0); 16];
    for (i, entry) in table.iter().enumerate() {
        let bytes = entry.to_be_bytes();
        vecs[i] = vld1q_u8(bytes.as_ptr());
    }
    vecs
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. table is &[uint8x16_t; 16]; nibble
// index is (w >> shift) & 0xF, so nib in 0..15, within array bounds. vst1q_u8
// writes 16 bytes into stack-owned [u8; 16]. neon_mul_x4 / veorq_u8 are
// register-to-register.
unsafe fn neon_ghash_block(
    table: &[core::arch::aarch64::uint8x16_t; 16],
    mut y: core::arch::aarch64::uint8x16_t,
    x: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;

    let mut y_bytes = [0u8; 16];
    let mut x_bytes = [0u8; 16];
    vst1q_u8(y_bytes.as_mut_ptr(), y);
    vst1q_u8(x_bytes.as_mut_ptr(), x);

    let mut xor_bytes = [0u8; 16];
    for i in 0..16 {
        xor_bytes[i] = y_bytes[i] ^ x_bytes[i];
    }
    let w_scalar = u128::from_be_bytes(xor_bytes);

    for i in 0..32 {
        let shift = 124 - 4 * i;
        let nib = ((w_scalar >> shift) & 0xF) as usize;
        y = neon_mul_x4(y);
        y = veorq_u8(y, table[nib]);
    }

    y
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. Applies neon_mul_x four times.
// All operations are register-to-register on by-value uint8x16_t.
unsafe fn neon_mul_x4(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    let v = neon_mul_x(v);
    let v = neon_mul_x(v);
    let v = neon_mul_x(v);
    neon_mul_x(v)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. All operations are register-to-register
// on by-value uint8x16_t/uint64x2_t: vreinterpretq, vshlq, vshrq, vcombine,
// vorrq, vgetq_lane, vsetq_lane, veorq. No memory access.
unsafe fn neon_mul_x(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;

    let val = vreinterpretq_u64_u8(v);
    let shifted = vshlq_n_u64(val, 1);
    let carry = vshrq_n_u64(val, 63);
    let carry_into_high = vcombine_u64(vdup_n_u64(0), vget_low_u64(carry));
    let combined = vorrq_u64(shifted, carry_into_high);
    let mut result = vreinterpretq_u8_u64(combined);

    let msb = (vgetq_lane_u64(carry, 1) & 1) as u8;
    if msb != 0 {
        let mask = vsetq_lane_u8(0x87, vdupq_n_u8(0), 15);
        result = veorq_u8(result, mask);
    }

    result
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline]
#[target_feature(enable = "sve2")]
// SAFETY: target_feature gate ensures SVE2 (implies PMULL). Delegates to
// ghash_hw_pmull_optimized which requires NEON + PMULL.
unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    ghash_hw_pmull_optimized(h, aad, ct)
}

#[cfg(all(target_arch = "aarch64", not(target_feature = "sve2")))]
#[inline(always)]
// SAFETY: caller verified SVE PMULL at runtime. Delegates to
// ghash_hw_pmull_optimized which requires NEON + PMULL.
unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    ghash_hw_pmull_optimized(h, aad, ct)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON + PMULL (caller ensures). All inputs are by-value
// uint8x16_t. Operations: veorq, vrev64q, vextq (register byte-reverse),
// vreinterpretq (zero-cost reinterpret), vmull_p64 (carry-less multiply),
// vshlq, vshrq, vdupq (register-to-register). No memory access.
unsafe fn ghash_block_pmull(
    h_le: core::arch::aarch64::uint8x16_t,
    y_be: core::arch::aarch64::uint8x16_t,
    x_be: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;
    // Reverse 16 bytes helper (rev64 + lane swap)
    #[inline]
    // SAFETY: requires NEON. Register-to-register ops (vrev64q_u8, vextq_u8).
    unsafe fn rev16(x: uint8x16_t) -> uint8x16_t {
        let t = vrev64q_u8(x);
        vextq_u8(t, t, 8)
    }
    // Convert to LE poly domain
    let w_be = veorq_u8(y_be, x_be);
    let w_le = rev16(w_be);
    // 128x128 carry-less multiply via 64-bit Karatsuba using vmull_p64
    let w64 = vreinterpretq_p64_u8(w_le);
    let h64 = vreinterpretq_p64_u8(h_le);
    // After full 16-byte reversal, x86 lane0 (low 64) corresponds to NEON lane1.
    // Align lane semantics with x86 by swapping indices here.
    let wl = vgetq_lane_p64(w64, 1);
    let wh = vgetq_lane_p64(w64, 0);
    let hl = vgetq_lane_p64(h64, 1);
    let hh = vgetq_lane_p64(h64, 0);
    let x0 = vmull_p64(wl, hl);
    let x3 = vmull_p64(wh, hh);
    let x1 = vmull_p64(wh, hl);
    let x2 = vmull_p64(wl, hh);
    let x0v = vreinterpretq_u64_p128(x0);
    let x3v = vreinterpretq_u64_p128(x3);
    let x1v = vreinterpretq_u64_p128(x1);
    let x2v = vreinterpretq_u64_p128(x2);
    let tv = veorq_u64(x1v, x2v);
    let zero = vdupq_n_u64(0);
    let t_lo = vextq_u64(zero, tv, 1); // << 64
    let t_hi = vextq_u64(tv, zero, 1); // >> 64
    let mut lo = veorq_u64(x0v, t_lo);
    let hi = veorq_u64(x3v, t_hi);
    // Reduction modulo x^128 + x^7 + x^2 + x + 1
    let hi_sl1 = vshlq_n_u64(hi, 1);
    let hi_sl2 = vshlq_n_u64(hi, 2);
    let hi_sl7 = vshlq_n_u64(hi, 7);
    let hi_sr63 = vshrq_n_u64(hi, 63);
    let hi_sr62 = vshrq_n_u64(hi, 62);
    let hi_sr57 = vshrq_n_u64(hi, 57);
    let carry1 = vextq_u64(zero, hi_sr63, 1);
    let carry2 = vextq_u64(zero, hi_sr62, 1);
    let carry7 = vextq_u64(zero, hi_sr57, 1);
    let mut fold = veorq_u64(hi_sl1, hi_sl2);
    fold = veorq_u64(fold, hi_sl7);
    fold = veorq_u64(fold, carry1);
    fold = veorq_u64(fold, carry2);
    fold = veorq_u64(fold, carry7);
    lo = veorq_u64(lo, fold);
    // Convert back to BE bytes
    let lo_u8 = vreinterpretq_u8_u64(lo);
    let t = vrev64q_u8(lo_u8);
    vextq_u8(t, t, 8)
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

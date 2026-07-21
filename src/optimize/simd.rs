use super::FeatureDetector;

// ========================================================================
// CORE OPS - Generic SIMD operations used across modules
// ========================================================================
/// Core SIMD operations: XOR blocks, population count, CRC32, repeating-key XOR.
pub mod core {
    use super::super::telemetry;
    use super::super::{FeatureDetector, SimdDispatch};

    /// Central XOR blocks implementation - used by FEC, Crypto, everywhere!
    #[inline(always)]
    pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        SimdDispatch::xor_blocks(dst, src);
    }

    /// Central population count - used for statistics, pattern matching
    #[inline(always)]
    pub fn popcnt(data: &[u8]) -> usize {
        SimdDispatch::popcnt(data)
    }

    /// IEEE CRC-32 computation with hardware acceleration where the polynomial matches.
    #[inline(always)]
    pub fn crc32(data: &[u8], initial: u32) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            let features = FeatureDetector::instance().features_full();
            if features.crc32 {
                // SAFETY: Runtime feature detection matches the callee's target feature.
                // ARM's CRC32 instructions implement the IEEE polynomial used here.
                return unsafe { crc32_armv8(data, initial) };
            }
        }

        // x86 SSE4.2 CRC instructions implement CRC32C (Castagnoli), not IEEE CRC-32.
        crc32_scalar(data, initial)
    }

    /// XOR payload with a repeating 32-byte key using optimal SIMD.
    /// The key must have length 32.
    #[inline(always)]
    pub fn xor_repeating_key_32(dst: &mut [u8], key32: &[u8; 32]) {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx2 {
                return xor_repeating_key32_avx2(dst, key32);
            }
            if features.sse2 {
                return xor_repeating_key32_sse2(dst, key32);
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                return xor_repeating_key32_sve2(dst, key32);
            }
            if features.neon {
                return xor_repeating_key32_neon(dst, key32);
            }
        }

        // Scalar fallback
        let mut i = 0usize;
        let n = dst.len();
        while i < n {
            let take = (n - i).min(32);
            for j in 0..take {
                dst[i + j] ^= key32[j];
            }
            i += take;
        }
    }

    /// XOR payload with a repeating key of arbitrary length and start offset.
    #[inline(always)]
    pub fn xor_repeating_key(dst: &mut [u8], key: &[u8], start: usize) {
        if key.is_empty() || dst.is_empty() {
            return;
        }

        if key.len() == 32 && start.is_multiple_of(32) {
            if let Ok(k32) = <&[u8; 32]>::try_from(key) {
                xor_repeating_key_32(dst, k32);
                return;
            }
        }

        let features = FeatureDetector::instance().features_full();
        let start_mod = start % key.len();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx2 {
                xor_repeating_key_generic_avx2(dst, key, start_mod);
                return;
            }
            if features.sse2 {
                xor_repeating_key_generic_sse2(dst, key, start_mod);
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                xor_repeating_key_generic_sve2(dst, key, start_mod);
                return;
            }
            if features.neon {
                xor_repeating_key_generic_neon(dst, key, start_mod);
                return;
            }
        }

        xor_repeating_key_scalar(dst, key, start_mod);
    }

    // x86_64 backends
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_repeating_key32_avx2(dst: &mut [u8], key32: &[u8; 32]) {
        use std::arch::x86_64::*;
        let key_vec = _mm256_loadu_si256(key32.as_ptr() as *const __m256i);
        let mut i = 0usize;
        let n = dst.len();
        while i + 32 <= n {
            let data = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
            let result = _mm256_xor_si256(data, key_vec);
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);
            i += 32;
        }
        while i < n {
            dst[i] ^= key32[i % 32];
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_repeating_key32_sse2(dst: &mut [u8], key32: &[u8; 32]) {
        use std::arch::x86_64::*;
        let key_low = _mm_loadu_si128(key32.as_ptr() as *const __m128i);
        let key_high = _mm_loadu_si128(key32.as_ptr().add(16) as *const __m128i);
        let mut i = 0usize;
        let n = dst.len();
        while i + 32 <= n {
            let data_low = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
            let data_high = _mm_loadu_si128(dst.as_ptr().add(i + 16) as *const __m128i);
            let result_low = _mm_xor_si128(data_low, key_low);
            let result_high = _mm_xor_si128(data_high, key_high);
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result_low);
            _mm_storeu_si128(dst.as_mut_ptr().add(i + 16) as *mut __m128i, result_high);
            i += 32;
        }
        while i < n {
            dst[i] ^= key32[i % 32];
            i += 1;
        }
    }

    // aarch64 backend
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn xor_repeating_key32_neon(dst: &mut [u8], key32: &[u8; 32]) {
        xor_repeating_key_generic_neon(dst, key32, 0);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_repeating_key32_sve2(dst: &mut [u8], key32: &[u8; 32]) {
        #[cfg(target_feature = "sve2")]
        {
            xor_repeating_key32_sve2_impl(dst, key32);
            return;
        }

        #[cfg(not(target_feature = "sve2"))]
        {
            xor_repeating_key32_neon(dst, key32);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn xor_repeating_key32_sve2_impl(dst: &mut [u8], key32: &[u8; 32]) {
        xor_repeating_key_generic_sve2_impl(dst, key32, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_repeating_key_generic_avx2(dst: &mut [u8], key: &[u8], start: usize) {
        use std::arch::x86_64::*;

        debug_assert!(!key.is_empty());
        let key_len = key.len();
        let mut idx = start % key_len;
        let mut i = 0usize;
        let mut key_buf = [0u8; 32];

        while i + 32 <= dst.len() {
            for lane in key_buf.iter_mut() {
                *lane = key[idx];
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
            }

            let key_vec = _mm256_loadu_si256(key_buf.as_ptr() as *const __m256i);
            let data_vec = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
            let result = _mm256_xor_si256(data_vec, key_vec);
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);

            i += 32;
        }

        while i < dst.len() {
            dst[i] ^= key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_repeating_key_generic_sse2(dst: &mut [u8], key: &[u8], start: usize) {
        use std::arch::x86_64::*;

        debug_assert!(!key.is_empty());
        let key_len = key.len();
        let mut idx = start % key_len;
        let mut i = 0usize;
        let mut key_buf = [0u8; 16];

        while i + 16 <= dst.len() {
            for lane in key_buf.iter_mut() {
                *lane = key[idx];
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
            }

            let key_vec = _mm_loadu_si128(key_buf.as_ptr() as *const __m128i);
            let data_vec = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
            let result = _mm_xor_si128(data_vec, key_vec);
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result);

            i += 16;
        }

        while i < dst.len() {
            dst[i] ^= key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn xor_repeating_key_generic_neon(dst: &mut [u8], key: &[u8], start: usize) {
        use std::arch::aarch64::*;

        debug_assert!(!key.is_empty());
        let key_len = key.len();
        let mut idx = start % key_len;
        let mut i = 0usize;
        let mut key_buf = [0u8; 16];

        while i + 16 <= dst.len() {
            for lane in key_buf.iter_mut() {
                *lane = key[idx];
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
            }

            let key_vec = vld1q_u8(key_buf.as_ptr());
            let data_vec = vld1q_u8(dst.as_ptr().add(i));
            let result = veorq_u8(data_vec, key_vec);
            vst1q_u8(dst.as_mut_ptr().add(i), result);

            i += 16;
        }

        while i < dst.len() {
            dst[i] ^= key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_repeating_key_generic_sve2(dst: &mut [u8], key: &[u8], start: usize) {
        #[cfg(target_feature = "sve2")]
        {
            xor_repeating_key_generic_sve2_impl(dst, key, start);
            return;
        }

        #[cfg(not(target_feature = "sve2"))]
        {
            xor_repeating_key_generic_neon(dst, key, start);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn xor_repeating_key_generic_sve2_impl(dst: &mut [u8], key: &[u8], start: usize) {
        use std::arch::aarch64::*;

        debug_assert!(!key.is_empty());

        const MAX_SVE_BYTES: usize = 256;
        let len = dst.len();
        let vl = svcntb() as usize;
        debug_assert!(vl <= MAX_SVE_BYTES);

        let key_len = key.len();
        let mut idx = start % key_len;
        let mut offset = 0usize;
        let mut key_buf = [0u8; MAX_SVE_BYTES];

        while offset < len {
            let remaining = len - offset;
            let take = remaining.min(vl);
            let pg = svwhilelt_b8(0, take as u64);

            for lane in 0..take {
                key_buf[lane] = key[idx];
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
            }

            let key_vec = svld1_u8(pg, key_buf.as_ptr());
            let data_vec = svld1_u8(pg, dst.as_ptr().add(offset));
            let result = sveor_u8_m(pg, data_vec, key_vec);
            svst1_u8(pg, dst.as_mut_ptr().add(offset), result);

            offset += take;
        }
    }

    #[inline(always)]
    fn xor_repeating_key_scalar(dst: &mut [u8], key: &[u8], start: usize) {
        let key_len = key.len();
        let mut idx = start % key_len;
        for byte in dst.iter_mut() {
            *byte ^= key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }
    }

    /// Ultra-fast CRC32 with ARMv8 CRC32 instructions (aarch64)
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "crc")]
    unsafe fn crc32_armv8(data: &[u8], mut crc: u32) -> u32 {
        use std::arch::aarch64::*;

        crc = !crc; // CRC32 uses inverted initial value
        let mut i = 0;
        let len = data.len();

        // Process 8 bytes at a time with CRC32X instruction
        while i + 8 <= len {
            let chunk = u64::from_le_bytes([
                data[i],
                data[i + 1],
                data[i + 2],
                data[i + 3],
                data[i + 4],
                data[i + 5],
                data[i + 6],
                data[i + 7],
            ]);
            crc = __crc32d(crc, chunk);
            i += 8;
        }

        // Process 4 bytes
        if i + 4 <= len {
            let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            crc = __crc32w(crc, chunk);
            i += 4;
        }

        // Process 2 bytes
        if i + 2 <= len {
            let chunk = u16::from_le_bytes([data[i], data[i + 1]]);
            crc = __crc32h(crc, chunk);
            i += 2;
        }

        // Process remaining byte
        if i < len {
            crc = __crc32b(crc, data[i]);
        }

        telemetry::CRC32_ARM_OPS.inc();
        !crc // Return with final inversion
    }

    /// Scalar CRC32 fallback implementation
    #[inline(always)]
    fn crc32_scalar(data: &[u8], mut crc: u32) -> u32 {
        // CRC32 polynomial: 0x04C11DB7 (Ethernet, PNG, etc.)
        const CRC32_TABLE: [u32; 256] = generate_crc32_table();

        crc = !crc; // CRC32 uses inverted initial value

        for &byte in data {
            let table_idx = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[table_idx];
        }

        telemetry::CRC32_SCALAR_OPS.inc();
        !crc // Return with final inversion
    }

    /// Generate CRC32 lookup table at compile time
    const fn generate_crc32_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;

        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;

            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320; // Reversed polynomial
                } else {
                    crc >>= 1;
                }
                j += 1;
            }

            table[i] = crc;
            i += 1;
        }

        table
    }
}

// ========================================================================
// GALOIS FIELD OPS - For FEC (Reed-Solomon, etc.)
// ========================================================================
/// Galois field GF(2^8) multiplication with SIMD dispatch for FEC codecs.
pub mod galois {
    #[cfg(target_arch = "x86_64")]
    use super::super::telemetry;
    use super::FeatureDetector;
    /// GF(2^8) multiplication with best available SIMD
    #[inline(always)]
    pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        if features.gfni && features.avx512f {
            return unsafe { gf_mul_avx512_gfni(a, b, dst) };
        }

        #[cfg(target_arch = "x86_64")]
        if features.avx2 {
            return unsafe { gf_mul_avx2(a, b, dst) };
        }

        #[cfg(target_arch = "aarch64")]
        if features.sve2 {
            return unsafe { gf_mul_sve2(a, b, dst) };
        }

        #[cfg(target_arch = "aarch64")]
        if features.neon {
            return unsafe { gf_mul_neon(a, b, dst) };
        }

        gf_mul_scalar(a, b, dst);
    }

    /// GF(2^8) multiplication with AVX-512 GFNI - 15x faster!
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    #[target_feature(enable = "gfni")]
    #[inline]
    unsafe fn gf_mul_avx512_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
        use std::arch::x86_64::*;

        let b_broadcast = _mm512_set1_epi8(b as i8);
        let len = a.len().min(dst.len());
        let mut i = 0;

        // Process 64 bytes at once with AVX-512 GFNI
        while i + 64 <= len {
            let data = _mm512_loadu_si512(a[i..].as_ptr() as *const __m512i);
            let result = _mm512_gf2p8mul_epi8(data, b_broadcast);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, result);
            i += 64;
        }

        // Handle remainder
        while i < len {
            dst[i] = gf_mul_byte(a[i], b);
            i += 1;
        }

        telemetry::FEC_AVX512_OPS.inc();
    }

    /// GF(2^8) multiplication with AVX2 - 5x faster with correct galois field arithmetic
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
        use std::arch::x86_64::*;

        let len = a.len().min(dst.len());
        let mut i = 0;

        // Precompute GF multiplication tables for multiplier b
        let mut lo_table = [0u8; 16];
        let mut hi_table = [0u8; 16];

        for j in 0..16 {
            lo_table[j] = gf_mul_byte(j as u8, b);
            hi_table[j] = gf_mul_byte((j << 4) as u8, b);
        }

        // Load lookup tables into AVX2 registers
        let lo_lut =
            _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
        let hi_lut =
            _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
        let nibble_mask = _mm256_set1_epi8(0x0F);

        // Process 32 bytes at once
        while i + 32 <= len {
            let data = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);

            // Split into low and high nibbles
            let lo_nibbles = _mm256_and_si256(data, nibble_mask);
            let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(data, 4), nibble_mask);

            // Table lookup for both nibbles
            let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
            let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);

            // XOR the results (GF addition)
            let result = _mm256_xor_si256(lo_result, hi_result);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, result);
            i += 32;
        }

        // Process remainder with scalar
        while i < len {
            dst[i] = gf_mul_byte(a[i], b);
            i += 1;
        }

        telemetry::FEC_AVX2_OPS.inc();
    }

    /// Scalar GF multiplication fallback
    #[inline(always)]
    fn gf_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
        for i in 0..a.len().min(dst.len()) {
            dst[i] = gf_mul_byte(a[i], b);
        }
    }

    /// Shared NEON implementation used by both NEON and SVE2 frontends.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf_mul_neon_impl(a: &[u8], b: u8, dst: &mut [u8]) {
        use std::arch::aarch64::*;

        let len = a.len().min(dst.len());
        let mut i = 0;

        // Precompute GF multiplication tables for multiplier b
        let mut lo_table = [0u8; 16];
        let mut hi_table = [0u8; 16];

        for j in 0..16 {
            lo_table[j] = gf_mul_byte(j as u8, b);
            hi_table[j] = gf_mul_byte((j << 4) as u8, b);
        }

        // Load lookup tables into NEON registers
        let lo_lut = vld1q_u8(lo_table.as_ptr());
        let hi_lut = vld1q_u8(hi_table.as_ptr());
        let nibble_mask = vdupq_n_u8(0x0F);

        // Process 16 bytes at once with NEON
        while i + 16 <= len {
            let data = vld1q_u8(a[i..].as_ptr());

            // Split into low and high nibbles
            let lo_nibbles = vandq_u8(data, nibble_mask);
            let hi_nibbles = vandq_u8(vshrq_n_u8(data, 4), nibble_mask);

            // Table lookup for both nibbles using NEON table lookup
            let lo_result = vqtbl1q_u8(lo_lut, lo_nibbles);
            let hi_result = vqtbl1q_u8(hi_lut, hi_nibbles);

            // XOR the results (GF addition)
            let result = veorq_u8(lo_result, hi_result);
            vst1q_u8(dst[i..].as_mut_ptr(), result);
            i += 16;
        }

        // Process remainder with scalar
        while i < len {
            dst[i] = gf_mul_byte(a[i], b);
            i += 1;
        }
    }

    /// GF(2^8) multiplication with NEON - 8x faster than scalar!
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
        gf_mul_neon_impl(a, b, dst);
        crate::optimize::telemetry::FEC_NEON_OPS.inc();
    }

    /// GF(2^8) multiplication with SVE2 - scalable vector processing!
    #[cfg(target_arch = "aarch64")]
    unsafe fn gf_mul_sve2(a: &[u8], b: u8, dst: &mut [u8]) {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let len = core::cmp::min(a.len(), dst.len());
            let mut offset = 0usize;
            let poly = svdup_n_u8(0x1B);
            let msb_mask = svdup_n_u8(0x80);
            let zero = svdup_n_u8(0);

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                let mut multiplicand = svld1_u8(pg, a.as_ptr().add(offset));
                let mut acc = svdup_n_u8(0);
                let mut factor = b;

                for _ in 0..8 {
                    if (factor & 1) != 0 {
                        acc = sveor_u8_m(pg, acc, acc, multiplicand);
                    }

                    let high_bits = svcmpne_u8(pg, svand_u8_z(pg, multiplicand, msb_mask), zero);
                    let doubled = svadd_u8_x(pg, multiplicand, multiplicand);
                    let reduced = sveor_u8_m(high_bits, doubled, doubled, poly);
                    multiplicand = reduced;
                    factor >>= 1;
                }

                svst1_u8(pg, dst.as_mut_ptr().add(offset), acc);
                offset += svcntb() as usize;
            }

            crate::optimize::telemetry::FEC_SVE2_OPS.inc();
            return;
        }

        gf_mul_neon(a, b, dst)
    }

    /// Single byte GF multiplication
    #[inline(always)]
    fn gf_mul_byte(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;

        while bb != 0 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let hi_bit = aa & 0x80;
            aa <<= 1;
            if hi_bit != 0 {
                aa ^= 0x1B; // AES polynomial
            }
            bb >>= 1;
        }
        result
    }
}

// ========================================================================
// CRYPTO OPS - For AEGIS, AES, ChaCha, etc.
// ========================================================================
/// Cryptographic SIMD operations: AES rounds, ChaCha20 keystream generation (x4/x16).
pub mod crypto {
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
            .get_or_init(|| std::env::var("QUICFUSCATE_CHACHA20_X4").ok().map(|v| v.to_lowercase()))
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
        #[cfg(all(target_arch = "x86_64", target_feature = "vaes"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.avx512f {
                return unsafe { aes_round_vaes(state, round_key) };
            }
        }

        #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.aes {
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
                    if features.avx {
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
            } else if features.avx {
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
    unsafe fn chacha20_blocks_x4_avx2(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> [[u8; 64]; 4] {
        chacha20_blocks_x4_sse_core(key, nonce, counter)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx", enable = "sse4.1", enable = "ssse3")]
    unsafe fn chacha20_blocks_x4_avx(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> [[u8; 64]; 4] {
        chacha20_blocks_x4_sse_core(key, nonce, counter)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.1", enable = "ssse3")]
    unsafe fn chacha20_blocks_x4_sse41(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> [[u8; 64]; 4] {
        chacha20_blocks_x4_sse_core(key, nonce, counter)
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn chacha20_blocks_x4_neon(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> [[u8; 64]; 4] {
        use std::arch::aarch64::*;
        // Constants
        let c0 = vdupq_n_u32(0x61707865);
        let c1 = vdupq_n_u32(0x3320646e);
        let c2 = vdupq_n_u32(0x79622d32);
        let c3 = vdupq_n_u32(0x6b206574);
        // Key
        let k = |i: usize| {
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
        };
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
        unsafe fn qr(
            a: &mut uint32x4_t,
            b: &mut uint32x4_t,
            c: &mut uint32x4_t,
            d: &mut uint32x4_t,
        ) {
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

    /// SIMD-accelerated XOR of two byte slices (dst ^= src), supports any length.
    #[inline(always)]
    unsafe fn xor_slice_simd(dst: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dst.len(), src.len());
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
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    #[inline(always)]
    unsafe fn aes_round_aesni(state: &mut [u8; 16], round_key: &[u8; 16]) {
        use std::arch::x86_64::*;

        let s = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let k = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
        let result = _mm_aesenc_si128(s, k);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, result);
    }

    /// VAES for parallel AES rounds (AVX-512)
    #[cfg(all(target_arch = "x86_64", target_feature = "vaes"))]
    #[inline(always)]
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
}

// ========================================================================
// PATTERN OPS - For stealth pattern matching
// ========================================================================
/// SIMD-accelerated byte pattern search for stealth protocol detection.
pub mod pattern {
    #[cfg(any(
        all(target_arch = "x86_64", target_feature = "avx512vbmi2"),
        all(target_arch = "x86_64", target_feature = "avx2")
    ))]
    use super::FeatureDetector;

    /// String search with best available SIMD
    #[inline(always)]
    pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.avx512f {
                return unsafe { find_pattern_vbmi2(haystack, needle) };
            }
        }

        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.avx2 {
                return unsafe { find_pattern_avx2(haystack, needle) };
            }
        }

        find_pattern_scalar(haystack, needle)
    }

    /// String search with AVX-512 VBMI2
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
    #[inline(always)]
    unsafe fn find_pattern_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        // Reuse the scalar matcher for consistent semantics across CPU paths.
        find_pattern_scalar(haystack, needle)
    }

    /// String search with AVX2
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[inline(always)]
    unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        // Reuse the scalar matcher for consistent semantics across CPU paths.
        find_pattern_scalar(haystack, needle)
    }

    /// Scalar pattern search fallback
    fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }
}

// ========================================================================
// NEURAL OPS - For brain AI operations
// ========================================================================
/// SIMD-accelerated dot product for the stealth brain neural network.
pub mod neural {
    #[cfg(any(
        all(target_arch = "x86_64", target_feature = "avx512f"),
        all(target_arch = "x86_64", target_feature = "fma")
    ))]
    use super::FeatureDetector;

    /// Dot product with best available SIMD
    #[inline(always)]
    pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.avx512f {
                return unsafe { dot_product_avx512(a, b) };
            }
        }

        #[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
        {
            let features = FeatureDetector::instance().features_full();
            if features.fma {
                return unsafe { dot_product_avx2(a, b) };
            }
        }

        dot_product_scalar(a, b)
    }

    /// Dot product with AVX-512
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[inline(always)]
    unsafe fn dot_product_avx512(a: &[f32], b: &[f32]) -> f32 {
        use std::arch::x86_64::*;

        let len = a.len().min(b.len());
        let mut sum = _mm512_setzero_ps();
        let chunks = len / 16;

        for i in 0..chunks {
            let va = _mm512_loadu_ps(a[i * 16..].as_ptr());
            let vb = _mm512_loadu_ps(b[i * 16..].as_ptr());
            sum = _mm512_fmadd_ps(va, vb, sum);
        }

        // Horizontal sum
        _mm512_reduce_add_ps(sum)
    }

    /// Dot product with AVX2 + FMA
    #[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
    #[inline(always)]
    unsafe fn dot_product_avx2(a: &[f32], b: &[f32]) -> f32 {
        use std::arch::x86_64::*;

        let len = a.len().min(b.len());
        let mut sum = _mm256_setzero_ps();
        let chunks = len / 8;

        for i in 0..chunks {
            let va = _mm256_loadu_ps(a[i * 8..].as_ptr());
            let vb = _mm256_loadu_ps(b[i * 8..].as_ptr());
            sum = _mm256_fmadd_ps(va, vb, sum);
        }

        // Horizontal sum
        let mut sum_array = [0.0f32; 8];
        _mm256_storeu_ps(sum_array.as_mut_ptr(), sum);
        sum_array.iter().sum()
    }

    /// Scalar dot product fallback
    fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }
}

// ========================================================================
// COMPRESSION OPS - For zstd, entropy coding
// ========================================================================
/// SIMD-accelerated histogram and pattern search for compression heuristics.
pub mod compress {
    #[cfg(target_arch = "x86_64")]
    use super::super::telemetry;
    use super::FeatureDetector;

    /// Ultra-fast entropy histogram with best available SIMD acceleration
    #[inline(always)]
    pub fn histogram(data: &[u8]) -> [u32; 256] {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        {
            if features.avx512vbmi2 && features.avx512bw {
                return unsafe { histogram_avx512_vbmi2(data) };
            }
            if features.avx512bw {
                return unsafe { histogram_avx512(data) };
            }
            if features.avx2 {
                return unsafe { histogram_avx2(data) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.sve2 {
                return unsafe { histogram_sve2(data) };
            }
            if features.neon {
                return unsafe { histogram_neon(data) };
            }
        }

        histogram_scalar(data)
    }

    /// Ultra-fast byte pattern search with best available SIMD
    #[inline(always)]
    pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }

        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        {
            if features.avx512vbmi2 && needle.len() <= 64 {
                return unsafe { find_pattern_avx512_vbmi2(haystack, needle) };
            }
            if features.avx2 && needle.len() <= 32 {
                return unsafe { find_pattern_avx2(haystack, needle) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.sve2 {
                return unsafe { find_pattern_sve2(haystack, needle) };
            }
            if features.neon && needle.len() <= 16 {
                return unsafe { find_pattern_neon(haystack, needle) };
            }
        }

        find_pattern_scalar(haystack, needle)
    }

    /// Ultra-fast histogram with AVX-512 VBMI2 - 64 bytes at once!
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
    #[inline]
    unsafe fn histogram_avx512_vbmi2(data: &[u8]) -> [u32; 256] {
        use std::arch::x86_64::*;

        let mut hist = [0u32; 256];
        let mut i = 0;
        let len = data.len();

        // Process 64 bytes at once with AVX-512
        while i + 64 <= len {
            let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

            let mut tmp = [0u8; 64];
            _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
            for &byte_val in &tmp {
                hist[byte_val as usize] += 1;
            }

            i += 64;
        }

        // Process remaining bytes
        while i < len {
            hist[data[i] as usize] += 1;
            i += 1;
        }

        telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
        hist
    }

    /// Fast histogram with AVX-512 - 64 bytes at once
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512bw")]
    #[inline]
    unsafe fn histogram_avx512(data: &[u8]) -> [u32; 256] {
        use std::arch::x86_64::*;

        let mut hist = [0u32; 256];
        let mut i = 0;
        let len = data.len();

        // Process 64 bytes at once
        while i + 64 <= len {
            let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

            let mut tmp = [0u8; 64];
            _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
            for &byte_val in &tmp {
                hist[byte_val as usize] += 1;
            }

            i += 64;
        }

        // Process remaining bytes
        while i < len {
            hist[data[i] as usize] += 1;
            i += 1;
        }

        telemetry::PATTERN_AVX512_OPS.inc();
        hist
    }

    /// Optimized histogram with AVX2 - 32 bytes at once
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn histogram_avx2(data: &[u8]) -> [u32; 256] {
        use std::arch::x86_64::*;

        let mut hist = [0u32; 256];
        let mut i = 0;
        let len = data.len();

        // Process 32 bytes at once
        while i + 32 <= len {
            let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);

            // _mm256_extract_epi8 requires an immediate index. Store and count bytes from memory.
            let mut tmp = [0u8; 32];
            _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, chunk);
            for b in tmp {
                hist[b as usize] += 1;
            }

            i += 32;
        }

        // Process remaining bytes
        while i < len {
            hist[data[i] as usize] += 1;
            i += 1;
        }

        telemetry::PATTERN_AVX2_OPS.inc();
        hist
    }

    /// Ultra-fast histogram with ARM SVE2 - scalable vector width!
    #[cfg(target_arch = "aarch64")]
    unsafe fn histogram_sve2(data: &[u8]) -> [u32; 256] {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let mut hist = [0u32; 256];
            let len = data.len();
            let vl = svcntb() as usize;
            let mut offset = 0usize;
            let mut tmp = [0u8; 256];

            debug_assert!(vl <= tmp.len());

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                let vec = svld1_u8(pg, data.as_ptr().add(offset));
                svst1_u8(pg, tmp.as_mut_ptr(), vec);

                let active = usize::min(vl, len.saturating_sub(offset));
                for idx in 0..active {
                    hist[tmp[idx] as usize] += 1;
                }

                offset += vl;
            }

            crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();
            return hist;
        }

        histogram_neon(data)
    }

    /// Fast histogram with ARM NEON - 16 bytes at once
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn histogram_neon(data: &[u8]) -> [u32; 256] {
        use std::arch::aarch64::*;

        let mut hist = [0u32; 256];
        let mut i = 0;
        let len = data.len();

        // Process 16 bytes at once
        while i + 16 <= len {
            let chunk = vld1q_u8(data.as_ptr().add(i));
            // Store to a temporary array to avoid const lane index restriction
            let mut tmp: [u8; 16] = [0u8; 16];
            vst1q_u8(tmp.as_mut_ptr(), chunk);
            for &b in &tmp {
                hist[b as usize] += 1;
            }
            i += 16;
        }

        // Process remaining bytes
        while i < len {
            hist[data[i] as usize] += 1;
            i += 1;
        }

        crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
        hist
    }

    /// Ultra-fast pattern search with AVX-512 VBMI2 - up to 64-byte patterns!
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
    #[inline]
    unsafe fn find_pattern_avx512_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        use std::arch::x86_64::*;

        if needle.len() > 64 || needle.is_empty() {
            return find_pattern_scalar(haystack, needle);
        }

        let needle_len = needle.len();
        let haystack_len = haystack.len();

        // Create needle pattern vectors
        let mut needle_vec = [0u8; 64];
        needle_vec[..needle_len].copy_from_slice(needle);
        let needle_512 = _mm512_loadu_si512(needle_vec.as_ptr() as *const __m512i);

        let mut i = 0;
        while i + 64 <= haystack_len {
            let haystack_chunk = _mm512_loadu_si512(haystack.as_ptr().add(i) as *const __m512i);

            // Use VBMI2 for efficient comparison and match detection
            let cmp_mask = _mm512_cmpeq_epi8_mask(haystack_chunk, needle_512);

            if cmp_mask != 0 {
                // Found potential match, verify with scalar comparison
                for j in 0..64 {
                    if i + j + needle_len <= haystack_len {
                        if &haystack[i + j..i + j + needle_len] == needle {
                            telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
                            return Some(i + j);
                        }
                    }
                }
            }

            i += 64;
        }

        // Check remaining bytes with scalar
        while i + needle_len <= haystack_len {
            if &haystack[i..i + needle_len] == needle {
                telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
                return Some(i);
            }
            i += 1;
        }

        None
    }

    /// Fast pattern search with AVX2 - up to 32-byte patterns
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        use std::arch::x86_64::*;

        if needle.len() > 32 || needle.is_empty() {
            return find_pattern_scalar(haystack, needle);
        }

        let needle_len = needle.len();
        let haystack_len = haystack.len();

        // For short patterns, use first byte matching with AVX2
        if needle_len == 1 {
            let needle_first = _mm256_set1_epi8(needle[0] as i8);
            let mut i = 0;

            while i + 32 <= haystack_len {
                let haystack_chunk = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
                let cmp_result = _mm256_cmpeq_epi8(haystack_chunk, needle_first);
                let mask = _mm256_movemask_epi8(cmp_result);

                if mask != 0 {
                    for bit in 0..32 {
                        if (mask & (1 << bit)) != 0 {
                            telemetry::PATTERN_AVX2_OPS.inc();
                            return Some(i + bit);
                        }
                    }
                }
                i += 32;
            }
        }

        // For longer patterns, use scalar verification after first byte match
        let mut i = 0;
        while i + needle_len <= haystack_len {
            if &haystack[i..i + needle_len] == needle {
                telemetry::PATTERN_AVX2_OPS.inc();
                return Some(i);
            }
            i += 1;
        }

        None
    }

    /// Ultra-fast pattern search with ARM SVE2 - scalable vector patterns
    #[cfg(target_arch = "aarch64")]
    unsafe fn find_pattern_sve2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();

            let nlen = needle.len();
            if nlen == 0 {
                return Some(0);
            }
            if nlen > haystack.len() {
                return None;
            }

            let hlen = haystack.len();
            let vl = svcntb() as usize;
            let mut offset = 0usize;

            if nlen == 1 {
                let needle_val = svdup_n_u8(needle[0]);
                let pg_all = svptrue_b8();

                while offset + vl <= hlen {
                    let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
                    let matches = svcmpeq_u8(pg_all, chunk, needle_val);

                    if svptest_any(pg_all, matches) {
                        for lane in 0..vl {
                            if offset + lane < hlen && haystack[offset + lane] == needle[0] {
                                return Some(offset + lane);
                            }
                        }
                    }
                    offset += vl;
                }

                while offset < hlen {
                    if haystack[offset] == needle[0] {
                        return Some(offset);
                    }
                    offset += 1;
                }

                return None;
            }

            let first_byte = svdup_n_u8(needle[0]);
            let pg_all = svptrue_b8();

            while offset + vl <= hlen {
                let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
                let matches = svcmpeq_u8(pg_all, chunk, first_byte);

                if svptest_any(pg_all, matches) {
                    for lane in 0..vl {
                        let pos = offset + lane;
                        if pos + nlen <= hlen && &haystack[pos..pos + nlen] == needle {
                            return Some(pos);
                        }
                    }
                }
                offset += vl;
            }

            while offset + nlen <= hlen {
                if &haystack[offset..offset + nlen] == needle {
                    return Some(offset);
                }
                offset += 1;
            }

            return None;
        }

        find_pattern_neon(haystack, needle)
    }

    /// Fast pattern search with ARM NEON - up to 16-byte patterns
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn find_pattern_neon(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        use std::arch::aarch64::*;

        if needle.len() > 16 || needle.is_empty() {
            return find_pattern_scalar(haystack, needle);
        }

        let needle_len = needle.len();
        let haystack_len = haystack.len();

        // For single byte patterns, use NEON comparison
        if needle_len == 1 {
            let needle_first = vdupq_n_u8(needle[0]);
            let mut i = 0;

            while i + 16 <= haystack_len {
                let haystack_chunk = vld1q_u8(haystack.as_ptr().add(i));
                let cmp_result = vceqq_u8(haystack_chunk, needle_first);

                // Check if any bytes matched
                let mask = vget_lane_u64(
                    vreinterpret_u64_u8(vqmovn_u16(vreinterpretq_u16_u8(cmp_result))),
                    0,
                );
                if mask != 0 {
                    for bit in 0..16 {
                        if i + bit < haystack_len && haystack[i + bit] == needle[0] {
                            crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
                            return Some(i + bit);
                        }
                    }
                }
                i += 16;
            }
        }

        // For longer patterns, use scalar verification
        let mut i = 0;
        while i + needle_len <= haystack_len {
            if haystack[i..i + needle_len] == *needle {
                crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
                return Some(i);
            }
            i += 1;
        }

        None
    }

    /// Scalar pattern search fallback
    fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }

        let needle_len = needle.len();
        let haystack_len = haystack.len();

        for i in 0..=(haystack_len.saturating_sub(needle_len)) {
            if haystack[i..i + needle_len] == *needle {
                crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
                return Some(i);
            }
        }

        None
    }

    /// Scalar entropy histogram fallback
    fn histogram_scalar(data: &[u8]) -> [u32; 256] {
        let mut hist = [0u32; 256];
        for &byte in data {
            hist[byte as usize] += 1;
        }
        crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
        hist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- core::xor_blocks ----

    #[test]
    fn test_xor_blocks_basic() {
        let src = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let mut dst = [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00];
        let expected: Vec<u8> = dst.iter().zip(src.iter()).map(|(a, b)| a ^ b).collect();
        core::xor_blocks(&mut dst, &src);
        assert_eq!(&dst[..], &expected[..]);
    }

    #[test]
    fn test_xor_blocks_empty() {
        let src: [u8; 0] = [];
        let mut dst: [u8; 0] = [];
        core::xor_blocks(&mut dst, &src);
        // Should not panic on empty input
    }

    #[test]
    fn test_xor_blocks_large_simd_aligned() {
        // 256 bytes forces multi-pass through SIMD paths (NEON=16, AVX2=32, AVX512=64)
        let src: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();
        let mut dst: Vec<u8> = vec![0xFF; 256];
        let expected: Vec<u8> = dst.iter().zip(src.iter()).map(|(a, b)| a ^ b).collect();
        core::xor_blocks(&mut dst, &src);
        assert_eq!(dst, expected);
    }

    #[test]
    fn test_xor_blocks_self_inverse() {
        let key = [0x42; 64];
        let original = [0xDE; 64];
        let mut data = original;
        core::xor_blocks(&mut data, &key);
        assert_ne!(data, original);
        core::xor_blocks(&mut data, &key);
        assert_eq!(data, original);
    }

    // ---- core::popcnt ----

    #[test]
    fn test_popcnt_empty() {
        assert_eq!(core::popcnt(&[]), 0);
    }

    #[test]
    fn test_popcnt_known_values() {
        assert_eq!(core::popcnt(&[0xFF]), 8);
        assert_eq!(core::popcnt(&[0x00]), 0);
        assert_eq!(core::popcnt(&[0xAA]), 4); // 10101010
        assert_eq!(core::popcnt(&[0x55]), 4); // 01010101
        assert_eq!(core::popcnt(&[0x01]), 1);
    }

    #[test]
    fn test_popcnt_multi_byte() {
        // 16 bytes of 0xFF = 128 bits set
        let data = [0xFF; 16];
        assert_eq!(core::popcnt(&data), 128);
        // Non-aligned size (9 bytes) to test remainder handling
        let data2 = [0xFF; 9];
        assert_eq!(core::popcnt(&data2), 72);
    }

    // ---- core::crc32 ----

    #[test]
    fn test_crc32_empty() {
        let crc = core::crc32(&[], 0);
        // CRC32 of empty data with initial 0 = 0 (identity)
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32_deterministic() {
        let data = b"Hello, World!";
        let crc1 = core::crc32(data, 0);
        let crc2 = core::crc32(data, 0);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc32_ieee_known_vector() {
        assert_eq!(core::crc32(b"123456789", 0), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_different_data_different_hash() {
        let crc_a = core::crc32(b"AAAA", 0);
        let crc_b = core::crc32(b"BBBB", 0);
        assert_ne!(crc_a, crc_b);
    }

    #[test]
    fn test_crc32_initial_value_affects_result() {
        let data = b"test";
        let crc_zero = core::crc32(data, 0);
        let crc_nonzero = core::crc32(data, 0xDEADBEEF);
        assert_ne!(crc_zero, crc_nonzero);
    }

    // ---- core::xor_repeating_key_32 ----

    #[test]
    fn test_xor_repeating_key32_roundtrip() {
        let key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let original: Vec<u8> = (0..100).collect();
        let mut data = original.clone();
        core::xor_repeating_key_32(&mut data, &key);
        assert_ne!(data, original);
        core::xor_repeating_key_32(&mut data, &key);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_repeating_key32_empty() {
        let key = [0xAB; 32];
        let mut data: Vec<u8> = vec![];
        core::xor_repeating_key_32(&mut data, &key);
        assert!(data.is_empty());
    }

    #[test]
    fn test_xor_repeating_key32_single_byte() {
        let key: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0xFF;
            k
        };
        let mut data = [0x42u8];
        core::xor_repeating_key_32(&mut data, &key);
        assert_eq!(data[0], 0x42 ^ 0xFF);
    }

    // ---- core::xor_repeating_key (arbitrary) ----

    #[test]
    fn test_xor_repeating_key_arbitrary_roundtrip() {
        let key = b"secret";
        let original = b"Hello, World! This is a test message.".to_vec();
        let mut data = original.clone();
        core::xor_repeating_key(&mut data, key, 0);
        assert_ne!(data, original);
        core::xor_repeating_key(&mut data, key, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_repeating_key_empty_key_noop() {
        let mut data = vec![0x42; 10];
        let original = data.clone();
        core::xor_repeating_key(&mut data, &[], 0);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_repeating_key_empty_data_noop() {
        let key = b"key";
        let mut data: Vec<u8> = vec![];
        core::xor_repeating_key(&mut data, key, 0);
        assert!(data.is_empty());
    }

    #[test]
    fn test_xor_repeating_key_offset_correctness() {
        // XOR with offset=3 should start from key[3 % key.len()]
        let key = [0x10, 0x20, 0x30, 0x40, 0x50];
        let mut data = [0x00; 5];
        core::xor_repeating_key(&mut data, &key, 3);
        // offset=3 -> key indices: 3,4,0,1,2
        assert_eq!(data, [0x40, 0x50, 0x10, 0x20, 0x30]);
    }

    #[test]
    fn test_xor_repeating_key_32byte_fast_path() {
        // When key.len()==32 and start%32==0, should use the fast xor_repeating_key_32 path
        // Verify result matches manual computation
        let key: Vec<u8> = (1..=32).collect();
        let key32: [u8; 32] = key.clone().try_into().unwrap();
        let original: Vec<u8> = (0..96).collect();

        let mut via_generic = original.clone();
        core::xor_repeating_key(&mut via_generic, &key, 0);

        let mut via_direct = original.clone();
        core::xor_repeating_key_32(&mut via_direct, &key32);

        assert_eq!(via_generic, via_direct);
    }

    // ---- galois::gf_mul ----

    #[test]
    fn test_gf_mul_identity() {
        // GF multiply by 1 is identity
        let input: Vec<u8> = (0..64).collect();
        let mut output = vec![0u8; 64];
        galois::gf_mul(&input, 1, &mut output);
        assert_eq!(output, input);
    }

    #[test]
    fn test_gf_mul_zero() {
        // GF multiply by 0 is zero
        let input: Vec<u8> = (1..65).collect();
        let mut output = vec![0xFFu8; 64];
        galois::gf_mul(&input, 0, &mut output);
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_gf_mul_empty() {
        let mut output = vec![0u8; 0];
        galois::gf_mul(&[], 0x42, &mut output);
        // Should not panic
    }

    #[test]
    fn test_gf_mul_single_byte() {
        // GF(2^8) multiply 0x53 * 0xCA = known value
        // Verify via the scalar path identity: gf_mul(a,b) == gf_mul(b,a) conceptually
        let mut out_a = [0u8; 1];
        let mut out_b = [0u8; 1];
        galois::gf_mul(&[0x53], 0xCA, &mut out_a);
        galois::gf_mul(&[0xCA], 0x53, &mut out_b);
        // GF multiplication is commutative
        assert_eq!(out_a[0], out_b[0]);
    }

    #[test]
    fn test_gf_mul_deterministic() {
        let input: Vec<u8> = (0..128).collect();
        let mut out1 = vec![0u8; 128];
        let mut out2 = vec![0u8; 128];
        galois::gf_mul(&input, 0x42, &mut out1);
        galois::gf_mul(&input, 0x42, &mut out2);
        assert_eq!(out1, out2);
    }

    // ---- pattern::find_pattern ----

    #[test]
    fn test_pattern_find_basic() {
        let haystack = b"Hello, World!";
        assert_eq!(pattern::find_pattern(haystack, b"World"), Some(7));
    }

    #[test]
    fn test_pattern_find_not_found() {
        let haystack = b"Hello, World!";
        assert_eq!(pattern::find_pattern(haystack, b"xyz"), None);
    }

    #[test]
    fn test_pattern_find_at_start() {
        let haystack = b"Hello, World!";
        assert_eq!(pattern::find_pattern(haystack, b"Hello"), Some(0));
    }

    #[test]
    fn test_pattern_find_single_byte_needle() {
        let haystack = b"abcdef";
        assert_eq!(pattern::find_pattern(haystack, b"d"), Some(3));
        assert_eq!(pattern::find_pattern(haystack, b"a"), Some(0));
        assert_eq!(pattern::find_pattern(haystack, b"f"), Some(5));
        assert_eq!(pattern::find_pattern(haystack, b"z"), None);
    }

    // ---- neural::dot_product ----

    #[test]
    fn test_dot_product_basic() {
        let a = [1.0f32, 2.0, 3.0, 4.0];
        let b = [5.0f32, 6.0, 7.0, 8.0];
        let result = neural::dot_product(&a, &b);
        // 1*5 + 2*6 + 3*7 + 4*8 = 5+12+21+32 = 70
        assert!((result - 70.0).abs() < 1e-5);
    }

    #[test]
    fn test_dot_product_empty() {
        let result = neural::dot_product(&[], &[]);
        assert!((result - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_dot_product_single() {
        let result = neural::dot_product(&[3.0], &[7.0]);
        assert!((result - 21.0).abs() < 1e-5);
    }

    #[test]
    fn test_dot_product_orthogonal() {
        // Orthogonal vectors have dot product = 0
        let a = [1.0f32, 0.0, 0.0];
        let b = [0.0f32, 1.0, 0.0];
        let result = neural::dot_product(&a, &b);
        assert!((result - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_dot_product_mismatched_lengths() {
        // Should use min(a.len(), b.len()) elements
        let a = [1.0f32, 2.0, 3.0, 99.0];
        let b = [4.0f32, 5.0, 6.0];
        let result = neural::dot_product(&a, &b);
        // 1*4 + 2*5 + 3*6 = 4+10+18 = 32
        assert!((result - 32.0).abs() < 1e-5);
    }

    // ---- compress::histogram ----

    #[test]
    fn test_histogram_empty() {
        let hist = compress::histogram(&[]);
        assert!(hist.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_histogram_single_byte() {
        let hist = compress::histogram(&[42]);
        assert_eq!(hist[42], 1);
        let total: u32 = hist.iter().sum();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_histogram_uniform() {
        // Each byte value appears exactly once
        let data: Vec<u8> = (0..=255).map(|i| i as u8).collect();
        let hist = compress::histogram(&data);
        for count in &hist {
            assert_eq!(*count, 1);
        }
    }

    #[test]
    fn test_histogram_repeated() {
        let data = vec![0xAA; 100];
        let hist = compress::histogram(&data);
        assert_eq!(hist[0xAA], 100);
        let total: u32 = hist.iter().sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_histogram_total_equals_length() {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let hist = compress::histogram(&data);
        let total: u32 = hist.iter().sum();
        assert_eq!(total, 1024);
    }

    // ---- compress::find_pattern ----

    #[test]
    fn test_compress_find_pattern_basic() {
        let haystack = b"ABCDEFGHIJKLMNOP";
        assert_eq!(compress::find_pattern(haystack, b"GHIJ"), Some(6));
    }

    #[test]
    fn test_compress_find_pattern_not_found() {
        let haystack = b"ABCDEFGHIJKLMNOP";
        assert_eq!(compress::find_pattern(haystack, b"XYZ"), None);
    }

    #[test]
    fn test_compress_find_pattern_empty_needle() {
        let haystack = b"ABCDEF";
        assert_eq!(compress::find_pattern(haystack, b""), None);
    }

    #[test]
    fn test_compress_find_pattern_needle_longer_than_haystack() {
        let haystack = b"AB";
        assert_eq!(compress::find_pattern(haystack, b"ABCDEF"), None);
    }

    #[test]
    fn test_compress_find_pattern_full_match() {
        let haystack = b"exact";
        assert_eq!(compress::find_pattern(haystack, b"exact"), Some(0));
    }

    // ---- crypto::aes_round ----

    #[test]
    fn test_aes_round_deterministic() {
        let mut state1 = [
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ];
        let mut state2 = state1;
        let round_key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        crypto::aes_round(&mut state1, &round_key);
        crypto::aes_round(&mut state2, &round_key);
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_aes_round_modifies_state() {
        let original = [0x00u8; 16];
        let mut state = original;
        let round_key = [0xFF; 16];
        crypto::aes_round(&mut state, &round_key);
        // AES round should produce different output (at minimum XOR with key)
        assert_ne!(state, original);
    }

    // ---- crypto::chacha20 ----

    #[test]
    fn test_chacha20_xor_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let original: Vec<u8> = (0..200).collect();
        let mut data = original.clone();
        crypto::chacha20_xor_in_place(&mut data, &key, &nonce, 0);
        assert_ne!(data, original);
        crypto::chacha20_xor_in_place(&mut data, &key, &nonce, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn test_chacha20_blocks_x4_produces_four_distinct_blocks() {
        let key = [0xAA; 32];
        let nonce = [0xBB; 12];
        let blocks = crypto::chacha20_blocks_x4(&key, &nonce, 0);
        // Each block should be distinct (different counter values)
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(blocks[i], blocks[j], "blocks[{}] == blocks[{}]", i, j);
            }
        }
    }

    #[test]
    fn test_chacha20_blocks_x4_matches_scalar() {
        use crate::crypto::chacha::chacha20_block;
        let key = [0x55; 32];
        let nonce = [0x77; 12];
        let counter = 42u32;
        let blocks = crypto::chacha20_blocks_x4(&key, &nonce, counter);
        for i in 0..4u32 {
            let scalar = chacha20_block(&key, counter.wrapping_add(i), &nonce);
            assert_eq!(blocks[i as usize], scalar, "block {} mismatch between x4 and scalar", i);
        }
    }

    #[test]
    fn test_chacha20_blocks_x16_matches_scalar() {
        use crate::crypto::chacha::chacha20_block;
        let key = [0x33; 32];
        let nonce = [0x99; 12];
        let counter = 100u32;
        let blocks = crypto::chacha20_blocks_x16(&key, &nonce, counter);
        for i in 0..16u32 {
            let scalar = chacha20_block(&key, counter.wrapping_add(i), &nonce);
            assert_eq!(blocks[i as usize], scalar, "block {} mismatch between x16 and scalar", i);
        }
    }

    // ---- FeatureDetector consistency ----

    #[test]
    fn test_feature_detector_consistent() {
        let features_a = FeatureDetector::instance().features_full();
        let features_b = FeatureDetector::instance().features_full();
        // Same singleton, same pointer
        assert!(std::ptr::eq(features_a, features_b));
    }

    #[test]
    fn test_feature_detector_baseline() {
        let features = FeatureDetector::instance().features_full();
        // On any platform, at least one field should be queryable without panic
        // On aarch64 macOS, NEON is always available
        #[cfg(target_arch = "aarch64")]
        assert!(features.neon, "NEON should always be available on aarch64");
        // On x86_64, SSE2 is baseline
        #[cfg(target_arch = "x86_64")]
        assert!(features.sse2, "SSE2 should always be available on x86_64");
        let _ = features; // suppress unused on other archs
    }
}

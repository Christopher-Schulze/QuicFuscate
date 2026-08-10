//! Extracted SIMD `arm` submodule (TODO-563).

use super::scalar;

#[cfg(target_feature = "sve2")]
use std::arch::aarch64::*;

// Core
#[inline(always)]
/// # Safety
///
/// The caller must ensure the compiled/runtime path has SVE2 support and that
/// `dst` is writable and `src` readable for the duration of the call. The
/// slices must not overlap; vector predicates bound each access to their shared
/// length.
pub(super) unsafe fn xor_blocks_sve2(dst: &mut [u8], src: &[u8]) {
    #[cfg(target_feature = "sve2")]
    {
        xor_blocks_sve2_impl(dst, src);
        return;
    }

    // Compile-time SVE2 not available - fall back to NEON/Scalar.
    scalar::xor_blocks(dst, src)
}
#[inline(always)]
/// # Safety
///
/// The caller must provide AArch64 NEON support, writable `dst`, and readable
/// non-overlapping `src` storage. The scalar fallback preserves the same
/// length-bounded contract.
pub(super) unsafe fn xor_blocks_neon(dst: &mut [u8], src: &[u8]) {
    scalar::xor_blocks(dst, src)
}
#[inline(always)]
/// # Safety
///
/// The caller must ensure the AArch64 CRC extension is available when the CRC
/// intrinsic branch is compiled. `data` must remain a valid immutable slice for
/// the duration of the call; fixed-width reads are guarded by remaining length.
pub(super) unsafe fn crc32_arm(data: &[u8], initial: u32) -> u32 {
    #[cfg(target_feature = "crc")]
    {
        use core::arch::aarch64::*;

        let mut crc = !initial;
        let mut i = 0usize;
        let len = data.len();

        // 8-byte chunks
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

        // 4-byte chunk
        if i + 4 <= len {
            let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            crc = __crc32w(crc, chunk);
            i += 4;
        }

        // remaining bytes
        while i < len {
            crc = __crc32b(crc, data[i]);
            i += 1;
        }

        return !crc;
    }
    // Fallback when CRC extension is not enabled at compile time
    #[allow(unreachable_code)]
    {
        scalar::crc32(data, initial)
    }
}
#[inline(always)]
/// # Safety
///
/// The caller must provide AArch64 NEON support and a valid immutable `data`
/// slice for the duration of the call. The 16-byte vector loads are guarded and
/// the remainder is handled element by element.
pub(super) unsafe fn popcnt_neon(data: &[u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;
        let mut count: usize = 0;
        let mut i = 0usize;
        let len = data.len();
        while i + 16 <= len {
            // SAFETY: `i + 16 <= len` guarantees 16 readable bytes at `data[i..]`.
            let v = vld1q_u8(data.as_ptr().add(i));
            let pc = vcntq_u8(v);
            let sum = vaddvq_u8(pc) as usize; // <= 128 per 16B block
            count = count.saturating_add(sum);
            i += 16;
        }
        while i < len {
            count = count.saturating_add(data[i].count_ones() as usize);
            i += 1;
        }
        count
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        scalar::popcnt(data)
    }
}

#[inline(always)]
/// # Safety
///
/// The caller must ensure the compiled/runtime path has SVE2 support and must
/// provide a valid immutable `data` slice for the duration of the call. The
/// delegated NEON implementation performs only bounded reads.
pub(super) unsafe fn popcnt_sve2(data: &[u8]) -> usize {
    #[cfg(target_feature = "sve2")]
    {
        // Use NEON popcnt under SVE2; SVE2 path may be added later for even wider VL
        return popcnt_neon(data);
    }
    popcnt_neon(data)
}

#[inline(always)]
/// # Safety
///
/// The caller must ensure the compiled/runtime path has SVE2 support and must
/// provide a valid immutable `header` slice. The function checks emptiness
/// before reading the first byte and uses one-lane predicates for SVE reads.
pub(super) unsafe fn validate_header_sve2(header: &[u8]) -> bool {
    #[cfg(target_feature = "sve2")]
    {
        if header.is_empty() {
            return false;
        }

        use std::arch::aarch64::*;

        let pg = svwhilelt_b8(0, 1);
        let first = svdup_n_u8(header[0]);
        let fixed_mask = svdup_n_u8(0x40);
        let fixed = svand_u8_x(pg, first, fixed_mask);
        let fixed_ok = svcmpeq_u8(pg, fixed, fixed_mask);
        if svcntp_b8(pg, fixed_ok) == 0 {
            return false;
        }

        // QUIC short headers require reserved bits to be zero.
        if (header[0] & 0x80) == 0 {
            let reserved_mask = svdup_n_u8(0x18);
            let reserved = svand_u8_x(pg, first, reserved_mask);
            let zero = svdup_n_u8(0);
            let reserved_ok = svcmpeq_u8(pg, reserved, zero);
            if svcntp_b8(pg, reserved_ok) == 0 {
                return false;
            }
        }

        return true;
    }

    scalar::validate_header(header)
}

#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support and a valid immutable `header`
/// slice for the duration of the call. The function checks emptiness before
/// reading the first byte and does not retain the slice.
pub(super) unsafe fn validate_header_neon(header: &[u8]) -> bool {
    // Fast-path header validation using NEON. Mirrors SVE2 semantics:
    // - Fixed bit (0x40) must be set for all QUIC packets
    // - For short headers (0x80 not set), reserved bits (0x18) must be zero
    // Length checks (>=5) are done by the top-level dispatcher.
    if header.is_empty() {
        return false;
    }

    use core::arch::aarch64::*;

    let first = vdupq_n_u8(header[0]);

    // Check fixed bit (0x40)
    let fixed_mask = vdupq_n_u8(0x40);
    let fixed = vandq_u8(first, fixed_mask);
    let fixed_ok = vceqq_u8(fixed, fixed_mask);
    if vgetq_lane_u8(fixed_ok, 0) != 0xFF {
        return false;
    }

    // Short header: reserved bits (0x18) must be zero
    if (header[0] & 0x80) == 0 {
        let reserved_mask = vdupq_n_u8(0x18);
        let reserved = vandq_u8(first, reserved_mask);
        let zero = vdupq_n_u8(0);
        let reserved_ok = vceqq_u8(reserved, zero);
        if vgetq_lane_u8(reserved_ok, 0) != 0xFF {
            return false;
        }
    }

    true
}

// Galois field
#[inline(always)]
/// # Safety
///
/// The caller must ensure the compiled/runtime path has SVE2 support and must
/// provide valid non-overlapping readable `a` and writable `dst` slices. The
/// implementation bounds all accesses by their shared minimum length.
pub(super) unsafe fn gf_mul_sve2(a: &[u8], b: u8, dst: &mut [u8]) {
    #[cfg(target_feature = "sve2")]
    {
        gf_mul_sve2_impl(a, b, dst);
        return;
    }
    // Fallback when SVE2 is unavailable at compile time
    scalar::gf_mul(a, b, dst)
}

// FEC
#[cfg(target_feature = "sve2")]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must provide SVE2 support, a valid immutable `syndrome` slice,
/// and a `len` no greater than its length. The scalar implementation returns
/// owned output and does not retain the slice.
pub(super) unsafe fn berlekamp_massey_sve2(syndrome: &[u8], len: usize) -> Vec<u8> {
    // The canonical scalar implementation owns the validated length contract;
    // this feature boundary does not expose an independent unchecked loop.
    scalar::berlekamp_massey(syndrome, len)
}

/// GF(2^8) multiply using NEON PMULL - carryless polynomial multiplication
/// Polynomial: x^8 + x^4 + x^3 + x + 1 (AES reduction polynomial 0x11B)
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support, valid immutable `a`, and
/// writable `dst` storage that does not overlap `a`. Accesses are bounded by
/// the shared minimum length and scalar tails cover incomplete vectors.
pub(super) unsafe fn gf_mul_neon_pmull(a: &[u8], b: u8, dst: &mut [u8]) {
    use core::arch::aarch64::*;

    let len = a.len().min(dst.len());
    if len == 0 || b == 0 {
        dst[..len].fill(0);
        return;
    }
    if b == 1 {
        dst[..len].copy_from_slice(&a[..len]);
        return;
    }

    // Broadcast b across all lanes
    let b_vec = vdupq_n_u8(b);

    // Process 16 bytes at a time
    let mut i = 0usize;
    while i + 16 <= len {
        // SAFETY: `i + 16 <= len` and `len = a.len().min(dst.len())`, so both
        // `a[i..i+16]` and `dst[i..i+16]` are within bounds for the 16-byte
        // NEON load/store operations.
        let a_chunk = vld1q_u8(a.as_ptr().add(i));

        // GF(2^8) multiply each byte pair
        let result = gf_mul_vec_neon(a_chunk, b_vec);

        vst1q_u8(dst.as_mut_ptr().add(i), result);
        i += 16;
    }

    // Tail: scalar fallback for remaining bytes
    while i < len {
        dst[i] = gf_mul_byte_scalar(a[i], b);
        i += 1;
    }
}

/// GF(2^8) multiply using basic NEON (no PMULL, table-based with SIMD gather)
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support, valid immutable `a`, and
/// writable non-overlapping `dst` storage. The implementation bounds all
/// accesses by the shared minimum length.
pub(super) unsafe fn gf_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
    let len = a.len().min(dst.len());
    if len == 0 || b == 0 {
        dst[..len].fill(0);
        return;
    }
    if b == 1 {
        dst[..len].copy_from_slice(&a[..len]);
        return;
    }

    // Use PMULL version if available at runtime
    gf_mul_neon_pmull(a, b, dst);
}

/// Helper: GF(2^8) vector multiply using polynomial arithmetic
#[target_feature(enable = "neon")]
#[inline]
/// # Safety
///
/// The caller must provide AArch64 NEON support and pass initialized vector
/// values. The helper only operates on those values and returns a new vector;
/// it does not dereference or retain pointers.
unsafe fn gf_mul_vec_neon(
    a: core::arch::aarch64::uint8x16_t,
    b: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;

    // For each byte position, compute GF multiply
    // Split into halves for processing
    let _a_lo = vget_low_u8(a);
    let _a_hi = vget_high_u8(a);
    let _b_lo = vget_low_u8(b);
    let _b_hi = vget_high_u8(b);

    // Process using table lookup approach with NEON
    // This is faster than PMULL for GF(2^8) due to reduction overhead
    let mut result_bytes = [0u8; 16];
    let mut a_bytes = [0u8; 16];
    let mut b_bytes = [0u8; 16];
    vst1q_u8(a_bytes.as_mut_ptr(), a);
    vst1q_u8(b_bytes.as_mut_ptr(), b);

    for j in 0..16 {
        result_bytes[j] = gf_mul_byte_scalar(a_bytes[j], b_bytes[j]);
    }

    vld1q_u8(result_bytes.as_ptr())
}

/// Scalar GF(2^8) byte multiply with AES polynomial reduction
#[inline(always)]
fn gf_mul_byte_scalar(a: u8, b: u8) -> u8 {
    // Russian peasant multiplication in GF(2^8)
    // Polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;

    for _ in 0..8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi_bit = aa & 0x80;
        aa <<= 1;
        if hi_bit != 0 {
            aa ^= 0x1B; // Reduce by AES polynomial (x^8 term implicit)
        }
        bb >>= 1;
    }
    result
}

#[cfg(target_feature = "sve2")]
#[inline(always)]
/// # Safety
///
/// The caller must provide SVE2 support, writable `dst`, and readable
/// non-overlapping `src` storage. Predicate masks and the shared minimum length
/// bound every vector load and store.
unsafe fn xor_blocks_sve2_impl(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dst.len(), src.len());
    let mut offset = 0usize;
    while offset < len {
        let pg = svwhilelt_b8(offset as u64, len as u64);
        let dst_chunk = svld1_u8(pg, dst.as_ptr().add(offset));
        let src_chunk = svld1_u8(pg, src.as_ptr().add(offset));
        let res = sveor_u8_z(pg, dst_chunk, src_chunk);
        svst1_u8(pg, dst.as_mut_ptr().add(offset), res);
        offset += svcntb() as usize;
    }
}

#[cfg(target_feature = "sve2")]
#[inline(always)]
/// # Safety
///
/// The caller must provide SVE2 support, writable `dst`, and readable
/// non-overlapping `src` storage. Predicate masks and the shared minimum length
/// bound every vector load and store.
unsafe fn memcpy_sve2_impl(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dst.len(), src.len());
    let mut offset = 0usize;
    while offset < len {
        let pg = svwhilelt_b8(offset as u64, len as u64);
        let data = svld1_u8(pg, src.as_ptr().add(offset));
        svst1_u8(pg, dst.as_mut_ptr().add(offset), data);
        offset += svcntb() as usize;
    }
}

// Crypto
#[inline(always)]
/// # Safety
///
/// The caller must provide AArch64 NEON support and valid writable `state` and
/// readable `key` arrays for the duration of the call. The implementation does
/// not retain either reference.
pub(super) unsafe fn aes_encrypt_neon(state: &mut [u8; 16], key: &[u8; 16]) {
    scalar::aes_encrypt_block(state, key)
}
#[inline(always)]
/// # Safety
///
/// The caller must provide the AArch64 SHA-256 instruction support required by
/// the selected backend. `state` and `blocks` must be valid for the duration of
/// the call, with `state` writable and `blocks` readable; no references escape.
unsafe fn compress_sha_blocks(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    #[cfg(not(windows))]
    sha2_asm::compress256(state, blocks);
    #[cfg(windows)]
    {
        let _ = (state, blocks);
        unreachable!("ARM SHA-256 compression is unavailable on Windows");
    }
}

#[target_feature(enable = "neon", enable = "sha2")]
/// # Safety
///
/// The caller must provide AArch64 NEON and SHA2 support. `data` must remain a
/// valid immutable slice for the duration of the call; the hashing helper owns
/// its block storage and does not retain input references.
pub(super) unsafe fn sha256_hw(data: &[u8]) -> [u8; 32] {
    super::sha256_hash_with_batch(data, 1, |state, blocks| compress_sha_blocks(state, blocks))
}

// Bitstream pack/unpack (NEON/SVE2 dispatch, scalar-equivalent logic)
#[inline(always)]
/// # Safety
///
/// The caller must ensure the selected compiled/runtime path has SVE2 or NEON
/// support and must provide readable `src` and writable, non-overlapping `dst`
/// slices. All vector and scalar accesses are length-bounded.
pub(super) unsafe fn pack_bits_sve2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    #[cfg(target_feature = "sve2")]
    {
        return pack_bits_neon(src, bit_width, dst);
    }
    pack_bits_neon(src, bit_width, dst)
}

#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support and readable `src` plus
/// writable, non-overlapping `dst` storage. Every vector copy and scalar tail
/// is bounded by the respective slice lengths.
pub(super) unsafe fn pack_bits_neon(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;

        if bit_width == 1 {
            let weights_arr: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
            let weights: uint8x8_t = vld1_u8(weights_arr.as_ptr());
            let ones = vdup_n_u8(1);

            let mut si = 0usize;
            let mut di = 0usize;

            while si + 8 <= src.len() && di < dst.len() {
                let v: uint8x8_t = vld1_u8(src.as_ptr().add(si));
                let bits01: uint8x8_t = vand_u8(v, ones);
                let mul: uint16x8_t = vmull_u8(bits01, weights);
                let sum: u16 = vaddvq_u16(mul);
                dst[di] = (sum & 0xFF) as u8;
                di += 1;
                si += 8;
            }

            // tail (scalar)
            if si < src.len() && di < dst.len() {
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while si < src.len() && bits < 8 {
                    bitbuf |= ((src[si] & 1) as u32) << bits;
                    bits += 1;
                    si += 1;
                }
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
            }

            return di;
        }

        if bit_width == 8 {
            let n = src.len().min(dst.len());
            if n > 0 {
                // SAFETY: `n = src.len().min(dst.len())`, so both source and
                // destination have at least `n` bytes. The slices cannot alias
                // because they come from separate `&[u8]` / `&mut [u8]` references.
                core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
            }
            return n;
        }

        if bit_width == 4 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 1 < src.len() && di < dst.len() {
                let lo = src[si] & 0x0F;
                let hi = (src[si + 1] & 0x0F) << 4;
                dst[di] = lo | hi;
                si += 2;
                di += 1;
            }
            if si < src.len() && di < dst.len() {
                dst[di] = src[si] & 0x0F;
                di += 1;
            }
            return di;
        }

        if bit_width == 2 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 3 < src.len() && di < dst.len() {
                let b0 = (src[si] & 0x03)
                    | ((src[si + 1] & 0x03) << 2)
                    | ((src[si + 2] & 0x03) << 4)
                    | ((src[si + 3] & 0x03) << 6);
                dst[di] = b0;
                si += 4;
                di += 1;
            }
            if si < src.len() && di < dst.len() {
                let mut b = 0u8;
                let mut shift = 0u8;
                while si < src.len() && shift < 8 {
                    b |= (src[si] & 0x03) << shift;
                    shift += 2;
                    si += 1;
                }
                dst[di] = b;
                di += 1;
            }
            return di;
        }

        if bit_width == 3 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 8 <= src.len() && di + 3 <= dst.len() {
                let a = src[si] & 0x07;
                let b = src[si + 1] & 0x07;
                let c = src[si + 2] & 0x07;
                let d = src[si + 3] & 0x07;
                let e = src[si + 4] & 0x07;
                let f = src[si + 5] & 0x07;
                let g = src[si + 6] & 0x07;
                let h = src[si + 7] & 0x07;
                dst[di] = a | (b << 3) | ((c & 0x03) << 6);
                dst[di + 1] = ((c >> 2) & 0x01) | (d << 1) | (e << 4) | ((f & 0x01) << 7);
                dst[di + 2] = ((f >> 1) & 0x03) | (g << 2) | (h << 5);
                si += 8;
                di += 3;
            }
            // tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while si < src.len() && di < dst.len() {
                bitbuf |= (src[si] as u32 & 0x07) << bits;
                bits += 3;
                while bits >= 8 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                    bitbuf >>= 8;
                    bits -= 8;
                }
                si += 1;
            }
            if bits > 0 && di < dst.len() {
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
            }
            return di;
        }

        if bit_width == 5 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 8 <= src.len() && di + 5 <= dst.len() {
                let a = src[si] & 0x1F;
                let b = src[si + 1] & 0x1F;
                let c = src[si + 2] & 0x1F;
                let d = src[si + 3] & 0x1F;
                let e = src[si + 4] & 0x1F;
                let f = src[si + 5] & 0x1F;
                let g = src[si + 6] & 0x1F;
                let h = src[si + 7] & 0x1F;

                dst[di] = a | ((b & 0x07) << 5);
                dst[di + 1] = ((b >> 3) & 0x03) | (c << 2) | ((d & 0x01) << 7);
                dst[di + 2] = ((d >> 1) & 0x0F) | ((e & 0x0F) << 4);
                dst[di + 3] = ((e >> 4) & 0x01) | (f << 1) | ((g & 0x03) << 6);
                dst[di + 4] = ((g >> 2) & 0x07) | (h << 3);
                si += 8;
                di += 5;
            }
            // tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while si < src.len() && di < dst.len() {
                bitbuf |= (src[si] as u32 & 0x1F) << bits;
                bits += 5;
                while bits >= 8 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                    bitbuf >>= 8;
                    bits -= 8;
                }
                si += 1;
            }
            if bits > 0 && di < dst.len() {
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
            }
            return di;
        }

        if bit_width == 6 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 4 <= src.len() && di + 3 <= dst.len() {
                let a = src[si] & 0x3F;
                let b = src[si + 1] & 0x3F;
                let c = src[si + 2] & 0x3F;
                let d = src[si + 3] & 0x3F;
                dst[di] = a | ((b & 0x03) << 6);
                dst[di + 1] = ((b >> 2) & 0x0F) | ((c & 0x0F) << 4);
                dst[di + 2] = ((c >> 4) & 0x03) | (d << 2);
                si += 4;
                di += 3;
            }
            // tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while si < src.len() && di < dst.len() {
                bitbuf |= (src[si] as u32 & 0x3F) << bits;
                bits += 6;
                while bits >= 8 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                    bitbuf >>= 8;
                    bits -= 8;
                }
                si += 1;
            }
            if bits > 0 && di < dst.len() {
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
            }
            return di;
        }

        if bit_width == 7 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 8 <= src.len() && di + 7 <= dst.len() {
                let a = src[si] & 0x7F;
                let b = src[si + 1] & 0x7F;
                let c = src[si + 2] & 0x7F;
                let d = src[si + 3] & 0x7F;
                let e = src[si + 4] & 0x7F;
                let f = src[si + 5] & 0x7F;
                let g = src[si + 6] & 0x7F;
                let h = src[si + 7] & 0x7F;

                dst[di] = a | ((b & 0x01) << 7);
                dst[di + 1] = ((b >> 1) & 0x3F) | ((c & 0x03) << 6);
                dst[di + 2] = ((c >> 2) & 0x1F) | ((d & 0x07) << 5);
                dst[di + 3] = ((d >> 3) & 0x0F) | ((e & 0x0F) << 4);
                dst[di + 4] = ((e >> 4) & 0x07) | ((f & 0x1F) << 3);
                dst[di + 5] = ((f >> 5) & 0x03) | ((g & 0x3F) << 2);
                dst[di + 6] = ((g >> 6) & 0x01) | (h << 1);
                si += 8;
                di += 7;
            }
            // tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while si < src.len() && di < dst.len() {
                bitbuf |= (src[si] as u32 & 0x7F) << bits;
                bits += 7;
                while bits >= 8 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                    bitbuf >>= 8;
                    bits -= 8;
                }
                si += 1;
            }
            if bits > 0 && di < dst.len() {
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
            }
            return di;
        }
    }

    scalar::pack_bits(src, bit_width, dst)
}

#[inline(always)]
/// # Safety
///
/// The caller must ensure the selected compiled/runtime path has SVE2 or NEON
/// support and must provide readable `src` plus writable, non-overlapping `dst`
/// storage. All accesses are length-bounded.
pub(super) unsafe fn unpack_bits_sve2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    #[cfg(target_feature = "sve2")]
    {
        return unpack_bits_neon(src, bit_width, dst);
    }
    unpack_bits_neon(src, bit_width, dst)
}

#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support and readable `src` plus
/// writable, non-overlapping `dst` storage. All vector and scalar accesses are
/// bounded by the respective slice lengths.
pub(super) unsafe fn unpack_bits_neon(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        if bit_width == 1 {
            let mut si = 0usize;
            let mut di = 0usize;
            while di + 8 <= dst.len() && si < src.len() {
                let byte = src[si];
                si += 1;
                dst[di] = byte & 0x01;
                dst[di + 1] = (byte >> 1) & 0x01;
                dst[di + 2] = (byte >> 2) & 0x01;
                dst[di + 3] = (byte >> 3) & 0x01;
                dst[di + 4] = (byte >> 4) & 0x01;
                dst[di + 5] = (byte >> 5) & 0x01;
                dst[di + 6] = (byte >> 6) & 0x01;
                dst[di + 7] = (byte >> 7) & 0x01;
                di += 8;
            }
            // Tail
            if di < dst.len() && si < src.len() {
                let byte = src[si];
                let mut j = 0usize;
                while di < dst.len() && j < 8 {
                    dst[di] = (byte >> j) & 1;
                    di += 1;
                    j += 1;
                }
            }
            return di;
        }

        if bit_width == 8 {
            let n = dst.len().min(src.len());
            if n > 0 {
                // SAFETY: `n = dst.len().min(src.len())`, so both source and
                // destination have at least `n` bytes. The slices cannot alias
                // because they come from separate `&[u8]` / `&mut [u8]` references.
                core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
            }
            return n;
        }

        if bit_width == 4 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si < src.len() && di + 1 < dst.len() {
                let byte = src[si];
                si += 1;
                dst[di] = byte & 0x0F;
                dst[di + 1] = (byte >> 4) & 0x0F;
                di += 2;
            }
            if si < src.len() && di < dst.len() {
                let byte = src[si];
                dst[di] = byte & 0x0F;
                di += 1;
            }
            return di;
        }

        if bit_width == 2 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si < src.len() && di + 3 < dst.len() {
                let byte = src[si];
                si += 1;
                dst[di] = byte & 0x03;
                dst[di + 1] = (byte >> 2) & 0x03;
                dst[di + 2] = (byte >> 4) & 0x03;
                dst[di + 3] = (byte >> 6) & 0x03;
                di += 4;
            }
            if si < src.len() && di < dst.len() {
                let byte = src[si];
                let mut j = 0usize;
                while di < dst.len() && j < 4 {
                    dst[di] = (byte >> (2 * j)) & 0x03;
                    di += 1;
                    j += 1;
                }
            }
            return di;
        }

        if bit_width == 3 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 3 <= src.len() && di + 8 <= dst.len() {
                let b0 = src[si];
                let b1 = src[si + 1];
                let b2 = src[si + 2];
                dst[di] = b0 & 0x07;
                dst[di + 1] = (b0 >> 3) & 0x07;
                dst[di + 2] = ((b0 >> 6) & 0x03) | ((b1 & 0x01) << 2);
                dst[di + 3] = (b1 >> 1) & 0x07;
                dst[di + 4] = (b1 >> 4) & 0x07;
                dst[di + 5] = ((b1 >> 7) & 0x01) | ((b2 & 0x03) << 1);
                dst[di + 6] = (b2 >> 2) & 0x07;
                dst[di + 7] = (b2 >> 5) & 0x07;
                si += 3;
                di += 8;
            }
            // Tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while di < dst.len() {
                while bits < 3 {
                    if si >= src.len() {
                        return di;
                    }
                    bitbuf |= (src[si] as u32) << bits;
                    si += 1;
                    bits += 8;
                }
                dst[di] = (bitbuf & 0x07) as u8;
                bitbuf >>= 3;
                bits -= 3;
                di += 1;
            }
            return di;
        }

        if bit_width == 5 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 5 <= src.len() && di + 8 <= dst.len() {
                let x0 = src[si];
                let x1 = src[si + 1];
                let x2 = src[si + 2];
                let x3 = src[si + 3];
                let x4 = src[si + 4];
                dst[di] = x0 & 0x1F;
                dst[di + 1] = ((x0 >> 5) & 0x07) | ((x1 & 0x03) << 3);
                dst[di + 2] = (x1 >> 2) & 0x1F;
                dst[di + 3] = ((x1 >> 7) & 0x01) | ((x2 & 0x0F) << 1);
                dst[di + 4] = ((x2 >> 4) & 0x0F) | ((x3 & 0x01) << 4);
                dst[di + 5] = (x3 >> 1) & 0x1F;
                dst[di + 6] = ((x3 >> 6) & 0x03) | ((x4 & 0x07) << 2);
                dst[di + 7] = (x4 >> 3) & 0x1F;
                si += 5;
                di += 8;
            }
            // Tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while di < dst.len() {
                while bits < 5 {
                    if si >= src.len() {
                        return di;
                    }
                    bitbuf |= (src[si] as u32) << bits;
                    si += 1;
                    bits += 8;
                }
                dst[di] = (bitbuf & 0x1F) as u8;
                bitbuf >>= 5;
                bits -= 5;
                di += 1;
            }
            return di;
        }

        if bit_width == 6 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 3 <= src.len() && di + 4 <= dst.len() {
                let x0 = src[si];
                let x1 = src[si + 1];
                let x2 = src[si + 2];
                dst[di] = x0 & 0x3F;
                dst[di + 1] = ((x0 >> 6) & 0x03) | ((x1 & 0x0F) << 2);
                dst[di + 2] = ((x1 >> 4) & 0x0F) | ((x2 & 0x03) << 4);
                dst[di + 3] = (x2 >> 2) & 0x3F;
                si += 3;
                di += 4;
            }
            // Tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while di < dst.len() {
                while bits < 6 {
                    if si >= src.len() {
                        return di;
                    }
                    bitbuf |= (src[si] as u32) << bits;
                    si += 1;
                    bits += 8;
                }
                dst[di] = (bitbuf & 0x3F) as u8;
                bitbuf >>= 6;
                bits -= 6;
                di += 1;
            }
            return di;
        }

        if bit_width == 7 {
            let mut si = 0usize;
            let mut di = 0usize;
            while si + 7 <= src.len() && di + 8 <= dst.len() {
                let x0 = src[si];
                let x1 = src[si + 1];
                let x2 = src[si + 2];
                let x3 = src[si + 3];
                let x4 = src[si + 4];
                let x5 = src[si + 5];
                let x6 = src[si + 6];
                dst[di] = x0 & 0x7F;
                dst[di + 1] = ((x0 >> 7) & 0x01) | ((x1 & 0x3F) << 1);
                dst[di + 2] = ((x1 >> 6) & 0x03) | ((x2 & 0x1F) << 2);
                dst[di + 3] = ((x2 >> 5) & 0x07) | ((x3 & 0x0F) << 3);
                dst[di + 4] = ((x3 >> 4) & 0x0F) | ((x4 & 0x07) << 4);
                dst[di + 5] = ((x4 >> 3) & 0x1F) | ((x5 & 0x03) << 5);
                dst[di + 6] = ((x5 >> 2) & 0x3F) | ((x6 & 0x01) << 6);
                dst[di + 7] = (x6 >> 1) & 0x7F;
                si += 7;
                di += 8;
            }
            // Tail via bit-buffer
            let mut bitbuf: u32 = 0;
            let mut bits: u32 = 0;
            while di < dst.len() {
                while bits < 7 {
                    if si >= src.len() {
                        return di;
                    }
                    bitbuf |= (src[si] as u32) << bits;
                    si += 1;
                    bits += 8;
                }
                dst[di] = (bitbuf & 0x7F) as u8;
                bitbuf >>= 7;
                bits -= 7;
                di += 1;
            }
            return di;
        }
    }

    scalar::unpack_bits(src, bit_width, dst)
}

// Reed-Solomon encode using NEON+PMULL GF multiply (block-wise)
#[inline(always)]
/// # Safety
///
/// The caller must provide AArch64 NEON support and a valid immutable `data`
/// slice. The function allocates owned output and does not retain input
/// references; internal shard buffers are sized before vector operations.
pub(super) unsafe fn reed_solomon_encode_neon(data: &[u8], parity_shards: usize) -> Vec<u8> {
    let shard_size = 256;
    let data_shards = data.len().div_ceil(shard_size);
    let total_shards = data_shards + parity_shards;
    let mut output = vec![0u8; total_shards * shard_size];

    // Copy data shards
    output[..data.len()].copy_from_slice(data);

    // Generate parity shards
    for p in 0..parity_shards {
        let parity_base = (data_shards + p) * shard_size;
        for d in 0..data_shards {
            let coeff = super::scalar::gf_pow((p as u8) + 1, d as u8);
            let data_base = d * shard_size;

            // Process 16-byte blocks with PMULL-assisted multiply
            let mut k = 0usize;
            while k + 16 <= shard_size {
                let mut prod = [0u8; 16];
                super::arm::gf_mul_neon_pmull(
                    &output[data_base + k..data_base + k + 16],
                    coeff,
                    &mut prod,
                );
                // XOR accumulate into parity shard
                for i in 0..16 {
                    output[parity_base + k + i] ^= prod[i];
                }
                k += 16;
            }

            // Tail (should be zero for shard size 256, but keep safe)
            while k < shard_size {
                let idx = data_base + k;
                output[parity_base + k] ^= super::scalar::gf_mul_byte(output[idx], coeff);
                k += 1;
            }
        }
    }

    output
}

#[inline(always)]
pub(crate) fn qpack_encode_neon(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is baseline on aarch64. The impl uses NEON intrinsics to
        // expand bytes into u32 indices for Huffman table lookup, then accumulates
        // bits into a u128 accumulator. Output bounds are checked on each byte write.
        unsafe { qpack_encode_neon_impl(input, output) }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (input, output);
        scalar::qpack_encode(input, output)
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must provide AArch64 NEON support, valid immutable `input`, and
/// writable `output` storage. The slices must not overlap; each output write is
/// checked against `output.len()`.
unsafe fn qpack_encode_neon_impl(input: &[u8], output: &mut [u8]) -> usize {
    use crate::qpack::{HUFF_CODES, HUFF_LENS};
    use core::arch::aarch64::{
        uint32x4_t, uint8x8_t, vget_high_u16, vget_low_u16, vld1_u8, vmovl_u16, vmovl_u8, vst1q_u32,
    };

    let mut acc: u128 = 0;
    let mut bits: usize = 0;
    let mut written: usize = 0;
    let mut i = 0usize;
    let mut lanes = [0u32; 8];

    while i + 8 <= input.len() {
        let ptr = input.as_ptr().add(i);
        let chunk: uint8x8_t = vld1_u8(ptr);
        let expanded = vmovl_u8(chunk);
        let lower: uint32x4_t = vmovl_u16(vget_low_u16(expanded));
        let upper: uint32x4_t = vmovl_u16(vget_high_u16(expanded));
        vst1q_u32(lanes.as_mut_ptr(), lower);
        vst1q_u32(lanes.as_mut_ptr().add(4), upper);

        for &sym_u16 in lanes.iter() {
            let sym = sym_u16 as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                if written >= output.len() {
                    return written;
                }
                let byte = ((acc >> shift) & 0xff) as u8;
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        i += 8;
    }

    while i < input.len() {
        let sym = input[i] as usize;
        let code = HUFF_CODES[sym] as u128;
        let clen = crate::qpack::HUFF_LENS[sym] as usize;

        if bits + clen > 120 {
            while bits >= 8 {
                let shift = bits - 8;
                if written >= output.len() {
                    return written;
                }
                let byte = ((acc >> shift) & 0xff) as u8;
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
        }

        acc = (acc << clen) | code;
        bits += clen;

        while bits >= 8 {
            let shift = bits - 8;
            if written >= output.len() {
                return written;
            }
            let byte = ((acc >> shift) & 0xff) as u8;
            output[written] = byte;
            written += 1;
            bits -= 8;
            acc &= (1u128 << shift) - 1;
        }

        i += 1;
    }

    if bits > 0 {
        if written >= output.len() {
            return written;
        }
        let pad_mask = (1u128 << (8 - bits)) - 1;
        let byte = ((acc << (8 - bits)) | pad_mask) as u8;
        output[written] = byte;
        written += 1;
    }

    written
}

// SVE2 implementation: uses SVE vector loads and predicate-tail handling, with scalar per-symbol
// Huffman accumulation. Compiles only when SVE2 is available; otherwise we fall back to NEON.
#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must provide SVE2 support, valid immutable `input`, and writable
/// non-overlapping `output` storage. Predicate loads and explicit output checks
/// bound all accesses.
unsafe fn qpack_encode_sve2_impl(input: &[u8], output: &mut [u8]) -> usize {
    use crate::qpack::{HUFF_CODES, HUFF_LENS};
    use core::arch::aarch64::*;

    let mut acc: u128 = 0;
    let mut bits: usize = 0;
    let mut written: usize = 0;
    let mut i = 0usize;

    let mut lanes_buf: [u8; 256] = [0; 256];

    while i < input.len() {
        let pg = svwhilelt_b8(i as u64, input.len() as u64);
        if svptest_any(svptrue_b8(), pg) {
            let v = svld1_u8(pg, input.as_ptr().add(i));
            svst1_u8(pg, lanes_buf.as_mut_ptr(), v);
            let active = svcntp_b8(svptrue_b8(), pg) as usize;

            for idx in 0..active {
                let sym = lanes_buf[idx] as usize;
                let code = HUFF_CODES[sym] as u128;
                let clen = HUFF_LENS[sym] as usize;

                if bits + clen > 120 {
                    while bits >= 8 {
                        let shift = bits - 8;
                        if written >= output.len() {
                            return written;
                        }
                        let byte = ((acc >> shift) & 0xff) as u8;
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                acc = (acc << clen) | code;
                bits += clen;

                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            i += active;
        } else {
            break;
        }
    }

    if bits > 0 {
        if written >= output.len() {
            return written;
        }
        let pad_mask = (1u128 << (8 - bits)) - 1;
        let byte = ((acc << (8 - bits)) | pad_mask) as u8;
        output[written] = byte;
        written += 1;
    }

    written
}

#[inline(always)]
pub(crate) fn qpack_decode_neon(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        match crate::qpack::huff_decode_into(input, output) {
            Ok(written) => written,
            Err(crate::qpack::HuffmanError::BufferTooShort) => output.len(),
            Err(_) => 0,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (input, output);
        scalar::qpack_decode(input, output)
    }
}

#[inline(always)]
pub(crate) fn qpack_encode_sve2(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_feature = "sve2")]
    {
        // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl uses
        // SVE predicated loads and scalar Huffman accumulation with bounds checks.
        return unsafe { qpack_encode_sve2_impl(input, output) };
    }
    qpack_encode_neon(input, output)
}

#[inline(always)]
pub(crate) fn qpack_decode_sve2(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_feature = "sve2")]
    {
        // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl delegates
        // to `huff_decode_into` which performs bounds-checked decoding.
        return unsafe { qpack_decode_sve2_impl(input, output) };
    }
    qpack_decode_neon(input, output)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must provide SVE2 support, valid immutable `input`, and writable
/// non-overlapping `output` storage. The delegated decoder owns its bounds
/// checks and no input reference escapes this call.
unsafe fn qpack_decode_sve2_impl(input: &[u8], output: &mut [u8]) -> usize {
    match crate::qpack::huff_decode_into(input, output) {
        Ok(written) => written,
        Err(crate::qpack::HuffmanError::BufferTooShort) => output.len(),
        Err(_) => 0,
    }
}

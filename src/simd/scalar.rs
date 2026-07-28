//! Extracted SIMD `scalar` submodule (TODO-563).

use crate::crypto::{aes, gcm, hkdf};
use crate::simd::{CpuFeature, FeatureDetector};
/// GF(256) exponentiation for Reed-Solomon generator polynomials.
pub fn gf_pow(base: u8, exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    let mut result = base;
    for _ in 1..exp {
        result = gf_mul_byte(result, base);
    }
    result
}

/// XOR `src` into `dst` byte-by-byte (scalar fallback).
pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// CRC-32 using a precomputed 256-entry table (scalar fallback).
pub fn crc32(data: &[u8], mut crc: u32) -> u32 {
    // CRC-32 polynomial: 0xEDB88320 (reversed representation)
    const POLY: u32 = 0xEDB88320;

    // Generate CRC32 table
    const fn make_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut j = 0;
            while j < 8 {
                if c & 1 != 0 {
                    c = POLY ^ (c >> 1);
                } else {
                    c >>= 1;
                }
                j += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    }

    const TABLE: [u32; 256] = make_table();

    crc = !crc;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Population count over a byte slice (scalar fallback).
pub fn popcnt(data: &[u8]) -> usize {
    data.iter().map(|&b| b.count_ones() as usize).sum()
}

/// GF(2^8) multiply each byte of `a` by scalar `b` into `dst` (scalar fallback).
pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
    for i in 0..a.len().min(dst.len()) {
        dst[i] = gf_mul_byte(a[i], b);
    }
}

/// Single GF(2^8) byte multiplication with AES reduction polynomial.
pub fn gf_mul_byte(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;
    while bb != 0 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let carry = aa & 0x80;
        aa <<= 1;
        if carry != 0 {
            aa ^= 0x1b; // GF(2^8) reduction polynomial
        }
        bb >>= 1;
    }
    result
}

/// AES-128 single-block encrypt in place (scalar, delegates to software AES).
pub fn aes_encrypt_block(state: &mut [u8; 16], key: &[u8; 16]) {
    let block = *state;
    let encrypted = aes::aes128_encrypt_block(key, &block);
    state.copy_from_slice(&encrypted);
}

/// GHASH for GCM mode (scalar fallback, delegates to crypto::gcm).
pub fn ghash(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
    let computed = gcm::ghash(*h, &[], data);
    tag.copy_from_slice(&computed);
}

/// SHA-256 digest (scalar fallback, delegates to hkdf::sha256).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hkdf::sha256(data)
}

/// Byte-frequency histogram over a data slice (scalar).
pub fn histogram(data: &[u8]) -> [u32; 256] {
    let mut hist = [0u32; 256];
    for &byte in data {
        hist[byte as usize] += 1;
    }
    hist
}

/// Find first occurrence of `needle` in `haystack` (scalar linear scan).
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// f32 dot product of two equal-length slices (scalar).
pub fn dot_product_f32(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// f32 matrix multiplication C = A * B with dimensions (m x k) * (k x n) (scalar).
pub fn matmul(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
    for i in 0..m {
        for j in 0..n {
            let mut sum = 0.0;
            for l in 0..k {
                sum += a[i * k + l] * b[l * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

/// Berlekamp-Massey algorithm over GF(256) for error-locator polynomial (scalar).
pub fn berlekamp_massey(syndrome: &[u8], len: usize) -> Vec<u8> {
    let mut error_locator = vec![0u8; len + 1];
    error_locator[0] = 1;

    let mut old_locator = vec![0u8; len + 1];
    old_locator[0] = 1;

    let mut syndrome_shift = 0u8;
    let mut error_degree = 0;
    let mut old_degree = 1;

    for i in 0..len {
        let mut discrepancy = syndrome[i];

        for j in 1..=error_degree.min(i) {
            discrepancy ^= super::scalar::gf_mul_byte(error_locator[j], syndrome[i - j]);
        }

        if discrepancy != 0 {
            let mut new_locator = error_locator.clone();

            if syndrome_shift != 0 {
                let factor = super::scalar::gf_mul_byte(
                    discrepancy,
                    super::scalar::gf_inv(syndrome_shift),
                );
                for j in 0..=old_degree {
                    if j + i >= old_degree {
                        new_locator[j + i - old_degree + 1] ^=
                            super::scalar::gf_mul_byte(factor, old_locator[j]);
                    }
                }
            }

            if 2 * error_degree <= i {
                old_locator = error_locator.clone();
                old_degree = error_degree;
                syndrome_shift = discrepancy;
                error_degree = i + 1 - error_degree;
            }

            error_locator = new_locator;
        }
    }

    error_locator.truncate(error_degree + 1);
    error_locator
}

/// GF(256) matrix multiplication C = A * B with dimensions (m x k) * (k x n) (scalar).
pub fn matmul_gf256(a: &[u8], b: &[u8], c: &mut [u8], m: usize, k: usize, n: usize) {
    // Zero the output
    for elem in c.iter_mut().take(m * n) {
        *elem = 0;
    }

    // GF(256) matrix multiplication
    for i in 0..m {
        for kk in 0..k {
            if a[i * k + kk] == 0 {
                continue;
            }
            for j in 0..n {
                c[i * n + j] ^= super::scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
            }
        }
    }
}

/// Reed-Solomon encode with SIMD dispatch; produces `parity_shards` extra shards.
pub fn reed_solomon_encode(data: &[u8], parity_shards: usize) -> Vec<u8> {
    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. Callees process 256-byte shards with SIMD
    // GF(256) multiplication and write to owned Vec output.
    #[cfg(target_arch = "x86_64")]
    {
        if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
            return unsafe { super::x86::reed_solomon_encode_gfni(data, parity_shards) };
        }
        if features.has_feature(CpuFeature::AVX2) {
            return unsafe { super::x86::reed_solomon_encode_avx2(data, parity_shards) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.has_feature(CpuFeature::NEON) {
            return unsafe { super::arm::reed_solomon_encode_neon(data, parity_shards) };
        }
    }

    reed_solomon_encode_scalar(data, parity_shards)
}

#[inline(always)]
pub(crate) fn reed_solomon_encode_scalar(data: &[u8], parity_shards: usize) -> Vec<u8> {
    // Scalar Reed-Solomon encoding
    let data_shards = data.len() / 256;
    let total_shards = data_shards + parity_shards;
    let mut output = vec![0u8; total_shards * 256];

    // Copy data
    output[..data.len()].copy_from_slice(data);

    // Generate parity
    for i in 0..parity_shards {
        for j in 0..data_shards {
            let coeff = gf_pow((i + 1) as u8, j as u8);
            for k in 0..256 {
                let idx = j * 256 + k;
                if idx < data.len() {
                    output[(data_shards + i) * 256 + k] ^= gf_mul_byte(data[idx], coeff);
                }
            }
        }
    }

    output
}

/// Reed-Solomon decode from available shards and their indices via Gaussian elimination.
pub fn reed_solomon_decode(
    shards: &[Vec<u8>],
    indices: &[usize],
) -> Result<Vec<u8>, &'static str> {
    if shards.is_empty() {
        return Err("No shards provided");
    }

    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. Callees read from `shards` and `indices`,
    // perform GF(256) Gaussian elimination, and return owned decoded data.
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance();
        if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
            return unsafe { super::x86::reed_solomon_decode_gfni(shards, indices) };
        }
        if features.has_feature(CpuFeature::AVX2) {
            return unsafe { super::x86::reed_solomon_decode_avx2(shards, indices) };
        }
    }

    if shards.len() != indices.len() {
        return Err("Shard/index length mismatch");
    }
    let shard_size = shards[0].len();
    if !shards.iter().all(|s| s.len() == shard_size) {
        return Err("Shard size mismatch");
    }

    let k = shards.len();
    let mut aug = vec![vec![0u8; 2 * k]; k];
    for row in 0..k {
        let x = indices[row] as u8;
        let mut col = 0usize;
        while col < k {
            aug[row][col] = gf_pow(x, col as u8);
            col += 1;
        }
        aug[row][k + row] = 1;
    }

    for pivot in 0..k {
        if aug[pivot][pivot] == 0 {
            let mut swap_row = None;
            let mut cand = pivot + 1;
            while cand < k {
                if aug[cand][pivot] != 0 {
                    swap_row = Some(cand);
                    break;
                }
                cand += 1;
            }
            if let Some(cand) = swap_row {
                aug.swap(pivot, cand);
            } else {
                return Err("Matrix not invertible");
            }
        }

        let inv = gf_inv(aug[pivot][pivot]);
        let mut col = pivot;
        while col < (2 * k) {
            aug[pivot][col] = gf_mul_byte(aug[pivot][col], inv);
            col += 1;
        }

        for row in 0..k {
            if row == pivot {
                continue;
            }
            let factor = aug[row][pivot];
            if factor == 0 {
                continue;
            }
            let mut col = pivot;
            while col < (2 * k) {
                let prod = gf_mul_byte(aug[pivot][col], factor);
                aug[row][col] ^= prod;
                col += 1;
            }
        }
    }

    let mut output = vec![0u8; k * shard_size];
    for out_row in 0..k {
        for shard_idx in 0..k {
            let coeff = aug[out_row][k + shard_idx];
            if coeff == 0 {
                continue;
            }
            let src = &shards[shard_idx];
            let dst = &mut output[out_row * shard_size..(out_row + 1) * shard_size];
            for i in 0..shard_size {
                dst[i] ^= gf_mul_byte(src[i], coeff);
            }
        }
    }

    Ok(output)
}

/// QPACK encode (scalar identity copy fallback).
pub fn qpack_encode(input: &[u8], output: &mut [u8]) -> usize {
    let len = input.len().min(output.len());
    output[..len].copy_from_slice(&input[..len]);
    len
}

/// QPACK decode (scalar identity copy fallback).
pub fn qpack_decode(input: &[u8], output: &mut [u8]) -> usize {
    let len = input.len().min(output.len());
    output[..len].copy_from_slice(&input[..len]);
    len
}

/// Validate QUIC fixed-bit and short-header reserved-bit constraints.
pub fn validate_header(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    let first = header[0];
    (first & 0x40) != 0 && ((first & 0x80) != 0 || (first & 0x18) == 0)
}

/// Pack values into a bitstream at the given bit width (scalar fallback).
pub fn pack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    if bit_width == 0 || bit_width > 8 {
        return 0;
    }
    let mut bitbuf: u32 = 0;
    let mut bits: u32 = 0;
    let mut di = 0usize;
    for &v in src {
        bitbuf |= (v as u32 & ((1u32 << bit_width) - 1)) << bits;
        bits += bit_width as u32;
        while bits >= 8 {
            if di >= dst.len() {
                return di;
            }
            dst[di] = (bitbuf & 0xFF) as u8;
            di += 1;
            bitbuf >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 && di < dst.len() {
        dst[di] = (bitbuf & 0xFF) as u8;
        di += 1;
    }
    di
}

/// Unpack a bitstream at the given bit width into individual bytes (scalar fallback).
pub fn unpack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    if bit_width == 0 || bit_width > 8 {
        return 0;
    }
    let mut bitbuf: u32 = 0;
    let mut bits: u32 = 0;
    let mut si = 0usize;
    let mut di = 0usize;
    let mask = (1u32 << bit_width) - 1;
    while di < dst.len() {
        while bits < bit_width as u32 {
            if si >= src.len() {
                return di;
            }
            bitbuf |= (src[si] as u32) << bits;
            si += 1;
            bits += 8;
        }
        dst[di] = (bitbuf & mask) as u8;
        bitbuf >>= bit_width;
        bits -= bit_width as u32;
        di += 1;
    }
    di
}

/// Encode a value as a variable-length integer into `buf` (scalar fallback).
pub fn encode_varint(mut value: u64, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    while value >= 128 {
        buf[pos] = (value as u8) | 0x80;
        value >>= 7;
        pos += 1;
    }

    buf[pos] = value as u8;
    pos + 1
}

/// Decode a variable-length integer from `buf`; returns (value, bytes_consumed) (scalar fallback).
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;

    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }

        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }

        shift += 7;
    }

    None
}

/// GF(256) inversion for Berlekamp-Massey
pub fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result = a;
    // Fermat's little theorem: a^254 = a^-1 in GF(256)
    for _ in 0..253 {
        result = gf_mul_byte(result, a);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn aes_encrypt_block_matches_crypto_module() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let mut state: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        aes_encrypt_block(&mut state, &key);

        let expected = aes::aes128_encrypt_block(
            &key,
            &[
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                0x37, 0x07, 0x34,
            ],
        );

        assert_eq!(state, expected);
    }

    #[test]
    fn ghash_matches_crypto_module() {
        let h = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let data = b"scalar-ghash-test-data-123";
        let mut tag = [0u8; 16];

        ghash(&h, data, &mut tag);

        let expected = gcm::ghash(h, &[], data);
        assert_eq!(tag, expected);
    }

    #[test]
    fn sha256_matches_reference() {
        let data = b"scalar-sha256-test";
        let hash = sha256(data);
        let digest = Sha256::digest(data);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest);
        assert_eq!(hash, expected);
    }
}

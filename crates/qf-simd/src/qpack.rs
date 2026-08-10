//! Extracted SIMD `qpack` submodule (TODO-563).

use super::*;

/// Errors returned by the shared HPACK/QPACK Huffman decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanError {
    /// The caller-provided output buffer cannot hold the decoded bytes.
    BufferTooShort,
    /// The input contains an invalid code, EOS symbol, or padding sequence.
    InvalidEncoding,
}

// HPACK/QPACK Huffman coding tables (RFC 7541 Appendix B) for 257 symbols.
pub const HUFF_CODES: [u32; 257] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, // 32..63
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16,
    0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20,
    0xffb, 0x3fc, // 64..95
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, // 96..127
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd,
    0xffffffc, // 128..159
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6,
    0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed,
    0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8,
    0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, // 160..191
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea,
    0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1,
    0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3,
    0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, // 192..223
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2,
    0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3,
    0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8,
    0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, // 224..255
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea,
    0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb, 0x7ffffe6,
    0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe,
    0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee, // EOS 256
    0x3fffffff,
];

pub const HUFF_LENS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

#[inline]
pub fn huff_estimate_len(input: &[u8]) -> usize {
    let bits = input.iter().map(|&byte| HUFF_LENS[byte as usize] as usize).sum::<usize>();
    bits.div_ceil(8)
}

#[inline]
pub fn huff_encode_into(input: &[u8], output: &mut [u8]) -> usize {
    let mut acc = 0u64;
    let mut acc_bits = 0usize;
    let mut written = 0usize;
    for &byte in input {
        let code = HUFF_CODES[byte as usize] as u64;
        let code_bits = HUFF_LENS[byte as usize] as usize;
        acc = (acc << code_bits) | code;
        acc_bits += code_bits;
        while acc_bits >= 8 {
            let shift = acc_bits - 8;
            if written >= output.len() {
                return written;
            }
            output[written] = ((acc >> shift) & 0xff) as u8;
            written += 1;
            acc_bits -= 8;
            acc &= (1u64 << shift).saturating_sub(1);
        }
    }
    if acc_bits > 0 {
        if written >= output.len() {
            return written;
        }
        let pad = (1u64 << (8 - acc_bits)) - 1;
        output[written] = ((acc << (8 - acc_bits)) | pad) as u8;
        written += 1;
    }
    written
}

#[derive(Default)]
struct Node {
    next: [i32; 2],
    sym: i32,
}

pub fn huff_decode_into(input: &[u8], output: &mut [u8]) -> Result<usize, HuffmanError> {
    fn build_trie() -> Vec<Node> {
        let mut trie = vec![Node { next: [-1, -1], sym: -1 }];
        for symbol in 0..257u32 {
            let code = HUFF_CODES[symbol as usize] as u64;
            let code_bits = HUFF_LENS[symbol as usize] as usize;
            let mut index = 0usize;
            for bit_index in (0..code_bits).rev() {
                let bit = ((code >> bit_index) & 1) as usize;
                let next = trie[index].next[bit];
                if next == -1 {
                    trie[index].next[bit] = trie.len() as i32;
                    trie.push(Node { next: [-1, -1], sym: -1 });
                    index = trie.len() - 1;
                } else {
                    index = next as usize;
                }
            }
            trie[index].sym = symbol as i32;
        }
        trie
    }

    static TRIE: std::sync::OnceLock<Vec<Node>> = std::sync::OnceLock::new();
    let trie = TRIE.get_or_init(build_trie);
    let mut index = 0usize;
    let mut written = 0usize;
    let mut pending_bits = 0usize;
    let mut pending_value = 0u8;
    for &byte in input {
        for bit_index in (0..8).rev() {
            let bit = ((byte >> bit_index) & 1) as usize;
            pending_bits += 1;
            pending_value = (pending_value << 1) | bit as u8;
            let next = trie[index].next[bit];
            if next < 0 {
                return Err(HuffmanError::InvalidEncoding);
            }
            index = next as usize;
            let symbol = trie[index].sym;
            if symbol >= 0 {
                if symbol == 256 {
                    return Err(HuffmanError::InvalidEncoding);
                }
                if written >= output.len() {
                    return Err(HuffmanError::BufferTooShort);
                }
                output[written] = symbol as u8;
                written += 1;
                index = 0;
                pending_bits = 0;
                pending_value = 0;
            }
        }
    }
    if index == 0 || (pending_bits <= 7 && pending_value == ((1u16 << pending_bits) - 1) as u8) {
        Ok(written)
    } else {
        Err(HuffmanError::InvalidEncoding)
    }
}

/// Encode bytes using QPACK Huffman coding with runtime SIMD dispatch.
#[inline(always)]
pub fn encode_huff_into(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let full = FeatureDetector::instance().features_full();
        if full.simd_dispatch_matrix().avx2 {
            // SAFETY: AVX2 feature verified by runtime detection. Callee reads
            // `input` and writes up to `output.len()` bytes with bounds checks.
            return unsafe { super::x86::qpack_encode_avx2(input, output) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let full = FeatureDetector::instance().features_full();
        if full.neon {
            return super::arm::qpack_encode_neon(input, output);
        }
    }
    huff_encode_into(input, output)
}

use super::OnceLock;
#[cfg(target_arch = "aarch64")]
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [SBOX[w[0] as usize], SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize]]
}
fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}
pub(crate) fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key);
    let mut i = 16;
    let mut rcon_iter = 0;
    while i < 176 {
        let mut temp = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
        if i % 16 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[rcon_iter];
            rcon_iter += 1;
        }
        for &t in &temp {
            w[i] = w[i - 16] ^ t;
            i += 1;
        }
    }
    w
}

#[inline(always)]
fn expand_round_keys_array(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut expanded = key_expansion(key);
    let mut keys = [[0u8; 16]; 11];
    for (idx, chunk) in expanded.chunks_exact(16).enumerate() {
        keys[idx].copy_from_slice(chunk);
    }
    // The flat expansion is a temporary secret schedule. Clear it before the
    // function returns the retained round-key representation.
    expanded.zeroize();
    keys
}

fn zeroize_round_keys(round_keys: &mut [[u8; 16]; 11]) {
    for round_key in round_keys {
        round_key.zeroize();
    }
}

fn zeroize_round_key_words(round_keys: &mut [[u32; 4]; 11]) {
    for round_key in round_keys {
        for word in round_key {
            *word = 0;
        }
    }
}

#[inline(always)]
fn inc32_be(counter: &mut [u8; 16]) {
    let value =
        u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
    counter[12..16].copy_from_slice(&value.to_be_bytes());
}
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}
fn shift_rows(state: &mut [u8; 16]) {
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    let t2 = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t2;
}
fn mix_single_column(a: &mut [u8; 4]) {
    fn xtime(x: u8) -> u8 {
        (x << 1) ^ (((x >> 7) & 1) * 0x1b)
    }
    let t = a[0] ^ a[1] ^ a[2] ^ a[3];
    let u = a[0];
    a[0] ^= t ^ xtime(a[0] ^ a[1]);
    a[1] ^= t ^ xtime(a[1] ^ a[2]);
    a[2] ^= t ^ xtime(a[2] ^ a[3]);
    a[3] ^= t ^ xtime(a[3] ^ u);
}
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let mut col = [state[4 * c], state[4 * c + 1], state[4 * c + 2], state[4 * c + 3]];
        mix_single_column(&mut col);
        state[4 * c..4 * c + 4].copy_from_slice(&col);
    }
}
fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for (i, b) in state.iter_mut().enumerate() {
        *b ^= round_key[i];
    }
}

/// Software equivalent of AESENC(state, round_key).
///
/// AESENC performs one AES round:
/// SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
#[inline(always)]
pub(crate) fn aesenc_round(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
    let mut state = *block;
    sub_bytes(&mut state);
    shift_rows(&mut state);
    mix_columns(&mut state);
    add_round_key(&mut state, round_key);
    state
}
#[derive(Debug)]
struct AesTables {
    t0: [u32; 256],
    t1: [u32; 256],
    t2: [u32; 256],
    t3: [u32; 256],
}

static AES_TABLES: OnceLock<AesTables> = OnceLock::new();

#[inline(always)]
fn gf_mul2(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn build_tables() -> AesTables {
    let mut t0 = [0u32; 256];
    let mut t1 = [0u32; 256];
    let mut t2 = [0u32; 256];
    let mut t3 = [0u32; 256];
    for (i, t_entry) in t0.iter_mut().enumerate() {
        let s = SBOX[i];
        let s2 = gf_mul2(s);
        let s3 = s2 ^ s;
        *t_entry =
            (u32::from(s2) << 24) ^ (u32::from(s) << 16) ^ (u32::from(s) << 8) ^ u32::from(s3);
        t1[i] = (u32::from(s3) << 24) ^ (u32::from(s2) << 16) ^ (u32::from(s) << 8) ^ u32::from(s);
        t2[i] = (u32::from(s) << 24) ^ (u32::from(s3) << 16) ^ (u32::from(s2) << 8) ^ u32::from(s);
        t3[i] = (u32::from(s) << 24) ^ (u32::from(s) << 16) ^ (u32::from(s3) << 8) ^ u32::from(s2);
    }
    AesTables { t0, t1, t2, t3 }
}

#[inline(always)]
fn aes_tables() -> &'static AesTables {
    AES_TABLES.get_or_init(build_tables)
}

#[inline]
fn round_keys_to_words(round_keys: &[[u8; 16]; 11]) -> [[u32; 4]; 11] {
    let mut out = [[0u32; 4]; 11];
    for (dst, key) in out.iter_mut().zip(round_keys.iter()) {
        dst[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
        dst[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
        dst[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
        dst[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);
    }
    out
}

#[inline(always)]
fn load_block_words(block: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ]
}

#[inline(always)]
fn store_block_words(words: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, word) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[inline(always)]
/// AES table fallback for hosts without AES instructions.
///
/// This backend is functionally correct but is not a constant-time or
/// cache-side-channel-resistant implementation: table indices depend on the
/// AES state. Security-sensitive callers must select an instruction-backed
/// backend or an approved constant-time implementation instead.
fn aes128_encrypt_block_tables_words(round_keys: &[[u32; 4]; 11], block: &[u8; 16]) -> [u8; 16] {
    let table = aes_tables();
    let mut state = load_block_words(block);
    let rk0 = round_keys[0];
    state[0] ^= rk0[0];
    state[1] ^= rk0[1];
    state[2] ^= rk0[2];
    state[3] ^= rk0[3];

    let mut s0 = state[0];
    let mut s1 = state[1];
    let mut s2 = state[2];
    let mut s3 = state[3];

    for rk in round_keys.iter().take(10).skip(1) {
        let t0 = table.t0[(s0 >> 24) as usize]
            ^ table.t1[((s1 >> 16) & 0xff) as usize]
            ^ table.t2[((s2 >> 8) & 0xff) as usize]
            ^ table.t3[(s3 & 0xff) as usize]
            ^ rk[0];
        let t1 = table.t0[(s1 >> 24) as usize]
            ^ table.t1[((s2 >> 16) & 0xff) as usize]
            ^ table.t2[((s3 >> 8) & 0xff) as usize]
            ^ table.t3[(s0 & 0xff) as usize]
            ^ rk[1];
        let t2 = table.t0[(s2 >> 24) as usize]
            ^ table.t1[((s3 >> 16) & 0xff) as usize]
            ^ table.t2[((s0 >> 8) & 0xff) as usize]
            ^ table.t3[(s1 & 0xff) as usize]
            ^ rk[2];
        let t3 = table.t0[(s3 >> 24) as usize]
            ^ table.t1[((s0 >> 16) & 0xff) as usize]
            ^ table.t2[((s1 >> 8) & 0xff) as usize]
            ^ table.t3[(s2 & 0xff) as usize]
            ^ rk[3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    let rk_last = round_keys[10];
    let o0 = (u32::from(SBOX[(s0 >> 24) as usize]) << 24)
        ^ (u32::from(SBOX[((s1 >> 16) & 0xff) as usize]) << 16)
        ^ (u32::from(SBOX[((s2 >> 8) & 0xff) as usize]) << 8)
        ^ u32::from(SBOX[(s3 & 0xff) as usize])
        ^ rk_last[0];
    let o1 = (u32::from(SBOX[(s1 >> 24) as usize]) << 24)
        ^ (u32::from(SBOX[((s2 >> 16) & 0xff) as usize]) << 16)
        ^ (u32::from(SBOX[((s3 >> 8) & 0xff) as usize]) << 8)
        ^ u32::from(SBOX[(s0 & 0xff) as usize])
        ^ rk_last[1];
    let o2 = (u32::from(SBOX[(s2 >> 24) as usize]) << 24)
        ^ (u32::from(SBOX[((s3 >> 16) & 0xff) as usize]) << 16)
        ^ (u32::from(SBOX[((s0 >> 8) & 0xff) as usize]) << 8)
        ^ u32::from(SBOX[(s1 & 0xff) as usize])
        ^ rk_last[2];
    let o3 = (u32::from(SBOX[(s3 >> 24) as usize]) << 24)
        ^ (u32::from(SBOX[((s0 >> 16) & 0xff) as usize]) << 16)
        ^ (u32::from(SBOX[((s1 >> 8) & 0xff) as usize]) << 8)
        ^ u32::from(SBOX[(s2 & 0xff) as usize])
        ^ rk_last[3];
    store_block_words([o0, o1, o2, o3])
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod legacy_simd_tests {
    use super::{
        aes128_encrypt_block_scalar_with_round_keys, aes128_encrypt_block_tables_words,
        expand_round_keys_array, round_keys_to_words,
    };

    fn decode_hex_block(s: &str) -> [u8; 16] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 32, "hex block must be 32 chars");
        let mut out = [0u8; 16];
        for (idx, chunk) in bytes.chunks(2).enumerate() {
            let hi = hex_value(chunk[0]);
            let lo = hex_value(chunk[1]);
            out[idx] = (hi << 4) | lo;
        }
        out
    }

    fn hex_value(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex byte"),
        }
    }

    #[test]
    fn tables_match_scalar_reference_vector() {
        let key = decode_hex_block("000102030405060708090a0b0c0d0e0f");
        let block = decode_hex_block("00112233445566778899aabbccddeeff");
        let round_keys = expand_round_keys_array(&key);
        let round_words = round_keys_to_words(&round_keys);

        let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
        let tables = aes128_encrypt_block_tables_words(&round_words, &block);
        assert_eq!(scalar, tables);
        assert_eq!(tables, decode_hex_block("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn context_matches_zero_key_counter_vector() {
        let key = [0u8; 16];
        let mut block = [0u8; 16];
        block[15] = 2;
        let context = super::Aes128Ctx::new(&key);

        assert_eq!(
            context.encrypt_block(&block),
            decode_hex_block("0388dace60b6a392f328c2b971b2fe78")
        );
    }

    #[test]
    fn tables_match_scalar_multiple_inputs() {
        let key = decode_hex_block("603deb1015ca71be2b73aef0857d7781");
        let mut block = decode_hex_block("6bc1bee22e409f96e93d7e117393172a");
        let round_keys = expand_round_keys_array(&key);
        let round_words = round_keys_to_words(&round_keys);

        for _ in 0..8 {
            let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
            let tables = aes128_encrypt_block_tables_words(&round_words, &block);
            assert_eq!(scalar, tables);
            // For next iteration, feed ciphertext back as input to increase coverage.
            block = tables;
        }
    }

    #[test]
    fn test_aes128_encrypt_block_determinism() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let block: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let result1 = super::aes128_encrypt_block(&key, &block);
        let result2 = super::aes128_encrypt_block(&key, &block);
        assert_eq!(result1, result2, "same key+block must produce same output");
        // Output must differ from input (AES is a permutation, not identity)
        assert_ne!(result1, block);
    }

    #[test]
    fn test_aes128_encrypt_block_key_sensitivity() {
        let block: [u8; 16] = [0xAA; 16];
        let key_a: [u8; 16] = [0x00; 16];
        let key_b: [u8; 16] = {
            let mut k = [0x00u8; 16];
            k[0] = 0x01; // single bit difference
            k
        };
        let out_a = super::aes128_encrypt_block(&key_a, &block);
        let out_b = super::aes128_encrypt_block(&key_b, &block);
        assert_ne!(out_a, out_b, "different keys must produce different output");
    }

    #[test]
    fn test_aes128_encrypt_block_plaintext_sensitivity() {
        let key: [u8; 16] = [0x55; 16];
        let block_a: [u8; 16] = [0x00; 16];
        let block_b: [u8; 16] = {
            let mut b = [0x00u8; 16];
            b[15] = 0x01; // single bit difference
            b
        };
        let out_a = super::aes128_encrypt_block(&key, &block_a);
        let out_b = super::aes128_encrypt_block(&key, &block_b);
        assert_ne!(out_a, out_b, "different plaintexts must produce different output");
    }

    #[test]
    fn test_key_expansion_determinism() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expanded1 = super::key_expansion(&key);
        let expanded2 = super::key_expansion(&key);
        assert_eq!(expanded1, expanded2, "same key must produce same schedule");
        // Verify first 16 bytes are the original key
        assert_eq!(&expanded1[..16], &key);
        // Verify round keys are not all zeros after expansion
        let non_zero_count = expanded1[16..].iter().filter(|&&b| b != 0).count();
        assert!(non_zero_count > 0, "expanded key schedule must have non-zero round keys");
    }

    #[test]
    fn test_aes128_ctx_determinism_and_nontrivial() {
        let key: [u8; 16] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81,
        ];
        let blocks: [[u8; 16]; 4] = [
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
            [
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51,
            ],
            [0x00; 16],
            [0xFF; 16],
        ];
        let ctx = super::Aes128Ctx::new(&key);
        for block in &blocks {
            let first = ctx.encrypt_block(block);
            let second = ctx.encrypt_block(block);
            assert_eq!(first, second, "Aes128Ctx::encrypt_block must be deterministic");
            // AES is a permutation - output must differ from input
            assert_ne!(first, *block, "Aes128Ctx output must differ from plaintext");
        }
        // Different blocks must produce different ciphertexts (collision-free for small set)
        let out0 = ctx.encrypt_block(&blocks[0]);
        let out1 = ctx.encrypt_block(&blocks[1]);
        assert_ne!(out0, out1, "different blocks must produce different ciphertexts");
    }

    #[test]
    fn test_ctr_xor_various_lengths() {
        let key: [u8; 16] = [0x01; 16];
        let ctx = super::Aes128Ctx::new(&key);
        let base_counter: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        for &len in &[0usize, 1, 15, 16, 17, 32, 100] {
            let input = vec![0xABu8; len];
            let mut output = vec![0u8; len];
            let mut counter = base_counter;
            ctx.ctr_xor(&mut counter, &input, &mut output);
            assert_eq!(output.len(), len);
            if len > 0 {
                // Encrypted output should differ from input for non-trivial data
                assert_ne!(output, input, "CTR output must differ from input for len={}", len);
            }
        }
    }

    #[test]
    fn test_ctr_xor_involution() {
        let key: [u8; 16] = [0xDE; 16];
        let ctx = super::Aes128Ctx::new(&key);
        let base_counter: [u8; 16] = [0; 16];

        // Test with various sizes to cover full blocks, partial block, and multi-block
        for &len in &[1usize, 15, 16, 31, 32, 48, 63, 64, 100] {
            let original: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
            let mut encrypted = vec![0u8; len];
            let mut decrypted = vec![0u8; len];

            let mut ctr_enc = base_counter;
            ctx.ctr_xor(&mut ctr_enc, &original, &mut encrypted);

            let mut ctr_dec = base_counter;
            ctx.ctr_xor(&mut ctr_dec, &encrypted, &mut decrypted);

            assert_eq!(
                original, decrypted,
                "CTR double-apply must recover original for len={}",
                len
            );
        }
    }
}
/// Encrypt a single AES-128 block with runtime backend dispatch (AES-NI/AESE/scalar).
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let features = qf_cpu::FeatureDetector::instance().features_full();
    #[cfg(target_arch = "x86_64")]
    if features.aesni {
        qf_telemetry::AES_BLOCK_AESNI_OPS.inc();
        // SAFETY: AES-NI confirmed by features. key and block are &[u8; 16].
        return unsafe { aes128_encrypt_block_aesni(key, block) };
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    if features.sve_aes {
        qf_telemetry::AES_BLOCK_SVE_OPS.inc();
        // SAFETY: SVE2 AES confirmed by features. key and block are &[u8; 16].
        return unsafe {
            let mut rk = expand_round_keys_array(key);
            let out = aes128_encrypt_block_sve_round_keys(&rk, block);
            zeroize_round_keys(&mut rk);
            out
        };
    }
    #[cfg(target_arch = "aarch64")]
    if features.aes {
        // Runtime self-test: ensure AESE sequence matches scalar on this CPU/layout
        static ARM_AES_OK: AtomicUsize = AtomicUsize::new(0); // 0 unknown, 1 ok, 2 broken
        let state = ARM_AES_OK.load(Ordering::Relaxed);
        let use_hw = if state == 0 {
            let k0 = [0u8; 16];
            let b0 = [0u8; 16];
            let sw = aes128_encrypt_block_scalar(&k0, &b0);
            // SAFETY: ARM AES confirmed by features. k0 and b0 are [u8; 16].
            let hw = unsafe { aes128_encrypt_block_aese(&k0, &b0) };
            let ok = sw == hw;
            ARM_AES_OK.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            ok
        } else {
            state == 1
        };
        if use_hw {
            qf_telemetry::AES_BLOCK_AESE_OPS.inc();
            // SAFETY: ARM AES confirmed by features. key and block are &[u8; 16].
            return unsafe { aes128_encrypt_block_aese(key, block) };
        }
    }
    #[cfg(target_arch = "x86_64")]
    if features.sse2 && !features.aesni {
        qf_telemetry::AES_BLOCK_SSSE3_OPS.inc();
        let mut round_keys = expand_round_keys_array(key);
        let mut round_key_words = round_keys_to_words(&round_keys);
        let out = aes128_encrypt_block_tables_words(&round_key_words, block);
        zeroize_round_key_words(&mut round_key_words);
        zeroize_round_keys(&mut round_keys);
        return out;
    }
    #[cfg(target_arch = "aarch64")]
    if features.neon && !features.aes && !features.sve_aes {
        qf_telemetry::AES_BLOCK_NEON_TABLE_OPS.inc();
        let mut round_keys = expand_round_keys_array(key);
        let mut round_key_words = round_keys_to_words(&round_keys);
        let out = aes128_encrypt_block_tables_words(&round_key_words, block);
        zeroize_round_key_words(&mut round_key_words);
        zeroize_round_keys(&mut round_keys);
        return out;
    }
    qf_telemetry::AES_BLOCK_SCALAR_OPS.inc();
    aes128_encrypt_block_scalar(key, block)
}

#[inline]
fn aes128_encrypt_block_scalar(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let mut round_keys = expand_round_keys_array(key);
    let out = aes128_encrypt_block_scalar_with_round_keys(&round_keys, block);
    zeroize_round_keys(&mut round_keys);
    out
}

#[inline(always)]
fn aes128_encrypt_block_scalar_with_round_keys(
    round_keys: &[[u8; 16]; 11],
    block: &[u8; 16],
) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, &round_keys[0]);
    for rk in round_keys.iter().take(10).skip(1) {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, rk);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);
    state
}

/// Pre-expanded AES-128 context with backend-specific round key storage.
pub struct Aes128Ctx {
    round_keys: [[u8; 16]; 11],
    round_keys_words: [[u32; 4]; 11],
    #[cfg(target_arch = "x86_64")]
    use_aesni: bool,
    #[cfg(target_arch = "x86_64")]
    use_table_fallback: bool,
    #[cfg(target_arch = "x86_64")]
    use_ssse3_fallback: bool,
    #[cfg(target_arch = "x86_64")]
    round_keys_ssse3: [core::arch::x86_64::__m128i; 11],
    #[cfg(target_arch = "aarch64")]
    use_aese: bool,
    #[cfg(target_arch = "aarch64")]
    use_neon_tables: bool,
    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    use_sve_aes: bool,
}

impl Aes128Ctx {
    /// Create a new context with pre-expanded round keys for the given 16-byte key.
    pub fn new(key: &[u8; 16]) -> Self {
        let round_keys = expand_round_keys_array(key);
        let round_keys_words = round_keys_to_words(&round_keys);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let features = qf_cpu::FeatureDetector::instance().features_full();
        #[cfg(target_arch = "x86_64")]
        let use_aesni = features.aesni;
        #[cfg(target_arch = "x86_64")]
        let use_ssse3_fallback = !use_aesni && features.ssse3 && features.sse2;
        #[cfg(target_arch = "x86_64")]
        let use_table_fallback = !use_aesni && !use_ssse3_fallback && features.sse2;
        #[cfg(target_arch = "x86_64")]
        let round_keys_ssse3 = {
            use core::arch::x86_64::_mm_loadu_si128;
            // SAFETY: core::mem::zeroed() for __m128i is valid - POD type where
            // all-zeros is a valid bit pattern.
            let mut tmp = [unsafe { core::mem::zeroed() }; 11];
            if use_ssse3_fallback {
                for (dst, rk) in tmp.iter_mut().zip(round_keys.iter()) {
                    // SAFETY: each rk is &[u8; 16]; _mm_loadu_si128 reads exactly 16 bytes.
                    *dst = unsafe { _mm_loadu_si128(rk.as_ptr() as *const _) };
                }
            }
            tmp
        };
        #[cfg(target_arch = "aarch64")]
        let use_aese = features.aes;
        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        let use_sve_aes = features.sve_aes;
        #[cfg(target_arch = "aarch64")]
        let use_neon_tables = {
            let has_neon = features.neon;
            #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
            let has_sve_aes = use_sve_aes;
            #[cfg(not(all(target_arch = "aarch64", target_feature = "sve2")))]
            let has_sve_aes = false;
            has_neon && !use_aese && !has_sve_aes
        };
        Self {
            round_keys,
            round_keys_words,
            #[cfg(target_arch = "x86_64")]
            use_aesni,
            #[cfg(target_arch = "x86_64")]
            use_table_fallback,
            #[cfg(target_arch = "x86_64")]
            use_ssse3_fallback,
            #[cfg(target_arch = "x86_64")]
            round_keys_ssse3,
            #[cfg(target_arch = "aarch64")]
            use_aese,
            #[cfg(target_arch = "aarch64")]
            use_neon_tables,
            #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
            use_sve_aes,
        }
    }

    /// Encrypt a single 16-byte block using the pre-expanded round keys.
    #[inline(always)]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            // SAFETY: use_aesni was set during construction only when runtime
            // detection confirmed AES-NI. round_keys and block are [u8; 16] arrays.
            return unsafe { aes128_encrypt_block_aesni_round_keys(&self.round_keys, block) };
        }
        #[cfg(target_arch = "x86_64")]
        if self.use_table_fallback {
            qf_telemetry::AES_BLOCK_SSSE3_OPS.inc();
            return aes128_encrypt_block_tables_words(&self.round_keys_words, block);
        }
        #[cfg(target_arch = "x86_64")]
        if self.use_ssse3_fallback {
            qf_telemetry::AES_BLOCK_SSSE3_OPS.inc();
            // SAFETY: use_ssse3_fallback was set only when SSSE3 detected at
            // construction. round_keys_ssse3 was populated with valid __m128i values.
            return unsafe { aes128_encrypt_block_ssse3(&self.round_keys_ssse3, block) };
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        if self.use_sve_aes {
            qf_telemetry::AES_BLOCK_SVE_OPS.inc();
            // SAFETY: use_sve_aes was set only when SVE2 AES detected at construction.
            return unsafe { aes128_encrypt_block_sve_round_keys(&self.round_keys, block) };
        }
        #[cfg(target_arch = "aarch64")]
        if self.use_aese {
            // SAFETY: use_aese was set only when ARM AES detected at construction.
            return unsafe { aes128_encrypt_block_aese_round_keys(&self.round_keys, block) };
        }
        #[cfg(target_arch = "aarch64")]
        if self.use_neon_tables {
            qf_telemetry::AES_BLOCK_NEON_TABLE_OPS.inc();
            return aes128_encrypt_block_tables_words(&self.round_keys_words, block);
        }
        aes128_encrypt_block_scalar_with_round_keys(&self.round_keys, block)
    }

    /// AES-CTR XOR: encrypt `input` into `output` using a 16-byte counter block.
    #[inline]
    pub fn ctr_xor(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        let mut offset = 0usize;

        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            // SAFETY: use_aesni confirmed AES-NI at construction. input/output have
            // equal length (asserted above). ctr_xor_aesni processes only full
            // 64-byte chunks within bounds and returns consumed offset.
            unsafe {
                offset = self.ctr_xor_aesni(counter, input, output);
            }
        }

        #[cfg(target_arch = "x86_64")]
        if self.use_ssse3_fallback {
            // SAFETY: use_ssse3_fallback confirmed SSSE3 at construction.
            // input/output lengths are equal. Processes 32-byte chunks within bounds.
            unsafe {
                offset = self.ctr_xor_ssse3(counter, input, output);
            }
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        {
            if self.use_sve_aes {
                // SAFETY: use_sve_aes confirmed SVE2 AES at construction.
                // input/output lengths are equal. Processes 16-byte blocks within bounds.
                unsafe {
                    offset = self.ctr_xor_sve(counter, input, output);
                }
            } else if self.use_aese {
                // SAFETY: use_aese confirmed ARM AES at construction.
                // input/output lengths are equal. Processes 64-byte chunks within bounds.
                unsafe {
                    offset = self.ctr_xor_aese(counter, input, output);
                }
            }
        }

        #[cfg(all(target_arch = "aarch64", not(target_feature = "sve2")))]
        if self.use_aese {
            // SAFETY: use_aese confirmed ARM AES at construction.
            // input/output lengths are equal. Processes 64-byte chunks within bounds.
            unsafe {
                offset = self.ctr_xor_aese(counter, input, output);
            }
        }

        while offset + 16 <= input.len() {
            if offset == 0 {
                qf_telemetry::AES_CTR_SCALAR_OPS.inc();
            }
            let ctr_block = *counter;
            let ks = self.encrypt_block(&ctr_block);
            for j in 0..16 {
                output[offset + j] = input[offset + j] ^ ks[j];
            }
            inc32_be(counter);
            offset += 16;
        }
        if offset < input.len() {
            if offset == 0 {
                qf_telemetry::AES_CTR_SCALAR_OPS.inc();
            }
            let ctr_block = *counter;
            let ks = self.encrypt_block(&ctr_block);
            for j in 0..(input.len() - offset) {
                output[offset + j] = input[offset + j] ^ ks[j];
            }
            // Counter increment not needed after processing the tail block.
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    // SAFETY: target_feature gate ensures AES-NI. Processes 64-byte chunks; the
    // while guard ensures input.len() - offset >= 64 before each iteration. Pointer
    // arithmetic into input/output uses offset + lane*16, staying within bounds.
    // Counter blocks are stack-owned [u8; 16] arrays. Round keys are pre-expanded.
    unsafe fn ctr_xor_aesni(
        &self,
        counter: &mut [u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> usize {
        use core::arch::x86_64::*;

        qf_telemetry::AES_CTR_AESNI_OPS.inc();

        let mut offset = 0usize;
        while input.len().saturating_sub(offset) >= 64 {
            let mut ctr_blocks = [[0u8; 16]; 4];
            let mut current = *counter;
            for slot in ctr_blocks.iter_mut() {
                *slot = current;
                inc32_be(&mut current);
            }
            *counter = current;

            let lanes = [
                _mm_loadu_si128(ctr_blocks[0].as_ptr() as *const __m128i),
                _mm_loadu_si128(ctr_blocks[1].as_ptr() as *const __m128i),
                _mm_loadu_si128(ctr_blocks[2].as_ptr() as *const __m128i),
                _mm_loadu_si128(ctr_blocks[3].as_ptr() as *const __m128i),
            ];
            let ks = aesni_encrypt4_round_keys(&self.round_keys, lanes);

            for (lane, keystream) in ks.into_iter().enumerate() {
                let idx = offset + lane * 16;
                let pt = _mm_loadu_si128(input.as_ptr().add(idx) as *const __m128i);
                let ct = _mm_xor_si128(pt, keystream);
                _mm_storeu_si128(output.as_mut_ptr().add(idx) as *mut __m128i, ct);
            }

            offset += 64;
        }
        offset
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    // SAFETY: target_feature gate ensures SVE2. Processes 16-byte blocks; the while
    // guard ensures sufficient remaining bytes. Output indexing uses offset + j < len.
    unsafe fn ctr_xor_sve(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) -> usize {
        qf_telemetry::AES_CTR_SVE_OPS.inc();
        let mut offset = 0usize;
        while input.len().saturating_sub(offset) >= 16 {
            let ctr_block = *counter;
            let ks = aes128_encrypt_block_sve_round_keys(&self.round_keys, &ctr_block);
            for j in 0..16 {
                let idx = offset + j;
                output[idx] = input[idx] ^ ks[j];
            }
            inc32_be(counter);
            offset += 16;
        }
        offset
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    // SAFETY: target_feature gate ensures SSSE3. Processes 32-byte chunks; the while
    // guard ensures input.len() - offset >= 32 per iteration. Loads at offset and
    // offset+16, both within bounds. Round keys are pre-expanded __m128i arrays.
    unsafe fn ctr_xor_ssse3(
        &self,
        counter: &mut [u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> usize {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};

        qf_telemetry::AES_CTR_SSSE3_OPS.inc();

        let mut offset = 0usize;
        while input.len().saturating_sub(offset) >= 32 {
            let ctr0 = *counter;
            inc32_be(counter);
            let ctr1 = *counter;
            inc32_be(counter);

            let ks0 = aes128_encrypt_block_ssse3_raw(&self.round_keys_ssse3, &ctr0);
            let ks1 = aes128_encrypt_block_ssse3_raw(&self.round_keys_ssse3, &ctr1);

            let pt0 = _mm_loadu_si128(input.as_ptr().add(offset) as *const _);
            let pt1 = _mm_loadu_si128(input.as_ptr().add(offset + 16) as *const _);

            let ct0 = _mm_xor_si128(pt0, ks0);
            let ct1 = _mm_xor_si128(pt1, ks1);

            _mm_storeu_si128(output.as_mut_ptr().add(offset) as *mut _, ct0);
            _mm_storeu_si128(output.as_mut_ptr().add(offset + 16) as *mut _, ct1);

            offset += 32;
        }
        offset
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    // SAFETY: target_feature gate ensures ARM AES. Processes 64-byte chunks; the
    // while guard ensures input.len() - offset >= 64 per iteration. Pointer
    // arithmetic uses offset + lane*16, staying within bounds. Round keys are
    // pre-expanded [[u8; 16]; 11].
    unsafe fn ctr_xor_aese(
        &self,
        counter: &mut [u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> usize {
        use core::arch::aarch64::*;

        qf_telemetry::AES_CTR_AESE_OPS.inc();

        let mut offset = 0usize;
        while input.len().saturating_sub(offset) >= 64 {
            let mut ctr_blocks = [[0u8; 16]; 4];
            let mut current = *counter;
            for slot in ctr_blocks.iter_mut() {
                *slot = current;
                inc32_be(&mut current);
            }
            *counter = current;

            let lanes = [
                vld1q_u8(ctr_blocks[0].as_ptr()),
                vld1q_u8(ctr_blocks[1].as_ptr()),
                vld1q_u8(ctr_blocks[2].as_ptr()),
                vld1q_u8(ctr_blocks[3].as_ptr()),
            ];
            let ks = aese_encrypt4_round_keys(&self.round_keys, lanes);

            for (lane, k) in ks.iter().enumerate() {
                let idx = offset + lane * 16;
                let pt = vld1q_u8(input.as_ptr().add(idx));
                let ct = veorq_u8(pt, *k);
                vst1q_u8(output.as_mut_ptr().add(idx), ct);
            }

            offset += 64;
        }
        offset
    }
}

impl Drop for Aes128Ctx {
    fn drop(&mut self) {
        zeroize_round_keys(&mut self.round_keys);
        zeroize_round_key_words(&mut self.round_keys_words);
        #[cfg(target_arch = "x86_64")]
        for round_key in &mut self.round_keys_ssse3 {
            // SAFETY: __m128i is an opaque 128-bit value and zero is a valid
            // bit pattern. The field contains no borrowed pointers.
            unsafe {
                *round_key = core::arch::x86_64::_mm_setzero_si128();
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures AES-NI. `key` and `block` are &[u8; 16].
// key_expansion produces a 176-byte round key schedule. All _mm_loadu_si128 reads
// at rk[16*r..16*(r+1)] stay within the 176-byte schedule. `out` is stack-owned.
unsafe fn aes128_encrypt_block_aesni(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use core::arch::x86_64::*;
    let mut rk = key_expansion(key);
    let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let k0 = _mm_loadu_si128(rk[0..16].as_ptr() as *const __m128i);
    s = _mm_xor_si128(s, k0);
    for r in 1..10 {
        let kr = _mm_loadu_si128(rk[16 * r..16 * (r + 1)].as_ptr() as *const __m128i);
        s = _mm_aesenc_si128(s, kr);
    }
    let kf = _mm_loadu_si128(rk[160..176].as_ptr() as *const __m128i);
    s = _mm_aesenclast_si128(s, kf);
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, s);
    rk.zeroize();
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
// SAFETY: target_feature gate ensures SSSE3. `buf` is stack-owned [u8; 16].
// SBOX lookup uses byte values 0..255, all within the 256-entry SBOX table.
unsafe fn sub_bytes_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128};
    let mut buf = [0u8; 16];
    _mm_storeu_si128(buf.as_mut_ptr() as *mut _, state);
    for byte in &mut buf {
        *byte = SBOX[*byte as usize];
    }
    _mm_loadu_si128(buf.as_ptr() as *const _)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSSE3 (caller ensures). All operations are register-to-register
// shuffles on by-value __m128i; no memory access.
unsafe fn shift_rows_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{_mm_setr_epi8, _mm_shuffle_epi8};
    let mask = _mm_setr_epi8(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
    _mm_shuffle_epi8(state, mask)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSE2 (caller ensures via SSSE3 gate). All operations are
// register-to-register on by-value __m128i; no memory access.
unsafe fn xtime_ssse3(x: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{
        _mm_add_epi8, _mm_and_si128, _mm_cmplt_epi8, _mm_set1_epi8, _mm_setzero_si128,
        _mm_xor_si128,
    };
    let shifted = _mm_add_epi8(x, x);
    let mask = _mm_cmplt_epi8(x, _mm_setzero_si128());
    let reduction = _mm_and_si128(mask, _mm_set1_epi8(0x1b));
    _mm_xor_si128(shifted, reduction)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSSE3 (caller ensures). All operations are register-to-register
// shuffles and XORs on by-value __m128i; no memory access. xtime_ssse3 is called
// with the same SSSE3 guarantee. Result is a pure register value.
unsafe fn mix_columns_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{_mm_setr_epi8, _mm_shuffle_epi8, _mm_xor_si128};

    let rot1 = _mm_shuffle_epi8(
        state,
        _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12),
    );
    let rot2 = _mm_shuffle_epi8(
        state,
        _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
    );
    let rot3 = _mm_shuffle_epi8(
        state,
        _mm_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14),
    );

    let maj = _mm_xor_si128(state, _mm_xor_si128(rot1, _mm_xor_si128(rot2, rot3)));

    let adjacent = xtime_ssse3(_mm_xor_si128(state, rot1));
    _mm_xor_si128(_mm_xor_si128(state, maj), adjacent)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
// SAFETY: target_feature gate ensures SSSE3. `round_keys` is &[__m128i; 11] -
// array indexing is bounded 0..=10. `block` is &[u8; 16]; _mm_loadu_si128 reads
// exactly 16 bytes. Sub-calls (sub_bytes_ssse3, shift_rows_ssse3,
// mix_columns_ssse3) all require only SSSE3. Returns __m128i register value.
unsafe fn aes128_encrypt_block_ssse3_raw(
    round_keys: &[core::arch::x86_64::__m128i; 11],
    block: &[u8; 16],
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{_mm_loadu_si128, _mm_xor_si128};

    let mut state = _mm_loadu_si128(block.as_ptr() as *const _);
    state = _mm_xor_si128(state, round_keys[0]);

    for round_key in round_keys.iter().take(10).skip(1) {
        state = sub_bytes_ssse3(state);
        state = shift_rows_ssse3(state);
        state = mix_columns_ssse3(state);
        state = _mm_xor_si128(state, *round_key);
    }

    state = sub_bytes_ssse3(state);
    state = shift_rows_ssse3(state);
    _mm_xor_si128(state, round_keys[10])
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
// SAFETY: target_feature gate ensures SSSE3. Delegates to
// aes128_encrypt_block_ssse3_raw (same SSSE3 requirement). `out` is stack-owned
// [u8; 16]; _mm_storeu_si128 writes exactly 16 bytes into it.
unsafe fn aes128_encrypt_block_ssse3(
    round_keys: &[core::arch::x86_64::__m128i; 11],
    block: &[u8; 16],
) -> [u8; 16] {
    use core::arch::x86_64::_mm_storeu_si128;
    let state = aes128_encrypt_block_ssse3_raw(round_keys, block);
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut _, state);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures AES-NI. `round_keys` is &[[u8; 16]; 11];
// each _mm_loadu_si128 reads exactly 16 bytes from a [u8; 16] subarray. `block`
// is &[u8; 16]. The round-key iterator is bounded to indices 1..10. `out` is
// stack-owned [u8; 16]; _mm_storeu_si128 writes exactly 16 bytes.
unsafe fn aes128_encrypt_block_aesni_round_keys(
    round_keys: &[[u8; 16]; 11],
    block: &[u8; 16],
) -> [u8; 16] {
    use core::arch::x86_64::*;
    let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let k0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
    s = _mm_xor_si128(s, k0);
    for round_key in round_keys.iter().take(10).skip(1) {
        let kr = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
        s = _mm_aesenc_si128(s, kr);
    }
    let kf = _mm_loadu_si128(round_keys[10].as_ptr() as *const __m128i);
    s = _mm_aesenclast_si128(s, kf);
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, s);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures AES-NI. `round_keys` is &[[u8; 16]; 11];
// the initial, middle, and final round-key accesses stay within 0..=10. Each
// _mm_loadu_si128 reads 16 bytes
// from a [u8; 16] subarray. `blocks` is by-value [__m128i; 4]; lane iteration
// via iter_mut is bounded. Returns owned array of 4 __m128i values.
unsafe fn aesni_encrypt4_round_keys(
    round_keys: &[[u8; 16]; 11],
    mut blocks: [core::arch::x86_64::__m128i; 4],
) -> [core::arch::x86_64::__m128i; 4] {
    use core::arch::x86_64::*;
    let rk0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
    for lane in blocks.iter_mut() {
        *lane = _mm_xor_si128(*lane, rk0);
    }
    for round_key in round_keys.iter().take(10).skip(1) {
        let kr = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
        for lane in blocks.iter_mut() {
            *lane = _mm_aesenc_si128(*lane, kr);
        }
    }
    let kf = _mm_loadu_si128(round_keys[10].as_ptr() as *const __m128i);
    for lane in blocks.iter_mut() {
        *lane = _mm_aesenclast_si128(*lane, kf);
    }
    blocks
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures ARM AES. `key` and `block` are &[u8; 16].
// key_expansion returns 176-byte schedule; rk[16*r..16*(r+1)] slices for r in
// 0..=10 are within bounds. vld1q_u8 reads 16 bytes from each valid slice pointer.
// `out` is stack-owned [u8; 16]; vst1q_u8 writes exactly 16 bytes.
unsafe fn aes128_encrypt_block_aese(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use core::arch::aarch64::*;
    let mut rk = key_expansion(key);
    let mut s = vld1q_u8(block.as_ptr());
    for r in 0..9 {
        let kr = vld1q_u8(rk[16 * r..16 * (r + 1)].as_ptr());
        s = vaeseq_u8(s, kr);
        s = vaesmcq_u8(s);
    }
    let k9 = vld1q_u8(rk[144..160].as_ptr());
    s = vaeseq_u8(s, k9);
    let kf = vld1q_u8(rk[160..176].as_ptr());
    s = veorq_u8(s, kf);
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), s);
    rk.zeroize();
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures ARM AES. `round_keys` is &[[u8; 16]; 11];
// iterator take(9) accesses indices 0..=8, within bounds. vld1q_u8
// reads 16 bytes from each [u8; 16] subarray pointer. `block` is &[u8; 16].
// `out` is stack-owned [u8; 16]; vst1q_u8 writes exactly 16 bytes.
unsafe fn aes128_encrypt_block_aese_round_keys(
    round_keys: &[[u8; 16]; 11],
    block: &[u8; 16],
) -> [u8; 16] {
    use core::arch::aarch64::*;
    let mut s = vld1q_u8(block.as_ptr());
    for rk in round_keys.iter().take(9) {
        let kr = vld1q_u8(rk.as_ptr());
        s = vaeseq_u8(s, kr);
        s = vaesmcq_u8(s);
    }
    let k9 = vld1q_u8(round_keys[9].as_ptr());
    s = vaeseq_u8(s, k9);
    let k10 = vld1q_u8(round_keys[10].as_ptr());
    s = veorq_u8(s, k10);
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), s);
    out
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline]
#[target_feature(enable = "sve2")]
// SAFETY: target_feature gate ensures SVE2 (implies AES). `round_keys` is
// &[[u8; 16]; 11]; take(9) accesses 0..=8, indices [9] and [10] are explicit.
// svptrue_b8 creates an all-true predicate for 128-bit vectors. svld1_u8 and
// svst1_u8 read/write 16 bytes under the predicate from valid [u8; 16] pointers.
// `out` is stack-owned [u8; 16].
unsafe fn aes128_encrypt_block_sve_round_keys(
    round_keys: &[[u8; 16]; 11],
    block: &[u8; 16],
) -> [u8; 16] {
    use core::arch::aarch64::*;
    let pg = svptrue_b8();
    let mut state = svld1_u8(pg, block.as_ptr());

    for rk in round_keys.iter().take(9) {
        let round = svld1_u8(pg, rk.as_ptr());
        state = svaeseq_u8(pg, state, round);
        state = svaesmcq_u8(pg, state);
    }

    let rk9 = svld1_u8(pg, round_keys[9].as_ptr());
    state = svaeseq_u8(pg, state, rk9);
    let rk10 = svld1_u8(pg, round_keys[10].as_ptr());
    state = sveor_u8_x(pg, state, rk10);

    let mut out = [0u8; 16];
    svst1_u8(pg, out.as_mut_ptr(), state);
    out
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests_ssse3_aes {
    use super::*;

    #[test]
    fn ssse3_round_transforms_match_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }

        for seed in 0u8..=u8::MAX {
            let input = core::array::from_fn(|index| {
                seed.wrapping_mul(17).wrapping_add((index as u8).wrapping_mul(29))
            });

            let mut expected_sub_bytes = input;
            sub_bytes(&mut expected_sub_bytes);
            let mut expected_shift_rows = input;
            shift_rows(&mut expected_shift_rows);
            let mut expected_mix_columns = input;
            mix_columns(&mut expected_mix_columns);

            let mut actual_sub_bytes = [0u8; 16];
            let mut actual_shift_rows = [0u8; 16];
            let mut actual_mix_columns = [0u8; 16];

            // SAFETY: SSSE3 was checked above. Every load and store accesses one
            // complete stack-owned [u8; 16] value.
            unsafe {
                use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128};

                let state = _mm_loadu_si128(input.as_ptr() as *const _);
                _mm_storeu_si128(actual_sub_bytes.as_mut_ptr() as *mut _, sub_bytes_ssse3(state));
                _mm_storeu_si128(actual_shift_rows.as_mut_ptr() as *mut _, shift_rows_ssse3(state));
                _mm_storeu_si128(
                    actual_mix_columns.as_mut_ptr() as *mut _,
                    mix_columns_ssse3(state),
                );
            }

            assert_eq!(expected_sub_bytes, actual_sub_bytes, "seed {seed}");
            assert_eq!(expected_shift_rows, actual_shift_rows, "seed {seed}");
            assert_eq!(expected_mix_columns, actual_mix_columns, "seed {seed}");
        }
    }

    #[test]
    fn aes128_ssse3_matches_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }

        let key = [0x42u8; 16];
        let block = [0x24u8; 16];
        let round_keys = expand_round_keys_array(&key);
        let expected = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);

        // SAFETY: core::mem::zeroed() for __m128i is valid - it is a POD type
        // (128-bit SIMD register) where all-zeros is a valid bit pattern.
        let mut round_keys_ssse3 = [unsafe { core::mem::zeroed() }; 11];
        // SAFETY: SSSE3 feature checked above. round_keys_ssse3 is [__m128i; 11];
        // zip iteration is bounded by the shorter (both len 11). Each rk is
        // &[u8; 16]; _mm_loadu_si128 reads exactly 16 bytes.
        unsafe {
            use core::arch::x86_64::_mm_loadu_si128;
            for (dst, rk) in round_keys_ssse3.iter_mut().zip(round_keys.iter()) {
                *dst = _mm_loadu_si128(rk.as_ptr() as *const _);
            }
            let actual = aes128_encrypt_block_ssse3(&round_keys_ssse3, &block);
            assert_eq!(expected, actual);
        }
    }
}

#[cfg(all(test, target_arch = "aarch64", target_feature = "sve2"))]
mod tests_sve {
    use super::*;

    #[test]
    fn aes128_sve_matches_scalar_block() {
        if !std::arch::is_aarch64_feature_detected!("sve2") {
            return;
        }

        let key = [0x11u8; 16];
        let block = [0x22u8; 16];
        let round_keys = expand_round_keys_array(&key);

        let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
        // SAFETY: SVE2 feature checked above. round_keys is [[u8;16];11], block is [u8;16].
        let sve = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &block) };
        assert_eq!(scalar, sve);
    }

    #[test]
    fn aes128_sve_ctr_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("sve2") {
            return;
        }

        let key = [0x0Fu8; 16];
        let round_keys = expand_round_keys_array(&key);
        let mut counter = [0xAAu8; 16];
        let mut sve_counter = counter;
        let mut scalar_counter = counter;
        let data = (0u8..96).collect::<Vec<u8>>();
        let mut sve_out = data.clone();
        let mut scalar_out = data;

        let mut offset = 0usize;
        while sve_out.len().saturating_sub(offset) >= 16 {
            // SAFETY: SVE2 checked above. round_keys is [[u8;16];11], sve_counter is [u8;16].
            let ks = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &sve_counter) };
            for i in 0..16 {
                sve_out[offset + i] ^= ks[i];
            }
            inc32_be(&mut sve_counter);
            offset += 16;
        }
        if offset < sve_out.len() {
            // SAFETY: SVE2 checked above. round_keys is [[u8;16];11], sve_counter is [u8;16].
            let ks = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &sve_counter) };
            for i in 0..(sve_out.len() - offset) {
                sve_out[offset + i] ^= ks[i];
            }
        }

        let mut offset_scalar = 0usize;
        while scalar_out.len().saturating_sub(offset_scalar) >= 16 {
            let ks = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &scalar_counter);
            for i in 0..16 {
                scalar_out[offset_scalar + i] ^= ks[i];
            }
            inc32_be(&mut scalar_counter);
            offset_scalar += 16;
        }
        if offset_scalar < scalar_out.len() {
            let ks = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &scalar_counter);
            for i in 0..(scalar_out.len() - offset_scalar) {
                scalar_out[offset_scalar + i] ^= ks[i];
            }
        }

        assert_eq!(sve_out, scalar_out);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
// SAFETY: target_feature gate ensures ARM AES. `round_keys` is &[[u8; 16]; 11];
// take(9) accesses indices 0..=8, indices [9] and [10] are explicit.
// vld1q_u8 reads 16 bytes from each [u8; 16] subarray pointer. `blocks` is
// by-value [uint8x16_t; 4]; iter_mut bounded to 4 lanes. Returns owned array.
unsafe fn aese_encrypt4_round_keys(
    round_keys: &[[u8; 16]; 11],
    mut blocks: [core::arch::aarch64::uint8x16_t; 4],
) -> [core::arch::aarch64::uint8x16_t; 4] {
    use core::arch::aarch64::*;
    for rk in round_keys.iter().take(9) {
        let kr = vld1q_u8(rk.as_ptr());
        for lane in blocks.iter_mut() {
            *lane = vaeseq_u8(*lane, kr);
        }
        for lane in blocks.iter_mut() {
            *lane = vaesmcq_u8(*lane);
        }
    }
    let k9 = vld1q_u8(round_keys[9].as_ptr());
    for lane in blocks.iter_mut() {
        *lane = vaeseq_u8(*lane, k9);
    }
    let k10 = vld1q_u8(round_keys[10].as_ptr());
    for lane in blocks.iter_mut() {
        *lane = veorq_u8(*lane, k10);
    }
    blocks
}

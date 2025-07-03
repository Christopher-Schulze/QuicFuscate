use crate::error::{CryptoError, Result};
use subtle::ConstantTimeEq;

pub struct Morus;

impl Morus {
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;

    const IV: u64 = 0x8040_0c06_0000_0000u64;
    const RATE: usize = 16;
    const PA_ROUNDS: usize = 12;
    const PB_ROUNDS: usize = 8;
    const ROUND_CONSTANTS: [u64; 12] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
    ];

    pub fn new() -> Self {
        Self
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; Self::TAG_SIZE],
    ) -> Result<()> {
        let mut state = [0u64; 5];
        state[0] = Self::IV;
        state[1] = Self::bytes_to_u64(&key[0..8]);
        state[2] = Self::bytes_to_u64(&key[8..16]);
        state[3] = Self::bytes_to_u64(&nonce[0..8]);
        state[4] = Self::bytes_to_u64(&nonce[8..16]);

        Self::morus_permutation(&mut state, Self::PA_ROUNDS);

        state[3] ^= Self::bytes_to_u64(&key[0..8]);
        state[4] ^= Self::bytes_to_u64(&key[8..16]);

        if !ad.is_empty() {
            let blocks = ad.len() / Self::RATE;
            for i in 0..blocks {
                state[0] ^= Self::bytes_to_u64(&ad[i * Self::RATE..i * Self::RATE + 8]);
                state[1] ^= Self::bytes_to_u64(&ad[i * Self::RATE + 8..i * Self::RATE + 16]);
                Self::morus_permutation(&mut state, Self::PB_ROUNDS);
            }
            if ad.len() % Self::RATE != 0 {
                let mut padded = [0u8; Self::RATE];
                let off = blocks * Self::RATE;
                padded[..ad.len() % Self::RATE].copy_from_slice(&ad[off..]);
                padded[ad.len() % Self::RATE] = 0x80;
                state[0] ^= Self::bytes_to_u64(&padded[0..8]);
                state[1] ^= Self::bytes_to_u64(&padded[8..16]);
                Self::morus_permutation(&mut state, Self::PB_ROUNDS);
            }
        }

        state[4] ^= 1;

        ciphertext.clear();
        let blocks = plaintext.len() / Self::RATE;
        for i in 0..blocks {
            state[0] ^= Self::bytes_to_u64(&plaintext[i * Self::RATE..i * Self::RATE + 8]);
            state[1] ^= Self::bytes_to_u64(&plaintext[i * Self::RATE + 8..i * Self::RATE + 16]);

            ciphertext.extend_from_slice(&Self::u64_to_bytes(state[0]));
            ciphertext.extend_from_slice(&Self::u64_to_bytes(state[1]));

            Self::morus_permutation(&mut state, Self::PB_ROUNDS);
        }

        if plaintext.len() % Self::RATE != 0 {
            let mut padded = [0u8; Self::RATE];
            let off = blocks * Self::RATE;
            padded[..plaintext.len() % Self::RATE]
                .copy_from_slice(&plaintext[off..off + plaintext.len() % Self::RATE]);
            padded[plaintext.len() % Self::RATE] = 0x80;

            state[0] ^= Self::bytes_to_u64(&padded[0..8]);
            state[1] ^= Self::bytes_to_u64(&padded[8..16]);

            let ct_block0 = Self::u64_to_bytes(state[0]);
            let ct_block1 = Self::u64_to_bytes(state[1]);
            ciphertext.extend_from_slice(&ct_block0[..]);
            ciphertext.extend_from_slice(&ct_block1[..]);
            ciphertext.truncate(plaintext.len());
        }

        state[1] ^= Self::bytes_to_u64(&key[0..8]);
        state[2] ^= Self::bytes_to_u64(&key[8..16]);
        Self::morus_permutation(&mut state, Self::PA_ROUNDS);
        state[3] ^= Self::bytes_to_u64(&key[0..8]);
        state[4] ^= Self::bytes_to_u64(&key[8..16]);

        let tag_bytes0 = Self::u64_to_bytes(state[3]);
        let tag_bytes1 = Self::u64_to_bytes(state[4]);
        tag.copy_from_slice(&[tag_bytes0, tag_bytes1].concat()[0..Self::TAG_SIZE]);
        Ok(())
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; Self::KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ad: &[u8],
        tag: &[u8; Self::TAG_SIZE],
        plaintext: &mut Vec<u8>,
    ) -> Result<()> {
        let mut state = [0u64; 5];
        state[0] = Self::IV;
        state[1] = Self::bytes_to_u64(&key[0..8]);
        state[2] = Self::bytes_to_u64(&key[8..16]);
        state[3] = Self::bytes_to_u64(&nonce[0..8]);
        state[4] = Self::bytes_to_u64(&nonce[8..16]);

        Self::morus_permutation(&mut state, Self::PA_ROUNDS);

        state[3] ^= Self::bytes_to_u64(&key[0..8]);
        state[4] ^= Self::bytes_to_u64(&key[8..16]);

        if !ad.is_empty() {
            let blocks = ad.len() / Self::RATE;
            for i in 0..blocks {
                state[0] ^= Self::bytes_to_u64(&ad[i * Self::RATE..i * Self::RATE + 8]);
                state[1] ^= Self::bytes_to_u64(&ad[i * Self::RATE + 8..i * Self::RATE + 16]);
                Self::morus_permutation(&mut state, Self::PB_ROUNDS);
            }
            if ad.len() % Self::RATE != 0 {
                let mut padded = [0u8; Self::RATE];
                let off = blocks * Self::RATE;
                padded[..ad.len() % Self::RATE].copy_from_slice(&ad[off..]);
                padded[ad.len() % Self::RATE] = 0x80;
                state[0] ^= Self::bytes_to_u64(&padded[0..8]);
                state[1] ^= Self::bytes_to_u64(&padded[8..16]);
                Self::morus_permutation(&mut state, Self::PB_ROUNDS);
            }
        }

        state[4] ^= 1;

        plaintext.clear();
        let blocks = ciphertext.len() / Self::RATE;
        for i in 0..blocks {
            let ct0 = Self::bytes_to_u64(&ciphertext[i * Self::RATE..i * Self::RATE + 8]);
            let ct1 = Self::bytes_to_u64(&ciphertext[i * Self::RATE + 8..i * Self::RATE + 16]);

            plaintext.extend_from_slice(&Self::u64_to_bytes(state[0] ^ ct0));
            plaintext.extend_from_slice(&Self::u64_to_bytes(state[1] ^ ct1));

            state[0] = ct0;
            state[1] = ct1;

            Self::morus_permutation(&mut state, Self::PB_ROUNDS);
        }

        if ciphertext.len() % Self::RATE != 0 {
            let mut ct_block = [0u8; Self::RATE];
            let off = blocks * Self::RATE;
            ct_block[..ciphertext.len() % Self::RATE]
                .copy_from_slice(&ciphertext[off..]);

            let mut state_bytes = [0u8; Self::RATE];
            state_bytes[..8].copy_from_slice(&Self::u64_to_bytes(state[0]));
            state_bytes[8..16].copy_from_slice(&Self::u64_to_bytes(state[1]));

            for i in 0..ciphertext.len() % Self::RATE {
                plaintext.push(state_bytes[i] ^ ct_block[i]);
                state_bytes[i] = ct_block[i];
            }
            state_bytes[ciphertext.len() % Self::RATE] = 0x80;
            state[0] = Self::bytes_to_u64(&state_bytes[0..8]);
            state[1] = Self::bytes_to_u64(&state_bytes[8..16]);
        }

        state[1] ^= Self::bytes_to_u64(&key[0..8]);
        state[2] ^= Self::bytes_to_u64(&key[8..16]);
        Self::morus_permutation(&mut state, Self::PA_ROUNDS);
        state[3] ^= Self::bytes_to_u64(&key[0..8]);
        state[4] ^= Self::bytes_to_u64(&key[8..16]);

        let mut computed_tag = [0u8; Self::TAG_SIZE];
        computed_tag[..8].copy_from_slice(&Self::u64_to_bytes(state[3]));
        computed_tag[8..].copy_from_slice(&Self::u64_to_bytes(state[4]));

        if tag.ct_eq(&computed_tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }

    fn morus_permutation(state: &mut [u64; 5], rounds: usize) {
        for i in (12 - rounds)..12 {
            state[2] ^= Self::ROUND_CONSTANTS[i];

            state[0] ^= state[4];
            state[4] ^= state[3];
            state[2] ^= state[1];

            let t0 = state[0];
            let t1 = state[1];
            let t2 = state[2];
            let t3 = state[3];
            let t4 = state[4];

            state[0] = t0 ^ ((!t1) & t2);
            state[1] = t1 ^ ((!t2) & t3);
            state[2] = t2 ^ ((!t3) & t4);
            state[3] = t3 ^ ((!t4) & t0);
            state[4] = t4 ^ ((!t0) & t1);

            state[1] ^= state[0];
            state[0] ^= state[4];
            state[3] ^= state[2];
            state[2] = !state[2];

            state[0] ^= Self::rotr64(state[0], 19) ^ Self::rotr64(state[0], 28);
            state[1] ^= Self::rotr64(state[1], 61) ^ Self::rotr64(state[1], 39);
            state[2] ^= Self::rotr64(state[2], 1) ^ Self::rotr64(state[2], 6);
            state[3] ^= Self::rotr64(state[3], 10) ^ Self::rotr64(state[3], 17);
            state[4] ^= Self::rotr64(state[4], 7) ^ Self::rotr64(state[4], 41);
        }
    }

    #[inline]
    fn bytes_to_u64(bytes: &[u8]) -> u64 {
        let mut res = 0u64;
        for &b in bytes.iter().take(8) {
            res = (res << 8) | b as u64;
        }
        res
    }

    #[inline]
    fn u64_to_bytes(v: u64) -> [u8; 8] {
        v.to_be_bytes()
    }

    #[inline]
    fn rotr64(v: u64, s: u32) -> u64 {
        (v >> s) | (v << (64 - s))
    }
}

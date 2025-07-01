use crate::error::CryptoError;
use subtle::ConstantTimeEq;

pub struct Morus1280;

impl Morus1280 {
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;

    const RATE: usize = 32;
    const ROUNDS: usize = 5;

    const IV: [u64; 20] = [
        0x0d08050302010100u64, 0x6279e99059372215u64, 0xf12fc26d55183ddbu64, 0xdd28b57342311120u64,
        0x5470917e43281e90u64, 0x8d9b7abacc626ab9u64, 0x142c3ba227d7cdcfu64, 0xf881e24d45a7ed8eu64,
        0x3c24ba1e0776a298u64, 0x8427a4364c417daeu64, 0x4d84c3ce9a7a26b8u64, 0x19dc8ce6c1356be5u64,
        0x874761517311cf32u64, 0x6d113b0f462f2c4au64, 0xc2b4ac11f1c13289u64, 0x915f2d99c2403f37u64,
        0x6d9b4cf2a8b8e8e9u64, 0x79607b532d176b19u64, 0xb49ac2e85c91745fu64, 0x7bcd371c9a220496u64,
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
    ) -> Result<(), CryptoError> {
        let mut state = Self::init_state(key, nonce);

        if !ad.is_empty() {
            Self::process_ad(&mut state, ad);
        }

        Self::process_pt(&mut state, plaintext, ciphertext);
        Self::finalize(&mut state, ad.len(), plaintext.len(), tag);
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
    ) -> Result<(), CryptoError> {
        let mut state = Self::init_state(key, nonce);

        if !ad.is_empty() {
            Self::process_ad(&mut state, ad);
        }

        Self::process_ct(&mut state, ciphertext, plaintext);

        let mut computed_tag = [0u8; Self::TAG_SIZE];
        Self::finalize(&mut state, ad.len(), ciphertext.len(), &mut computed_tag);
        if tag.ct_eq(&computed_tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }

    fn init_state(key: &[u8; Self::KEY_SIZE], nonce: &[u8; Self::NONCE_SIZE]) -> [u64; 20] {
        let mut state = Self::IV;
        let mut key_words = [0u64; 2];
        let mut nonce_words = [0u64; 2];
        Self::bytes_to_words(&mut key_words, key);
        Self::bytes_to_words(&mut nonce_words, nonce);

        state[0] ^= key_words[0];
        state[1] ^= key_words[1];
        state[4] ^= key_words[0];
        state[5] ^= key_words[1];

        state[8] ^= nonce_words[0];
        state[9] ^= nonce_words[1];
        state[12] ^= nonce_words[0];
        state[13] ^= nonce_words[1];

        for _ in 0..16 {
            Self::permutation(&mut state);
        }
        state
    }

    fn process_ad(state: &mut [u64; 20], ad: &[u8]) {
        let blocks = ad.len() / Self::RATE;
        for i in 0..blocks {
            let mut block = [0u64; 4];
            Self::bytes_to_words(&mut block, &ad[i * Self::RATE..i * Self::RATE + Self::RATE]);
            let mut tmp = [0u64; 4];
            Self::xor_256(&mut tmp, &state[0..4], &block);
            state[0..4].copy_from_slice(&tmp);
            Self::permutation(state);
        }
        if ad.len() % Self::RATE != 0 {
            let mut padded = [0u8; Self::RATE];
            let off = blocks * Self::RATE;
            padded[..ad.len() % Self::RATE].copy_from_slice(&ad[off..]);
            padded[ad.len() % Self::RATE] = 0x80;
            let mut block = [0u64; 4];
            Self::bytes_to_words(&mut block, &padded);
            let mut tmp = [0u64; 4];
            Self::xor_256(&mut tmp, &state[0..4], &block);
            state[0..4].copy_from_slice(&tmp);
            Self::permutation(state);
        }
    }

    fn process_pt(state: &mut [u64; 20], pt: &[u8], ct: &mut Vec<u8>) {
        let blocks = pt.len() / Self::RATE;
        ct.clear();
        for i in 0..blocks {
            let mut pt_words = [0u64; 4];
            Self::bytes_to_words(&mut pt_words, &pt[i * Self::RATE..i * Self::RATE + Self::RATE]);

            let mut keystream = [0u64; 4];
            Self::xor_256(&mut keystream, &state[0..4], &state[4..8]);
            let mut ks_tmp = [0u64; 4];
            Self::xor_256(&mut ks_tmp, &keystream, &state[8..12]);
            keystream.copy_from_slice(&ks_tmp);

            let mut ct_block = [0u64; 4];
            Self::xor_256(&mut ct_block, &pt_words, &keystream);
            Self::words_to_bytes_vec(ct, &ct_block);

            let mut tmp = [0u64;4];
            Self::xor_256(&mut tmp, &state[0..4], &pt_words);
            state[0..4].copy_from_slice(&tmp);
            Self::permutation(state);
        }

        if pt.len() % Self::RATE != 0 {
            let mut pt_block = [0u8; Self::RATE];
            let off = blocks * Self::RATE;
            pt_block[..pt.len() % Self::RATE].copy_from_slice(&pt[off..]);
            let mut pt_words = [0u64; 4];
            Self::bytes_to_words(&mut pt_words, &pt_block);

            let mut keystream = [0u64; 4];
            Self::xor_256(&mut keystream, &state[0..4], &state[4..8]);
            let mut ks_tmp = [0u64;4];
            Self::xor_256(&mut ks_tmp, &keystream, &state[8..12]);
            keystream.copy_from_slice(&ks_tmp);

            let mut ct_words = [0u64; 4];
            Self::xor_256(&mut ct_words, &pt_words, &keystream);
            let mut tmp = Vec::new();
            Self::words_to_bytes_vec(&mut tmp, &ct_words);
            ct.extend_from_slice(&tmp[..pt.len() % Self::RATE]);

            pt_block[pt.len() % Self::RATE] = 0x80;
            let mut padded = [0u64; 4];
            Self::bytes_to_words(&mut padded, &pt_block);
            let mut tmp_state = [0u64;4];
            Self::xor_256(&mut tmp_state, &state[0..4], &padded);
            state[0..4].copy_from_slice(&tmp_state);
            Self::permutation(state);
        }
    }

    fn process_ct(state: &mut [u64; 20], ct: &[u8], pt: &mut Vec<u8>) {
        let blocks = ct.len() / Self::RATE;
        pt.clear();
        for i in 0..blocks {
            let mut ct_words = [0u64; 4];
            Self::bytes_to_words(&mut ct_words, &ct[i * Self::RATE..i * Self::RATE + Self::RATE]);

            let mut keystream = [0u64; 4];
            Self::xor_256(&mut keystream, &state[0..4], &state[4..8]);
            let mut ks_tmp = [0u64;4];
            Self::xor_256(&mut ks_tmp, &keystream, &state[8..12]);
            keystream.copy_from_slice(&ks_tmp);

            let mut pt_words = [0u64; 4];
            Self::xor_256(&mut pt_words, &ct_words, &keystream);
            Self::words_to_bytes_vec(pt, &pt_words);

            let mut tmp_state = [0u64;4];
            Self::xor_256(&mut tmp_state, &state[0..4], &ct_words);
            state[0..4].copy_from_slice(&tmp_state);
            Self::permutation(state);
        }

        if ct.len() % Self::RATE != 0 {
            let mut ct_block = [0u8; Self::RATE];
            let off = blocks * Self::RATE;
            ct_block[..ct.len() % Self::RATE].copy_from_slice(&ct[off..]);
            let mut ct_words = [0u64; 4];
            Self::bytes_to_words(&mut ct_words, &ct_block);

            let mut keystream = [0u64; 4];
            Self::xor_256(&mut keystream, &state[0..4], &state[4..8]);
            let mut ks_tmp2 = [0u64;4];
            Self::xor_256(&mut ks_tmp2, &keystream, &state[8..12]);
            keystream.copy_from_slice(&ks_tmp2);

            let mut pt_words = [0u64; 4];
            Self::xor_256(&mut pt_words, &ct_words, &keystream);
            let mut tmp = Vec::new();
            Self::words_to_bytes_vec(&mut tmp, &pt_words);
            pt.extend_from_slice(&tmp[..ct.len() % Self::RATE]);

            ct_block[ct.len() % Self::RATE] = 0x80;
            let mut padded = [0u64; 4];
            Self::bytes_to_words(&mut padded, &ct_block);
            let mut tmp_state2 = [0u64;4];
            Self::xor_256(&mut tmp_state2, &state[0..4], &padded);
            state[0..4].copy_from_slice(&tmp_state2);
            Self::permutation(state);
        }
    }

    fn finalize(state: &mut [u64; 20], ad_len: usize, pt_len: usize, tag: &mut [u8; Self::TAG_SIZE]) {
        let mut lengths = [0u64; 4];
        lengths[0] = (ad_len as u64) * 8;
        lengths[2] = (pt_len as u64) * 8;

        for i in 0..4 {
            state[16 + i] ^= lengths[i];
        }

        for _ in 0..10 {
            Self::permutation(state);
        }

        let tag_words = [
            state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16],
            state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17],
        ];
        let mut tmp = Vec::new();
        Self::words_to_bytes_vec(&mut tmp, &tag_words);
        tag.copy_from_slice(&tmp[..Self::TAG_SIZE]);
    }

    fn permutation(state: &mut [u64; 20]) {
        for round in 0..Self::ROUNDS {
            let mut tmp0 = [0u64; 4];
            let mut tmp1 = [0u64; 4];
            let mut tmp2 = [0u64; 4];
            Self::and_256(&mut tmp0, &state[4..8], &state[8..12]);
            Self::rotl_256(&mut tmp1, &state[4..8], 13);
            Self::xor_256(&mut tmp2, &state[0..4], &tmp0);
            let mut tmp3 = [0u64;4];
            Self::xor_256(&mut tmp3, &tmp2, &state[12..16]);
            tmp2.copy_from_slice(&tmp3);
            Self::xor_256(&mut tmp3, &tmp2, &tmp1);
            state[0..4].copy_from_slice(&tmp3);

            let mut tmp_state = [0u64; 4];
            tmp_state.copy_from_slice(&state[0..4]);
            state.copy_within(4..20, 0);
            state[16..20].copy_from_slice(&tmp_state);

            let mut src_block = [0u64; 4];
            src_block.copy_from_slice(&state[0..4]);
            Self::rotl_256(&mut state[0..4], &src_block, ((round + 1) * 7) as i32);
        }
    }

    #[inline]
    fn rotl_256(dst: &mut [u64], src: &[u64], bits: i32) {
        if bits == 0 {
            dst.copy_from_slice(src);
            return;
        }
        let word_shift = (bits / 64) as usize;
        let bit_shift = bits % 64;
        for i in 0..4 {
            let src_idx = (i + 4 - word_shift) % 4;
            if bit_shift == 0 {
                dst[i] = src[src_idx];
            } else {
                let next_idx = (src_idx + 1) % 4;
                dst[i] = (src[src_idx] << bit_shift) | (src[next_idx] >> (64 - bit_shift));
            }
        }
    }

    #[inline]
    fn xor_256(dst: &mut [u64], a: &[u64], b: &[u64]) {
        #[cfg(all(target_arch="x86_64", target_feature="avx2"))]
        unsafe {
            use std::arch::x86_64::*;
            if dst.len() == 4 {
                let va = _mm256_loadu_si256(a.as_ptr() as *const __m256i);
                let vb = _mm256_loadu_si256(b.as_ptr() as *const __m256i);
                let vc = _mm256_xor_si256(va, vb);
                _mm256_storeu_si256(dst.as_mut_ptr() as *mut __m256i, vc);
                return;
            }
        }
        for i in 0..dst.len() {
            dst[i] = a[i] ^ b[i];
        }
    }

    #[inline]
    fn and_256(dst: &mut [u64], a: &[u64], b: &[u64]) {
        #[cfg(all(target_arch="x86_64", target_feature="avx2"))]
        unsafe {
            use std::arch::x86_64::*;
            if dst.len() == 4 {
                let va = _mm256_loadu_si256(a.as_ptr() as *const __m256i);
                let vb = _mm256_loadu_si256(b.as_ptr() as *const __m256i);
                let vc = _mm256_and_si256(va, vb);
                _mm256_storeu_si256(dst.as_mut_ptr() as *mut __m256i, vc);
                return;
            }
        }
        for i in 0..dst.len() {
            dst[i] = a[i] & b[i];
        }
    }

    #[inline]
    fn bytes_to_words(words: &mut [u64], bytes: &[u8]) {
        for w in words.iter_mut() { *w = 0; }
        for (i, b) in bytes.iter().enumerate().take(words.len() * 8) {
            words[i / 8] |= (*b as u64) << ((i % 8) * 8);
        }
    }

    #[inline]
    fn words_to_bytes_vec(out: &mut Vec<u8>, words: &[u64]) {
        for i in 0..words.len() * 8 {
            out.push(((words[i / 8] >> ((i % 8) * 8)) & 0xFF) as u8);
        }
    }
}

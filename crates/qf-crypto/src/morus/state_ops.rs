use core::ptr;

impl super::Morus1280State {
    /// Initialize MORUS-1280-128 state with key and nonce.
    pub(super) fn init(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        // k0 = K128 || K128
        let k0 =
            u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let k1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);
        let k_block = [k0, k1, k0, k1];

        // IV128 || 0^128
        let n0 = u64::from_le_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);
        let n1 = u64::from_le_bytes([
            nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
        ]);

        // Constants: const0 || const1 (Fibonacci sequence modulo 256)
        const C0: u64 = 0x0d08050302010100;
        const C1: u64 = 0x6279e99059372215;
        const C2: u64 = 0xf12fc26d55183ddb;
        const C3: u64 = 0xdd28b57342311120;

        let mut state = Self {
            s: [
                [n0, n1, 0, 0],   // S0 = IV128 || 0^128
                k_block,          // S1 = k0
                [u64::MAX; 4],    // S2 = 1^256
                [0u64; 4],        // S3 = 0^256
                [C0, C1, C2, C3], // S4 = const0 || const1
            ],
        };

        // 16 steps with m = 0
        for _ in 0..16 {
            state.update([0u64; 4]);
        }

        // XOR key block into S1 again
        for (i, kv) in k_block.iter().enumerate() {
            state.s[1][i] ^= *kv;
        }

        state
    }

    // Miri cannot execute NEON intrinsics, so the SIMD path is UB there even
    // when target_feature="neon" is compiled in. Miri takes the scalar path.
    #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
    #[inline(always)]
    pub(super) fn keystream_block(&self) -> [u64; 4] {
        // SAFETY: compile-time target_feature="neon" guarantees NEON availability;
        // `self.s` is a valid `[[u64;4];5]` providing aligned readable storage.
        unsafe { self.keystream_block_neon() }
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon", not(miri))))]
    #[inline(always)]
    pub(super) fn keystream_block(&self) -> [u64; 4] {
        let s0 = self.s[0];
        let s1r = Self::rotl_words_256(self.s[1], 1); // word[j + 1], per MORUS v2
        let s2 = self.s[2];
        let s3 = self.s[3];
        [
            s0[0] ^ s1r[0] ^ (s2[0] & s3[0]),
            s0[1] ^ s1r[1] ^ (s2[1] & s3[1]),
            s0[2] ^ s1r[2] ^ (s2[2] & s3[2]),
            s0[3] ^ s1r[3] ^ (s2[3] & s3[3]),
        ]
    }

    pub(super) fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 16] {
        let ad_bits = (ad_len as u64).wrapping_mul(8);
        let msg_bits = (msg_len as u64).wrapping_mul(8);

        // S4 ^= S0
        for i in 0..4 {
            self.s[4][i] ^= self.s[0][i];
        }

        // tmp = (adlen || msglen || 0^128)
        let tmp = [ad_bits, msg_bits, 0, 0];
        for _ in 0..10 {
            self.update(tmp);
        }

        // T0 = S0 XOR (S1 <<< 192) XOR (S2 & S3)
        let t = self.keystream_block();
        let mut tag = [0u8; 16];
        // 128 LSB: words 0 and 1 (little-endian)
        tag[0..8].copy_from_slice(&t[0].to_le_bytes());
        tag[8..16].copy_from_slice(&t[1].to_le_bytes());
        tag
    }

    pub(super) fn process_ad(&mut self, ad: &[u8]) {
        let (chunks, rem) = ad.as_chunks::<32>();
        for block in chunks {
            #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
            {
                // SAFETY: compile-time neon gate; `block` is a valid &[u8;32]
                // providing 32 readable bytes for vld1q_u64 loads.
                unsafe { self.update(Self::load_block32_neon(block)) };
            }
            #[cfg(not(all(target_arch = "aarch64", target_feature = "neon", not(miri))))]
            {
                self.update(Self::load_block32(block));
            }
        }

        if !rem.is_empty() {
            let mut padded = [0u8; 32];
            padded[..rem.len()].copy_from_slice(rem);
            self.update(Self::load_block32(&padded));
        }
    }

    pub(super) fn encrypt(&mut self, plaintext: &mut [u8]) {
        let mut chunks = plaintext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_encrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_encrypt(rem, &ks);
            self.update(plain_words);
        }
    }

    pub(super) fn decrypt(&mut self, ciphertext: &mut [u8]) {
        let mut chunks = ciphertext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_decrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_decrypt(rem, &ks);
            self.update(plain_words);
        }
    }

    #[inline(always)]
    fn load_block32(block: &[u8; 32]) -> [u64; 4] {
        // SAFETY: the array reference proves that all four 8-byte reads are within the
        // 32-byte input. `read_unaligned` does not require alignment.
        unsafe {
            [
                u64::from_le(ptr::read_unaligned(block.as_ptr() as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(8) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(16) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(24) as *const u64)),
            ]
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `block` is &[u8; 32] providing 32 readable
    // bytes. vld1q_u8 reads 16 bytes at offsets 0 and 16, both within bounds.
    // `out` is [u64; 4] (32 bytes); vst1q_u64 writes 16 bytes at offsets 0 and 16.
    unsafe fn load_block32_neon(block: &[u8; 32]) -> [u64; 4] {
        use std::arch::aarch64::*;
        let v0 = vld1q_u8(block.as_ptr());
        let v1 = vld1q_u8(block.as_ptr().add(16));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), vreinterpretq_u64_u8(v0));
        vst1q_u64(out.as_mut_ptr().add(2), vreinterpretq_u64_u8(v1));
        out
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `self.s` is [[u64;4];5]; vld1q_u64_x2 reads
    // 32 bytes per row, within the 32-byte row bounds. `out` is stack-owned [u64;4].
    unsafe fn keystream_block_neon(&self) -> [u64; 4] {
        use std::arch::aarch64::*;
        let s0_pair = vld1q_u64_x2(self.s[0].as_ptr());
        let s1_pair = vld1q_u64_x2(self.s[1].as_ptr());
        let s2_pair = vld1q_u64_x2(self.s[2].as_ptr());
        let s3_pair = vld1q_u64_x2(self.s[3].as_ptr());
        let (s1r_lo, s1r_hi) = Self::rot_words_pair_neon(s1_pair.0, s1_pair.1, 1);
        let t0 = veorq_u64(veorq_u64(s0_pair.0, s1r_lo), vandq_u64(s2_pair.0, s3_pair.0));
        let t1 = veorq_u64(veorq_u64(s0_pair.1, s1r_hi), vandq_u64(s2_pair.1, s3_pair.1));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), t0);
        vst1q_u64(out.as_mut_ptr().add(2), t1);
        out
    }

    #[inline(always)]
    fn zero_tail(words: &mut [u64; 4], valid_bytes: usize) {
        if valid_bytes >= 32 {
            return;
        }
        let full_words = valid_bytes / 8;
        let tail_bytes = valid_bytes % 8;
        for (idx, w) in words.iter_mut().enumerate().skip(full_words) {
            if idx > full_words {
                *w = 0;
            } else {
                let mask = if tail_bytes == 0 { 0 } else { (1u64 << (tail_bytes * 8)) - 1 };
                *w &= mask;
            }
        }
    }

    #[inline(always)]
    fn xor_keystream_block_encrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            // SAFETY: `block` is &mut [u8; 32]; offset is 0/8/16/24, so offset+8 <= 32.
            // read_unaligned does not require alignment. Read is within bounds.
            let word = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            plain[i] = word;
            let cipher = word ^ keystream[i];
            // SAFETY: same bounds reasoning - offset+8 <= 32, write_unaligned is safe
            // for any alignment. block is exclusively borrowed (&mut).
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, cipher.to_le());
            }
        }
        plain
    }

    #[inline(always)]
    fn xor_keystream_block_decrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            // SAFETY: `block` is &mut [u8; 32]; offset is 0/8/16/24, so offset+8 <= 32.
            // read_unaligned does not require alignment. Read is within bounds.
            let cipher = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            let word = cipher ^ keystream[i];
            plain[i] = word;
            // SAFETY: same bounds reasoning - offset+8 <= 32, write_unaligned safe
            // for any alignment. block is exclusively borrowed.
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, word.to_le());
            }
        }
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    // SAFETY: target_feature gate ensures SSE2. `block` is &mut [u8; 32] and
    // `keystream` is &[u64; 4], so both pairs of unaligned 16-byte loads and
    // stores stay within their 32-byte bounds. Exclusive borrowing prevents
    // aliasing while the ciphertext is updated in place.
    pub(super) unsafe fn xor_keystream_block_encrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;

        let mut plain = [0u64; 4];
        let block_ptr = block.as_mut_ptr() as *mut __m128i;
        let block_lo = _mm_loadu_si128(block_ptr);
        let block_hi = _mm_loadu_si128(block_ptr.add(1));
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, block_lo);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, block_hi);

        let keystream_ptr = keystream.as_ptr() as *const __m128i;
        let keystream_lo = _mm_loadu_si128(keystream_ptr);
        let keystream_hi = _mm_loadu_si128(keystream_ptr.add(1));
        _mm_storeu_si128(block_ptr, _mm_xor_si128(block_lo, keystream_lo));
        _mm_storeu_si128(block_ptr.add(1), _mm_xor_si128(block_hi, keystream_hi));
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    // SAFETY: target_feature gate ensures SSE2. The input and keystream each
    // provide 32 readable bytes, and all unaligned loads/stores remain inside
    // those fixed-size arrays. The block is exclusively borrowed in place.
    pub(super) unsafe fn xor_keystream_block_decrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;

        let mut plain = [0u64; 4];
        let block_ptr = block.as_mut_ptr() as *mut __m128i;
        let ciphertext_lo = _mm_loadu_si128(block_ptr);
        let ciphertext_hi = _mm_loadu_si128(block_ptr.add(1));
        let keystream_ptr = keystream.as_ptr() as *const __m128i;
        let keystream_lo = _mm_loadu_si128(keystream_ptr);
        let keystream_hi = _mm_loadu_si128(keystream_ptr.add(1));
        let plaintext_lo = _mm_xor_si128(ciphertext_lo, keystream_lo);
        let plaintext_hi = _mm_xor_si128(ciphertext_hi, keystream_hi);
        _mm_storeu_si128(block_ptr, plaintext_lo);
        _mm_storeu_si128(block_ptr.add(1), plaintext_hi);
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, plaintext_lo);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, plaintext_hi);
        plain
    }

    #[inline(always)]
    pub(super) fn xor_keystream_partial_encrypt(
        block: &mut [u8],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_encrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[inline(always)]
    pub(super) fn xor_keystream_partial_decrypt(
        block: &mut [u8],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_decrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. `block` is &mut [u8; 32]; vld1q_u8 reads 16
    // bytes at offsets 0 and 16, within bounds. `keystream` is &[u64; 4] (32 bytes);
    // vld1q_u64 reads 16 bytes at offsets 0 and 16. `plain` is stack-owned [u64; 4].
    // vst1q writes stay within bounds of their respective target arrays.
    pub(super) unsafe fn xor_keystream_block_encrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let p0 = vld1q_u8(block.as_ptr());
        let p1 = vld1q_u8(block.as_ptr().add(16));
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let c0 = veorq_u8(p0, vreinterpretq_u8_u64(ks0));
        let c1 = veorq_u8(p1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), c0);
        vst1q_u8(block.as_mut_ptr().add(16), c1);
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    // SAFETY: compile-time neon gate. Same invariants as
    // xor_keystream_block_encrypt_neon: `block` is &mut [u8; 32], `keystream` is
    // &[u64; 4]. All NEON loads/stores stay within the 32-byte bounds of each array.
    pub(super) unsafe fn xor_keystream_block_decrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let c0 = vld1q_u8(block.as_ptr());
        let c1 = vld1q_u8(block.as_ptr().add(16));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let p0 = veorq_u8(c0, vreinterpretq_u8_u64(ks0));
        let p1 = veorq_u8(c1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), p0);
        vst1q_u8(block.as_mut_ptr().add(16), p1);
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        plain
    }
}

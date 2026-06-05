use crate::optimize::FeatureDetector;

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn initial_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&constants);
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        let w = [chunk[0], chunk[1], chunk[2], chunk[3]];
        state[4 + i] = u32::from_le_bytes(w);
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    state
}

#[inline(always)]
fn core(state: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

/// Compute one 64-byte ChaCha20 block from key, counter, and nonce.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = initial_state(key, counter, nonce);
    let working = state;
    core(&mut state);
    for i in 0..16 {
        state[i] = state[i].wrapping_add(working[i]);
    }
    let mut block = [0u8; 64];
    for (i, chunk) in block.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    block
}

/// XOR the ChaCha20 keystream into `data` in place, starting at `counter`.
#[inline]
pub fn xor_keystream_in_place(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }

    let features = FeatureDetector::instance().features_full();

    // SAFETY: runtime feature detection verified before dispatch. Each SIMD backend
    // has a matching target_feature gate. key is &[u8; 32], nonce is &[u8; 12],
    // data is &mut [u8] - all have valid provenance. Each backend XORs keystream
    // in-place, respecting data.len() bounds via internal offset guards.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if features.avx512f {
            xor_keystream_avx512(key, counter, nonce, data);
            return;
        }
        if features.avx2 {
            xor_keystream_avx2(key, counter, nonce, data);
            return;
        }
        if features.sse2 {
            xor_keystream_sse2(key, counter, nonce, data);
            return;
        }
    }

    // SAFETY: runtime feature detection verified before dispatch. Each SIMD backend
    // has a matching target_feature gate. Same invariants as x86_64 block above.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if features.sve2 {
            xor_keystream_sve2(key, counter, nonce, data);
            return;
        }
        if features.neon {
            xor_keystream_neon(key, counter, nonce, data);
            return;
        }
    }

    xor_keystream_scalar(key, counter, nonce, data);
}

#[inline(always)]
fn xor_keystream_scalar(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= 64 {
        let block = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        let chunk = &mut data[offset..offset + 64];
        let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
        let block_ptr = block.as_ptr() as *const u64;
        for word_idx in 0..8 {
            // SAFETY: block is [u8; 64] (8 u64s). word_idx in 0..8 so
            // block_ptr.add(word_idx) stays within the 64-byte block.
            // chunk is 64 bytes (&mut data[offset..offset+64]). Unaligned
            // read/write used because u8 slices have no alignment guarantee.
            let ks = unsafe { core::ptr::read_unaligned(block_ptr.add(word_idx)) };
            let dst = unsafe { chunk_ptr.add(word_idx) };
            // SAFETY: same bounds as above - dst points within the 64-byte chunk.
            let existing = unsafe { core::ptr::read_unaligned(dst as *const u64) };
            unsafe { core::ptr::write_unaligned(dst, existing ^ ks) };
        }
        offset += 64;
    }

    if offset < data.len() {
        let block = chacha20_block(key, counter, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires AVX2 (caller ensures). All operations are register-to-register
// on by-value __m256i; no memory access. Shift amounts are masked to 0..31.
unsafe fn rotl32_avx2(v: core::arch::x86_64::__m256i, n: i32) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let n = ((n as u32) & 31) as i32;
    if n == 0 {
        return v;
    }
    let cnt = _mm_cvtsi32_si128(n);
    let left = _mm256_sll_epi32(v, cnt);
    let right = _mm256_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
    _mm256_or_si256(left, right)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires AVX2 (caller ensures). All operations are register-to-register
// adds, XORs, and rotations on by-value __m256i. rotl32_avx2 has the same
// requirement. No memory access; returns pure register values.
unsafe fn quarter_round_avx2(
    mut a: core::arch::x86_64::__m256i,
    mut b: core::arch::x86_64::__m256i,
    mut c: core::arch::x86_64::__m256i,
    mut d: core::arch::x86_64::__m256i,
) -> (
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
    core::arch::x86_64::__m256i,
) {
    use core::arch::x86_64::*;
    a = _mm256_add_epi32(a, b);
    d = _mm256_xor_si256(d, a);
    d = rotl32_avx2(d, 16);

    c = _mm256_add_epi32(c, d);
    b = _mm256_xor_si256(b, c);
    b = rotl32_avx2(b, 12);

    a = _mm256_add_epi32(a, b);
    d = _mm256_xor_si256(d, a);
    d = rotl32_avx2(d, 8);

    c = _mm256_add_epi32(c, d);
    b = _mm256_xor_si256(b, c);
    b = rotl32_avx2(b, 7);

    (a, b, c, d)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
// SAFETY: target_feature gate ensures AVX2. key is &[u8; 32], nonce is &[u8; 12].
// Main loop processes 512-byte chunks; while guard ensures data.len()-offset >= 512.
// _mm256_storeu_si256 writes into stack-owned words[] array. Per-lane pointer
// arithmetic: offset + lane*64 + word_idx*4 stays within the 512-byte window.
// Unaligned read/write used for data[] since u8 slices have no alignment guarantee.
// Tail loop processes remaining 64-byte blocks, then byte-level XOR for remainder.
unsafe fn xor_keystream_avx2(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    use core::arch::x86_64::*;

    let key_words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    });
    let nonce_words = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= 512 {
        let ctr_lane = [
            counter,
            counter.wrapping_add(1),
            counter.wrapping_add(2),
            counter.wrapping_add(3),
            counter.wrapping_add(4),
            counter.wrapping_add(5),
            counter.wrapping_add(6),
            counter.wrapping_add(7),
        ];
        counter = counter.wrapping_add(8);

        let base = [
            _mm256_set1_epi32(constants[0] as i32),
            _mm256_set1_epi32(constants[1] as i32),
            _mm256_set1_epi32(constants[2] as i32),
            _mm256_set1_epi32(constants[3] as i32),
            _mm256_set1_epi32(key_words[0] as i32),
            _mm256_set1_epi32(key_words[1] as i32),
            _mm256_set1_epi32(key_words[2] as i32),
            _mm256_set1_epi32(key_words[3] as i32),
            _mm256_set1_epi32(key_words[4] as i32),
            _mm256_set1_epi32(key_words[5] as i32),
            _mm256_set1_epi32(key_words[6] as i32),
            _mm256_set1_epi32(key_words[7] as i32),
            _mm256_set_epi32(
                ctr_lane[7] as i32,
                ctr_lane[6] as i32,
                ctr_lane[5] as i32,
                ctr_lane[4] as i32,
                ctr_lane[3] as i32,
                ctr_lane[2] as i32,
                ctr_lane[1] as i32,
                ctr_lane[0] as i32,
            ),
            _mm256_set1_epi32(nonce_words[0] as i32),
            _mm256_set1_epi32(nonce_words[1] as i32),
            _mm256_set1_epi32(nonce_words[2] as i32),
        ];

        let mut state = base;

        for _ in 0..10 {
            let (a, b, c, d) = quarter_round_avx2(state[0], state[4], state[8], state[12]);
            state[0] = a;
            state[4] = b;
            state[8] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_avx2(state[1], state[5], state[9], state[13]);
            state[1] = a;
            state[5] = b;
            state[9] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_avx2(state[2], state[6], state[10], state[14]);
            state[2] = a;
            state[6] = b;
            state[10] = c;
            state[14] = d;
            let (a, b, c, d) = quarter_round_avx2(state[3], state[7], state[11], state[15]);
            state[3] = a;
            state[7] = b;
            state[11] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_avx2(state[0], state[5], state[10], state[15]);
            state[0] = a;
            state[5] = b;
            state[10] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_avx2(state[1], state[6], state[11], state[12]);
            state[1] = a;
            state[6] = b;
            state[11] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_avx2(state[2], state[7], state[8], state[13]);
            state[2] = a;
            state[7] = b;
            state[8] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_avx2(state[3], state[4], state[9], state[14]);
            state[3] = a;
            state[4] = b;
            state[9] = c;
            state[14] = d;
        }

        for i in 0..16 {
            state[i] = _mm256_add_epi32(state[i], base[i]);
        }

        let mut words = [0u32; 16 * 8];
        for (i, slot) in state.iter().enumerate() {
            _mm256_storeu_si256(words[i * 8..].as_mut_ptr() as *mut __m256i, *slot);
        }

        for lane in 0..8 {
            let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
            for word_idx in 0..16 {
                let word = words[word_idx * 8 + lane];
                let ptr_word = lane_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                core::ptr::write_unaligned(ptr_word, existing ^ word);
            }
        }

        offset += 512;
    }

    if data.len().saturating_sub(offset) >= 64 {
        while data.len().saturating_sub(offset) >= 64 {
            let block = super::chacha::chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                let dst = chunk_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(dst as *const u64);
                core::ptr::write_unaligned(dst, existing ^ ks);
            }
            offset += 64;
        }
    }

    if offset < data.len() {
        let block = super::chacha::chacha20_block(key, counter, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires AVX-512F (caller ensures). All operations are register-to-register
// on by-value __m512i; no memory access. Shift amounts are masked to 0..31.
unsafe fn rotl32_avx512(v: core::arch::x86_64::__m512i, n: i32) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::*;
    let n = ((n as u32) & 31) as i32;
    if n == 0 {
        return v;
    }
    let cnt = _mm_cvtsi32_si128(n);
    let left = _mm512_sll_epi32(v, cnt);
    let right = _mm512_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
    _mm512_or_si512(left, right)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires AVX-512F (caller ensures). All operations are register-to-register
// adds, XORs, and rotations on by-value __m512i. rotl32_avx512 has the same
// requirement. No memory access; returns pure register values.
unsafe fn quarter_round_avx512(
    mut a: core::arch::x86_64::__m512i,
    mut b: core::arch::x86_64::__m512i,
    mut c: core::arch::x86_64::__m512i,
    mut d: core::arch::x86_64::__m512i,
) -> (
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
) {
    use core::arch::x86_64::*;
    a = _mm512_add_epi32(a, b);
    d = _mm512_xor_si512(d, a);
    d = rotl32_avx512(d, 16);

    c = _mm512_add_epi32(c, d);
    b = _mm512_xor_si512(b, c);
    b = rotl32_avx512(b, 12);

    a = _mm512_add_epi32(a, b);
    d = _mm512_xor_si512(d, a);
    d = rotl32_avx512(d, 8);

    c = _mm512_add_epi32(c, d);
    b = _mm512_xor_si512(b, c);
    b = rotl32_avx512(b, 7);

    (a, b, c, d)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
// SAFETY: target_feature gate ensures AVX-512F. key is &[u8; 32], nonce is &[u8; 12].
// Main loop processes 1024-byte chunks; while guard ensures data.len()-offset >= 1024.
// _mm512_storeu_si512 writes into stack-owned words[] array. Per-lane pointer
// arithmetic: offset + lane*64 + word_idx*4 stays within the 1024-byte window.
// Unaligned read/write for data[]. Tail loop handles remaining 64-byte blocks.
unsafe fn xor_keystream_avx512(
    key: &[u8; 32],
    mut counter: u32,
    nonce: &[u8; 12],
    data: &mut [u8],
) {
    use core::arch::x86_64::*;

    let key_words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    });
    let nonce_words = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= 1024 {
        let ctr_lane: [u32; 16] = core::array::from_fn(|i| counter.wrapping_add(i as u32));
        counter = counter.wrapping_add(16);

        let base = [
            _mm512_set1_epi32(constants[0] as i32),
            _mm512_set1_epi32(constants[1] as i32),
            _mm512_set1_epi32(constants[2] as i32),
            _mm512_set1_epi32(constants[3] as i32),
            _mm512_set1_epi32(key_words[0] as i32),
            _mm512_set1_epi32(key_words[1] as i32),
            _mm512_set1_epi32(key_words[2] as i32),
            _mm512_set1_epi32(key_words[3] as i32),
            _mm512_set1_epi32(key_words[4] as i32),
            _mm512_set1_epi32(key_words[5] as i32),
            _mm512_set1_epi32(key_words[6] as i32),
            _mm512_set1_epi32(key_words[7] as i32),
            _mm512_set_epi32(
                ctr_lane[15] as i32,
                ctr_lane[14] as i32,
                ctr_lane[13] as i32,
                ctr_lane[12] as i32,
                ctr_lane[11] as i32,
                ctr_lane[10] as i32,
                ctr_lane[9] as i32,
                ctr_lane[8] as i32,
                ctr_lane[7] as i32,
                ctr_lane[6] as i32,
                ctr_lane[5] as i32,
                ctr_lane[4] as i32,
                ctr_lane[3] as i32,
                ctr_lane[2] as i32,
                ctr_lane[1] as i32,
                ctr_lane[0] as i32,
            ),
            _mm512_set1_epi32(nonce_words[0] as i32),
            _mm512_set1_epi32(nonce_words[1] as i32),
            _mm512_set1_epi32(nonce_words[2] as i32),
        ];

        let mut state = base;

        for _ in 0..10 {
            let (a, b, c, d) = quarter_round_avx512(state[0], state[4], state[8], state[12]);
            state[0] = a;
            state[4] = b;
            state[8] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_avx512(state[1], state[5], state[9], state[13]);
            state[1] = a;
            state[5] = b;
            state[9] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_avx512(state[2], state[6], state[10], state[14]);
            state[2] = a;
            state[6] = b;
            state[10] = c;
            state[14] = d;
            let (a, b, c, d) = quarter_round_avx512(state[3], state[7], state[11], state[15]);
            state[3] = a;
            state[7] = b;
            state[11] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_avx512(state[0], state[5], state[10], state[15]);
            state[0] = a;
            state[5] = b;
            state[10] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_avx512(state[1], state[6], state[11], state[12]);
            state[1] = a;
            state[6] = b;
            state[11] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_avx512(state[2], state[7], state[8], state[13]);
            state[2] = a;
            state[7] = b;
            state[8] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_avx512(state[3], state[4], state[9], state[14]);
            state[3] = a;
            state[4] = b;
            state[9] = c;
            state[14] = d;
        }

        for i in 0..16 {
            state[i] = _mm512_add_epi32(state[i], base[i]);
        }

        let mut words = [0u32; 16 * 16];
        for (i, slot) in state.iter().enumerate() {
            _mm512_storeu_si512(words[i * 16..].as_mut_ptr() as *mut __m512i, *slot);
        }

        for lane in 0..16 {
            let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
            for word_idx in 0..16 {
                let word = words[word_idx * 16 + lane];
                let ptr_word = lane_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                core::ptr::write_unaligned(ptr_word, existing ^ word);
            }
        }

        offset += 1024;
    }

    if data.len().saturating_sub(offset) >= 64 {
        while data.len().saturating_sub(offset) >= 64 {
            let block = chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                let dst = chunk_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(dst as *const u64);
                core::ptr::write_unaligned(dst, existing ^ ks);
            }
            offset += 64;
        }
    }

    if offset < data.len() {
        let block = chacha20_block(key, counter, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSE2 (caller ensures, baseline x86_64). All operations are
// register-to-register on by-value __m128i; no memory access. Shift masked to 0..31.
unsafe fn rotl32_sse2(v: core::arch::x86_64::__m128i, n: i32) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;
    let n = ((n as u32) & 31) as i32;
    if n == 0 {
        return v;
    }
    let cnt = _mm_cvtsi32_si128(n);
    let left = _mm_sll_epi32(v, cnt);
    let right = _mm_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
    _mm_or_si128(left, right)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
// SAFETY: requires SSE2 (caller ensures). All operations are register-to-register
// adds, XORs, and rotations on by-value __m128i. rotl32_sse2 has the same
// requirement. No memory access; returns pure register values.
unsafe fn quarter_round_sse2(
    mut a: core::arch::x86_64::__m128i,
    mut b: core::arch::x86_64::__m128i,
    mut c: core::arch::x86_64::__m128i,
    mut d: core::arch::x86_64::__m128i,
) -> (
    core::arch::x86_64::__m128i,
    core::arch::x86_64::__m128i,
    core::arch::x86_64::__m128i,
    core::arch::x86_64::__m128i,
) {
    use core::arch::x86_64::*;
    a = _mm_add_epi32(a, b);
    d = _mm_xor_si128(d, a);
    d = rotl32_sse2(d, 16);

    c = _mm_add_epi32(c, d);
    b = _mm_xor_si128(b, c);
    b = rotl32_sse2(b, 12);

    a = _mm_add_epi32(a, b);
    d = _mm_xor_si128(d, a);
    d = rotl32_sse2(d, 8);

    c = _mm_add_epi32(c, d);
    b = _mm_xor_si128(b, c);
    b = rotl32_sse2(b, 7);

    (a, b, c, d)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
// SAFETY: target_feature gate ensures SSE2. key is &[u8; 32], nonce is &[u8; 12].
// Main loop processes 256-byte chunks; while guard ensures data.len()-offset >= 256.
// _mm_storeu_si128 writes into stack-owned words[] array. Per-lane pointer
// arithmetic: offset + lane*64 + word_idx*4 stays within the 256-byte window.
// Unaligned read/write for data[]. Tail loop handles remaining 64-byte blocks.
unsafe fn xor_keystream_sse2(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    use core::arch::x86_64::*;

    let key_words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    });
    let nonce_words = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= 256 {
        let ctr_lane =
            [counter, counter.wrapping_add(1), counter.wrapping_add(2), counter.wrapping_add(3)];
        counter = counter.wrapping_add(4);

        let base = [
            _mm_set1_epi32(constants[0] as i32),
            _mm_set1_epi32(constants[1] as i32),
            _mm_set1_epi32(constants[2] as i32),
            _mm_set1_epi32(constants[3] as i32),
            _mm_set1_epi32(key_words[0] as i32),
            _mm_set1_epi32(key_words[1] as i32),
            _mm_set1_epi32(key_words[2] as i32),
            _mm_set1_epi32(key_words[3] as i32),
            _mm_set1_epi32(key_words[4] as i32),
            _mm_set1_epi32(key_words[5] as i32),
            _mm_set1_epi32(key_words[6] as i32),
            _mm_set1_epi32(key_words[7] as i32),
            _mm_set_epi32(
                ctr_lane[3] as i32,
                ctr_lane[2] as i32,
                ctr_lane[1] as i32,
                ctr_lane[0] as i32,
            ),
            _mm_set1_epi32(nonce_words[0] as i32),
            _mm_set1_epi32(nonce_words[1] as i32),
            _mm_set1_epi32(nonce_words[2] as i32),
        ];

        let mut state = base;

        for _ in 0..10 {
            let (a, b, c, d) = quarter_round_sse2(state[0], state[4], state[8], state[12]);
            state[0] = a;
            state[4] = b;
            state[8] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_sse2(state[1], state[5], state[9], state[13]);
            state[1] = a;
            state[5] = b;
            state[9] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_sse2(state[2], state[6], state[10], state[14]);
            state[2] = a;
            state[6] = b;
            state[10] = c;
            state[14] = d;
            let (a, b, c, d) = quarter_round_sse2(state[3], state[7], state[11], state[15]);
            state[3] = a;
            state[7] = b;
            state[11] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_sse2(state[0], state[5], state[10], state[15]);
            state[0] = a;
            state[5] = b;
            state[10] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_sse2(state[1], state[6], state[11], state[12]);
            state[1] = a;
            state[6] = b;
            state[11] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_sse2(state[2], state[7], state[8], state[13]);
            state[2] = a;
            state[7] = b;
            state[8] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_sse2(state[3], state[4], state[9], state[14]);
            state[3] = a;
            state[4] = b;
            state[9] = c;
            state[14] = d;
        }

        for i in 0..16 {
            state[i] = _mm_add_epi32(state[i], base[i]);
        }

        let mut words = [0u32; 64];
        for (i, slot) in state.iter().enumerate() {
            _mm_storeu_si128(words[i * 4..].as_mut_ptr() as *mut __m128i, *slot);
        }

        for lane in 0..4 {
            let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
            for word_idx in 0..16 {
                // Layout: words are stored interleaved (structure of arrays).
                let word = words[word_idx * 4 + lane];
                let ptr_word = lane_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                core::ptr::write_unaligned(ptr_word, existing ^ word);
            }
        }

        offset += 256;
    }

    if data.len().saturating_sub(offset) >= 64 {
        while data.len().saturating_sub(offset) >= 64 {
            let block = chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                let dst = chunk_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(dst as *const u64);
                core::ptr::write_unaligned(dst, existing ^ ks);
            }
            offset += 64;
        }
    }

    if offset < data.len() {
        let block = chacha20_block(key, counter, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
// SAFETY: requires SVE2 (caller ensures). All operations are register-to-register
// predicated shifts and OR on by-value svuint32_t. pg is the governing predicate.
// No memory access. n is used as constant shift amount (0..31).
unsafe fn rotl32_sve2(
    pg: std::arch::aarch64::svbool_t,
    v: std::arch::aarch64::svuint32_t,
    n: i32,
) -> std::arch::aarch64::svuint32_t {
    use std::arch::aarch64::*;
    let left = svlsl_n_u32_x(pg, v, n);
    let right = svlsr_n_u32_x(pg, v, 32 - n);
    svorr_u32(left, right)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
// SAFETY: requires SVE2 (caller ensures). All operations are register-to-register
// predicated adds, XORs, and rotations on by-value svuint32_t. rotl32_sve2 has
// the same requirement. No memory access; returns pure register values.
unsafe fn quarter_round_sve2(
    pg: std::arch::aarch64::svbool_t,
    mut a: std::arch::aarch64::svuint32_t,
    mut b: std::arch::aarch64::svuint32_t,
    mut c: std::arch::aarch64::svuint32_t,
    mut d: std::arch::aarch64::svuint32_t,
) -> (
    std::arch::aarch64::svuint32_t,
    std::arch::aarch64::svuint32_t,
    std::arch::aarch64::svuint32_t,
    std::arch::aarch64::svuint32_t,
) {
    use std::arch::aarch64::*;
    a = svadd_u32_x(pg, a, b);
    d = sveor_u32_x(pg, d, a);
    d = rotl32_sve2(pg, d, 16);

    c = svadd_u32_x(pg, c, d);
    b = sveor_u32_x(pg, b, c);
    b = rotl32_sve2(pg, b, 12);

    a = svadd_u32_x(pg, a, b);
    d = sveor_u32_x(pg, d, a);
    d = rotl32_sve2(pg, d, 8);

    c = svadd_u32_x(pg, c, d);
    b = sveor_u32_x(pg, b, c);
    b = rotl32_sve2(pg, b, 7);

    (a, b, c, d)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
// SAFETY: requires SVE2 (caller ensures). active_blocks <= lanes (SVE vector
// width in 32-bit elements). svwhilelt_b32 creates a predicate masking only
// active_blocks lanes. svst1_u32 writes exactly active_blocks * sizeof(u32) per
// call into heap-allocated words[]. Per-lane pointer: offset + lane*64 + word*4
// stays within data.len() because caller guarantees active_blocks * 64 bytes
// available from offset. ptr::read_unaligned/write_unaligned for data XOR.
unsafe fn process_sve2_chunk(
    lanes: usize,
    active_blocks: usize,
    counter: &mut u32,
    constants: &[u32; 4],
    key_words: &[u32; 8],
    nonce_words: &[u32; 3],
    data: &mut [u8],
    offset: usize,
) {
    use core::ptr;
    use std::arch::aarch64::*;

    let pg_active = svwhilelt_b32(0, active_blocks as u64);

    let mut base = [
        svdup_n_u32(constants[0]),
        svdup_n_u32(constants[1]),
        svdup_n_u32(constants[2]),
        svdup_n_u32(constants[3]),
        svdup_n_u32(key_words[0]),
        svdup_n_u32(key_words[1]),
        svdup_n_u32(key_words[2]),
        svdup_n_u32(key_words[3]),
        svdup_n_u32(key_words[4]),
        svdup_n_u32(key_words[5]),
        svdup_n_u32(key_words[6]),
        svdup_n_u32(key_words[7]),
        svdup_n_u32(0),
        svdup_n_u32(nonce_words[0]),
        svdup_n_u32(nonce_words[1]),
        svdup_n_u32(nonce_words[2]),
    ];

    let counter_offsets = svindex_u32(0, 1);
    let ctr_vec = svadd_u32_x(pg_active, svdup_n_u32(*counter), counter_offsets);
    *counter = counter.wrapping_add(active_blocks as u32);

    base[12] = ctr_vec;

    let mut state = base;

    for _ in 0..10 {
        let (a0, b0, c0, d0) =
            quarter_round_sve2(pg_active, state[0], state[4], state[8], state[12]);
        state[0] = a0;
        state[4] = b0;
        state[8] = c0;
        state[12] = d0;

        let (a1, b1, c1, d1) =
            quarter_round_sve2(pg_active, state[1], state[5], state[9], state[13]);
        state[1] = a1;
        state[5] = b1;
        state[9] = c1;
        state[13] = d1;

        let (a2, b2, c2, d2) =
            quarter_round_sve2(pg_active, state[2], state[6], state[10], state[14]);
        state[2] = a2;
        state[6] = b2;
        state[10] = c2;
        state[14] = d2;

        let (a3, b3, c3, d3) =
            quarter_round_sve2(pg_active, state[3], state[7], state[11], state[15]);
        state[3] = a3;
        state[7] = b3;
        state[11] = c3;
        state[15] = d3;

        let (a4, b4, c4, d4) =
            quarter_round_sve2(pg_active, state[0], state[5], state[10], state[15]);
        state[0] = a4;
        state[5] = b4;
        state[10] = c4;
        state[15] = d4;

        let (a5, b5, c5, d5) =
            quarter_round_sve2(pg_active, state[1], state[6], state[11], state[12]);
        state[1] = a5;
        state[6] = b5;
        state[11] = c5;
        state[12] = d5;

        let (a6, b6, c6, d6) =
            quarter_round_sve2(pg_active, state[2], state[7], state[8], state[13]);
        state[2] = a6;
        state[7] = b6;
        state[8] = c6;
        state[13] = d6;

        let (a7, b7, c7, d7) =
            quarter_round_sve2(pg_active, state[3], state[4], state[9], state[14]);
        state[3] = a7;
        state[4] = b7;
        state[9] = c7;
        state[14] = d7;
    }

    for i in 0..16 {
        state[i] = svadd_u32_x(pg_active, state[i], base[i]);
    }

    let mut words = vec![0u32; lanes * 16];
    for (idx, slot) in state.iter().enumerate() {
        let ptr = words[idx * lanes..].as_mut_ptr();
        svst1_u32(pg_active, ptr, *slot);
    }

    for lane in 0..active_blocks {
        let lane_offset = offset + lane * 64;
        let lane_ptr = data.as_mut_ptr().add(lane_offset) as *mut u32;
        for word_idx in 0..16 {
            let ks = words[word_idx * lanes + lane];
            let dst = lane_ptr.add(word_idx);
            let current = ptr::read_unaligned(dst);
            ptr::write_unaligned(dst, current ^ ks);
        }
    }
}

#[cfg(target_arch = "aarch64")]
// SAFETY: caller verified SVE2 at runtime. Dispatches to xor_keystream_sve2_impl
// (with target_feature gate) or falls back to xor_keystream_neon. All args are
// borrowed slices with valid provenance.
unsafe fn xor_keystream_sve2(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    #[cfg(target_feature = "sve2")]
    {
        xor_keystream_sve2_impl(key, counter, nonce, data);
        return;
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        xor_keystream_neon(key, counter, nonce, data);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
// SAFETY: target_feature gate ensures SVE2. svcntw() returns SVE vector width
// in 32-bit elements (>= 4). Main loop delegates to process_sve2_chunk which
// processes min(remaining_blocks, lanes) blocks per iteration. Tail loops use
// scalar chacha20_block with ptr::read/write_unaligned bounded by offset guards.
unsafe fn xor_keystream_sve2_impl(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    use core::arch::aarch64::*;
    use core::ptr;

    let lanes = svcntw() as usize;
    if lanes == 0 {
        xor_keystream_neon(key, counter, nonce, data);
        return;
    }

    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let key_words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    });
    let nonce_words = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let mut offset = 0usize;
    let mut ctr = counter;

    while data.len().saturating_sub(offset) >= 64 {
        let remaining_blocks = (data.len() - offset) / 64;
        if remaining_blocks == 0 {
            break;
        }
        let active_blocks = remaining_blocks.min(lanes);
        process_sve2_chunk(
            lanes,
            active_blocks,
            &mut ctr,
            &constants,
            &key_words,
            &nonce_words,
            data,
            offset,
        );
        offset += active_blocks * 64;
        if remaining_blocks <= lanes {
            break;
        }
    }

    while data.len().saturating_sub(offset) >= 64 {
        let block = chacha20_block(key, ctr, nonce);
        ctr = ctr.wrapping_add(1);
        let chunk = &mut data[offset..offset + 64];
        let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
        let block_ptr = block.as_ptr() as *const u64;
        for word_idx in 0..8 {
            let ks = ptr::read_unaligned(block_ptr.add(word_idx));
            let dst = chunk_ptr.add(word_idx);
            let current = ptr::read_unaligned(dst as *const u64);
            ptr::write_unaligned(dst, current ^ ks);
        }
        offset += 64;
    }

    if offset < data.len() {
        let block = chacha20_block(key, ctr, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). Register-to-register shift + OR
// on by-value uint32x4_t; no memory access.
unsafe fn rotl32_neon_16(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    vorrq_u32(vshlq_n_u32(v, 16), vshrq_n_u32(v, 16))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). Register-to-register shift + OR
// on by-value uint32x4_t; no memory access.
unsafe fn rotl32_neon_12(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). Register-to-register shift + OR
// on by-value uint32x4_t; no memory access.
unsafe fn rotl32_neon_8(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    vorrq_u32(vshlq_n_u32(v, 8), vshrq_n_u32(v, 24))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). Register-to-register shift + OR
// on by-value uint32x4_t; no memory access.
unsafe fn rotl32_neon_7(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
    use core::arch::aarch64::*;
    vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
// SAFETY: requires NEON (baseline aarch64). All operations are register-to-register
// adds, XORs, and rotations on by-value uint32x4_t. rotl32_neon_* helpers have
// the same requirement. No memory access; returns pure register values.
unsafe fn quarter_round_neon(
    mut a: core::arch::aarch64::uint32x4_t,
    mut b: core::arch::aarch64::uint32x4_t,
    mut c: core::arch::aarch64::uint32x4_t,
    mut d: core::arch::aarch64::uint32x4_t,
) -> (
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
    core::arch::aarch64::uint32x4_t,
) {
    use core::arch::aarch64::*;
    a = vaddq_u32(a, b);
    d = veorq_u32(d, a);
    d = rotl32_neon_16(d);

    c = vaddq_u32(c, d);
    b = veorq_u32(b, c);
    b = rotl32_neon_12(b);

    a = vaddq_u32(a, b);
    d = veorq_u32(d, a);
    d = rotl32_neon_8(d);

    c = vaddq_u32(c, d);
    b = veorq_u32(b, c);
    b = rotl32_neon_7(b);

    (a, b, c, d)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
// SAFETY: target_feature gate ensures NEON. key is &[u8; 32], nonce is &[u8; 12].
// Main loop processes 256-byte chunks (4 x 64-byte blocks); while guard ensures
// data.len()-offset >= 256. vld1q_u32 / vst1q_u32 operate on stack-owned
// arrays. Per-lane pointer arithmetic stays within the 256-byte window.
// Unaligned ptr::read/write for data XOR. Tail handles remaining blocks.
unsafe fn xor_keystream_neon(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    use core::arch::aarch64::*;

    let key_words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    });
    let nonce_words = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= 256 {
        let ctr_lane =
            [counter, counter.wrapping_add(1), counter.wrapping_add(2), counter.wrapping_add(3)];
        counter = counter.wrapping_add(4);

        let ctr_words = ctr_lane;
        let base = [
            vdupq_n_u32(constants[0]),
            vdupq_n_u32(constants[1]),
            vdupq_n_u32(constants[2]),
            vdupq_n_u32(constants[3]),
            vdupq_n_u32(key_words[0]),
            vdupq_n_u32(key_words[1]),
            vdupq_n_u32(key_words[2]),
            vdupq_n_u32(key_words[3]),
            vdupq_n_u32(key_words[4]),
            vdupq_n_u32(key_words[5]),
            vdupq_n_u32(key_words[6]),
            vdupq_n_u32(key_words[7]),
            vld1q_u32(ctr_words.as_ptr()),
            vdupq_n_u32(nonce_words[0]),
            vdupq_n_u32(nonce_words[1]),
            vdupq_n_u32(nonce_words[2]),
        ];

        let mut state = base;

        for _ in 0..10 {
            let (a, b, c, d) = quarter_round_neon(state[0], state[4], state[8], state[12]);
            state[0] = a;
            state[4] = b;
            state[8] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_neon(state[1], state[5], state[9], state[13]);
            state[1] = a;
            state[5] = b;
            state[9] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_neon(state[2], state[6], state[10], state[14]);
            state[2] = a;
            state[6] = b;
            state[10] = c;
            state[14] = d;
            let (a, b, c, d) = quarter_round_neon(state[3], state[7], state[11], state[15]);
            state[3] = a;
            state[7] = b;
            state[11] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_neon(state[0], state[5], state[10], state[15]);
            state[0] = a;
            state[5] = b;
            state[10] = c;
            state[15] = d;
            let (a, b, c, d) = quarter_round_neon(state[1], state[6], state[11], state[12]);
            state[1] = a;
            state[6] = b;
            state[11] = c;
            state[12] = d;
            let (a, b, c, d) = quarter_round_neon(state[2], state[7], state[8], state[13]);
            state[2] = a;
            state[7] = b;
            state[8] = c;
            state[13] = d;
            let (a, b, c, d) = quarter_round_neon(state[3], state[4], state[9], state[14]);
            state[3] = a;
            state[4] = b;
            state[9] = c;
            state[14] = d;
        }

        for i in 0..16 {
            state[i] = vaddq_u32(state[i], base[i]);
        }

        let mut words = [0u32; 64];
        for (i, slot) in state.iter().enumerate() {
            vst1q_u32(words[i * 4..].as_mut_ptr(), *slot);
        }

        for lane in 0..4 {
            let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
            for word_idx in 0..16 {
                let word = words[word_idx * 4 + lane];
                let ptr_word = lane_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                core::ptr::write_unaligned(ptr_word, existing ^ word);
            }
        }

        offset += 256;
    }

    if data.len().saturating_sub(offset) >= 64 {
        while data.len().saturating_sub(offset) >= 64 {
            let block = super::chacha::chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                let dst = chunk_ptr.add(word_idx);
                let existing = core::ptr::read_unaligned(dst as *const u64);
                core::ptr::write_unaligned(dst, existing ^ ks);
            }
            offset += 64;
        }
    }

    if offset < data.len() {
        let block = super::chacha::chacha20_block(key, counter, nonce);
        for (i, byte) in data[offset..].iter_mut().enumerate() {
            *byte ^= block[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_block_rfc7539_test_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] =
            [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(block[0], 0x10);
        assert_eq!(block[1], 0xf1);
        assert_eq!(block[2], 0xe7);
        assert_eq!(block[3], 0xe4);
    }

    #[test]
    fn chacha20_block_different_counters_differ() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        assert_ne!(chacha20_block(&key, 0, &nonce), chacha20_block(&key, 1, &nonce));
    }

    #[test]
    fn chacha20_block_deterministic() {
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        assert_eq!(chacha20_block(&key, 42, &nonce), chacha20_block(&key, 42, &nonce));
    }

    #[test]
    fn xor_keystream_empty_noop() {
        let mut data = [];
        xor_keystream_in_place(&[0u8; 32], 0, &[0u8; 12], &mut data);
    }

    #[test]
    fn xor_keystream_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];
        let original = b"Hello ChaCha20 test!".to_vec();
        let mut data = original.clone();
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_ne!(&data[..], &original[..]);
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn xor_keystream_multi_block_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x77u8; 12];
        let original = vec![0xAA; 200];
        let mut data = original.clone();
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_ne!(data, original);
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn xor_keystream_exact_block_matches_block_fn() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let mut data = vec![0; 64];
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_eq!(&data[..], &chacha20_block(&key, 0, &nonce)[..]);
    }

    #[test]
    fn xor_keystream_partial_block() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let mut data = vec![0; 10];
        xor_keystream_in_place(&key, 0, &nonce, &mut data);
        assert_eq!(&data[..], &chacha20_block(&key, 0, &nonce)[..10]);
    }

    #[test]
    fn initial_state_has_correct_constants() {
        let state = initial_state(&[0u8; 32], 0, &[0u8; 12]);
        assert_eq!(state[0], 0x61707865);
        assert_eq!(state[1], 0x3320646e);
        assert_eq!(state[2], 0x79622d32);
        assert_eq!(state[3], 0x6b206574);
        assert_eq!(state[12], 0);
    }

    #[test]
    fn quarter_round_transforms_state() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;
        let before = state;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_ne!(state, before);
    }
}

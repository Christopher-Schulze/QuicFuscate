#![cfg(feature = "rust-tests")]
#[cfg(target_arch = "x86_64")]
#[test]
fn chacha20_x16_matches_scalar_when_avx512() {
    if !std::arch::is_x86_feature_detected!("avx512f") {
        eprintln!("SIMD_SKIP test=chacha20_x16_matches_scalar_when_avx512 required=avx512f");
        return;
    }
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let ctr = 12345u32;
    let blocks = quicfuscate::optimize::crypto::chacha20_blocks_x16(&key, &nonce, ctr);
    for i in 0..16 {
        let scalar =
            quicfuscate::crypto::chacha::chacha20_block(&key, ctr.wrapping_add(i as u32), &nonce);
        assert_eq!(scalar, blocks[i]);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_chacha20_x16_parity_on_non_x86_64() {}

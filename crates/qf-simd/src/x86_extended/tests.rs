use super::*;
use crate::qpack;
use std::is_x86_feature_detected;

const SAMPLES: &[&[u8]] = &[
    b"",
    b"quicfuscate",
    b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    b"content-type: application/json\r\nacceptable: */*\r\n",
];

fn report_simd_skip(test: &str, required: &str) {
    eprintln!("SIMD_SKIP test={test} required={required}");
}

#[test]
fn qpack_avx2_matches_scalar() {
    if !is_x86_feature_detected!("avx2") {
        report_simd_skip("qpack_avx2_matches_scalar", "avx2");
        return;
    }

    let mut all_symbols_storage = vec![0xAA];
    all_symbols_storage.extend(0..=u8::MAX);
    let all_symbols = &all_symbols_storage[1..];

    for sample in SAMPLES.iter().copied().chain(std::iter::once(all_symbols)) {
        let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
        let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
        scalar_buf.truncate(scalar_len);

        let mut avx_buf = vec![0u8; scalar_len + 8];
        let avx_len = unsafe { qpack_encode_avx2(sample, &mut avx_buf) };
        avx_buf.truncate(avx_len);

        assert_eq!(scalar_buf, avx_buf);

        let mut decode_buf = vec![0u8; sample.len() + 8];
        let decoded = unsafe { qpack_decode_avx2(&avx_buf, &mut decode_buf) };
        assert_eq!(&decode_buf[..decoded], sample);
    }
}

#[test]
fn qpack_ssse3_matches_scalar() {
    if !is_x86_feature_detected!("ssse3") || !is_x86_feature_detected!("sse4.1") {
        report_simd_skip("qpack_ssse3_matches_scalar", "ssse3+sse4.1");
        return;
    }

    let mut all_symbols_storage = vec![0xAA];
    all_symbols_storage.extend(0..=u8::MAX);
    let all_symbols = &all_symbols_storage[1..];

    for sample in SAMPLES.iter().copied().chain(std::iter::once(all_symbols)) {
        let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
        let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
        scalar_buf.truncate(scalar_len);

        let mut sse_buf = vec![0u8; scalar_len + 8];
        let sse_len = unsafe { qpack_encode_ssse3(sample, &mut sse_buf) };
        sse_buf.truncate(sse_len);

        assert_eq!(scalar_buf, sse_buf);

        let mut decode_buf = vec![0u8; sample.len() + 8];
        let decoded = unsafe { qpack_decode_ssse3(&sse_buf, &mut decode_buf) };
        assert_eq!(&decode_buf[..decoded], sample);
    }
}

#[test]
fn avx2_rs_encode_and_decode_roundtrip_with_tail() {
    if !is_x86_feature_detected!("avx2") {
        report_simd_skip("avx2_rs_encode_and_decode_roundtrip_with_tail", "avx2");
        return;
    }

    let data: Vec<u8> =
        (0..512).map(|index| (index as u8).wrapping_mul(37).wrapping_add(9)).collect();
    let scalar = crate::scalar::reed_solomon_encode_scalar(&data, 2);
    let avx2 = unsafe { reed_solomon_encode_avx2(&data, 2) };
    assert_eq!(avx2, scalar);

    let shard_size = 65;
    let available = vec![avx2[..shard_size].to_vec(), avx2[512..512 + shard_size].to_vec()];
    let decoded =
        unsafe { reed_solomon_decode_avx2(&available, &[0, 2]) }.expect("AVX2 Reed-Solomon decode");
    let expected = [avx2[..shard_size].to_vec(), avx2[256..256 + shard_size].to_vec()].concat();
    assert_eq!(decoded, expected);
}

#[test]
fn avx2_rs_decode_validates_shard_metadata() {
    if !is_x86_feature_detected!("avx2") {
        report_simd_skip("avx2_rs_decode_validates_shard_metadata", "avx2");
        return;
    }

    let shards = vec![vec![0u8; 65]];
    assert_eq!(
        unsafe { reed_solomon_decode_avx2(&shards, &[]) },
        Err("Shard/index length mismatch")
    );

    let mismatched = vec![vec![0u8; 65], vec![0u8; 64]];
    assert_eq!(
        unsafe { reed_solomon_decode_avx2(&mismatched, &[0, 1]) },
        Err("Shard size mismatch")
    );
}

#[test]
fn avx2_gf256_matmul_matches_scalar_for_all_byte_positions() {
    if !is_x86_feature_detected!("avx2") {
        report_simd_skip("avx2_gf256_matmul_matches_scalar_for_all_byte_positions", "avx2");
        return;
    }

    let a = [0x57, 0xA3];
    let b: Vec<u8> = (0..130).map(|index| (index as u8).wrapping_mul(19).wrapping_add(7)).collect();
    let mut scalar_output = vec![0u8; 65];
    let mut avx2_output = vec![0u8; 65];
    crate::scalar::matmul_gf256(&a, &b, &mut scalar_output, 1, 2, 65);
    unsafe { matmul_gf256_avx2(&a, &b, &mut avx2_output, 1, 2, 65) };
    assert_eq!(avx2_output, scalar_output);
}

#[test]
fn avx2_matmul_rejects_invalid_dimensions_and_slices() {
    if !is_x86_feature_detected!("avx2") {
        report_simd_skip("avx2_matmul_rejects_invalid_dimensions_and_slices", "avx2");
        return;
    }

    let mut output = vec![0xA5; 4];
    unsafe { matmul_gf256_avx2(&[1], &[1, 2, 3, 4], &mut output, 2, 1, 2) };
    assert_eq!(output, vec![0xA5; 4]);

    unsafe { matmul_gf256_avx2(&[1, 2], &[1], &mut output, 1, 2, 2) };
    assert_eq!(output, vec![0xA5; 4]);

    let mut short_output = vec![0xA5; 1];
    unsafe { matmul_gf256_avx2(&[1, 2], &[1, 2, 3, 4], &mut short_output, 1, 2, 2) };
    assert_eq!(short_output, vec![0xA5]);

    unsafe { matmul_gf256_avx2(&[], &[], &mut output, usize::MAX, 2, 1) };
    assert_eq!(output, vec![0xA5; 4]);
}

#[test]
fn gfni_matmul_rejects_invalid_dimensions_and_slices() {
    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("gfni") {
        report_simd_skip("gfni_matmul_rejects_invalid_dimensions_and_slices", "avx512f+gfni");
        return;
    }

    let mut output = vec![0xA5; 4];
    unsafe { matmul_gf256_gfni(&[1], &[1, 2, 3, 4], &mut output, 2, 1, 2) };
    assert_eq!(output, vec![0xA5; 4]);

    unsafe { matmul_gf256_gfni(&[1, 2], &[1], &mut output, 1, 2, 2) };
    assert_eq!(output, vec![0xA5; 4]);

    let mut short_output = vec![0xA5; 1];
    unsafe { matmul_gf256_gfni(&[1, 2], &[1, 2, 3, 4], &mut short_output, 1, 2, 2) };
    assert_eq!(short_output, vec![0xA5]);

    unsafe { matmul_gf256_gfni(&[], &[], &mut output, usize::MAX, 2, 1) };
    assert_eq!(output, vec![0xA5; 4]);
}

#[test]
fn berlekamp_massey_x86_entries_reject_overlong_prefixes() {
    let syndrome = [1u8, 2, 3];

    if is_x86_feature_detected!("avx2") {
        assert!(unsafe { berlekamp_massey_avx2(&syndrome, 4) }.is_empty());
        assert!(unsafe { berlekamp_massey_avx2(&syndrome, usize::MAX) }.is_empty());
    } else {
        report_simd_skip("berlekamp_massey_x86_entries_reject_overlong_prefixes", "avx2");
    }
    if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni") {
        assert!(unsafe { berlekamp_massey_gfni(&syndrome, 4) }.is_empty());
        assert!(unsafe { berlekamp_massey_gfni(&syndrome, usize::MAX) }.is_empty());
    } else {
        report_simd_skip("berlekamp_massey_x86_entries_reject_overlong_prefixes", "avx512f+gfni");
    }
}

#[test]
fn bmi2_varint_rejects_short_output_and_preserves_leb128_bytes() {
    if !is_x86_feature_detected!("bmi2") {
        report_simd_skip("bmi2_varint_rejects_short_output_and_preserves_leb128_bytes", "bmi2");
        return;
    }

    for value in [0, 127, 128, 16_383, 16_384, u64::MAX] {
        let mut expected = Vec::new();
        let mut remaining = value;
        while remaining >= 128 {
            expected.push((remaining as u8 & 0x7F) | 0x80);
            remaining >>= 7;
        }
        expected.push(remaining as u8);

        for short_len in 0..expected.len() {
            let mut output = vec![0xA5; short_len];
            let before = output.clone();
            assert_eq!(unsafe { varint_encode_bmi2(value, &mut output) }, 0);
            assert_eq!(output, before, "value {value}, short length {short_len}");
        }

        let mut output = vec![0u8; expected.len()];
        let written = unsafe { varint_encode_bmi2(value, &mut output) };
        assert_eq!(written, expected.len());
        assert_eq!(output, expected, "value {value}");
    }
}

#[test]
fn gfni_rs_encode_preserves_partial_input_shard() {
    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("gfni") {
        report_simd_skip("gfni_rs_encode_preserves_partial_input_shard", "avx512f+gfni");
        return;
    }

    let data: Vec<u8> =
        (0..257).map(|index| (index as u8).wrapping_mul(23).wrapping_add(5)).collect();
    let scalar = crate::scalar::reed_solomon_encode_scalar(&data, 2);
    let gfni = unsafe { reed_solomon_encode_gfni(&data, 2) };

    assert_eq!(gfni, scalar);
    assert_eq!(&gfni[..data.len()], data.as_slice());
    assert!(gfni[data.len()..2 * 256].iter().all(|&byte| byte == 0));
}

#[test]
fn gfni_rs_encode_and_decode_roundtrip_with_tail() {
    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("gfni") {
        report_simd_skip("gfni_rs_encode_and_decode_roundtrip_with_tail", "avx512f+gfni");
        return;
    }

    let data: Vec<u8> =
        (0..512).map(|index| (index as u8).wrapping_mul(41).wrapping_add(3)).collect();
    let scalar = crate::scalar::reed_solomon_encode_scalar(&data, 2);
    let gfni = unsafe { reed_solomon_encode_gfni(&data, 2) };
    assert_eq!(gfni, scalar);

    let shard_size = 65;
    let available = vec![gfni[..shard_size].to_vec(), gfni[512..512 + shard_size].to_vec()];
    let decoded =
        unsafe { reed_solomon_decode_gfni(&available, &[0, 2]) }.expect("GFNI Reed-Solomon decode");
    let expected = [gfni[..shard_size].to_vec(), gfni[256..256 + shard_size].to_vec()].concat();
    assert_eq!(decoded, expected);
}

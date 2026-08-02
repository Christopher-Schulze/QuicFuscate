//! Extracted SIMD `tests` submodule (TODO-563).

use super::fec::validate_header;
use super::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn scalar_encode_quic_varint(mut val: u64, buf: &mut [u8]) -> usize {
    let (len, prefix): (usize, u8) = if val < (1u64 << 6) {
        (1, 0b00)
    } else if val < (1u64 << 14) {
        (2, 0b01)
    } else if val < (1u64 << 30) {
        (4, 0b10)
    } else if val < (1u64 << 62) {
        (8, 0b11)
    } else {
        return 0;
    };

    if buf.len() < len {
        return 0;
    }

    match len {
        1 => {
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        2 => {
            buf[1] = (val & 0xFF) as u8;
            val >>= 8;
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        4 => {
            for i in (1..4).rev() {
                buf[i] = (val & 0xFF) as u8;
                val >>= 8;
            }
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        8 => {
            for i in (1..8).rev() {
                buf[i] = (val & 0xFF) as u8;
                val >>= 8;
            }
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        _ => {
            debug_assert!(false, "invalid varint encoded length");
            return 0;
        }
    }
    len
}

fn scalar_decode_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            debug_assert!(false, "invalid QUIC varint prefix");
            return None;
        }
    };
    if buf.len() < len {
        return None;
    }

    let mut value = (first & 0x3F) as u64;
    for byte in buf.iter().take(len).skip(1) {
        value = (value << 8) | (*byte as u64);
    }
    Some((value, len))
}

fn reference_validate_header(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    let first = header[0];
    if (first & 0x40) == 0 {
        return false;
    }
    if (first & 0x80) != 0 {
        // Long header: only fixed bit enforced here.
        true
    } else {
        // Short header: reserved bits (0x18) must be zero.
        (first & 0x18) == 0
    }
}

#[test]
fn neon_validate_header_semantics_examples() {
    // Long header: 0xC0 (0x80 long + fixed bit 0x40) -> valid
    let long_ok = [0xC0u8, 0, 0, 0, 0];
    assert!(validate_header(&long_ok));
    assert!(unsafe { super::arm::validate_header_neon(&long_ok) });

    // Short header: fixed set (0x40), reserved zero -> valid
    let short_ok = [0x40u8, 0, 0, 0, 0];
    assert!(validate_header(&short_ok));
    assert!(unsafe { super::arm::validate_header_neon(&short_ok) });

    // Short header: fixed set but reserved bits (0x18) non-zero -> invalid
    let short_reserved = [0x50u8, 0, 0, 0, 0]; // 0x40 + 0x10
    assert!(!validate_header(&short_reserved));
    assert!(!unsafe { super::arm::validate_header_neon(&short_reserved) });

    // Missing fixed bit -> invalid
    let no_fixed = [0x00u8, 0, 0, 0, 0];
    assert!(!validate_header(&no_fixed));
    assert!(!unsafe { super::arm::validate_header_neon(&no_fixed) });
}

#[test]
fn neon_validate_header_random_parity() {
    let mut rng = StdRng::seed_from_u64(0xA1B2_C3D4_E5F6_0718);
    for _ in 0..512 {
        let mut header = [0u8; 64];
        rng.fill(&mut header[..]);
        let scalar = reference_validate_header(&header);
        let neon = unsafe { super::arm::validate_header_neon(&header) };
        assert_eq!(
            scalar,
            neon,
            "NEON header mismatch: scalar={}, neon={}, bytes={:02x?}",
            scalar,
            neon,
            &header[..8.min(header.len())]
        );
        #[cfg(target_feature = "sve2")]
        {
            if FeatureDetector::instance().has_feature(crate::optimize::CpuFeature::SVE2) {
                let sve = unsafe { super::arm::validate_header_sve2(&header) };
                assert_eq!(scalar, sve, "SVE2 header mismatch for prefix {:02x}", header[0]);
            }
        }
    }
}

#[test]
fn neon_varint_random_parity() {
    let mut rng = StdRng::seed_from_u64(0x0F0E_0D0C_0B0A_0908);
    for _ in 0..1024 {
        let val = rng.random::<u64>() & ((1u64 << 62) - 1);
        let mut buf_scalar = [0u8; 16];
        let mut buf_neon = [0u8; 16];
        let len_scalar = scalar_encode_quic_varint(val, &mut buf_scalar);
        let len_neon = crate::simd::arm_varint::encode_varint_neon(val, &mut buf_neon);
        assert_eq!(len_scalar, len_neon, "encode len mismatch for {val}");
        assert_eq!(&buf_scalar[..len_scalar], &buf_neon[..len_neon]);

        let (dec_scalar, used_scalar) =
            scalar_decode_quic_varint(&buf_scalar[..len_scalar]).expect("scalar decode");
        let (dec_neon, used_neon) =
            crate::simd::arm_varint::decode_varint_neon(&buf_neon[..len_neon])
                .expect("neon decode");
        assert_eq!(dec_scalar, dec_neon, "decode mismatch for {val}");
        assert_eq!(used_scalar, used_neon, "decode len mismatch for {val}");

        #[cfg(target_feature = "sve2")]
        {
            if FeatureDetector::instance().has_feature(crate::optimize::CpuFeature::SVE2) {
                let mut buf_sve = [0u8; 16];
                let len_sve = crate::simd::arm_varint::encode_varint_sve2(val, &mut buf_sve);
                assert_eq!(len_scalar, len_sve, "SVE2 encode len mismatch for {val}");
                assert_eq!(&buf_scalar[..len_scalar], &buf_sve[..len_sve]);
                let (dec_sve, used_sve) =
                    crate::simd::arm_varint::decode_varint_sve2(&buf_sve[..len_sve])
                        .expect("sve2 decode");
                assert_eq!(dec_scalar, dec_sve, "SVE2 decode mismatch for {val}");
                assert_eq!(used_scalar, used_sve, "SVE2 decode len mismatch for {val}");
            }
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_rs_neon {
    #[test]
    fn neon_rs_encode_matches_scalar() {
        // Two data shards (512 bytes), two parity shards
        let mut data = vec![0u8; 512];
        for (i, v) in data.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let scalar = super::scalar::reed_solomon_encode_scalar(&data, 2);
        let neon = unsafe { super::arm::reed_solomon_encode_neon(&data, 2) };
        assert_eq!(scalar, neon);
    }

    #[test]
    fn neon_rs_encode_preserves_partial_input_shard() {
        let data: Vec<u8> =
            (0..257).map(|index| (index as u8).wrapping_mul(29).wrapping_add(11)).collect();

        let scalar = super::scalar::reed_solomon_encode_scalar(&data, 2);
        let neon = unsafe { super::arm::reed_solomon_encode_neon(&data, 2) };

        assert_eq!(neon, scalar);
        assert_eq!(&neon[..data.len()], data.as_slice());
        assert!(neon[data.len()..2 * 256].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn neon_bitpack_roundtrip_matches_scalar() {
        let mut src = vec![0u8; 257];
        for (i, v) in src.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(13).wrapping_add(5);
        }

        for bw in 1u8..=8 {
            let mut packed_scalar = vec![0u8; 512];
            let mut unpack_scalar = vec![0u8; src.len()];
            let used = super::scalar::pack_bits(&src, bw, &mut packed_scalar);
            super::scalar::unpack_bits(&packed_scalar[..used], bw, &mut unpack_scalar);

            let mut packed_neon = vec![0u8; 512];
            let mut unpack_neon = vec![0u8; src.len()];
            let used_neon = unsafe { super::arm::pack_bits_neon(&src, bw, &mut packed_neon) };
            unsafe {
                super::arm::unpack_bits_neon(&packed_neon[..used_neon], bw, &mut unpack_neon)
            };

            assert_eq!(unpack_scalar, unpack_neon, "bit-width {}", bw);
        }
    }

    #[test]
    fn neon_popcnt_matches_scalar() {
        let mut data = vec![0u8; 4096];
        for (i, v) in data.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(97).wrapping_add(33);
        }
        let scalar = super::scalar::popcnt(&data);
        let neon = unsafe { super::arm::popcnt_neon(&data) };
        assert_eq!(scalar, neon);
    }
}

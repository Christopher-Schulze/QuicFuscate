//! Extracted SIMD `tests_arm` submodule (TODO-563).

use super::*;
use crate::transport::h3::qpack;
use std::arch::is_aarch64_feature_detected;

const SAMPLES: &[&[u8]] = &[
    b"",
    b"quicfuscate",
    b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    b"content-type: application/json\r\nacceptable: */*\r\n",
];

#[test]
fn qpack_neon_matches_scalar() {
    if !is_aarch64_feature_detected!("neon") {
        return;
    }

    for sample in SAMPLES {
        let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
        let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
        scalar_buf.truncate(scalar_len);

        let mut neon_buf = vec![0u8; scalar_len + 8];
        let neon_len = arm::qpack_encode_neon(sample, &mut neon_buf);
        neon_buf.truncate(neon_len);

        assert_eq!(neon_buf, scalar_buf);

        let mut decode_buf = vec![0u8; sample.len() + 8];
        let decoded = arm::qpack_decode_neon(&neon_buf, &mut decode_buf);
        decode_buf.truncate(decoded);

        let mut scalar_decode = vec![0u8; sample.len() + 8];
        let scalar_decoded = qpack::huff_decode_into(&scalar_buf, &mut scalar_decode).unwrap();
        scalar_decode.truncate(scalar_decoded);

        assert_eq!(decode_buf, scalar_decode);
    }
}
